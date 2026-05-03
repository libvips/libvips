/* Fuzz the complete libvips operation API.
 *
 * This exercises the operation dispatch, argument parsing, and execution
 * paths for all operations, similar to the standalone vips CLI tool.
 *
 * Input format:
 *   Line 1: operation name (e.g. "invert", "add", "embed")
 *   Lines 2..N: required non-image argument strings, one per line
 *   Lines N+1..M: optional arguments as "--name=value", one per line
 *   Remaining bytes: raw image data (decoded via vips_image_new_from_buffer)
 */

#include "config.h"

#include "vips_fuzzer_common.h"

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (VIPS_INIT(*argv[0]))
		return -1;

	vips_concurrency_set(1);
	vips_cache_set_max(0);

	FuzzApplyBlocklist();

	return 0;
}

// Force evaluation of required output images.
static void *
EvalRequiredOutput(VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b)
{
	GType type = G_PARAM_SPEC_VALUE_TYPE(pspec);

	if (!(argument_class->flags & VIPS_ARGUMENT_REQUIRED) ||
		!(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ||
		!(argument_class->flags & VIPS_ARGUMENT_OUTPUT) ||
		(argument_class->flags & VIPS_ARGUMENT_DEPRECATED))
		return nullptr;

	if (g_type_is_a(type, VIPS_TYPE_IMAGE)) {
		VipsImage *out;
		const char *name = g_param_spec_get_name(pspec);

		g_object_get(object, name, &out, nullptr);
		if (out) {
			// Sanity-check output dimensions to avoid OOM.
			if (out->Xsize <= 10000 &&
				out->Ysize <= 10000 &&
				out->Bands <= 256) {
				double d;
				vips_min(out, &d, nullptr);
			}
			g_object_unref(out);
		}
	}

	return nullptr;
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	VipsOperation *operation;
	VipsOperationFlags op_flags;
	VipsAccess access;
	FuzzCtx ctx = {};
	char *op_name;
	int i;

	// Extract the operation name from the first line.
	op_name = FuzzExtractLine(&data, &size);
	if (!op_name)
		return 0;

	// Create the operation.
	operation = vips_operation_new(op_name);
	g_free(op_name);
	if (!operation)
		return 0;

	op_flags = vips_operation_get_flags(operation);

	// Skip deprecated or blocked operations.
	if ((op_flags & VIPS_OPERATION_DEPRECATED) ||
		(op_flags & VIPS_OPERATION_BLOCKED)) {
		g_object_unref(operation);
		return 0;
	}

	access = op_flags & VIPS_OPERATION_SEQUENTIAL
		? VIPS_ACCESS_SEQUENTIAL
		: VIPS_ACCESS_RANDOM;

	// Count how many string-valued required input args we need.
	vips_argument_map(VIPS_OBJECT(operation),
		FuzzCountStringArgs, &ctx.n_string_args, nullptr);

	// Parse that many lines from the fuzzer data.
	ctx.string_args = g_new0(char *, VIPS_MAX(ctx.n_string_args, 1));
	for (i = 0; i < ctx.n_string_args; i++) {
		ctx.string_args[i] = FuzzExtractLine(&data, &size);
		if (!ctx.string_args[i]) {
			for (int j = 0; j < i; j++)
				g_free(ctx.string_args[j]);
			g_free(ctx.string_args);
			g_object_unref(operation);
			return 0;
		}
	}

	// Get the option_string from the input
	const guint8 *save_data = data;
	size_t save_size = size;
	char *line = FuzzExtractLine(&data, &size);
	char *option_string;
	if (line && line[0] == '[') {
		option_string = line;
	} else {
		// Not an option_string -- put the data back.
		g_free(line);
		data = save_data;
		size = save_size;
		option_string = g_strdup("");
	}

	// Parse optional arguments (lines starting with "--").
	char *opt_names[MAX_OPTIONAL_ARGS];
	char *opt_values[MAX_OPTIONAL_ARGS];
	int n_optional = 0;

	while (n_optional < MAX_OPTIONAL_ARGS) {
		// Peek at the next line without consuming it.
		const guint8 *save_data = data;
		size_t save_size = size;
		char *line = FuzzExtractLine(&data, &size);

		if (!line)
			break;

		if (line[0] != '-' || line[1] != '-') {
			// Not an optional arg -- put the data back.
			g_free(line);
			data = save_data;
			size = save_size;
			break;
		}

		// Split "--name=value"
		char *eq = strchr(line + 2, '=');
		if (eq) {
			*eq = '\0';
			opt_names[n_optional] = g_strdup(line + 2);
			opt_values[n_optional] = g_strdup(eq + 1);
			n_optional++;
		}

		g_free(line);
	}

	// Stash the remaining bytes so FuzzEnsureInputFile() can lazily
	// materialise them to a /tmp file if a load op actually needs one.
	ctx.pending_data = data;
	ctx.pending_size = size;

	// Try to load an image from the remaining data.
	if (size > 0 &&
		((ctx.source = vips_source_new_from_memory(data, size))) &&
		(!(ctx.image = vips_image_new_from_source(ctx.source, option_string,
			"access", access,
			nullptr)))) {
		g_object_unref(ctx.source);
		ctx.source = nullptr;
	}

	if (ctx.image &&
		(ctx.image->Xsize > 100 ||
			ctx.image->Ysize > 100 ||
			ctx.image->Bands > 4)) {
		g_object_unref(ctx.image);
		ctx.image = nullptr;

		g_object_unref(ctx.source);
		ctx.source = nullptr;
	}

	// Set all required input arguments.
	vips_argument_map(VIPS_OBJECT(operation),
		FuzzSetRequiredInput, &ctx, nullptr);

	// Set optional arguments (ignore failures).
	for (i = 0; i < n_optional; i++) {
		VipsArgumentFlags flags =
			vips_object_get_argument_flags(VIPS_OBJECT(operation),
				opt_names[i]);

		if ((flags & VIPS_ARGUMENT_REQUIRED) ||
			!(flags & VIPS_ARGUMENT_CONSTRUCT) ||
			!(flags & VIPS_ARGUMENT_INPUT) ||
			(flags & VIPS_ARGUMENT_DEPRECATED))
			continue;

		vips_object_set_argument_from_string(VIPS_OBJECT(operation),
			opt_names[i], opt_values[i]);
	}

	if (!ctx.failed) {
		// Build (execute) the operation.
		if (!vips_object_build(VIPS_OBJECT(operation))) {
			// Evaluate output images to force computation.
			vips_argument_map(VIPS_OBJECT(operation),
				EvalRequiredOutput, nullptr, nullptr);
		}
	}

	// Clean up.
	vips_object_unref_outputs(VIPS_OBJECT(operation));
	g_object_unref(operation);

	if (ctx.image)
		g_object_unref(ctx.image);
	if (ctx.source)
		g_object_unref(ctx.source);
	for (i = 0; i < ctx.n_string_args; i++)
		g_free(ctx.string_args[i]);
	g_free(ctx.string_args);
	for (i = 0; i < n_optional; i++) {
		g_free(opt_names[i]);
		g_free(opt_values[i]);
	}
	g_free(option_string);

	if (ctx.output_filename) {
		g_unlink(ctx.output_filename);
		g_free(ctx.output_filename);
	}
	if (ctx.input_filename) {
		g_unlink(ctx.input_filename);
		g_free(ctx.input_filename);
	}

	vips_error_clear();

	return 0;
}
