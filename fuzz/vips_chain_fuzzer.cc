/* Fuzz chains of libvips operations.
 *
 * Like vips_fuzzer but applies up to MAX_CHAIN_LEN operations in sequence,
 * piping the first image output of each op into the next op's input image.
 * This exercises pipeline construction, intermediate VipsImage state, and
 * combinations of ops that single-op fuzzers cannot reach. Operations that
 * do not produce an image output (e.g. min, avg, save ops) leave the
 * pipeline image unchanged so subsequent ops can still consume it.
 *
 * Input format:
 *   Line 1: optional [option_string] for the initial source-from-memory load
 *   Repeated up to MAX_CHAIN_LEN times:
 *     Line: operation name (must be a known op nickname; otherwise the chain
 *       ends and remaining bytes become image data)
 *     Lines: required non-image argument strings, one per line
 *     Lines: optional arguments as "--name=value", one per line
 *   Remaining bytes: raw image data fed to vips_image_new_from_source
 */

#include "config.h"

#include "vips_fuzzer_common.h"

#define MAX_CHAIN_LEN 8
/* Cap intermediate image dimensions so an early enlarge op cannot make
 * downstream ops slow or OOM-prone.
 */
#define MAX_CHAIN_IMAGE_DIM 1000
#define MAX_CHAIN_IMAGE_BANDS 16

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

typedef struct _OpSpec {
	VipsOperation *op;
	char **string_args;
	int n_string_args;
	char *opt_names[MAX_OPTIONAL_ARGS];
	char *opt_values[MAX_OPTIONAL_ARGS];
	int n_optional;
} OpSpec;

static void
op_spec_clear(OpSpec *spec)
{
	if (spec->op) {
		g_object_unref(spec->op);
		spec->op = nullptr;
	}
	for (int j = 0; j < spec->n_string_args; j++)
		g_free(spec->string_args[j]);
	g_free(spec->string_args);
	spec->string_args = nullptr;
	spec->n_string_args = 0;
	for (int j = 0; j < spec->n_optional; j++) {
		g_free(spec->opt_names[j]);
		g_free(spec->opt_values[j]);
	}
	spec->n_optional = 0;
}

/* Capture the first image output of an op (taking a ref) so we can chain
 * it into the next op. Subsequent image outputs are force-evaluated and
 * dropped.
 */
typedef struct _CaptureCtx {
	VipsImage *captured;
} CaptureCtx;

static void *
CaptureFirstImageOutput(VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b)
{
	CaptureCtx *cctx = static_cast<CaptureCtx *>(a);
	GType type = G_PARAM_SPEC_VALUE_TYPE(pspec);

	if (!(argument_class->flags & VIPS_ARGUMENT_REQUIRED) ||
		!(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ||
		!(argument_class->flags & VIPS_ARGUMENT_OUTPUT) ||
		(argument_class->flags & VIPS_ARGUMENT_DEPRECATED))
		return nullptr;

	if (!g_type_is_a(type, VIPS_TYPE_IMAGE))
		return nullptr;

	VipsImage *out;
	const char *name = g_param_spec_get_name(pspec);
	g_object_get(object, name, &out, nullptr);
	if (!out)
		return nullptr;

	if (cctx->captured == nullptr) {
		cctx->captured = out;
	}
	else {
		// We already kept the first one; force-eval and unref this.
		if (out->Xsize <= MAX_CHAIN_IMAGE_DIM &&
			out->Ysize <= MAX_CHAIN_IMAGE_DIM &&
			out->Bands <= MAX_CHAIN_IMAGE_BANDS) {
			double d;
			(void) vips_min(out, &d, nullptr);
		}
		g_object_unref(out);
	}

	return nullptr;
}

/* Parse one op block: opname, required string args, then a run of
 * "--name=value" lines. Returns TRUE if the spec is fully populated and
 * the op was created. Returns FALSE if no more ops can be parsed (the
 * caller should treat (data, size) as image data).
 *
 * On a partial parse failure (e.g. ran out of lines mid-required-args)
 * we drop what we read and return FALSE so the chain ends cleanly.
 */
static gboolean
parse_op_block(OpSpec *spec, const guint8 **data, size_t *size)
{
	const guint8 *save_data = *data;
	size_t save_size = *size;
	char *opname = FuzzExtractLine(data, size);
	if (!opname)
		return FALSE;

	VipsOperation *op = vips_operation_new(opname);
	g_free(opname);
	if (!op) {
		// Not a valid op; restore so trailing bytes remain intact.
		*data = save_data;
		*size = save_size;
		return FALSE;
	}

	VipsOperationFlags flags = vips_operation_get_flags(op);
	if ((flags & VIPS_OPERATION_DEPRECATED) ||
		(flags & VIPS_OPERATION_BLOCKED)) {
		g_object_unref(op);
		// Restore so trailing image bytes are preserved.
		*data = save_data;
		*size = save_size;
		return FALSE;
	}

	spec->op = op;

	int n_str = 0;
	vips_argument_map(VIPS_OBJECT(op),
		FuzzCountStringArgs, &n_str, nullptr);
	spec->n_string_args = n_str;
	spec->string_args = g_new0(char *, VIPS_MAX(n_str, 1));

	for (int j = 0; j < n_str; j++) {
		spec->string_args[j] = FuzzExtractLine(data, size);
		if (!spec->string_args[j]) {
			op_spec_clear(spec);
			return FALSE;
		}
	}

	while (spec->n_optional < MAX_OPTIONAL_ARGS) {
		const guint8 *od = *data;
		size_t os = *size;
		char *line = FuzzExtractLine(data, size);
		if (!line)
			break;
		if (line[0] != '-' || line[1] != '-') {
			// Not an optional arg -- put it back so the next op
			// (or the image data) sees it.
			g_free(line);
			*data = od;
			*size = os;
			break;
		}
		char *eq = strchr(line + 2, '=');
		if (eq) {
			*eq = '\0';
			spec->opt_names[spec->n_optional] = g_strdup(line + 2);
			spec->opt_values[spec->n_optional] = g_strdup(eq + 1);
			spec->n_optional++;
		}
		g_free(line);
	}

	return TRUE;
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	FuzzCtx ctx = {};
	OpSpec chain[MAX_CHAIN_LEN] = {};
	int n_ops = 0;

	// Optional [option_string] for the initial image load.
	char *option_string;
	{
		const guint8 *save_data = data;
		size_t save_size = size;
		char *line = FuzzExtractLine(&data, &size);
		if (line && line[0] == '[') {
			option_string = line;
		}
		else {
			g_free(line);
			data = save_data;
			size = save_size;
			option_string = g_strdup("");
		}
	}

	// Parse the op chain.
	for (int i = 0; i < MAX_CHAIN_LEN; i++) {
		if (!parse_op_block(&chain[i], &data, &size))
			break;
		n_ops = i + 1;
	}

	// What's left is the initial image bytes.
	ctx.pending_data = data;
	ctx.pending_size = size;

	if (size > 0 &&
		((ctx.source = vips_source_new_from_memory(data, size))) &&
		(!(ctx.image = vips_image_new_from_source(ctx.source,
			option_string, "access", VIPS_ACCESS_RANDOM, nullptr)))) {
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

	// Run the chain.
	for (int i = 0; i < n_ops; i++) {
		OpSpec *spec = &chain[i];
		VipsOperation *op = spec->op;

		// Reset the per-op string arg cursor in ctx but keep
		// source/image/files persistent across the chain.
		ctx.string_args = spec->string_args;
		ctx.n_string_args = spec->n_string_args;
		ctx.string_idx = 0;
		ctx.failed = FALSE;

		vips_argument_map(VIPS_OBJECT(op),
			FuzzSetRequiredInput, &ctx, nullptr);

		for (int j = 0; j < spec->n_optional; j++) {
			VipsArgumentFlags af =
				vips_object_get_argument_flags(VIPS_OBJECT(op),
					spec->opt_names[j]);
			if ((af & VIPS_ARGUMENT_REQUIRED) ||
				!(af & VIPS_ARGUMENT_CONSTRUCT) ||
				!(af & VIPS_ARGUMENT_INPUT) ||
				(af & VIPS_ARGUMENT_DEPRECATED))
				continue;
			vips_object_set_argument_from_string(VIPS_OBJECT(op),
				spec->opt_names[j], spec->opt_values[j]);
		}

		CaptureCtx cctx = {};
		gboolean built = FALSE;
		if (!ctx.failed &&
			!vips_object_build(VIPS_OBJECT(op))) {
			built = TRUE;
			vips_argument_map(VIPS_OBJECT(op),
				CaptureFirstImageOutput, &cctx, nullptr);
		}

		// Detach references the op holds on its outputs; we own
		// `cctx.captured` via g_object_get already.
		vips_object_unref_outputs(VIPS_OBJECT(op));

		// We're done with the op; the spec keeps no other handle.
		g_object_unref(op);
		spec->op = nullptr;

		if (cctx.captured) {
			VipsImage *next_image = cctx.captured;

			gboolean ok = next_image->Xsize <= MAX_CHAIN_IMAGE_DIM &&
				next_image->Ysize <= MAX_CHAIN_IMAGE_DIM &&
				next_image->Bands <= MAX_CHAIN_IMAGE_BANDS;
			if (ok) {
				double d;
				if (vips_min(next_image, &d, nullptr))
					ok = FALSE;
			}

			if (ok) {
				if (ctx.image)
					g_object_unref(ctx.image);
				ctx.image = next_image;
			}
			else {
				g_object_unref(next_image);
				// Halt the chain; subsequent ops would either
				// inherit a too-big image or a stale one.
				ctx.string_args = nullptr;
				ctx.n_string_args = 0;
				break;
			}
		}
		else if (built) {
			// Op built but produced no image output (e.g. min,
			// avg, a save op). Leave ctx.image alone so the next
			// op can still consume it.
		}

		ctx.string_args = nullptr;
		ctx.n_string_args = 0;
	}

	// Cleanup. op_spec_clear unrefs any op left behind by an early break.
	for (int i = 0; i < n_ops; i++)
		op_spec_clear(&chain[i]);

	if (ctx.image)
		g_object_unref(ctx.image);
	if (ctx.source)
		g_object_unref(ctx.source);

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
