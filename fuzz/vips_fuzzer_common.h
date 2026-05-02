/* Helpers shared by vips_fuzzer.cc and vips_chain_fuzzer.cc.
 *
 * Includes the FuzzCtx context, line-based input parsing, lazy /tmp file
 * materialisation for filename args, and the argument_map callbacks that
 * count and set required inputs.
 */

#pragma once

#include <vips/vips.h>

#define MAX_LINE_LEN 4096 // =VIPS_PATH_MAX
#define MAX_OPTIONAL_ARGS 32

// Context passed through vips_argument_map callbacks.
typedef struct _FuzzCtx {
	VipsSource *source; // Input source, may be NULL
	VipsImage *image;	// Input image, may be NULL
	char **string_args; // Pre-parsed string arguments
	int n_string_args;
	int string_idx; // Next string argument to consume
	gboolean failed;
	const guint8 *pending_data; // Bytes to lazily write to input_filename
	size_t pending_size;
	char *input_filename;  // /tmp path holding the raw fuzz bytes, or NULL
	gboolean input_written; // TRUE if input_filename was written ok
	gboolean input_tried;	// TRUE once we've tried to materialise input
	char *output_filename; // /tmp path handed to save ops, or NULL
} FuzzCtx;

static inline char *
FuzzExtractLine(const guint8 **data, size_t *size)
{
	const guint8 *end;

	if (*size == 0)
		return nullptr;

	end = static_cast<const guint8 *>(
		memchr(*data, '\n', VIPS_MIN(*size, MAX_LINE_LEN)));
	if (end == nullptr)
		return nullptr;

	size_t n = end - *data;
	char *line = g_strndup(reinterpret_cast<const char *>(*data), n);
	*data += n + 1;
	*size -= n + 1;

	return line;
}

// Lazily write the pending fuzz bytes to a unique /tmp file. Returns the
// path, or NULL if size is zero or the write failed.
static inline const char *
FuzzEnsureInputFile(FuzzCtx *ctx)
{
	if (ctx->input_written)
		return ctx->input_filename;
	if (ctx->input_tried)
		return nullptr;
	ctx->input_tried = TRUE;

	if (ctx->pending_size == 0)
		return nullptr;

	ctx->input_filename = vips__temp_name("%s");
	if (!ctx->input_filename)
		return nullptr;
	if (!g_file_set_contents(ctx->input_filename,
			reinterpret_cast<const char *>(ctx->pending_data),
			ctx->pending_size, nullptr))
		return nullptr;

	ctx->input_written = TRUE;
	return ctx->input_filename;
}

/* Count how many required input arguments need a string value (i.e. are
 * not image, array-of-images, source, target, or blob).
 */
static inline void *
FuzzCountStringArgs(VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b)
{
	int *count = static_cast<int *>(a);
	GType type = G_PARAM_SPEC_VALUE_TYPE(pspec);

	if (!(argument_class->flags & VIPS_ARGUMENT_REQUIRED) ||
		!(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ||
		!(argument_class->flags & VIPS_ARGUMENT_INPUT) ||
		(argument_class->flags & VIPS_ARGUMENT_DEPRECATED))
		return nullptr;

	if (!g_type_is_a(type, VIPS_TYPE_IMAGE) &&
		!g_type_is_a(type, VIPS_TYPE_ARRAY_IMAGE) &&
		!g_type_is_a(type, VIPS_TYPE_SOURCE) &&
		!g_type_is_a(type, VIPS_TYPE_TARGET) &&
		!g_type_is_a(type, VIPS_TYPE_BLOB))
		(*count)++;

	return nullptr;
}

// Set all required input arguments from the fuzz context.
static inline void *
FuzzSetRequiredInput(VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b)
{
	FuzzCtx *ctx = static_cast<FuzzCtx *>(a);
	const char *name = g_param_spec_get_name(pspec);
	GType type = G_PARAM_SPEC_VALUE_TYPE(pspec);

	if (!(argument_class->flags & VIPS_ARGUMENT_REQUIRED) ||
		!(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ||
		!(argument_class->flags & VIPS_ARGUMENT_INPUT) ||
		(argument_class->flags & VIPS_ARGUMENT_DEPRECATED))
		return nullptr;

	if (g_type_is_a(type, VIPS_TYPE_IMAGE)) {
		if (!ctx->image) {
			ctx->failed = TRUE;
			return pspec;
		}
		g_object_set(object, name, ctx->image, nullptr);
	}
	else if (g_type_is_a(type, VIPS_TYPE_ARRAY_IMAGE)) {
		if (!ctx->image) {
			ctx->failed = TRUE;
			return pspec;
		}
		VipsArrayImage *array = vips_array_image_new(&ctx->image, 1);
		g_object_set(object, name, array, nullptr);
		vips_area_unref(VIPS_AREA(array));
	}
	else if (g_type_is_a(type, VIPS_TYPE_SOURCE)) {
		if (!ctx->source) {
			ctx->failed = TRUE;
			return pspec;
		}
		g_object_set(object, name, ctx->source, nullptr);
	}
	else if (g_type_is_a(type, VIPS_TYPE_TARGET)) {
		VipsTarget *target = vips_target_new_to_memory();
		if (!target) {
			ctx->failed = TRUE;
			return pspec;
		}
		g_object_set(object, name, target, nullptr);
		g_object_unref(target);
	}
	else if (g_type_is_a(type, VIPS_TYPE_BLOB)) {
		if (!ctx->source) {
			ctx->failed = TRUE;
			return pspec;
		}
		g_object_set(object, name, ctx->source->blob, nullptr);
	}
	else {
		if (ctx->string_idx >= ctx->n_string_args) {
			ctx->failed = TRUE;
			return pspec;
		}
		const char *value = ctx->string_args[ctx->string_idx++];

		/* Never let fuzzer-controlled strings reach the filesystem via
		 * a filename arg. Route loads at our fuzz-data temp file and
		 * saves at a unique /tmp output file we'll unlink afterwards.
		 * The temp files are materialised lazily so ops that don't
		 * touch a filename pay no IO cost.
		 */
		if (strcmp(name, "filename") == 0) {
			GType self_type = G_TYPE_FROM_INSTANCE(object);
			GType foreign_save = g_type_from_name("VipsForeignSave");
			GType foreign_load = g_type_from_name("VipsForeignLoad");

			if (foreign_save &&
				g_type_is_a(self_type, foreign_save)) {
				if (!ctx->output_filename)
					ctx->output_filename =
						vips__temp_name("%s");
				value = ctx->output_filename
					? ctx->output_filename
					: "/dev/null";
			}
			else if (foreign_load &&
				g_type_is_a(self_type, foreign_load)) {
				const char *path = FuzzEnsureInputFile(ctx);
				value = path ? path : "/dev/null";
			}
			else {
				value = "/dev/null";
			}
		}

		if (vips_object_set_argument_from_string(object, name,
				value)) {
			ctx->failed = TRUE;
			return pspec;
		}
	}

	return nullptr;
}

/* Apply the standard fuzz-target blocklist:
 *   - timeout-prone create-from-scratch ops (worley, fractsurf)
 *   - ops that write images to stdout
 *   - dzsave's tile sidecar that g_unlink can't clean up
 *   - vips_system, which spawns external commands
 */
static inline void
FuzzApplyBlocklist(void)
{
	const char *blocklist[] = {
		/* Avoid possible timeout errors, e.g.:
		 * $ vips fractsurf x.v 9999 9999 3
		 * $ vips worley x.v 9999 9999
		 * is likely taking more than 60 seconds.
		 */
		"VipsWorley",
		"VipsFractsurf",
		/* Block matrixprint and {jpeg,webp}save_mime to prevent image data
		 * from being written to stdout and cluttering the output.
		 */
		"VipsForeignPrintMatrix",
		"VipsForeignSaveJpegMime",
		"VipsForeignSaveWebpMime",
		/* dzsave writes a .dzi sidecar and a _files/ tile directory
		 * alongside the primary path; a single g_unlink can't clean
		 * that up, so the tmpdir would grow each iteration.
		 */
		"VipsForeignSaveDzFile",
		/* vips_system spawns external commands; never let fuzzer-
		 * controlled strings reach a shell.
		 */
		"VipsSystem",
	};
	for (const char *operation : blocklist)
		vips_operation_block_set(operation, TRUE);
}
