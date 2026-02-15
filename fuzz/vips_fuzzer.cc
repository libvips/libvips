/* Fuzz the complete libvips operation API.
 *
 * This exercises the operation dispatch, argument parsing, and execution
 * paths for all non-deprecated processing operations, similar to the
 * standalone vips CLI tool.
 *
 * Input format:
 *   Line 1: operation name (e.g. "invert", "add", "embed")
 *   Lines 2..N: non-image argument strings, one per line
 *   Remaining bytes: raw image data (decoded via vips_image_new_from_buffer)
 *
 * Foreign load/save operations are skipped since they are already covered
 * by existing fuzz targets.
 */

#include <vips/vips.h>

#define MAX_LINE_LEN 4096 // =VIPS_PATH_MAX

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (VIPS_INIT(*argv[0]))
		return -1;

	vips_concurrency_set(1);
	vips_cache_set_max(0);

	return 0;
}

static char *
ExtractLine(const guint8 **data, size_t *size)
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

/* Context passed through vips_argument_map callbacks. */
typedef struct _FuzzCtx {
	VipsImage *image;     /* Pre-loaded input image, may be NULL */
	const guint8 *buf;    /* Raw fuzzer data (for source/blob args) */
	size_t buf_size;
	char **string_args;   /* Pre-parsed string arguments */
	int n_string_args;
	int string_idx;       /* Next string argument to consume */
	gboolean failed;
} FuzzCtx;

/* Count how many required input arguments need a string value (i.e. are
 * not image, array-of-images, source, target, or blob).
 */
static void *
CountStringArgs(VipsObject *object,
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

/* Set all required input arguments from the fuzz context. */
static void *
SetRequiredInput(VipsObject *object,
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
		if (ctx->buf_size == 0) {
			ctx->failed = TRUE;
			return pspec;
		}
		VipsSource *source =
			vips_source_new_from_memory(ctx->buf, ctx->buf_size);
		if (!source) {
			ctx->failed = TRUE;
			return pspec;
		}
		g_object_set(object, name, source, nullptr);
		g_object_unref(source);
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
		if (ctx->buf_size == 0) {
			ctx->failed = TRUE;
			return pspec;
		}
		VipsBlob *blob = vips_blob_copy(ctx->buf, ctx->buf_size);
		if (!blob) {
			ctx->failed = TRUE;
			return pspec;
		}
		g_object_set(object, name, blob, nullptr);
		vips_area_unref(VIPS_AREA(blob));
	}
	else {
		if (ctx->string_idx >= ctx->n_string_args) {
			ctx->failed = TRUE;
			return pspec;
		}
		if (vips_object_set_argument_from_string(object, name,
				ctx->string_args[ctx->string_idx++])) {
			ctx->failed = TRUE;
			return pspec;
		}
	}

	return nullptr;
}

/* Force evaluation of required output images. */
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
			/* Sanity-check output dimensions to avoid OOM. */
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
	VipsOperationClass *oclass;
	FuzzCtx ctx = {};
	char *op_name;
	int i;

	/* Extract the operation name from the first line. */
	op_name = ExtractLine(&data, &size);
	if (!op_name)
		return 0;

	/* Create the operation. */
	operation = vips_operation_new(op_name);
	g_free(op_name);
	if (!operation)
		return 0;

	/* Skip deprecated or blocked operations. */
	oclass = VIPS_OPERATION_GET_CLASS(operation);
	if (VIPS_OBJECT_CLASS(oclass)->deprecated ||
		(oclass->flags & VIPS_OPERATION_DEPRECATED) ||
		(oclass->flags & VIPS_OPERATION_BLOCKED)) {
		g_object_unref(operation);
		return 0;
	}

	/* Count how many string-valued required input args we need. */
	ctx.n_string_args = 0;
	vips_argument_map(VIPS_OBJECT(operation),
		CountStringArgs, &ctx.n_string_args, nullptr);

	/* Parse that many lines from the fuzzer data. */
	ctx.string_args = g_new0(char *, VIPS_MAX(ctx.n_string_args, 1));
	for (i = 0; i < ctx.n_string_args; i++) {
		ctx.string_args[i] = ExtractLine(&data, &size);
		if (!ctx.string_args[i]) {
			for (int j = 0; j < i; j++)
				g_free(ctx.string_args[j]);
			g_free(ctx.string_args);
			g_object_unref(operation);
			return 0;
		}
	}

	/* Try to load an image from the remaining data. */
	ctx.image = nullptr;
	if (size > 0) {
		ctx.image = vips_image_new_from_buffer(data, size, "", nullptr);
		if (ctx.image &&
			(ctx.image->Xsize > 100 ||
				ctx.image->Ysize > 100 ||
				ctx.image->Bands > 4)) {
			g_object_unref(ctx.image);
			ctx.image = nullptr;
		}
	}

	ctx.buf = data;
	ctx.buf_size = size;
	ctx.string_idx = 0;
	ctx.failed = FALSE;

	/* Set all required input arguments. */
	vips_argument_map(VIPS_OBJECT(operation),
		SetRequiredInput, &ctx, nullptr);

	if (!ctx.failed) {
		/* Build (execute) the operation. */
		if (!vips_object_build(VIPS_OBJECT(operation))) {
			/* Evaluate output images to force computation. */
			vips_argument_map(VIPS_OBJECT(operation),
				EvalRequiredOutput, nullptr, nullptr);
		}
	}

	/* Clean up. */
	vips_object_unref_outputs(VIPS_OBJECT(operation));
	g_object_unref(operation);

	if (ctx.image)
		g_object_unref(ctx.image);
	for (i = 0; i < ctx.n_string_args; i++)
		g_free(ctx.string_args[i]);
	g_free(ctx.string_args);

	vips_error_clear();

	return 0;
}
