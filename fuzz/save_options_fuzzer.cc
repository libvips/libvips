/* Fuzz the saver option matrices.
 *
 * The generic save harnesses fix every option at its default, and
 * vips_fuzzer only reaches an option when a mutated input assembles the op
 * name, an exact "--name=value" line and a valid image simultaneously, so
 * the encoder option matrices stay dark (vips2tiff.c 688/1292 with most
 * option branches unhit, 2026-11-12 report).
 *
 * This harness pins the structure and frees only the option space: a byte
 * selects the saver (tiff/png/webp/gif/jpeg/jxl/heif/rad buffer savers),
 * the following lines are "--name=value" options validated by libvips'
 * own argument machinery, and the remainder is the image (<=100x100x4).
 * A dictionary carries the multi-byte option tokens so the mutator can
 * assemble valid option lines.
 *
 * Input format:
 *   byte 0      saver selector
 *   bytes 1..   option lines "--name=value" (up to 16, each <= 128 bytes),
 *               then the image data, decoded via vips_image_new_from_buffer()
 */

#include "config.h"

#include <vips/vips.h>

#define MAX_DIM 100
#define MAX_LINE_LEN 128
#define MAX_OPTIONAL_ARGS 16

static const char *savers[] = {
	"tiffsave_buffer",
	"pngsave_buffer",
	"webpsave_buffer",
	"gifsave_buffer",
	"jpegsave_buffer",
	"jxlsave_buffer",
	"heifsave_buffer",
	"radsave_buffer",
};

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

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	VipsOperation *operation;
	char *opt_names[MAX_OPTIONAL_ARGS];
	char *opt_values[MAX_OPTIONAL_ARGS];
	int n_optional = 0;
	int i;
	VipsImage *image;

	if (size < 1)
		return 0;

	operation = vips_operation_new(savers[data[0] % VIPS_NUMBER(savers)]);
	if (!operation)
		return 0;

	data += 1;
	size -= 1;

	// Parse optional arguments (lines starting with "--").
	while (n_optional < MAX_OPTIONAL_ARGS) {
		const guint8 *save_data = data;
		size_t save_size = size;
		char *line = ExtractLine(&data, &size);

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

	if (!(image = vips_image_new_from_buffer(data, size, "", nullptr))) {
		for (i = 0; i < n_optional; i++) {
			g_free(opt_names[i]);
			g_free(opt_values[i]);
		}
		vips_object_unref_outputs(VIPS_OBJECT(operation));
		g_object_unref(operation);
		vips_error_clear();
		return 0;
	}

	if (image->Xsize > MAX_DIM ||
		image->Ysize > MAX_DIM ||
		image->Bands > 4) {
		g_object_unref(image);
		for (i = 0; i < n_optional; i++) {
			g_free(opt_names[i]);
			g_free(opt_values[i]);
		}
		vips_object_unref_outputs(VIPS_OBJECT(operation));
		g_object_unref(operation);
		vips_error_clear();
		return 0;
	}

	// Set all required input image arguments from the loaded image.
	vips_argument_map(VIPS_OBJECT(operation),
		[](VipsObject *object, GParamSpec *pspec,
			VipsArgumentClass *argument_class,
			VipsArgumentInstance *argument_instance,
			void *a, void *b) -> void * {
			const char *name = g_param_spec_get_name(pspec);
			GType type = G_PARAM_SPEC_VALUE_TYPE(pspec);

			if (!(argument_class->flags & VIPS_ARGUMENT_REQUIRED) ||
				!(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ||
				!(argument_class->flags & VIPS_ARGUMENT_INPUT) ||
				(argument_class->flags & VIPS_ARGUMENT_DEPRECATED))
				return nullptr;

			if (g_type_is_a(type, VIPS_TYPE_IMAGE))
				g_object_set(object, name,
					static_cast<VipsImage *>(a), nullptr);

			return nullptr;
		},
		image, nullptr);

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

	// Build (encode).
	vips_object_build(VIPS_OBJECT(operation));

	vips_object_unref_outputs(VIPS_OBJECT(operation));
	g_object_unref(operation);

	g_object_unref(image);

	for (i = 0; i < n_optional; i++) {
		g_free(opt_names[i]);
		g_free(opt_values[i]);
	}

	vips_error_clear();

	return 0;
}
