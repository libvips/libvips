#include <vips/vips.h>

#define MAX_ARG_LEN 4096 // =VIPS_PATH_MAX

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (VIPS_INIT(*argv[0]))
		return -1;

	vips_concurrency_set(1);
	return 0;
}

static char *
ExtractLine(const guint8 *data, size_t size, size_t *n)
{
	const guint8 *end;

	end = static_cast<const guint8 *>(
		memchr(data, '\n', VIPS_MIN(size, MAX_ARG_LEN)));
	if (end == nullptr)
		return nullptr;

	*n = end - data;
	return g_strndup(reinterpret_cast<const char *>(data), *n);
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	VipsImage *image;
	void *buf;
	char *option_string, *suffix;
	size_t len, n;

	option_string = ExtractLine(data, size, &n);
	if (option_string == nullptr)
		return 0;

	data += n + 1;
	size -= n + 1;

	suffix = ExtractLine(data, size, &n);
	if (suffix == nullptr) {
		g_free(option_string);
		return 0;
	}

	data += n + 1;
	size -= n + 1;

	if (!(image = vips_image_new_from_buffer(data, size, option_string, nullptr))) {
		g_free(option_string);
		g_free(suffix);
		return 0;
	}

	// We're done with option_string, free early.
	g_free(option_string);

	if (image->Xsize > 100 ||
		image->Ysize > 100 ||
		image->Bands > 4) {
		g_object_unref(image);
		g_free(suffix);
		return 0;
	}

	if (vips_image_write_to_buffer(image, suffix, &buf, &len, nullptr)) {
		g_object_unref(image);
		g_free(suffix);
		return 0;
	}

	g_free(buf);
	g_free(suffix);
	g_object_unref(image);

	return 0;
}
