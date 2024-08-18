#include <vips/vips.h>

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	vips_concurrency_set(1);
	return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	VipsImage *image;
	void *buf;
	const char *loader, *loader_end;
	char *tmp, *suffix;
	size_t len;

	if (!(image = vips_image_new_from_buffer(data, size, "", nullptr)))
		return 0;

	if (image->Xsize > 100 ||
		image->Ysize > 100 ||
		image->Bands > 4) {
		g_object_unref(image);
		return 0;
	}

	if (vips_image_get_typeof(image, VIPS_META_LOADER) &&
		vips_image_get_string(image, VIPS_META_LOADER, &loader)) {
		g_object_unref(image);
		return 0;
	}

	loader_end = g_strrstr(loader, "load");
	g_assert(loader_end);

	tmp = g_strndup(loader, strlen(loader) - strlen(loader_end));
	suffix = g_strconcat(".", tmp, NULL);
	g_free(tmp);

	if (strcmp(suffix, ".rad") == 0) {
		g_free(suffix);
		// .rad -> .hdr
		suffix = g_strdup(".hdr");
	}
	else if (strcmp(suffix, ".heif") == 0) {
		g_free(suffix);
		// Set the default compression for heifsave to AV1 instead of HEVC
		suffix = g_strdup(".avif");
	}

	if (vips_image_write_to_buffer(image, suffix, &buf, &len, nullptr)) {
		g_free(suffix);
		g_object_unref(image);
		return 0;
	}

	g_free(buf);
	g_free(suffix);
	g_object_unref(image);

	return 0;
}
