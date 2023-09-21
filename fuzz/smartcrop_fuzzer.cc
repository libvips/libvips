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
	VipsImage *image, *out;
	double d;

	if (size > 100 * 1024 * 1024)
		return 0;

	if (!(image = vips_image_new_from_buffer(data, size, "", nullptr)))
		return 0;

	if (image->Xsize > 100 ||
		image->Ysize > 100 ||
		image->Bands > 4) {
		g_object_unref(image);
		return 0;
	}

	if (vips_smartcrop(image, &out, 32, 32, nullptr)) {
		g_object_unref(image);
		return 0;
	}

	vips_min(out, &d, nullptr);

	g_object_unref(out);
	g_object_unref(image);

	return 0;
}
