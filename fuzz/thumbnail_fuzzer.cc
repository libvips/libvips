#include <vips/vips.h>

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (VIPS_INIT(*argv[0]))
		return -1;

	vips_concurrency_set(1);
	return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	VipsImage *image, *out;
	double d;

	if (!(image = vips_image_new_from_buffer(data, size, "", nullptr)))
		return 0;

	if (image->Xsize > 100 ||
		image->Ysize > 100 ||
		image->Bands > 4) {
		g_object_unref(image);
		return 0;
	}

	if (vips_thumbnail_image(image, &out, 42, nullptr)) {
		g_object_unref(image);
		return 0;
	}

	vips_avg(out, &d, nullptr);

	g_object_unref(out);
	g_object_unref(image);

	return 0;
}
