#include <png.h>
#include <vips/vips.h>

int
main(int argc, char **argv)
{
#if defined(PNG_READ_cLLI_SUPPORTED) && \
	defined(PNG_WRITE_cLLI_SUPPORTED) && \
	defined(PNG_FIXED_POINT_SUPPORTED)
	VipsImage *image = NULL;
	VipsImage *roundtrip = NULL;
	void *buffer = NULL;
	size_t length = 0;
	int max_cll;
	int max_fall;
	int result = 1;

	if (VIPS_INIT(argv[0]))
		return 1;

	if (vips_black(&image, 1, 1,
			"bands", 3,
			NULL))
		goto done;

	vips_image_set_int(image, "clli-max-content-light-level", 1624);
	vips_image_set_int(image, "clli-max-frame-average-light-level", 182);

	if (vips_pngsave_buffer(image, &buffer, &length, NULL) ||
		vips_pngload_buffer(buffer, length, &roundtrip, NULL))
		goto done;

	if (vips_image_get_int(roundtrip,
			"clli-max-content-light-level", &max_cll) ||
		vips_image_get_int(roundtrip,
			"clli-max-frame-average-light-level", &max_fall) ||
		max_cll != 1624 ||
		max_fall != 182)
		goto done;

	result = 0;

done:
	VIPS_UNREF(roundtrip);
	VIPS_UNREF(image);
	g_free(buffer);
	vips_shutdown();

	return result;
#else
	return 77;
#endif
}
