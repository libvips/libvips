/* compile with
 *
 * gcc -g -Wall assemble-animated.c `pkg-config vips --cflags --libs`
 */

#include <stdlib.h>
#include <vips/vips.h>

/* for libvips before 8.16, add this line:
 *	G_DEFINE_AUTOPTR_CLEANUP_FUNC(VipsImage, g_object_unref)
 */

int
main(int argc, char *argv[])
{
	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);
	if (argc < 3)
		vips_error_exit("usage: %s outfile infile1 infile2 ...", argv[0]);

	/* Load a set of input files.
	 */
	g_autoptr(GPtrArray) frames = g_ptr_array_new_full(argc, g_object_unref);
	for (int i = 2; i < argc; i++) {
		VipsImage *frame;
		if (!(frame = vips_image_new_from_file(argv[i],
			"access", VIPS_ACCESS_SEQUENTIAL,
			NULL)))
			vips_error_exit(NULL);

		g_ptr_array_add(frames, frame);
	}

	/* Combine to form a vertical strip.
	 */
	g_autoptr(VipsImage) strip;
	if (vips_arrayjoin((VipsImage **) frames->pdata, &strip, frames->len,
		"across", 1,
		NULL))
		vips_error_exit(NULL);

	/* Set the animation metadata. Delay times are in milliseconds.
	 */
	VipsImage *frame0 = VIPS_IMAGE(frames->pdata[0]);
	vips_image_set_int(strip, "page-height", frame0->Ysize);
	vips_image_set_int(strip, "loop", 10);
	int delays[] = { 300, 300, 300 };
	vips_image_set_array_int(strip, "delay", delays, VIPS_NUMBER(delays));

	if (vips_image_write_to_file(strip, argv[1], NULL))
		vips_error_exit(NULL);

	return 0;
}
