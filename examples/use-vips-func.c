/* Example showing how to call a couple of vips functions using an input
 * image file and creating an output file
 * also gathers some info on the input image
 */
#include <stdio.h>
#include <vips/vips.h>

int
main(int argc, char **argv)
{
	VipsImage *in;
	double mean;
	VipsImage *out;

	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	if (argc != 3)
		vips_error_exit("usage: %s infile outfile", argv[0]);

	if (!(in = vips_image_new_from_file(argv[1], NULL)))
		vips_error_exit(NULL);

	printf("image width = %d\n", vips_image_get_width(in));

	if (vips_avg(in, &mean, NULL))
		vips_error_exit(NULL);

	printf("mean pixel value = %g\n", mean);

	/* generate photo nexative - replace with other vips_ funcs */
	if (vips_invert(in, &out, NULL))
		vips_error_exit(NULL);

	g_object_unref(in);

	if (vips_image_write_to_file(out, argv[2], NULL))
		vips_error_exit(NULL);

	g_object_unref(out);

	return 0;
}
