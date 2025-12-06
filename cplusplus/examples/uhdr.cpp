/*
 * compile with:
 *
 *      g++ -g -Wall uhdr.cpp `pkg-config vips-cpp --cflags --libs`
 *
 * run with:
 *
 *      ./a.out test/test-suite/images/ultra-hdr.jpg x.jpg
 *
 */

#include <vips/vips8>

using namespace vips;

int
main(int argc, char **argv)
{
	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	if (argc != 3)
		vips_error_exit("usage: %s infile outfile", argv[0]);

	int left = 60;
	int top = 1560;
	int width = 128;
	int height = 128;

	VImage in = VImage::new_from_file(argv[1],
		VImage::option()->set("access", VIPS_ACCESS_SEQUENTIAL));

	VImage out = in.crop(left, top, width, height);

	// vips_image_prepare_gainmap() can modify the metadata, so we need to
	// make a unique copy of the image ... you can skip this step if you
	// know your image is already unique
	out = out.copy();

	// also crop the gainmap, if there is one
	VImage gainmap = out.gainmap();
	if (!gainmap.is_null()) {
		// the gainmap can be smaller than the image, we must scale the
		// crop area
		double hscale = (double) gainmap.width() / in.width();
		double vscale = (double) gainmap.height() / in.height();

		VImage x = gainmap.crop(left * hscale, top * vscale,
			width * hscale, height * vscale);

		// update the gainmap
		out.set("gainmap", x);
	}

	out.write_to_file(argv[2]);

	vips_shutdown();

	return 0;
}
