/*
 * compile with:
 *
 *      g++ -g -Wall keep.cpp `pkg-config vips-cpp --cflags --libs`
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

	{
		VImage img = VImage::new_from_file(argv[1],
			VImage::option()->set("access", "sequential"));
		img.write_to_file(argv[2],
			VImage::option()->set("keep", VIPS_FOREIGN_KEEP_ALL ^ VIPS_FOREIGN_KEEP_EXIF));
	}

	vips_shutdown();

	return 0;
}
