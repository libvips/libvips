/*
 * compile with:
 *
 *      g++ -g -Wall draw_line.cpp `pkg-config vips-cpp --cflags --libs`
 *
 */

#include <vips/vips8>
#include <iostream>

using namespace vips;

void custom_draw(VipsImage *image, VipsPel *ink,
	int x, int y, void *client)
{
	g_assert(GPOINTER_TO_INT(client) == 42);
	std::cout << x << ' ' << y << std::endl;
}

int
main(int argc, char **argv)
{
	if (vips_init(argv[0]))
		vips_error_exit(NULL);

	VImage in = VImage::black(100, 100);
	in.draw_line({ 100 }, 0, 0, 100, 0,
		VImage::option()
			->set("draw-point", reinterpret_cast<void *>(custom_draw))
			->set("client", GINT_TO_POINTER(42)));

	vips_shutdown();

	return 0;
}
