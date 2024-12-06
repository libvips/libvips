/* compile with:
 *
 *  g++ -g -Wall tomemory.cpp `pkg-config vips-cpp --cflags --libs`
 */

#include <vips/vips8>
#include <iostream>

int
main(int argc, char* argv[])
{
    if (VIPS_INIT(argv[0]))
        vips_error_exit(nullptr);

    for (int i = 0; i < 1000; i++) {
        std::cout << "loop " << i << " ..." << std::endl;

        // create a uint8 RGBA VImage
        // `black` makes a mono image, so you need to explicitly tag it as srgb
        const int width = 50;
        const int height = 50;
        const int channels = 3;
        vips::VImage image =
            vips::VImage::black(width, height, vips::VImage::option()
                ->set("bands", channels))
            .copy(vips::VImage::option()
                ->set("interpretation", "srgb"))
            .bandjoin(255);

        // C libvips API to print a vips subclass ... handy for debugging
        std::cout << "built: ";
        vips_object_print_summary(VIPS_OBJECT(image.get_image()));

        // render to an area of memory ... you can use `.data()`, but this is
		// just as quick, and is threadsafe
        size_t len;
        void *data = image.write_to_memory(&len);

        std::cout << len << " bytes of data at address " << data << std::endl;

        // you own this pointer and must free it
        g_free(data);
    }

    return 0;
}
