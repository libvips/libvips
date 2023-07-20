/* Read and write formatted images to memory.
 *
 * Compile with:
 *
 * 	gcc -g -Wall new-from-buffer.c `pkg-config vips --cflags --libs`
 *
 */

#include <vips/vips.h>

int
main(int argc, char **argv)
{
	gchar *buf;
	gsize len;
	int i;

	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	if (argc != 2)
		vips_error_exit("usage: %s FILENAME", argv[0]);

	if (!g_file_get_contents(argv[1], &buf, &len, NULL))
		vips_error_exit(NULL);

	for (i = 0; i < 10; i++) {
		VipsImage *image;
		void *new_buf;
		size_t new_len;

		printf("loop %d ...\n", i);

		if (!(image = vips_image_new_from_buffer(buf, len, "",
				  "access", VIPS_ACCESS_SEQUENTIAL,
				  NULL)))
			vips_error_exit(NULL);

		if (vips_image_write_to_buffer(image,
				".jpg", &new_buf, &new_len,
				"Q", 95,
				NULL))
			vips_error_exit(NULL);

		g_object_unref(image);
		g_free(new_buf);
	}

	g_free(buf);

	vips_shutdown();

	return 0;
}
