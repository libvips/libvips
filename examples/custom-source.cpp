/* Load an image from a custom source.
 */

#include <fcntl.h>

#include <vips/vips8>

/* The data struct we carry the read state in ... just a file descriptor for
 * this example.
 */
struct MySource {
	int fd;
};

/* Called for read actions on the source.
 */
gint64
my_read(void *buf, gint64 count, void *client)
{
	MySource *my_source = (MySource *) client;

	return read(my_source->fd, buf, count);
}

/* Called for seek actions on the source. This is optional: if you don't
 * define this, libvips will treat your source like a pipe and buffer bytes in
 * memory as necessary.
 */
gint64
my_seek(gint64 offset, int whence, void *client)
{
	MySource *my_source = (MySource *) client;

	return lseek(my_source->fd, offset, whence);
}

int
main(int argc, char **argv)
{
	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	MySource my_source;
	if ((my_source.fd = open(argv[1], O_RDONLY)) < 0)
		vips_error_exit("unable to open %s", argv[1]);

	vips::VSourceCustom source;
	source.on_read(my_read, (void*) &my_source);

	return 0;
}
