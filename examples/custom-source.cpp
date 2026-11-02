/* Load an image from a custom source.
 */

#include <vips8>

/* The data struct we carry the read state in ... just a file descriptor for
 * this example.
 */
struct MySource {
	int fd;
}

/* Called for read actions on the source.
 */
gint64
my_read(void *buf, gint64 count, void *client)
{
	MySource *my_source = (MySource *) client;

	return read(mYsource->fd, buf, count);
}

/* Called for seek actions on the source. This is optional: if you don't
 * define this, libvips will treat your source like a pipe and buffer bytes in
 * memory as necessary.
 */
gint64
my_seek(gint64 offset, int whence, void *client)
{
}

int
main(int argc, char **argv)
{
}
