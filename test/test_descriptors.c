/* Read an image and check that file handles are being closed on minimise.
 *
 * This will only work on linux: we signal success and do nothing if
 * /proc/self/fd does not exist.
 */

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/

#define _GNU_SOURCE
#include <stdlib.h>

#include <vips/vips.h>

/**
 * get_open_files:
 *
 * Get a list of open files for this process.
 *
 * Returns (transfer full) (nullable): a new #GSList, or %NULL
 */
static GSList *
get_open_files()
{
#ifdef G_OS_WIN32
	/* realpath() and /proc/self/fd is not available on Windows.
	 */
	return NULL;
#else
	GSList *list = NULL;
	GDir *dir;
	const char *name;

	if (!(dir = g_dir_open("/proc/self/fd", 0, NULL)))
		return NULL;

	while ((name = g_dir_read_name(dir))) {
		char *fullname = g_build_filename("/proc/self/fd", name, NULL);

		list = g_slist_prepend(list, realpath(fullname, NULL));

		g_free(fullname);
	}

	g_dir_close(dir);

	return list;
#endif
}

/**
 * fd_check:
 * @stage: the originating stage for the error message
 * @fds: a #GSList of file descriptors to check against
 *
 * Check for a leak by comparing the currently open files for this
 * process with the file descriptors in @fds. If there's a leak,
 * print an error message and return %FALSE.
 *
 * See also: get_open_files().
 *
 * Returns: %TRUE if there are no leaks; %FALSE otherwise
 */
static gboolean
fd_check(const char *stage, GSList *fds)
{
	GSList *unique_list = NULL, *list, *iter;

	list = get_open_files();

	for (iter = list; iter; iter = iter->next)
		if (!g_slist_find_custom(fds, iter->data,
				(GCompareFunc) g_strcmp0))
			unique_list = g_slist_prepend(unique_list, iter->data);

	if (unique_list == NULL) {
		g_slist_free_full(list, g_free);
		return TRUE;
	}

	fprintf(stderr, "%s: file descriptors not closed after %s:\n",
		vips_get_prgname(), stage);
	for (iter = unique_list; iter; iter = iter->next)
		fprintf(stderr, "%s\n", (char *) iter->data);

	g_slist_free(unique_list);
	g_slist_free_full(list, g_free);

	return FALSE;
}

int
main(int argc, char **argv)
{
	VipsSource *source;
	VipsImage *image, *x;
	GSList *list;
	double average;

	if (VIPS_INIT(argv[0]))
		vips_error_exit("unable to start");

	if (argc != 2)
		vips_error_exit("usage: %s test-image", argv[0]);

	list = get_open_files();
	if (list == NULL)
		/* Probably not *nix, skip test with return code 77.
		 */
		return 77;

	/* This is usually a list of 4 files. stdout / stdin / stderr plus one
	 * more made for us by glib, I think, doing what I don't know.
	 */

	/* Opening an image should read the header, then close the fd.
	 */
	printf("** rand open ..\n");
	if (!(source = vips_source_new_from_file(argv[1])))
		goto error;
	if (!(image = vips_image_new_from_source(source, "",
			  "access", VIPS_ACCESS_RANDOM,
			  NULL)))
		goto error;
	if (!fd_check("header read", list))
		goto error;

	/* We should be able to read a chunk near the top, then have the fd
	 * closed again.
	 */
	printf("** crop1, avg ..\n");
	if (vips_crop(image, &x, 0, 0, image->Xsize, 10, NULL) ||
		vips_avg(x, &average, NULL))
		goto error;

	g_object_unref(x);
	if (!fd_check("first read", list))
		goto error;

	/* We should be able to read again, a little further down, and have
	 * the input restarted and closed again.
	 */
	printf("** crop2, avg ..\n");
	if (vips_crop(image, &x, 0, 20, image->Xsize, 10, NULL) ||
		vips_avg(x, &average, NULL))
		goto error;

	g_object_unref(x);
	if (!fd_check("second read", list))
		goto error;

	/* Clean up, and we should still just have three open.
	 */
	printf("** unref ..\n");
	g_object_unref(image);
	g_object_unref(source);
	printf("** shutdown ..\n");
	vips_shutdown();

	if (!fd_check("shutdown", list))
		goto error;

	g_slist_free_full(list, g_free);
	return 0;

error:
	g_slist_free_full(list, g_free);
	return 1;
}
