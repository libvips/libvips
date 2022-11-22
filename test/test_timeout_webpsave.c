#include <vips/vips.h>

#define TIMEOUT_SECONDS 2

static void
eval_callback(VipsImage *image, VipsProgress *progress, gboolean *is_killed)
{
	if (progress->run >= TIMEOUT_SECONDS) {
		*is_killed = TRUE;
		vips_image_set_kill(image, TRUE);
	}
}

int
main(int argc, char **argv)
{
	VipsImage *im;
	void *buf;
	size_t len;
	gboolean is_killed = FALSE;

	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	if (!vips_type_find("VipsOperation", "webpsave"))
		/* webpsave not available, skip test with return code 77.
		 */
		return 77;

	if (vips_black(&im, 16383, 16383, NULL))
		vips_error_exit(NULL);

	vips_image_set_progress(im, TRUE);
	g_signal_connect(im, "eval",
		G_CALLBACK(eval_callback), &is_killed);

	buf = NULL;
	if (vips_webpsave_buffer(im, &buf, &len, NULL))
		printf("error return from vips_webpsave_buffer()\n");

	g_object_unref(im);
	if (buf)
		g_free(buf);
	g_assert(is_killed);

	return 0;
}
