/* Show progress feedback and computation cancel.
 *
 * compile with
 *
 * gcc -g -Wall progress-cancel.c `pkg-config vips --cflags --libs`
 */

#include <stdio.h>
#include <vips/vips.h>
#include <errno.h>

void
preeval_callback(VipsImage *image, VipsProgress *progress, void *pdata)
{
	printf("preeval_callback:\n");
}

void
eval_callback(VipsImage *image, VipsProgress *progress, void *pdata)
{
	printf("eval_callback: percent = %d\n", progress->percent);

	if (progress->percent >= 25) {
		printf("calling vips_image_set_kill() ...\n");
		vips_image_set_kill(image, TRUE);
	}
}

void
posteval_callback(VipsImage *image, VipsProgress *progress, void *pdata)
{
	printf("posteval_callback: finished in %.3gs\n",
		g_timer_elapsed(progress->start, NULL));
}

int
main(int argc, char **argv)
{
	VipsImage *image;
	VipsImage *out;
	void *output;
	size_t output_length;

	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	if (argc != 3)
		vips_error_exit("usage: %s INPUT-FILE OUTPUT-FILE", argv[0]);

	if (!(image = vips_image_new_from_file(argv[1],
			  "access", VIPS_ACCESS_SEQUENTIAL,
			  NULL)))
		vips_error_exit(NULL);

	if (vips_resize(image, &out, 0.5, NULL))
		vips_error_exit(NULL);

	vips_image_set_progress(out, TRUE);
	g_signal_connect(out, "preeval",
		G_CALLBACK(preeval_callback), NULL);
	g_signal_connect(out, "eval",
		G_CALLBACK(eval_callback), NULL);
	g_signal_connect(out, "posteval",
		G_CALLBACK(posteval_callback), NULL);

	output = NULL;
	if (vips_image_write_to_buffer(out, argv[2], &output, &output_length,
			NULL))
		printf("error return from vips_image_write_to_buffer()\n");

	g_object_unref(out);
	g_object_unref(image);
	if (output)
		g_free(output);
	vips_shutdown();

	return 0;
}
