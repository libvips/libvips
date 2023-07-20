/* Draw something on every frame of an animated image.
 *
 * compile with:
 *
 * 	gcc -g -Wall annotate-animated.c `pkg-config vips --cflags --libs`
 *
 * run with:
 *
 *      annotate-animated ~/pics/3198.gif[n=-1] x.webp
 */

#include <vips/vips.h>

static int
annotate_image(VipsObject *context, VipsImage *image, VipsImage **out)
{
	int page_height = vips_image_get_page_height(image);
	int n_pages = image->Ysize / page_height;
	VipsImage **overlay = (VipsImage **)
		vips_object_local_array(context, n_pages);
	VipsImage **page = (VipsImage **)
		vips_object_local_array(context, n_pages);
	VipsImage **annotated = (VipsImage **)
		vips_object_local_array(context, n_pages);

	/* Red as RGBA.
	 */
	double red[] = { 255, 0, 0, 255 };
	double transparent[] = { 0, 0, 0, 0 };

	int i;

	/* Split the image into frames.
	 */
	for (i = 0; i < n_pages; i++)
		if (vips_crop(image, &page[i],
				0, page_height * i, image->Xsize, page_height, NULL))
			return -1;

	/* Make an overlay ... a solid red square, with a transparent hole.
	 */
	if (
		!(overlay[0] = vips_image_new_from_image(page[0],
			  red, VIPS_NUMBER(red))) ||
		vips_draw_rect(overlay[0],
			transparent, VIPS_NUMBER(transparent),
			10, 10, overlay[0]->Xsize - 20, overlay[0]->Ysize - 20,
			"fill", TRUE,
			NULL))
		return -1;

	/* Draw the overlay on every page.
	 */
	for (i = 0; i < n_pages; i++)
		if (vips_composite2(page[i], overlay[0], &annotated[i],
				VIPS_BLEND_MODE_OVER, NULL))
			return -1;

	/* Reassemble the frames.
	 */
	if (vips_arrayjoin(annotated, out, n_pages,
			"across", 1,
			NULL))
		return -1;

	return 0;
}

int
main(int argc, char **argv)
{
	VipsImage *image;
	VipsObject *context;
	VipsImage *x;

	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	if (argc != 3)
		vips_error_exit("usage: %s xxx.gif[n=-1] yyy.gif", argv[0]);

	if (!(image = vips_image_new_from_file(argv[1],
			  "access", VIPS_ACCESS_SEQUENTIAL,
			  NULL)))
		vips_error_exit(NULL);

	context = VIPS_OBJECT(vips_image_new());
	if (annotate_image(context, image, &x)) {
		g_object_unref(image);
		g_object_unref(context);
		vips_error_exit(NULL);
	}
	g_object_unref(image);
	g_object_unref(context);
	image = x;

	if (vips_image_write_to_file(image, argv[2], NULL)) {
		g_object_unref(image);
		vips_error_exit(NULL);
	}

	g_object_unref(image);

	return 0;
}
