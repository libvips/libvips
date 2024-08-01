/* A tiny example operation. This adds two uchar images to make a ushort
 * image.
 *
 * It only outputs the common pixels, so both inputs are cropped to the common
 * size in all three dimensions (width, height, bands).
 *
 * compile with
 *
 *		gcc my-add.c -g -Wall `pkg-config vips --cflags --libs`
 *
 * (derived from code by @prasadbandodkar with thanks)
 */

#include <vips/vips.h>
#include <stdio.h>

static int
my_add_generate(VipsRegion *out_region,
	void *vseq, void *a, void *b, gboolean *stop)
{
	// output area and output image
    VipsRect *r = &out_region->valid;
    VipsImage *out = out_region->im;

	// input regions and input images
    VipsRegion **ir = (VipsRegion **) vseq;
    VipsImage **inputs = (VipsImage **) a;

    // request matching part of input regions
    if (vips_reorder_prepare_many(out_region->im, ir, r))
        return -1;

    for (int y = 0; y < r->height; y++)
    {
        unsigned char *p1 = VIPS_REGION_ADDR(ir[0], r->left, r->top + y);
        unsigned char *p2 = VIPS_REGION_ADDR(ir[1], r->left, r->top + y);
        unsigned short *q = (unsigned short *)
			VIPS_REGION_ADDR(out_region, r->left, r->top + y);

        for (int x = 0; x < r->width; x++) {
			for (int b = 0; b < out->Bands; b++)
				q[b] = p1[b] + p2[b];

			p1 += inputs[0]->Bands;
			p2 += inputs[1]->Bands;
			q += out->Bands;
		}
    }

    return 0;
}

static int
my_add_operation(VipsImage *in1, VipsImage *in2, VipsImage **out_reference)
{
	// we only work for uchar images
	if (vips_check_format("try", in1, VIPS_FORMAT_UCHAR) ||
		vips_check_format("try", in2, VIPS_FORMAT_UCHAR))
		return -1;

    // make the output image
    VipsImage *out = vips_image_new();

	// make a self-freeing, null-terminated array of input images
	VipsImage **inputs = vips_allocate_input_array(out, in1, in2, NULL);

    if (vips_image_pipeline_array(out, VIPS_DEMAND_STYLE_THINSTRIP, inputs)) {
        g_object_unref(out);
		return -1;
    }

	// out will inherit all the properties of the inputs ... we must override
	// the ones we want to change (dimensions and format)
	out->Xsize = VIPS_MIN(in1->Xsize, in2->Xsize);
	out->Ysize = VIPS_MIN(in1->Ysize, in2->Ysize);
	out->Bands = VIPS_MIN(in1->Bands, in2->Bands);
	out->BandFmt = VIPS_FORMAT_USHORT;

    // generate pixels
    if (vips_image_generate(out,
		vips_start_many, my_add_generate, vips_stop_many, inputs, NULL)) {
		g_object_unref(out);
		return -1;
    }

	// success! set the output pointer
	*out_reference = out;

	return 0;
}

int
main(int argc, char **argv)
{
    // initialize vips
    if (VIPS_INIT(argv[0]))
		vips_error_exit("try");

	if (argc != 4)
		vips_error_exit("usage: %s in1 in2 out", argv[0]);

    // open inputs ... sequential access is fine for our operation
    VipsImage *in1 = vips_image_new_from_file(argv[1],
		"access", VIPS_ACCESS_SEQUENTIAL,
		NULL);
    VipsImage *in2 = vips_image_new_from_file(argv[2],
		"access", VIPS_ACCESS_SEQUENTIAL,
		NULL);

	// call our operation
	VipsImage *out;
	if (my_add_operation(in1, in2, &out)) {
        g_object_unref(in1);
        g_object_unref(in2);
		vips_error_exit("try");
    }

    // save the result
    if (vips_image_write_to_file(out, argv[3], NULL)) {
        g_object_unref(in1);
        g_object_unref(in2);
        g_object_unref(out);
		vips_error_exit("try");
    }

    // release any resources
	g_object_unref(in1);
	g_object_unref(in2);
    g_object_unref(out);

    return 0;
}
