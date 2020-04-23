/* Unsharp Mask that resembles that of ImageMagick.
 * 
 * 9/3/20 Elad Laufer
 *	- from sharpen.c
 *	
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/

#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

typedef struct _VipsUnsharpMask {
    VipsOperation parent_instance;

    VipsImage *in;
    VipsImage *out;

    double radius;
    double sigma;
    double amount;
    double threshold;

    /* The lut we build.
     */
    int *lut;
} VipsUnsharpMask;

typedef VipsOperationClass VipsUnsharpMaskClass;

G_DEFINE_TYPE(VipsUnsharpMask, vips_unsharpmask, VIPS_TYPE_OPERATION)

#define MAX_KERNEL_WIDTH 257
#define SQRT_2_PI 2.50662827463100024161235523934010416269302368164062 // sqrt(2 * pi)
#define EPSILON 1.0e-15
#define KERNEL_RANK 3

static int
vips_unsharpmask_build(VipsObject *object);

static int
vips_unsharpmask_generate(VipsRegion *or, void *vseq, void *a, void *b,
                          gboolean *stop);

static int
vips_unsharpmask_calculate_kernel(VipsUnsharpMask *unsharp_mask, float *kernel, int *out_kernel_width);

static int
vips_unsharpmask_optimal_kernel_width_1d(VipsUnsharpMask *unsharp_mask);

static void
vips_unsharpmask_class_init(VipsUnsharpMaskClass *class) {
    GObjectClass *gobject_class = G_OBJECT_CLASS(class);
    VipsObjectClass *object_class = (VipsObjectClass *) class;
    VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);

    gobject_class->set_property = vips_object_set_property;
    gobject_class->get_property = vips_object_get_property;

    object_class->nickname = "unsharpmask";
    object_class->description = _("unsharp masking for screen");
    object_class->build = vips_unsharpmask_build;

    operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

    VIPS_ARG_IMAGE(class, "in", 1,
                   _("Input"),
                   _("Input image"),
                   VIPS_ARGUMENT_REQUIRED_INPUT,
                   G_STRUCT_OFFSET(VipsUnsharpMask, in));

    VIPS_ARG_IMAGE(class, "out", 2,
                   _("Output"),
                   _("Output image"),
                   VIPS_ARGUMENT_REQUIRED_OUTPUT,
                   G_STRUCT_OFFSET(VipsUnsharpMask, out));

    VIPS_ARG_DOUBLE(class, "radius", 3,
                    _("Radius"),
                    _("The radius of the gaussian"),
                    VIPS_ARGUMENT_OPTIONAL_INPUT,
                    G_STRUCT_OFFSET(VipsUnsharpMask, radius),
                    0.000001, 128, 0.66);

    VIPS_ARG_DOUBLE(class, "sigma", 4,
                    _("Sigma"),
                    _("The standard deviation of the gaussian"),
                    VIPS_ARGUMENT_OPTIONAL_INPUT,
                    G_STRUCT_OFFSET(VipsUnsharpMask, sigma),
                    0.000001, 10000.0, 0.5);

    VIPS_ARG_DOUBLE(class, "amount", 5,
                    _("Amount"),
                    _("The percentage of difference that is added"),
                    VIPS_ARGUMENT_OPTIONAL_INPUT,
                    G_STRUCT_OFFSET(VipsUnsharpMask, amount),
                    0, 1000000, 1.0);

    VIPS_ARG_DOUBLE(class, "threshold", 6,
                    _("Threshold"),
                    _("Threshold controls the minimal brightness change that will be applied"),
                    VIPS_ARGUMENT_OPTIONAL_INPUT,
                    G_STRUCT_OFFSET(VipsUnsharpMask, threshold),
                    0, 1000000, 0.01);
}

static void
vips_unsharpmask_init(VipsUnsharpMask *unsharpmask) {
    unsharpmask->radius = 0.66;
    unsharpmask->sigma = 0.5;
    unsharpmask->amount = 1.0;
    unsharpmask->threshold = 0.01;
}


static int
vips_unsharpmask_build(VipsObject *object) {
    VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
    VipsUnsharpMask *unsharp_mask = (VipsUnsharpMask *) object;
    float kernel[MAX_KERNEL_WIDTH] = {0};
    int kernel_width;

    if ((unsharp_mask->in->BandFmt != VIPS_FORMAT_UCHAR)  && (unsharp_mask->in->BandFmt != VIPS_FORMAT_USHORT)) {
        vips_error(class->nickname, "band format must be either UCHAR or USHORT");
        return -1;
    }

    if (vips_unsharpmask_calculate_kernel(unsharp_mask, kernel, &kernel_width)) {
        return (-2);
    }

    return (0);
}

static int
vips_unsharpmask_calculate_kernel(VipsUnsharpMask *unsharp_mask, float *kernel, int *out_kernel_width) {
    VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(unsharp_mask);
    double sigma = unsharp_mask->sigma;
    int kernel_width;
    double precise_kernel[MAX_KERNEL_WIDTH] = {0}; // calc in double precision and cast to float
    double sum = 0;
    int u;
    int v;

    // calculate kernel width
    kernel_width = VIPS_CEIL(unsharp_mask->radius) * 2 + 1;

    if (VIPS_ABS(unsharp_mask->radius) < EPSILON)
        kernel_width = vips_unsharpmask_optimal_kernel_width_1d(unsharp_mask);

    if (kernel_width < 0 || kernel_width > MAX_KERNEL_WIDTH) {
        vips_error(class->nickname, "unsupported kernel size");
        return -1;
    }

    if (sigma <= EPSILON) {
        // special case - generate a unity kernel
        kernel[kernel_width / 2] = 1.0f;
        *out_kernel_width = kernel_width;
        return (0);
    }

    v = (kernel_width * KERNEL_RANK - 1) / 2;
    sigma *= KERNEL_RANK;
    for (u = -v; u <= v; ++u) {
        double interval = exp(-(1.0 / (2.0 * sigma * sigma)) * u * u) * (1.0 / (SQRT_2_PI * sigma));
        precise_kernel[(u + v) / KERNEL_RANK] += interval;
        sum += interval;
    }

    for (u = 0; u < kernel_width; ++u) // casting to float
        kernel[u] = (float) (precise_kernel[u] / sum);

    *out_kernel_width = kernel_width;
    return (0);
}

// The function returns the width of the filter depending on the value of Sigma
// The kernel width is expected to be between 1 and 253
static int
vips_unsharpmask_optimal_kernel_width_1d(VipsUnsharpMask *unsharp_mask) {
    double bit_cond = unsharp_mask->in->BandFmt == VIPS_FORMAT_UCHAR ? 3.921568627450980e-03 : 1.525902189669642e-05;
    double GAMMA = VIPS_ABS(unsharp_mask->sigma);
    double ALPHA = 1.0 / (2.0 * GAMMA * GAMMA);
    double BETA = 1.0 / (SQRT_2_PI * GAMMA);
    int width = 5;

    if (GAMMA < EPSILON)
        return 1;

    for (int index = 0; index < 1000; ++index) {
        double normalize = 0.0;
        int i;
        int j = (width - 1) / 2;

        for (i = -j; i <= j; ++i)
            normalize += (exp(-ALPHA * (i * i)) * BETA);

        double value = exp(-ALPHA * (j * j)) * BETA / normalize;
        if (value < bit_cond || value < EPSILON)
            break;

        width += 2;
    }

    return width - 2;
}


static int
vips_unsharpmask_generate(VipsRegion *or, void *vseq, void *a, void *b, gboolean *stop) {
    VipsRegion **in = (VipsRegion **) vseq;
    VipsUnsharpMask *unsharpmask = (VipsUnsharpMask *) b;
    VipsRect *r = &or->valid;
    int *lut = unsharpmask->lut;

    int x, y;

    if (vips_reorder_prepare_many(or->im, in, r))
        return (-1);

    VIPS_GATE_START("vips_unsharpmask_generate: work");

    for (y = 0; y < r->height; y++) {
        short *p1 = (short *restrict)
                VIPS_REGION_ADDR(in[0], r->left, r->top + y);
        short *p2 = (short *restrict)
                VIPS_REGION_ADDR(in[1], r->left, r->top + y);
        short *q = (short *restrict)
                VIPS_REGION_ADDR(or, r->left, r->top + y);

        for (x = 0; x < r->width; x++) {
            int v1 = p1[x];
            int v2 = p2[x];


        }
    }

    VIPS_GATE_STOP("vips_unsharpmask_generate: work");

    return (0);
}

/**
 * vips_unsharpmask: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @sigma: the standard deviation of the Gaussian
 * * @radius: the radius of the Gaussian
 * * @amount: maximum amount of brightening
 * * @threshold: maximum amount of darkening
 *
 * The operation performs a gaussian blur and subtracts from @in to generate a
 * high-frequency signal. This signal is multiplied by the amount and added back to @in.
 * 
 * Returns: 0 on success, -1 on error.
 */
int
vips_unsharpmask(VipsImage *in, VipsImage **out, ...) {
    va_list ap;
    int result;

    va_start(ap, out);
    result = vips_call_split("unsharpmask", ap, in, out);
    va_end(ap);

    return (result);
}
