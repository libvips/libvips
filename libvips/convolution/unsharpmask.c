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

typedef struct _VipsUnsharpMask
{
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

G_DEFINE_TYPE( VipsUnsharpMask, vips_unsharpmask, VIPS_TYPE_OPERATION );

static int
vips_unsharpmask_generate( VipsRegion *or, void *vseq, void *a, void *b,
                           gboolean *stop )
{
    VipsRegion **in = (VipsRegion **) vseq;
    VipsUnsharpMask *unsharpmask = (VipsUnsharpMask *) b;
    VipsRect *r = &or->valid;
    int *lut = unsharpmask->lut;

    int x, y;

    if ( vips_reorder_prepare_many( or->im, in, r ))
        return ( -1 );

    VIPS_GATE_START( "vips_unsharpmask_generate: work" );

    for ( y = 0; y < r->height; y++ ) {
        short *p1 = (short *restrict)
            VIPS_REGION_ADDR( in[0], r->left, r->top + y );
        short *p2 = (short *restrict)
            VIPS_REGION_ADDR( in[1], r->left, r->top + y );
        short *q = (short *restrict)
            VIPS_REGION_ADDR( or, r->left, r->top + y );

        for ( x = 0; x < r->width; x++ ) {
            int v1 = p1[x];
            int v2 = p2[x];

            /* Our LUT is -32768 - 32767. For the v1, v2
             * difference to be in this range, both must be 0 -
             * 32767.
             */
            int diff = (( v1 & 0x7fff ) - ( v2 & 0x7fff ));

            int out;

            g_assert( diff + 32768 >= 0 );
            g_assert( diff + 32768 < 65536 );

            out = v1 + lut[diff + 32768];

            if ( out < 0 )
                out = 0;
            if ( out > 32767 )
                out = 32767;

            q[x] = out;
        }
    }

    VIPS_GATE_STOP( "vips_unsharpmask_generate: work" );

    return ( 0 );
}

static int
vips_unsharpmask_build( VipsObject *object )
{
    VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
    VipsUnsharpMask *unsharpmask = (VipsUnsharpMask *) object;
    VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );
    VipsImage **args = (VipsImage **) vips_object_local_array( object, 2 );

    VipsImage *in;
    VipsInterpretation original_interpretation;

    VIPS_GATE_START( "vips_unsharpmask_build: build" );

    if ( VIPS_OBJECT_CLASS( vips_unsharpmask_parent_class )->build( object ))
        return ( -1 );

    in = unsharpmask->in;

    // force RGB colorspace
    original_interpretation = in->Type;
    if ( vips_colourspace( in, &t[0], VIPS_INTERPRETATION_sRGB, NULL))
        return ( -1 );

    // assign RGB image to in 
    in = t[0];

    if ( vips_check_uncoded( class->nickname, in ) ||
        vips_check_bands_atleast( class->nickname, in, 3 ) ||
        vips_check_format( class->nickname, in, VIPS_FORMAT_SHORT ))
        return ( -1 );

    /* create the blurred image
     * Stop at 10% of max ... a bit mean.
     * We always unsharpmask a short, 
     * so there's no point using a float mask.
     */
    if ( vips_gaussblur( in, &t[1], unsharpmask->sigma,
                         "min_ampl", 0.1,
                         "precision", VIPS_PRECISION_INTEGER,
                         NULL))
        return ( -1 );

    t[2] = vips_image_new( );
    if ( vips_image_pipeline_array( t[2],
                                    VIPS_DEMAND_STYLE_FATSTRIP, args ))
        return ( -1 );

    if ( vips_image_generate( t[2],
                              vips_start_many, vips_unsharpmask_generate, vips_stop_many,
                              args, unsharpmask ))
        return ( -1 );

    g_object_set( object, "out", vips_image_new( ), NULL);

    /* Reattach the rest.
     */
    if ( vips_colourspace( t[2], &t[3], original_interpretation, NULL) ||
        vips_image_write( t[3], unsharpmask->out ))
        return ( -1 );

    VIPS_GATE_STOP( "vips_unsharpmask_build: build" );

    return ( 0 );
}

static void
vips_unsharpmask_class_init( VipsUnsharpMaskClass *class )
{
    GObjectClass *gobject_class = G_OBJECT_CLASS( class );
    VipsObjectClass *object_class = (VipsObjectClass *) class;
    VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

    gobject_class->set_property = vips_object_set_property;
    gobject_class->get_property = vips_object_get_property;

    object_class->nickname = "unsharpmask";
    object_class->description = _( "unsharp masking for print" );
    object_class->build = vips_unsharpmask_build;

    operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

    VIPS_ARG_IMAGE( class, "in", 1,
                    _( "Input" ),
                    _( "Input image" ),
                    VIPS_ARGUMENT_REQUIRED_INPUT,
                    G_STRUCT_OFFSET( VipsUnsharpMask, in ));

    VIPS_ARG_IMAGE( class, "out", 2,
                    _( "Output" ),
                    _( "Output image" ),
                    VIPS_ARGUMENT_REQUIRED_OUTPUT,
                    G_STRUCT_OFFSET( VipsUnsharpMask, out ));

    VIPS_ARG_DOUBLE( class, "radius", 3,
                     _( "Radius" ),
                     _( "The radius of the gaussian" ),
                     VIPS_ARGUMENT_OPTIONAL_INPUT,
                     G_STRUCT_OFFSET( VipsUnsharpMask, radius ),
                     0.000001, 128, 0.66 );

    VIPS_ARG_DOUBLE( class, "sigma", 4,
                     _( "Sigma" ),
                     _( "The standard deviation of the gaussian" ),
                     VIPS_ARGUMENT_OPTIONAL_INPUT,
                     G_STRUCT_OFFSET( VipsUnsharpMask, sigma ),
                     0.000001, 10000.0, 0.5 );

    VIPS_ARG_DOUBLE( class, "amount", 5,
                     _( "Amount" ),
                     _( "The percentage of difference that is added" ),
                     VIPS_ARGUMENT_OPTIONAL_INPUT,
                     G_STRUCT_OFFSET( VipsUnsharpMask, amount ),
                     0, 1000000, 1.0 );

    VIPS_ARG_DOUBLE( class, "threshold", 6,
                     _( "Threshold" ),
                     _( "Threshold controls the minimal brightness change that will be applied" ),
                     VIPS_ARGUMENT_OPTIONAL_INPUT,
                     G_STRUCT_OFFSET( VipsUnsharpMask, threshold ),
                     0, 1000000, 0.01 );
}

static void
vips_unsharpmask_init( VipsUnsharpMask *unsharpmask )
{
    unsharpmask->radius = 0.66;
    unsharpmask->sigma = 0.5;
    unsharpmask->amount = 1.0;
    unsharpmask->threshold = 0.01;
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
vips_unsharpmask( VipsImage *in, VipsImage **out, ... )
{
    va_list ap;
    int result;

    va_start( ap, out );
    result = vips_call_split( "unsharpmask", ap, in, out );
    va_end( ap );

    return ( result );
}
