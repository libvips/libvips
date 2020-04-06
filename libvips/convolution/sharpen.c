/* Cored sharpen of LABQ image.
 * 
 * Returns 0 on success and -1 on error
 *
 * Copyright: 1995 A. Abbood 
 * Author: A. Abbood
 * Written on: 30/01/1995
 * 15/5/95 JC
 *	- updated for latest 7.3 mods
 *	- m3 parameter removed
 *	- bug fixes and speed-ups
 * 4/7/95 JC
 *	- x3 parameter added
 *	- xs are now double
 * 6/7/95 JC
 *	- xs are now ys
 *	- better LUT generation
 * 12/3/01 JC
 *	- uses seperable convolution for umask
 *	- tiny clean ups
 * 23/7/01 JC
 *	- fix for band extract index changed
 * 21/4/04
 *	- switched to gaussian mask and radius
 * 20/11/04 
 *	- uses extract_bands() to remove and reattach ab for slight speedup
 *	- accepts LabS as well as LabQ for slight speedup
 *	- small code tidies
 *	- ~15% speed up in total
 * 29/11/06
 * 	- convolve first to help region sharing
 * 3/2/10
 * 	- gtkdoc
 * 	- cleanups
 * 13/11/13
 * 	- redo as a class
 * 	- does any type, any number of bands
 * 24/2/16
 * 	- swap "radius" for "sigma", allows finer control
 * 	- allow a much greater range of parameters
 * 	- move to defaults suitable for screen output
 * 28/8/19
 * 	- fix sigma 0.5 case (thanks 2h4dl)
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

typedef struct _VipsSharpen {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

	double sigma; 
	double x1;
	double y2;
	double y3;
	double m1;
	double m2;

	/* The lut we build.
	 */
	int *lut;		

	/* We used to have a radius control.
	 */
	int radius;

} VipsSharpen;

typedef VipsOperationClass VipsSharpenClass;

G_DEFINE_TYPE( VipsSharpen, vips_sharpen, VIPS_TYPE_OPERATION )

int *vips_sharpen_make_lut(VipsObject *object, const VipsSharpen *sharpen);

static int
vips_sharpen_generate( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsRegion **in = (VipsRegion **) vseq;
	VipsSharpen *sharpen = (VipsSharpen *) b;
	VipsRect *r = &or->valid;
	int *lut = sharpen->lut;

	int x, y; 

	if( vips_reorder_prepare_many( or->im, in, r ) )
		return( -1 );

	VIPS_GATE_START( "vips_sharpen_generate: work" ); 

	for( y = 0; y < r->height; y++ ) {
		short *p1 = (short * restrict) 
			VIPS_REGION_ADDR( in[0], r->left, r->top + y );
		short *p2 = (short * restrict) 
			VIPS_REGION_ADDR( in[1], r->left, r->top + y );
		short *q = (short * restrict) 
			VIPS_REGION_ADDR( or, r->left, r->top + y );

		for( x = 0; x < r->width; x++ ) {
			int v1 = p1[x];
			int v2 = p2[x];

			/* Our LUT is -32768 - 32767. For the v1, v2
			 * difference to be in this range, both must be 0 -
			 * 32767.
			 */
			int diff = ((v1 & 0x7fff) - (v2 & 0x7fff));

			int out;

			g_assert( diff + 32768 >= 0 );
			g_assert( diff + 32768 < 65536 );

			out = v1 + lut[diff + 32768];
			
			if( out < 0 )
				out = 0;
			if( out > 32767 )
				out = 32767;

			q[x] = out;
		}
	}

	VIPS_GATE_STOP( "vips_sharpen_generate: work" ); 

	return( 0 );
}

static int
vips_sharpen_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsSharpen *sharpen = (VipsSharpen *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 8 );
	VipsImage **l_band_and_convolution = (VipsImage **) vips_object_local_array(object, 2 );
    VipsInterpretation old_interpretation;

#define in_labs t[0]
#define gaussmat t[1]
#define other_bands t[3]
#define sharpened_l_band t[5]
#define joined_bands t[6]
#define joined_bands_old_interpretation t[7]

#define l_band l_band_and_convolution[0]
#define convolution l_band_and_convolution[1]

	VIPS_GATE_START( "vips_sharpen_build: build" ); 

	if( VIPS_OBJECT_CLASS( vips_sharpen_parent_class )->build( object ) )
		return( -1 );

	/* We used to have a radius control. If that's set but sigma isn't,
	 * use it to set a reasonable value for sigma.
	 */
	if( !vips_object_argument_isset( object, "sigma" )  &&
		vips_object_argument_isset( object, "radius" ) )
		sharpen->sigma = 1 + sharpen->radius / 2;

	old_interpretation = sharpen->in->Type;
	if( vips_colourspace( sharpen->in, &in_labs, VIPS_INTERPRETATION_LABS, NULL ) )
		return( -1 );

  	if( vips_check_uncoded( class->nickname, in_labs ) ||
		vips_check_bands_atleast( class->nickname, in_labs, 3 ) ||
		vips_check_format( class->nickname, in_labs, VIPS_FORMAT_SHORT ) )
  		return( -1 );

	/* Stop at 10% of max ... a bit mean. We always sharpen a short, 
	 * so there's no point using a float mask. 
	 */
	if( vips_gaussmat( &gaussmat, sharpen->sigma, 0.1,
		"separable", TRUE,
		"precision", VIPS_PRECISION_INTEGER,
		NULL ) )
		return( -1 ); 

#ifdef DEBUG
	printf( "sharpen: blurring with:\n" ); 
	vips_matrixprint( gaussmat, NULL );
#endif /*DEBUG*/

	/* Index with the signed difference between two 0 - 32767 images.
	 */
	if( !(sharpen->lut = vips_sharpen_make_lut(object, sharpen)) )
		return( -1 );

    /* Extract L and the rest, convolve L.
	 */
	if( vips_extract_band( in_labs, &l_band, 0, NULL ) ||
		vips_extract_band( in_labs, &other_bands, 1, "n", in_labs->Bands - 1, NULL ) ||
		vips_convsep( l_band, &convolution, gaussmat,
			"precision", VIPS_PRECISION_INTEGER,
			NULL ) )
		return( -1 );

	sharpened_l_band = vips_image_new();
	if( vips_image_pipeline_array(sharpened_l_band,
                                  VIPS_DEMAND_STYLE_FATSTRIP, l_band_and_convolution ) )
		return( -1 );

	if( vips_image_generate(sharpened_l_band,
                            vips_start_many, vips_sharpen_generate, vips_stop_many,
                            l_band_and_convolution, sharpen ) )
		return( -1 );

	g_object_set( object, "out", vips_image_new(), NULL ); 

	/* Reattach the rest.
	 */
	if( vips_bandjoin2( sharpened_l_band, other_bands, &joined_bands, NULL ) ||
		vips_colourspace( joined_bands, &joined_bands_old_interpretation, old_interpretation, NULL ) ||
		vips_image_write( joined_bands_old_interpretation, sharpen->out ) )
		return( -1 );

	VIPS_GATE_STOP( "vips_sharpen_build: build" ); 

	return( 0 );
}

int* vips_sharpen_make_lut(VipsObject *object, const VipsSharpen *sharpen) {
    int *lut;
    int i;

    if( !(lut = VIPS_ARRAY( object, 65536, int )))
        return NULL;

    for (i = 0; i < 65536; i++) {
        /* Rescale to +/- 100.
         */
        double v = (i - 32767) / 327.67;
        double y;

        if (v < -sharpen->x1)
            /* Left of -x1.
             */
            y = (v + sharpen->x1) * sharpen->m2 +
                -sharpen->x1 * sharpen->m1;
        else if (v < sharpen->x1)
            /* Centre section.
             */
            y = v * sharpen->m1;
        else
            /* Right of x1.
             */
            y = (v - sharpen->x1) * sharpen->m2 +
                sharpen->x1 * sharpen->m1;

        if (y < -sharpen->y3)
            y = -sharpen->y3;
        if (y > sharpen->y2)
            y = sharpen->y2;

        lut[i] = VIPS_RINT(y * 327.67);
    }

#ifdef DEBUG
    {
        VipsImage *mat = vips_image_new_matrix(65536, 1);
        for (i = 0; i < 65536; i++)
            *VIPS_MATRIX(mat, i1, 0) = lut[i];
        vips_image_write_to_file(mat, "x.v", NULL);
        printf("lut written to x.v\n");
        g_object_unref(mat);
    }
#endif /*DEBUG*/

    return lut;
}

static void
vips_sharpen_class_init( VipsSharpenClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "sharpen";
	object_class->description = _( "unsharp masking for print" );
	object_class->build = vips_sharpen_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsSharpen, out ) );

	VIPS_ARG_DOUBLE( class, "sigma", 3, 
		_( "Sigma" ), 
		_( "Sigma of Gaussian" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, sigma ),
		0.000001, 10000.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "x1", 5, 
		_( "x1" ), 
		_( "Flat/jaggy threshold" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, x1 ),
		0, 1000000, 2.0 );

	VIPS_ARG_DOUBLE( class, "y2", 6, 
		_( "y2" ), 
		_( "Maximum brightening" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, y2 ),
		0, 1000000, 10 );

	VIPS_ARG_DOUBLE( class, "y3", 7, 
		_( "y3" ), 
		_( "Maximum darkening" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, y3 ),
		0, 1000000, 20 );

	VIPS_ARG_DOUBLE( class, "m1", 8, 
		_( "m1" ), 
		_( "Slope for flat areas" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, m1 ),
		0, 1000000, 0.0 );

	VIPS_ARG_DOUBLE( class, "m2", 9, 
		_( "m2" ), 
		_( "Slope for jaggy areas" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, m2 ),
		0, 1000000, 3.0 );

	/* We used to have a radius control.
	 */
	VIPS_ARG_INT( class, "radius", 3, 
		_( "Radius" ), 
		_( "radius of Gaussian" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsSharpen, radius ),
		1, 100, 1 );

}

static void
vips_sharpen_init( VipsSharpen *sharpen )
{
	sharpen->sigma = 0.5;
	sharpen->x1 = 2.0;
	sharpen->y2 = 10.0; 
	sharpen->y3 = 20.0; 
	sharpen->m1 = 0.0; 
	sharpen->m2 = 3.0;
}

/**
 * vips_sharpen: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @sigma: sigma of gaussian
 * * @x1: flat/jaggy threshold
 * * @y2: maximum amount of brightening
 * * @y3: maximum amount of darkening
 * * @m1: slope for flat areas
 * * @m2: slope for jaggy areas
 *
 * Selectively sharpen the L channel of a LAB image. The input image is
 * transformed to #VIPS_INTERPRETATION_LABS. 
 *
 * The operation performs a gaussian blur and subtracts from @in to generate a
 * high-frequency signal. This signal is passed through a lookup table formed
 * from the five parameters and added back to @in.
 *
 * The lookup table is formed like this:
 *
 * |[
 * .                     ^
 * .                  y2 |- - - - - -----------
 * .                     |         / 
 * .                     |        / slope m2
 * .                     |    .../    
 * .             -x1     | ...   |    
 * . -------------------...---------------------->
 * .             |   ... |      x1           
 * .             |... slope m1
 * .             /       |
 * .            / m2     |
 * .           /         |
 * .          /          |
 * .         /           |
 * .        /            |
 * . ______/ _ _ _ _ _ _ | -y3
 * .                     |
 * ]|
 *
 * For screen output, we suggest the following settings (the defaults):
 *
 * |[
 *   sigma == 0.5
 *   x1 == 2
 *   y2 == 10         (don't brighten by more than 10 L*)
 *   y3 == 20         (can darken by up to 20 L*)
 *   m1 == 0          (no sharpening in flat areas)
 *   m2 == 3          (some sharpening in jaggy areas)
 * ]|
 *
 * If you want more or less sharpening, we suggest you just change the 
 * m2 parameter. 
 *
 * The @sigma parameter changes the width of the fringe and can be 
 * adjusted according to the output printing resolution. As an approximate 
 * guideline, use 0.5 for 4 pixels/mm (display resolution), 
 * 1.0 for 12 pixels/mm and 1.5 for 16 pixels/mm (300 dpi == 12 
 * pixels/mm). These figures refer to the image raster, not the half-tone 
 * resolution.
 *
 * See also: vips_conv().
 * 
 * Returns: 0 on success, -1 on error.
 */
int 
vips_sharpen( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sharpen", ap, in, out );  
	va_end( ap );

	return( result );
}
