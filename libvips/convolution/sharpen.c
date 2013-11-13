/* Cored sharpen of LABQ image.
 * 
 * Usage:
 *
 *   	int im_sharpen( IMAGE *in, IMAGE *out, 
 *		int mask_size, 
 *		int x1, int x2,
 *		double m1, double m2 )
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

	int mask_size, 
	double x1;
	double y2;
	double y3;
	double m1;
	double m2;

	double x2;
	double x3;

	/* Parameters scaled up to int.
	 *
	 * We need indexes in the range [-x3,x2], so add x3 to 
	 * indexes before starting to index table.
	 */
	int ix1;
	int ix2;
	int ix3;		

	/* The lut we build.
	 */
	int *lut;		

} VipsSharpen;

typedef VipsOperationClass VipsSharpenClass;

G_DEFINE_TYPE( VipsSharpen, vips_sharpen, VIPS_TYPE_OPERATION );

/* Take the difference of in1 and in2 and LUT it.
 */
static void
buf_difflut( short **in, short *out, int n, SharpenLut *slut )
{
	int range = slut->x2 + slut->x3;
	int *lut = slut->lut;
	int x3 = slut->x3;
	short *p1 = in[1];
	short *p2 = in[0];
	int i;

	for( i = 0; i < n; i++ ) {
		int v1 = p1[i];
		int v2 = p2[i];

		/* v2 is the area average. If this is zero, then we pass the
		 * original image through unaltered.
		 */
		if( v2 == 0 ) 
			out[i] = v1;
		else {
			/* Find difference. Offset by x3 to get the expected 
			 * range of values.
			 */
			int s1 = x3 + (v1 - v2);
			int s2;

			/* Clip to LUT range.
			 */
			if( s1 < 0 )
				s1 = 0;
			else if( s1 > range )
				s1 = range;

			/* Transform!
			 */
			s2 = v1 + lut[s1];

			/* Clip to LabS range.
			 */
			if( s2 < 0 ) 
				s2 = 0;
			else if( s2 > 32767 ) 
				s2 = 32767;

			/* And write.
			 */
			out[i] = s2;
		}
	}
}

int
im_sharpen( IMAGE *in, IMAGE *out, 
	int mask_size, 
	double x1, double y2, double y3, 
	double m1, double m2 )
{
	IMAGE *arry[3];
	IMAGE *t[4];
	VipsImage *mask;

	/* Turn y parameters into xs.
	 */
	double x2 = (y2 - x1 * (m1 - m2)) / m2;
	double x3 = (y3 - x1 * (m1 - m2)) / m2;

	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *tc[2];

		if( im_open_local_array( out, tc, 2, "im_sharpen:1", "p" ) ||
			im_LabQ2LabS( in, tc[0] ) ||
			im_sharpen( tc[0], tc[1], 
				mask_size, x1, y2, y3, m1, m2 ) ||
			im_LabS2LabQ( tc[1], out ) )
			return( -1 );

		return( 0 );
	}

	/* Check IMAGE parameters 
	 */
  	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_sharpen", in ) ||
		im_check_bands( "im_gradcor", in, 3 ) || 
		im_check_format( "im_gradcor", in, IM_BANDFMT_SHORT ) )
  		return( -1 );

	/* Check number range.
	 */
	if( x1 < 0 || x1 > 99 || 
		x2 < 0 || x2 > 99 || 
		x1 > x2 ||
		x3 < 0 || x3 > 99 || 
		x1 > x3 ) {
		im_error( "im_sharpen", "%s", _( "parameters out of range" ) );
		return( -1 );
	}

	/* Open a set of local image descriptors.
	 */
	if( im_open_local_array( out, t, 4, "im_sharpen:2", "p" ) )
		return( -1 );

	return( 0 );
}

/* Our sequence value: the region this sequence is using, and local stats.
 */
typedef struct {
	VipsRegion *ir;		/* Input region */

	/* A 256-element hist for evry band.
	 */
	unsigned int **hist;
} VipsSharpenSequence;

static int
vips_sharpen_stop( void *vseq, void *a, void *b )
{
	VipsSharpenSequence *seq = (VipsSharpenSequence *) vseq;
	VipsImage *in = (VipsImage *) a;

	VIPS_UNREF( seq->ir );
	if( seq->hist ) {
		int i; 

		for( i = 0; i < in->Bands; i++ )
			VIPS_FREE( seq->hist[i] );
		VIPS_FREE( seq->hist );
	}
	VIPS_FREE( seq );

	return( 0 );
}

static void *
vips_sharpen_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsSharpenSequence *seq;

	int i;

	if( !(seq = VIPS_NEW( NULL, VipsSharpenSequence )) )
		 return( NULL );
	seq->ir = NULL;
	seq->hist = NULL;

	if( !(seq->ir = vips_region_new( in )) || 
		!(seq->hist = VIPS_ARRAY( NULL, in->Bands, unsigned int * )) ) {
		vips_sharpen_stop( seq, NULL, NULL );
		return( NULL ); 
	}

	for( i = 0; i < in->Bands; i++ )
		if( !(seq->hist[i] = VIPS_ARRAY( NULL, 256, unsigned int )) ) {
		vips_sharpen_stop( seq, NULL, NULL );
		return( NULL ); 
	}

	return( seq );
}

static int
vips_sharpen_generate( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsRegion **in = (VipsRegion **) vseq;
	VipsSharpen *sharpen = (VipsSharpen *) b;
	VipsRect *r = &or->valid;

	VipsRect irect;

	if( vips_region_prepare( in[0], r ) ||
		vips_region_prepare( in[1], r ) )
		return( -1 );

	lsk = VIPS_REGION_LSKIP( seq->ir );
	centre = lsk * (local->height / 2) + bands * local->width / 2;

	for( y = 0; y < r->height; y++ ) {
		/* Get input and output pointers for this line.
		 */
		VipsPel *p = VIPS_REGION_ADDR( seq->ir, r->left, r->top + y );
		VipsPel *q = VIPS_REGION_ADDR( or, r->left, r->top + y );

			}
		}
	}

	return( 0 );
}

static int
vips_sharpen_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsSharpen *local = (VipsSharpen *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 3 );
	VipsImage **args = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_sharpen_parent_class )->build( object ) )
		return( -1 );

	/* Turn y parameters into xs.
	 */
	sharpen->x2 = (sharpen->y2 - 
		sharpen->x1 * (sharpen->m1 - sharpen->m2)) / sharpen->m2;
	sharpen->x3 = (sharpen->y3 - 
		sharpen->x1 * (sharpen->m1 - sharpen->m2)) / sharpen->m2;

	in = sharpen->in; 

	if( vips_colourspace( in, &t[0], VIPS_INTERPRETATION_LABS, NULL ) )
		return( -1 );
	in = t[0];

  	if( vips_check_uncoded( class->nickname, in ) ||
		vips_check_bands( class->nickname, in, 3 ) || 
		vips_check_format( class->nickname, in, VIPS_FORMAT_SHORT ) )
  		return( -1 );

	if( sharpen->x1 < 0 || sharpen->x1 > 99 || 
		sharpen->x2 < 0 || sharpen->x2 > 99 || 
		sharpen->x1 > sharpen->x2 ||
		sharpen->x3 < 0 || sharpen->x3 > 99 || 
		sharpen->x1 > sharpen->x3 ) {
		vips_error( class->nickname, 
			"%s", _( "parameters out of range" ) );
		return( -1 );
	}

	/* Stop at 20% of max ... bit mean, but means mask radius is roughly
	 * right.
	 */
	if( vips_gaussmat( &t[1], radius / 2, 0.2, 
		"separable", TRUE,
		"integer", TRUE,
		NULL ) )
		return( -1 ); 

	/* Build the int lut.
	 */
	sharpen->ix1 = x1 * 327.67;
	sharpen->ix2 = x2 * 327.67;
	sharpen->ix3 = x3 * 327.67;

	if( !(sharpen->lut = VIPS_ARRAY( sharpen->out, 
		sharpen->ix2 + sharpen->ix3 + 1, int )) )
		return( -1 );

	for( i = 0; i < sharpen->ix1; i++ ) {
		slut->lut[sharpen->ix3 + i] = i * m1;
		slut->lut[sharpen->ix3 - i] = -i * m1;
	}
	for( i = sharpen->ix1; i <= sharpen->ix2; i++ ) 
		slut->lut[sharpen->ix3 + i] = 
			sharpen->ix1 * sharpen->m1 + 
				(i - sharpen->ix1) * sharpen->m2; 
	for( i = sharpen->ix1; i <= sharpen->ix3; i++ )
		slut->lut[sharpen->ix3 - i] = 
			-(sharpen->ix1 * sharpen->m1 + 
				(i - sharpen->ix1) * sharpen->m2);

	/* Extract L and ab, convolve L.
	 */
	if( vips_extract_band( in, &args[0], 0, NULL ) ||
		vips_extract_bands( in, &t[3], 1, "n", 2, NULL ) ||
		vips_convsep( args[0], &args[1], t[1], NULL ) )
		return( -1 );

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	t[5] = vips_image_new();
	if( vips_image_pipeline_array( t[5], 
		VIPS_DEMAND_STYLE_FATSTRIP, args ) )
		return( -1 );

	if( vips_image_generate( t[5], 
		vips_start_many, vips_sharpen_generate, vips_stop_many, 
		args, sharpen ) )
		return( -1 );

	g_object_set( object, "out", vips_image_new(), NULL ); 

	/* Reattach ab.
	 */
	if( vips_bandjoin2( t[5], t[3], &t[6], NULL ) ||
		vips_image_write( t[6], sharpen->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_sharpen_class_init( VipsSharpenClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "sharpen";
	object_class->description = _( "Unsharp masking for print" );
	object_class->build = vips_sharpen_build;

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

	VIPS_ARG_INT( class, "mask_size", 4, 
		_( "mask_size" ), 
		_( "Mask radius" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, mask_radius ),
		1, 1000000, 7 );

	VIPS_ARG_DOUBLE( class, "x1", 4, 
		_( "x1" ), 
		_( "Flat/jaggy threshold" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, x1 ),
		1, 1000000, 1.5 );

	VIPS_ARG_DOUBLE( class, "y2", 5, 
		_( "y2" ), 
		_( "Maximum brightening" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, y2 ),
		1, 1000000, 20 );

	VIPS_ARG_DOUBLE( class, "y3", 6, 
		_( "y3" ), 
		_( "Maximum darkening" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, y3 ),
		1, 1000000, 50 );

	VIPS_ARG_DOUBLE( class, "m1", 6, 
		_( "m1" ), 
		_( "Slope for flat areas" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, m1 ),
		1, 1000000, 1 );

	VIPS_ARG_DOUBLE( class, "m2", 7, 
		_( "m2" ), 
		_( "Slope for jaggy areas" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, m2 ),
		1, 1000000, 2 );

}

static void
vips_sharpen_init( VipsSharpen *sharpen )
{
	sharpen->mask_size = 7; 
	sharpen->x1 = 1.5; 
	sharpen->y2 = 20; 
	sharpen->y3 = 50; 
	sharpen->m1 = 1; 
	sharpen->m2 = 2; 
}

/**
 * vips_sharpen:
 * @in: input image
 * @out: output image
 * @mask_size: how large a mask to use
 * @x1: flat/jaggy threshold
 * @y2: maximum amount of brightening
 * @y3: maximum amount of darkening
 * @m1: slope for flat areas
 * @m2: slope for jaggy areas
 * @...: %NULL-terminated list of optional named arguments
 *
 * Selectively sharpen the L channel of a LAB image. Works for 
 * #VIPS_CODING_LABQ and LABS images. 
 *
 * The operation performs a gaussian blur of size @mask_size and subtracts 
 * from @in to
 * generate a high-frequency signal. This signal is passed through a lookup
 * table formed from the five parameters and added back to @in.
 *
 * The lookup table is formed like this:
 *
 * |[
                      ^
                   y2 |- - - - - -----------
                      |         / 
                      |        / slope m2
                      |    .../    
              -x1     | ...   |    
  -------------------...---------------------->
              |   ... |      x1           
              |... slope m1
              /       |
             / m2     |
            /         |
           /          |
          /           |
         /            |
  ______/ _ _ _ _ _ _ | -y3
                      |
 * ]|
 *
 * For printing, we recommend the following settings:
 *
 * |[
   mask_size == 7
   x1 == 1.5
   y2 == 20         (don't brighten by more than 20 L*)
   y3 == 50         (can darken by up to 50 L*)

   m1 == 1          (some sharpening in flat areas)
   m2 == 2          (more sharpening in jaggy areas)
 * ]|
 *
 * If you want more or less sharpening, we suggest you just change the m1 
 * and m2 parameters. 
 *
 * The @mask_size parameter changes the width of the fringe and can be 
 * adjusted according to the output printing resolution. As an approximate 
 * guideline, use 3 for 4 pixels/mm (CRT display resolution), 5 for 8 
 * pixels/mm, 7 for 12 pixels/mm and 9 for 16 pixels/mm (300 dpi == 12 
 * pixels/mm). These figures refer to the image raster, not the half-tone 
 * resolution.
 *
 * See also: im_conv().
 * 
 * Returns: 0 on success, -1 on error.
 */
int 
vips_sharpen( VipsImage *in, VipsImage **out, 
	int mask_size, 
	double x1, double y2, double y3, double m1, double m2,
	... )
{
	va_list ap;
	int result;

	va_start( ap, m2 );
	result = vips_call_split( "sharpen", ap, in, out, 
		mask_size, x1, y2, y3, m1, m2 ); 
	va_end( ap );

	return( result );
}
