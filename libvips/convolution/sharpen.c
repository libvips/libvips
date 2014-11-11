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
 * 	- does any type, any number of bands
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

	int radius; 
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

static int
vips_sharpen_generate( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsRegion **in = (VipsRegion **) vseq;
	VipsSharpen *sharpen = (VipsSharpen *) b;
	VipsRect *r = &or->valid;
	int ix3 = sharpen->ix3;
	int range = sharpen->ix2 + sharpen->ix3;
	int *lut = sharpen->lut;

	int x, y; 

	if( vips_region_prepare( in[0], r ) ||
		vips_region_prepare( in[1], r ) )
		return( -1 );

	VIPS_GATE_START( "vips_sharpen_generate: work" ); 

	for( y = 0; y < r->height; y++ ) {
		short *p1 = (short *) 
			VIPS_REGION_ADDR( in[0], r->left, r->top + y );
		short *p2 = (short *) 
			VIPS_REGION_ADDR( in[1], r->left, r->top + y );
		short *q = (short *) 
			VIPS_REGION_ADDR( or, r->left, r->top + y );

		for( x = 0; x < r->width; x++ ) {
			int v1 = p1[x];
			int v2 = p2[x];

			/* v2 is the area average. If this is zero, then we 
			 * pass the original image through unaltered.
			 */
			if( v2 == 0 ) 
				q[x] = v1;
			else {
				/* Find difference. Offset by x3 to get the 
				 * expected range of values.
				 */
				int s1 = ix3 + (v1 - v2);
				int s2;

				if( s1 < 0 )
					s1 = 0;
				else if( s1 > range )
					s1 = range;

				s2 = v1 + lut[s1];

				if( s2 < 0 ) 
					s2 = 0;
				else if( s2 > 32767 ) 
					s2 = 32767;

				q[x] = s2;
			}
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
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );
	VipsImage **args = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;
	int ix1, ix2, ix3;
	int i;

	VIPS_GATE_START( "vips_sharpen_build: build" ); 

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
		vips_check_bands_atleast( class->nickname, in, 3 ) || 
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
	 * right. We always sharpen a short, so no point using a float mask. 
	 */
	if( vips_gaussmat( &t[1], 1 + sharpen->radius / 2, 0.2, 
		"separable", TRUE,
		"integer", TRUE,
		NULL ) )
		return( -1 ); 

#ifdef DEBUG
	printf( "sharpen: blurring with:\n" ); 
	vips_matrixprint( t[1], NULL ); 
#endif /*DEBUG*/

	/* Build the int lut.
	 */
	sharpen->ix1 = ix1 = sharpen->x1 * 327.67;
	sharpen->ix2 = ix2 = sharpen->x2 * 327.67;
	sharpen->ix3 = ix3 = sharpen->x3 * 327.67;

	if( !(sharpen->lut = VIPS_ARRAY( object, ix2 + ix3 + 1, int )) )
		return( -1 );

	for( i = 0; i < ix1; i++ ) {
		sharpen->lut[ix3 + i] = i * sharpen->m1;
		sharpen->lut[ix3 - i] = -i * sharpen->m1;
	}
	for( i = ix1; i <= ix2; i++ ) 
		sharpen->lut[ix3 + i] = 
			ix1 * sharpen->m1 + (i - ix1) * sharpen->m2; 
	for( i = ix1; i <= ix3; i++ )
		sharpen->lut[ix3 - i] = 
			-(ix1 * sharpen->m1 + (i - ix1) * sharpen->m2);

	/* Extract L and the rest, convolve L.
	 */
	if( vips_extract_band( in, &args[0], 0, NULL ) ||
		vips_extract_band( in, &t[3], 1, "n", in->Bands - 1, NULL ) ||
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

	/* Reattach the rest.
	 */
	if( vips_bandjoin2( t[5], t[3], &t[6], NULL ) ||
		vips_image_write( t[6], sharpen->out ) )
		return( -1 );

	VIPS_GATE_STOP( "vips_sharpen_build: build" ); 

	return( 0 );
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

	VIPS_ARG_INT( class, "radius", 3, 
		_( "Radius" ), 
		_( "Mask radius" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, radius ),
		1, 1000000, 3 );

	VIPS_ARG_DOUBLE( class, "x1", 5, 
		_( "x1" ), 
		_( "Flat/jaggy threshold" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, x1 ),
		1, 1000000, 1.5 );

	VIPS_ARG_DOUBLE( class, "y2", 6, 
		_( "y2" ), 
		_( "Maximum brightening" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, y2 ),
		1, 1000000, 20 );

	VIPS_ARG_DOUBLE( class, "y3", 7, 
		_( "y3" ), 
		_( "Maximum darkening" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, y3 ),
		1, 1000000, 50 );

	VIPS_ARG_DOUBLE( class, "m1", 8, 
		_( "m1" ), 
		_( "Slope for flat areas" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, m1 ),
		0, 1000000, 1 );

	VIPS_ARG_DOUBLE( class, "m2", 9, 
		_( "m2" ), 
		_( "Slope for jaggy areas" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSharpen, m2 ),
		0, 1000000, 2 );

}

static void
vips_sharpen_init( VipsSharpen *sharpen )
{
	sharpen->radius = 3; 
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
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @radius: how large a mask to use
 * @x1: flat/jaggy threshold
 * @y2: maximum amount of brightening
 * @y3: maximum amount of darkening
 * @m1: slope for flat areas
 * @m2: slope for jaggy areas
 *
 * Selectively sharpen the L channel of a LAB image. The input image is
 * transformed to #VIPS_INTERPRETATION_LABS. 
 *
 * The operation performs a gaussian blur of radius @radius and subtracts 
 * from @in to generate a high-frequency signal. This signal is passed 
 * through a lookup table formed from the five parameters and added back to 
 * @in.
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
 * For printing, we recommend the following settings (the defaults):
 *
 * |[
   radius == 3
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
 * The @radius parameter changes the width of the fringe and can be 
 * adjusted according to the output printing resolution. As an approximate 
 * guideline, use 1 for 4 pixels/mm (CRT display resolution), 2 for 8 
 * pixels/mm, 3 for 12 pixels/mm and 4 for 16 pixels/mm (300 dpi == 12 
 * pixels/mm). These figures refer to the image raster, not the half-tone 
 * resolution.
 *
 * See also: im_conv().
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
