/* Turn displayable rgb files to scRGB.
 *
 * Modified:
 * 15/11/94 JC
 *	- memory leak fixed
 *	- error message added
 * 16/11/94 JC
 *	- partialed
 * 21/9/12
 * 	- redone as a class
 * 	- sRGB only, support for other RGBs is now via lcms
 * 6/11/12
 * 	- add 16-bit sRGB import
 * 11/12/12
 * 	- cut about to make sRGB2scRGB.c
 * 12/2/15
 * 	- add 16-bit alpha handling
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#include "pcolour.h"

/* We can't use VipsColourCode as our parent class. We want to handle
 * alpha ourselves so we can get 16 -> 8 bit conversion right.
 */

typedef struct _VipssRGB2scRGB {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
} VipssRGB2scRGB; 

typedef VipsOperationClass VipssRGB2scRGBClass;

G_DEFINE_TYPE( VipssRGB2scRGB, vips_sRGB2scRGB, VIPS_TYPE_OPERATION );

/* Convert a buffer of 8-bit pixels.
 */
static void
vips_sRGB2scRGB_line_8( float * restrict q, VipsPel * restrict p, 
	int extra_bands, int width )
{
	int i, j;

	for( i = 0; i < width; i++ ) {
		int r = p[0];
		int g = p[1];
		int b = p[2];

		float R, G, B;

		p += 3;

		vips_col_sRGB2scRGB_8( r, g, b, &R, &G, &B );

		q[0] = R;
		q[1] = G;
		q[2] = B;

		q += 3;

		for( j = 0; j < extra_bands; j++ ) 
			q[j] = p[j];
		p += extra_bands;
		q += extra_bands;
	}
}

/* Convert a buffer of 16-bit pixels.
 */
static void
vips_sRGB2scRGB_line_16( float * restrict q, unsigned short * restrict p, 
	int extra_bands, int width )
{
	int i, j;

	for( i = 0; i < width; i++ ) {
		int r = p[0];
		int g = p[1];
		int b = p[2];

		float R, G, B;

		p += 3;

		vips_col_sRGB2scRGB_16( r, g, b, &R, &G, &B );

		q[0] = R;
		q[1] = G;
		q[2] = B;

		q += 3;

		for( j = 0; j < extra_bands; j++ ) 
			q[j] = p[j] / 256.0; 
		p += extra_bands;
		q += extra_bands;
	}
}

static int
vips_sRGB2scRGB_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &or->valid;
	VipsImage *in = ir->im;

	int y;

	if( vips_region_prepare( ir, r ) ) 
		return( -1 );

	VIPS_GATE_START( "vips_sRGB2scRGB_gen: work" ); 

	for( y = 0; y < r->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir, r->left, r->top + y );
		float *q = (float *) 
			VIPS_REGION_ADDR( or, r->left, r->top + y );

		if( in->BandFmt == VIPS_FORMAT_UCHAR )
			vips_sRGB2scRGB_line_8( q, p, 
				in->Bands - 3, r->width );
		else
			vips_sRGB2scRGB_line_16( q, (unsigned short *) p, 
				in->Bands - 3, r->width );
	}

	VIPS_GATE_STOP( "vips_sRGB2scRGB_gen: work" ); 

	return( 0 );
}

static int
vips_sRGB2scRGB_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipssRGB2scRGB *sRGB2scRGB = (VipssRGB2scRGB *) object;

	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;
	VipsImage *out;
	VipsBandFormat format;

	if( VIPS_OBJECT_CLASS( vips_sRGB2scRGB_parent_class )->
		build( object ) )
		return( -1 );

	in = sRGB2scRGB->in;
	if( vips_check_bands_atleast( class->nickname, in, 3 ) )
		return( -1 ); 

	format = in->BandFmt == VIPS_FORMAT_USHORT ?
		VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR;
	if( vips_cast( in, &t[0], format, NULL ) )
		return( -1 );
	in = t[0];

	out = vips_image_new();
	if( vips_image_pipelinev( out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) ) {
		g_object_unref( out );
		return( -1 );
	}
	out->Type = VIPS_INTERPRETATION_scRGB;
	out->BandFmt = VIPS_FORMAT_FLOAT;

	if( vips_image_generate( out,
		vips_start_one, vips_sRGB2scRGB_gen, vips_stop_one, 
		in, sRGB2scRGB ) ) {
		g_object_unref( out );
		return( -1 );
	}

	g_object_set( object, "out", out, NULL ); 

	return( 0 );
}

static void
vips_sRGB2scRGB_class_init( VipssRGB2scRGBClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "sRGB2scRGB";
	object_class->description = _( "convert an sRGB image to scRGB" );
	object_class->build = vips_sRGB2scRGB_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipssRGB2scRGB, in ) );

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipssRGB2scRGB, out ) );

}

static void
vips_sRGB2scRGB_init( VipssRGB2scRGB *sRGB2scRGB )
{
}

/**
 * vips_sRGB2scRGB:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convert an sRGB image to scRGB. The input image can be 8 or 16-bit 
 * unsigned int.
 *
 * If the input image is unsigned 16-bit, any extra channels after RGB are 
 * divided by 256. Thus, scRGB alpha is always 0 - 255.99.
 *
 * See also: vips_scRGB2XYZ(), vips_scRGB2sRGB(), vips_rad2float().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_sRGB2scRGB( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sRGB2scRGB", ap, in, out );
	va_end( ap );

	return( result );
}
