/* Turn scRGB files into displayable rgb.
 *
 * Author: J-P. Laurent
 * Modified:
 * 15/11/94 JC
 *	- error message added
 *	- out->Type set to IM_TYPE_RGB
 *	- memory leak fixed
 * 16/11/94 JC
 *	- uses im_wrapone()
 * 15/2/95 JC
 *	- oops! now uses PEL, not float for output pointer
 * 2/1/96 JC
 *	- sometimes produced incorrect result at extrema
 *	- reformatted
 *	- now uses IM_RINT() and clip()
 * 18/9/96 JC
 *	- some speed-ups ... 3x faster
 *	- slightly less accurate, but who cares
 *	- added out-of-mem check for table build
 * 21/9/12
 * 	- redone as a class
 * 	- sRGB only, support for other RGBs is now via lcms
 * 6/11/12
 * 	- added 16-bit option
 * 11/12/12
 * 	- cut about to make scRGB2sRGB.c
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

typedef struct _VipsscRGB2sRGB {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	int depth;
} VipsscRGB2sRGB;

typedef VipsOperationClass VipsscRGB2sRGBClass;

G_DEFINE_TYPE( VipsscRGB2sRGB, vips_scRGB2sRGB, VIPS_TYPE_OPERATION );

/* Process a buffer of data.
 */
static void
vips_scRGB2sRGB_line_8( VipsPel * restrict q, float * restrict p, 
	int extra_bands, int width )
{
	int i, j;

	for( i = 0; i < width; i++ ) {
		float R = p[0];
		float G = p[1];
		float B = p[2];

		int r, g, b;
		int or;

		vips_col_scRGB2sRGB_8( R, G, B, &r, &g, &b, &or );

		p += 3;

		q[0] = r;
		q[1] = g;
		q[2] = b;

		q += 3;

		for( j = 0; j < extra_bands; j++ ) 
			q[j] = p[j];
		p += extra_bands;
		q += extra_bands;
	}
}

static void
vips_scRGB2sRGB_line_16( unsigned short * restrict q, float * restrict p, 
	int extra_bands, int width )
{
	int i, j;

	for( i = 0; i < width; i++ ) {
		float R = p[0];
		float G = p[1];
		float B = p[2];

		int r, g, b;
		int or;

		vips_col_scRGB2sRGB_16( R, G, B, &r, &g, &b, &or );

		p += 3;

		q[0] = r;
		q[1] = g;
		q[2] = b;

		q += 3;

		for( j = 0; j < extra_bands; j++ ) 
			q[j] = VIPS_FCLIP( 0, p[j] * 256.0, USHRT_MAX ); 
		p += extra_bands;
		q += extra_bands;
	}
}

static int
vips_scRGB2sRGB_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsscRGB2sRGB *scRGB2sRGB = (VipsscRGB2sRGB *) b;
	VipsRect *r = &or->valid;
	VipsImage *in = ir->im;

	int y;

	if( vips_region_prepare( ir, r ) ) 
		return( -1 );

	VIPS_GATE_START( "vips_scRGB2sRGB_gen: work" ); 

	for( y = 0; y < r->height; y++ ) {
		float *p = (float *) 
			VIPS_REGION_ADDR( ir, r->left, r->top + y );
		VipsPel *q = (VipsPel *) 
			VIPS_REGION_ADDR( or, r->left, r->top + y );

		if( scRGB2sRGB->depth == 16 ) 
			vips_scRGB2sRGB_line_16( (unsigned short *) q, p, 
				in->Bands - 3, r->width );
		else
			vips_scRGB2sRGB_line_8( q, p, 
				in->Bands - 3, r->width );
	}

	VIPS_GATE_STOP( "vips_scRGB2sRGB_gen: work" ); 

	return( 0 );
}

static int
vips_scRGB2sRGB_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsscRGB2sRGB *scRGB2sRGB = (VipsscRGB2sRGB *) object;

	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in; 
	VipsBandFormat format;
	VipsInterpretation interpretation;
	VipsImage *out; 

	if( VIPS_OBJECT_CLASS( vips_scRGB2sRGB_parent_class )->build( object ) )
		return( -1 );

	in = scRGB2sRGB->in;
	if( vips_check_bands_atleast( class->nickname, in, 3 ) )
		return( -1 ); 

	switch( scRGB2sRGB->depth ) { 
	case 16:
		interpretation = VIPS_INTERPRETATION_RGB16;
		format = VIPS_FORMAT_USHORT;
		break;

	case 8:
		interpretation = VIPS_INTERPRETATION_sRGB;
		format = VIPS_FORMAT_UCHAR;
		break;

	default:
		vips_error( class->nickname, 
			"%s", _( "depth must be 8 or 16" ) );
		return( -1 );
	}

	if( vips_cast_float( in, &t[0], NULL ) )
		return( -1 );
	in = t[0];

	out = vips_image_new();
	if( vips_image_pipelinev( out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) ) {
		g_object_unref( out );
		return( -1 );
	}
	out->Type = interpretation;
	out->BandFmt = format;

	if( vips_image_generate( out,
		vips_start_one, vips_scRGB2sRGB_gen, vips_stop_one, 
		in, scRGB2sRGB ) ) {
		g_object_unref( out );
		return( -1 );
	}

	g_object_set( object, "out", out, NULL ); 

	return( 0 );
}

static void
vips_scRGB2sRGB_class_init( VipsscRGB2sRGBClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "scRGB2sRGB";
	object_class->description = _( "convert an scRGB image to sRGB" ); 
	object_class->build = vips_scRGB2sRGB_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsscRGB2sRGB, in ) );

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsscRGB2sRGB, out ) );

	VIPS_ARG_INT( class, "depth", 130, 
		_( "Depth" ),
		_( "Output device space depth in bits" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsscRGB2sRGB, depth ),
		8, 16, 8 );

}

static void
vips_scRGB2sRGB_init( VipsscRGB2sRGB *scRGB2sRGB )
{
	scRGB2sRGB->depth = 8;
}

/**
 * vips_scRGB2sRGB:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @depth: depth of output image in bits
 *
 * Convert an scRGB image to sRGB. Set @depth to 16 to get 16-bit output.
 *
 * If @depth is 16, any extra channels after RGB are 
 * multiplied by 256. 
 *
 * See also: vips_LabS2LabQ(), vips_sRGB2scRGB(), vips_rad2float().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_scRGB2sRGB( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "scRGB2sRGB", ap, in, out );
	va_end( ap );

	return( result );
}

