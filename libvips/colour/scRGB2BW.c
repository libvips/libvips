/* Turn scRGB into greyscale.
 *
 * 17/4/15
 * 	- from scRGB2BW.c
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

typedef struct _VipsscRGB2BW {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	int depth;
} VipsscRGB2BW;

typedef VipsOperationClass VipsscRGB2BWClass;

G_DEFINE_TYPE( VipsscRGB2BW, vips_scRGB2BW, VIPS_TYPE_OPERATION );

/* Process a buffer of data.
 */
static void
vips_scRGB2BW_line_8( VipsPel * restrict q, float * restrict p, 
	int extra_bands, int width )
{
	int i, j;

	for( i = 0; i < width; i++ ) {
		float R = p[0];
		float G = p[1];
		float B = p[2];

		int g;
		int or;

		vips_col_scRGB2BW_8( R, G, B, &g, &or );

		p += 3;

		q[0] = g;

		q += 1;

		for( j = 0; j < extra_bands; j++ ) 
			q[j] = p[j];
		p += extra_bands;
		q += extra_bands;
	}
}

static void
vips_scRGB2BW_line_16( unsigned short * restrict q, float * restrict p, 
	int extra_bands, int width )
{
	int i, j;

	for( i = 0; i < width; i++ ) {
		float R = p[0];
		float G = p[1];
		float B = p[2];

		int g;
		int or;

		vips_col_scRGB2BW_16( R, G, B, &g, &or );

		p += 3;

		q[0] = g;

		q += 1;

		for( j = 0; j < extra_bands; j++ ) 
			q[j] = VIPS_CLIP( 0, p[j] * 256.0, USHRT_MAX ); 
		p += extra_bands;
		q += extra_bands;
	}
}

static int
vips_scRGB2BW_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsscRGB2BW *scRGB2BW = (VipsscRGB2BW *) b;
	VipsRect *r = &or->valid;
	VipsImage *in = ir->im;

	int y;

	if( vips_region_prepare( ir, r ) ) 
		return( -1 );

	VIPS_GATE_START( "vips_scRGB2BW_gen: work" ); 

	for( y = 0; y < r->height; y++ ) {
		float *p = (float *) 
			VIPS_REGION_ADDR( ir, r->left, r->top + y );
		VipsPel *q = (VipsPel *) 
			VIPS_REGION_ADDR( or, r->left, r->top + y );

		if( scRGB2BW->depth == 16 ) 
			vips_scRGB2BW_line_16( (unsigned short *) q, p, 
				in->Bands - 3, r->width );
		else
			vips_scRGB2BW_line_8( q, p, 
				in->Bands - 3, r->width );
	}

	VIPS_GATE_STOP( "vips_scRGB2BW_gen: work" ); 

	return( 0 );
}

static int
vips_scRGB2BW_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsscRGB2BW *scRGB2BW = (VipsscRGB2BW *) object;

	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in; 
	VipsBandFormat format;
	VipsInterpretation interpretation;
	VipsImage *out; 

	if( VIPS_OBJECT_CLASS( vips_scRGB2BW_parent_class )->build( object ) )
		return( -1 );

	in = scRGB2BW->in;
	if( vips_check_bands_atleast( class->nickname, in, 3 ) )
		return( -1 ); 

	switch( scRGB2BW->depth ) { 
	case 16:
		interpretation = VIPS_INTERPRETATION_GREY16;
		format = VIPS_FORMAT_USHORT;
		break;

	case 8:
		interpretation = VIPS_INTERPRETATION_B_W;
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
	out->Bands = in->Bands - 2;

	if( vips_image_generate( out,
		vips_start_one, vips_scRGB2BW_gen, vips_stop_one, 
		in, scRGB2BW ) ) {
		g_object_unref( out );
		return( -1 );
	}

	g_object_set( object, "out", out, NULL ); 

	return( 0 );
}

static void
vips_scRGB2BW_class_init( VipsscRGB2BWClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "scRGB2BW";
	object_class->description = _( "convert scRGB to BW" ); 
	object_class->build = vips_scRGB2BW_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsscRGB2BW, in ) );

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsscRGB2BW, out ) );

	VIPS_ARG_INT( class, "depth", 130, 
		_( "Depth" ),
		_( "Output device space depth in bits" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsscRGB2BW, depth ),
		8, 16, 8 );

}

static void
vips_scRGB2BW_init( VipsscRGB2BW *scRGB2BW )
{
	scRGB2BW->depth = 8;
}

/**
 * vips_scRGB2BW:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @depth: depth of output image in bits
 *
 * Convert an scRGB image to greyscale. Set @depth to 16 to get 16-bit output.
 *
 * If @depth is 16, any extra channels after RGB are 
 * multiplied by 256. 
 *
 * See also: vips_LabS2LabQ(), vips_sRGB2scRGB(), vips_rad2float().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_scRGB2BW( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "scRGB2BW", ap, in, out );
	va_end( ap );

	return( result );
}

