/* premultiply and unpremultiply alpha
 *
 * Author: John Cupitt
 * Written on: 7/5/15
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pconversion.h"

typedef struct _VipsPremultiply {
	VipsConversion parent_instance;

	VipsImage *in;

	/* Set for the inverse transform (divide, or unpremultiply).
	 */
	gboolean unpremultiply;

} VipsPremultiply;

typedef VipsConversionClass VipsPremultiplyClass;

G_DEFINE_TYPE( VipsPremultiply, vips_premultiply, VIPS_TYPE_CONVERSION );

/* Pre and unpre ops.
 */

#define PRE_MULTIPLY( Q, P ) { \
	(Q) = (P) * nalpha; \
}

#define UNPRE_MULTIPLY( Q, P ) { \
	if( clip_alpha == 0 ) \
		(Q) = 0.0; \
	else \
		(Q) = (P) / nalpha; \
}

/* Premultiply a greyscale (two band) image.
 */
#define PRE_GREY( IN, OUT, OP ) { \
	IN * restrict p = (IN *) in; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		IN alpha = p[1]; \
		int clip_alpha = VIPS_CLIP( 0, alpha, max_value ); \
		double nalpha = clip_alpha / max_value; \
		\
		OP( q[0], p[0] ); \
		q[1] = alpha; \
		\
		p += 2; \
		q += 2; \
	} \
}

/* Premultiply an RGB (four band) image.
 */
#define PRE_RGB( IN, OUT, OP ) { \
	IN * restrict p = (IN *) in; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		IN alpha = p[3]; \
		int clip_alpha = VIPS_CLIP( 0, alpha, max_value ); \
		double nalpha = clip_alpha / max_value; \
		\
		OP( q[0], p[0] ); \
		OP( q[1], p[1] ); \
		OP( q[2], p[2] ); \
		q[3] = alpha; \
		\
		p += 4; \
		q += 4; \
	} \
}

/* Premultiply a CMYK (five band) image.
 */
#define PRE_CMYK( IN, OUT, OP ) { \
	IN * restrict p = (IN *) in; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		IN alpha = p[4]; \
		int clip_alpha = VIPS_CLIP( 0, alpha, max_value ); \
		double nalpha = clip_alpha / max_value; \
		\
		OP( q[0], p[0] ); \
		OP( q[1], p[1] ); \
		OP( q[2], p[2] ); \
		OP( q[3], p[3] ); \
		q[4] = alpha; \
		\
		p += 5; \
		q += 5; \
	} \
}

#define PRE_OP( IN, OUT, OP ) { \
	if( bands == 2 ) { \
		PRE_GREY( IN, OUT, OP ); \
	} \
	else if( bands == 4 ) { \
		PRE_RGB( IN, OUT, OP ); \
	} \
	else { \
		PRE_CMYK( IN, OUT, OP ); \
	} \
}

#define PRE( IN, OUT ) { \
	if( premultiply->unpremultiply ) { \
		PRE_OP( IN, OUT, UNPRE_MULTIPLY ); \
	} \
	else { \
		PRE_OP( IN, OUT, PRE_MULTIPLY ); \
	} \
}

static int
vips_premultiply_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsImage *im = ir->im;
	VipsPremultiply *premultiply = (VipsPremultiply *) b;
	VipsRect *r = &or->valid;
	int width = r->width;
	int bands = im->Bands; 

	int max_value;
	int x, y;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	if( im->Type == VIPS_INTERPRETATION_GREY16 ||
		im->Type == VIPS_INTERPRETATION_RGB16 )
		max_value = 65535;
	else
		max_value = 255;

	for( y = 0; y < r->height; y++ ) {
		VipsPel *in = VIPS_REGION_ADDR( ir, r->left, r->top + y ); 
		VipsPel *out = VIPS_REGION_ADDR( or, r->left, r->top + y ); 

		switch( im->BandFmt ) { 
		case VIPS_FORMAT_UCHAR: 
			PRE( unsigned char, float ); 
			break; 

		case VIPS_FORMAT_CHAR: 
			PRE( signed char, float ); 
			break; 

		case VIPS_FORMAT_USHORT: 
			PRE( unsigned short, float ); 
			break; 

		case VIPS_FORMAT_SHORT: 
			PRE( signed short, float ); 
			break; 

		case VIPS_FORMAT_UINT: 
			PRE( unsigned int, float ); 
			break; 

		case VIPS_FORMAT_INT: 
			PRE( signed int, float ); 
			break; 

		case VIPS_FORMAT_FLOAT: 
			PRE( float, float ); 
			break; 

		case VIPS_FORMAT_DOUBLE: 
			PRE( double, double ); 
			break; 

		case VIPS_FORMAT_COMPLEX: 
		case VIPS_FORMAT_DPCOMPLEX: 
		default: 
			g_assert( 0 ); 
		} 
	}

	return( 0 );
}


static int
vips_premultiply_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsPremultiply *premultiply = (VipsPremultiply *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 1 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_premultiply_parent_class )->
		build( object ) )
		return( -1 );

	in = premultiply->in; 

	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0]; 

	/* Trivial case: fall back to copy().
	 */
	if( in->Bands == 1 || 
		in->Bands == 3 || 
		(in->Bands == 4 && 
		 in->Type == VIPS_INTERPRETATION_CMYK) ) 
		return( vips_image_write( in, conversion->out ) );

	if( vips_check_noncomplex( class->nickname, in ) )
		return( -1 );

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );

	if( in->BandFmt == VIPS_FORMAT_DOUBLE )
		conversion->out->BandFmt = VIPS_FORMAT_DOUBLE;
	else
		conversion->out->BandFmt = VIPS_FORMAT_FLOAT;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_premultiply_gen, vips_stop_one, 
		in, premultiply ) )
		return( -1 );

	return( 0 );
}

static void
vips_premultiply_class_init( VipsPremultiplyClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_premultiply_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "premultiply";
	vobject_class->description = _( "premultiply image alpha" );
	vobject_class->build = vips_premultiply_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPremultiply, in ) );

	VIPS_ARG_BOOL( class, "unpremultiply", 2, 
		_( "Unpremultiply" ), 
		_( "Reverse transform" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsPremultiply, unpremultiply ),
		FALSE );
}

static void
vips_premultiply_init( VipsPremultiply *premultiply )
{
}

/**
 * vips_premultiply:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @unpremultiply: %gboolean, set this to reverse the transform
 *
 * Premultiplies any alpha channel. If @in is an 8-bit RGBA image, @out will 
 * also have four bands, where:
 *
 * |[
 *   n = in[3] / 255; // normalised alpha
 *   out = [in[0] * n, in[1] * n, in[2] * n, in[3]];
 * |]
 *
 * So the RGB bands are scaled by alpha, alpha is untouched. The result is
 * always #VIPS_FORMAT_FLOAT. If you set @unpremultiply, the inverse operation
 * is performed, so RGB are divided by normalised alpha. If there is no alpha,
 * the image is passed through unaltered.
 *
 * The operation works for 1 - 5 band images, from greyscale to CMYKA. 16-bit
 * unsigned int image are assumed to have a 16-bit alpha, all other images are
 * expected to have 0 - 255 alpha. 
 *
 * See also: vips_flatten().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_premultiply( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "premultiply", ap, in, out );
	va_end( ap );

	return( result );
}
