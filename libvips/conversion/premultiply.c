/* premultiply alpha
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

	double max_alpha;

} VipsPremultiply;

typedef VipsConversionClass VipsPremultiplyClass;

G_DEFINE_TYPE( VipsPremultiply, vips_premultiply, VIPS_TYPE_CONVERSION );

/* Premultiply an n-band image.
 */
#define PRE_MANY( IN, OUT ) { \
	IN * restrict p = (IN *) in; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		IN alpha = p[bands - 1]; \
		IN clip_alpha = VIPS_CLIP( 0, alpha, max_alpha ); \
		double nalpha = (double) clip_alpha / max_alpha; \
		\
		for( i = 0; i < bands - 1; i++ ) \
			q[i] = p[i] * nalpha; \
		q[i] = alpha; \
		\
		p += bands; \
		q += bands; \
	} \
}

/* Special case for RGBA, it's very common.
 */
#define PRE_RGB( IN, OUT ) { \
	IN * restrict p = (IN *) in; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		IN alpha = p[3]; \
		IN clip_alpha = VIPS_CLIP( 0, alpha, max_alpha ); \
		double nalpha = (double) clip_alpha / max_alpha; \
		\
		q[0] = p[0] * nalpha; \
		q[1] = p[1] * nalpha; \
		q[2] = p[2] * nalpha; \
		q[3] = alpha; \
		\
		p += 4; \
		q += 4; \
	} \
}

#define PRE( IN, OUT ) { \
	if( bands == 3 ) { \
		PRE_RGB( IN, OUT ); \
	} \
	else { \
		PRE_MANY( IN, OUT ); \
	} \
}

static int
vips_premultiply_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsPremultiply *premultiply = (VipsPremultiply *) b;
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsImage *im = ir->im;
	VipsRect *r = &or->valid;
	int width = r->width;
	int bands = im->Bands; 
	double max_alpha = premultiply->max_alpha;

	int x, y, i;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

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
	if( in->Bands == 1 )
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

	VIPS_ARG_DOUBLE( class, "max_alpha", 115, 
		_( "Maximum alpha" ), 
		_( "Maximum value of alpha channel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsPremultiply, max_alpha ),
		0, 100000000, 255 );
}

static void
vips_premultiply_init( VipsPremultiply *premultiply )
{
	premultiply->max_alpha = 255.0;
}

/**
 * vips_premultiply:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @max_alpha: %gdouble, maximum value for alpha
 *
 * Premultiplies any alpha channel. 
 * The final band is taken to be the alpha
 * and the bands are transformed as:
 *
 * |[
 *   alpha = clip( 0, in[in.bands - 1], @max_alpha ); 
 *   norm = alpha / @max_alpha; 
 *   out = [in[0] * norm, ..., in[in.bands - 1] * norm, alpha];
 * |]
 *
 * So for an N-band image, the first N - 1 bands are multiplied by the clipped 
 * and normalised final band, the final band is clipped. 
 * If there is only a single band, 
 * the image is passed through unaltered.
 *
 * The result is
 * #VIPS_FORMAT_FLOAT unless the input format is #VIPS_FORMAT_DOUBLE, in which
 * case the output is double as well.
 *
 * @max_alpha has the default value 255. You will need to set this to 65535
 * for images with a 16-bit alpha, or perhaps 1.0 for images with a float
 * alpha. 
 *
 * See also: vips_unpremultiply(), vips_flatten().
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
