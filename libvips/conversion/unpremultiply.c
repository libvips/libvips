/* unpremultiply alpha
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

typedef struct _VipsUnpremultiply {
	VipsConversion parent_instance;

	VipsImage *in;

} VipsUnpremultiply;

typedef VipsConversionClass VipsUnpremultiplyClass;

G_DEFINE_TYPE( VipsUnpremultiply, vips_unpremultiply, VIPS_TYPE_CONVERSION );

/* Unpremultiply a greyscale (two band) image.
 */
#define UNPRE_GREY( IN, OUT ) { \
	IN * restrict p = (IN *) in; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		IN alpha = p[1]; \
		int clip_alpha = VIPS_CLIP( 0, alpha, max_value ); \
		double nalpha = (double) clip_alpha / max_value; \
		\
		if( clip_alpha == 0 ) \
			q[0] = 0; \
		else \
			q[0] = p[0] / nalpha; \
		q[1] = clip_alpha; \
		\
		p += 2; \
		q += 2; \
	} \
}

/* Unpremultiply an RGB (four band) image.
 */
#define UNPRE_RGB( IN, OUT ) { \
	IN * restrict p = (IN *) in; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		IN alpha = p[3]; \
		int clip_alpha = VIPS_CLIP( 0, alpha, max_value ); \
		double nalpha = (double) clip_alpha / max_value; \
		\
		if( clip_alpha == 0 ) { \
			q[0] = 0; \
			q[1] = 0; \
			q[2] = 0; \
		} \
		else { \
			q[0] = p[0] / nalpha; \
			q[1] = p[1] / nalpha; \
			q[2] = p[2] / nalpha; \
		} \
		q[3] = clip_alpha; \
		\
		p += 4; \
		q += 4; \
	} \
}

/* Unpremultiply a CMYK (five band) image.
 */
#define UNPRE_CMYK( IN, OUT ) { \
	IN * restrict p = (IN *) in; \
	OUT * restrict q = (OUT *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		IN alpha = p[4]; \
		int clip_alpha = VIPS_CLIP( 0, alpha, max_value ); \
		double nalpha = (double) clip_alpha / max_value; \
		\
		if( clip_alpha == 0 ) { \
			q[0] = 0; \
			q[1] = 0; \
			q[2] = 0; \
			q[3] = 0; \
		} \
		else { \
			q[0] = p[0] / nalpha; \
			q[1] = p[1] / nalpha; \
			q[2] = p[2] / nalpha; \
			q[3] = p[3] / nalpha; \
		} \
		q[4] = clip_alpha; \
		\
		p += 5; \
		q += 5; \
	} \
}

#define UNPRE( IN, OUT ) { \
	if( bands == 2 ) { \
		UNPRE_GREY( IN, OUT ); \
	} \
	else if( bands == 4 ) { \
		UNPRE_RGB( IN, OUT ); \
	} \
	else { \
		UNPRE_CMYK( IN, OUT ); \
	} \
}

static int
vips_unpremultiply_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsImage *im = ir->im;
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
			UNPRE( unsigned char, float ); 
			break; 

		case VIPS_FORMAT_CHAR: 
			UNPRE( signed char, float ); 
			break; 

		case VIPS_FORMAT_USHORT: 
			UNPRE( unsigned short, float ); 
			break; 

		case VIPS_FORMAT_SHORT: 
			UNPRE( signed short, float ); 
			break; 

		case VIPS_FORMAT_UINT: 
			UNPRE( unsigned int, float ); 
			break; 

		case VIPS_FORMAT_INT: 
			UNPRE( signed int, float ); 
			break; 

		case VIPS_FORMAT_FLOAT: 
			UNPRE( float, float ); 
			break; 

		case VIPS_FORMAT_DOUBLE: 
			UNPRE( double, double ); 
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
vips_unpremultiply_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsUnpremultiply *unpremultiply = (VipsUnpremultiply *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 1 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_unpremultiply_parent_class )->
		build( object ) )
		return( -1 );

	in = unpremultiply->in; 

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
		vips_start_one, vips_unpremultiply_gen, vips_stop_one, 
		in, unpremultiply ) )
		return( -1 );

	return( 0 );
}

static void
vips_unpremultiply_class_init( VipsUnpremultiplyClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_unpremultiply_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "unpremultiply";
	vobject_class->description = _( "unpremultiply image alpha" );
	vobject_class->build = vips_unpremultiply_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsUnpremultiply, in ) );

}

static void
vips_unpremultiply_init( VipsUnpremultiply *unpremultiply )
{
}

/**
 * vips_unpremultiply:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Unpremultiplies any alpha channel. If @in is a four-band RGBA image, @out 
 * will also have four bands, where:
 *
 * |[
 *   alpha = (unsigned char) clip( 0, in[3], 255 ); // clip alphha range
 *   n = alpha / 255; // normalised alpha
 *   if( n == 0 )
 *   	out = [0, 0, 0, in[3]];
 *   else
 *   	out = [in[0] / n, in[1] / n, in[2] / n, in[3]];
 * |]
 *
 * So the RGB bands are divided by alpha, alpha is untouched. 
 * The result is
 * #VIPS_FORMAT_FLOAT unless the input format is #VIPS_FORMAT_DOUBLE, in which
 * case the output is double as well.
 * If there is no alpha,
 * the image is passed through unaltered.
 *
 * The operation works for 1 - 5 band images, from greyscale to CMYKA. 
 * If interpretation is #VIPS_INTERPRETATION_GREY16 or
 * #VIPS_INTERPRETATION_RGB16, alpha is assumed to have a 0 - 65535 range.
 * Otherwise alpha is assumed to have a 0 - 255 range. 
 *
 * See also: vips_premultiply(), vips_flatten().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_unpremultiply( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "unpremultiply", ap, in, out );
	va_end( ap );

	return( result );
}
