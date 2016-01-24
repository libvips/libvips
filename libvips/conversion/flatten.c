/* flatten the alpha out of an image, replacing it with a constant background
 *
 * Author: John Cupitt
 * Written on: 18/6/12
 *
 * 4/1/14
 * 	- better rounding 
 * 9/5/15
 * 	- add max_alpha to match vips_premultiply() etc.
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

typedef struct _VipsFlatten {
	VipsConversion parent_instance;

	VipsImage *in;

	/* Background colour.
	 */
	VipsArrayDouble *background;

	/* The [double] converted to the input image format.
	 */
	VipsPel *ink;

	/* Use this to scale alpha to 0 - 1.
	 */
	double max_alpha;

} VipsFlatten;

typedef VipsConversionClass VipsFlattenClass;

G_DEFINE_TYPE( VipsFlatten, vips_flatten, VIPS_TYPE_CONVERSION );

/* Flatten with black background.
 */
#define VIPS_FLATTEN_BLACK( TYPE ) { \
	TYPE * restrict p = (TYPE *) in; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		TYPE alpha = p[bands - 1]; \
		int b; \
		\
		for( b = 0; b < bands - 1; b++ ) \
			q[b] = (p[b] * alpha) / max_alpha; \
		\
		p += bands; \
		q += bands - 1; \
	} \
}

/* Flatten with any background.
 */
#define VIPS_FLATTEN( TYPE ) { \
	TYPE * restrict p = (TYPE *) in; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		TYPE alpha = p[bands - 1]; \
		TYPE nalpha = max_alpha - alpha; \
		TYPE * restrict bg = (TYPE *) flatten->ink; \
		int b; \
		\
		for( b = 0; b < bands - 1; b++ ) \
			q[b] = (p[b] * alpha) / max_alpha + \
				(bg[b] * nalpha) / max_alpha; \
		\
		p += bands; \
		q += bands - 1; \
	} \
}

/* Same, but with float arithmetic. Necessary for int/uint to prevent
 * overflow.
 */
#define VIPS_FLATTEN_BLACK_FLOAT( TYPE ) { \
	TYPE * restrict p = (TYPE *) in; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		TYPE alpha = p[bands - 1]; \
		int b; \
		\
		for( b = 0; b < bands - 1; b++ ) \
			q[b] = ((double) p[b] * alpha) / max_alpha; \
		\
		p += bands; \
		q += bands - 1; \
	} \
}

#define VIPS_FLATTEN_FLOAT( TYPE ) { \
	TYPE * restrict p = (TYPE *) in; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		TYPE alpha = p[bands - 1]; \
		TYPE nalpha = max_alpha - alpha; \
		TYPE * restrict bg = (TYPE *) flatten->ink; \
		int b; \
		\
		for( b = 0; b < bands - 1; b++ ) \
			q[b] = ((double) p[b] * alpha) / max_alpha + \
				((double) bg[b] * nalpha) / max_alpha; \
		\
		p += bands; \
		q += bands - 1; \
	} \
}

static int
vips_flatten_black_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsFlatten *flatten = (VipsFlatten *) b;
	VipsRect *r = &or->valid;
	int width = r->width;
	int bands = ir->im->Bands; 
	double max_alpha = flatten->max_alpha;

	int x, y;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *in = VIPS_REGION_ADDR( ir, r->left, r->top + y ); 
		VipsPel *out = VIPS_REGION_ADDR( or, r->left, r->top + y ); 

		switch( flatten->in->BandFmt ) { 
		case VIPS_FORMAT_UCHAR: 
			VIPS_FLATTEN_BLACK( unsigned char ); 
			break; 

		case VIPS_FORMAT_CHAR: 
			VIPS_FLATTEN_BLACK( signed char ); 
			break; 

		case VIPS_FORMAT_USHORT: 
			VIPS_FLATTEN_BLACK( unsigned short ); 
			break; 

		case VIPS_FORMAT_SHORT: 
			VIPS_FLATTEN_BLACK( signed short ); 
			break; 

		case VIPS_FORMAT_UINT: 
			VIPS_FLATTEN_BLACK_FLOAT( unsigned int ); 
			break; 

		case VIPS_FORMAT_INT: 
			VIPS_FLATTEN_BLACK_FLOAT( signed int ); 
			break; 

		case VIPS_FORMAT_FLOAT: 
			VIPS_FLATTEN_BLACK_FLOAT( float ); 
			break; 

		case VIPS_FORMAT_DOUBLE: 
			VIPS_FLATTEN_BLACK_FLOAT( double ); 
			break; 

		case VIPS_FORMAT_COMPLEX: 
		case VIPS_FORMAT_DPCOMPLEX: 
		default: 
			g_assert_not_reached(); 
		} 
	}

	return( 0 );
}

/* Any background.
 */
static int
vips_flatten_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsFlatten *flatten = (VipsFlatten *) b;
	VipsRect *r = &or->valid;
	int width = r->width;
	int bands = ir->im->Bands; 
	double max_alpha = flatten->max_alpha;

	int x, y;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *in = VIPS_REGION_ADDR( ir, r->left, r->top + y ); 
		VipsPel *out = VIPS_REGION_ADDR( or, r->left, r->top + y ); 

		switch( flatten->in->BandFmt ) { 
		case VIPS_FORMAT_UCHAR: 
			VIPS_FLATTEN( unsigned char ); 
			break; 

		case VIPS_FORMAT_CHAR: 
			VIPS_FLATTEN( signed char ); 
			break; 

		case VIPS_FORMAT_USHORT: 
			VIPS_FLATTEN( unsigned short ); 
			break; 

		case VIPS_FORMAT_SHORT: 
			VIPS_FLATTEN( signed short ); 
			break; 

		case VIPS_FORMAT_UINT: 
			VIPS_FLATTEN_FLOAT( unsigned int ); 
			break; 

		case VIPS_FORMAT_INT: 
			VIPS_FLATTEN_FLOAT( signed int ); 
			break; 

		case VIPS_FORMAT_FLOAT: 
			VIPS_FLATTEN_FLOAT( float ); 
			break; 

		case VIPS_FORMAT_DOUBLE: 
			VIPS_FLATTEN_FLOAT( double ); 
			break; 

		case VIPS_FORMAT_COMPLEX: 
		case VIPS_FORMAT_DPCOMPLEX: 
		default: 
			g_assert_not_reached(); 
		} 
	}

	return( 0 );
}


static int
vips_flatten_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsFlatten *flatten = (VipsFlatten *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 1 );

	VipsImage *in;
	int i;
	gboolean black;

	if( VIPS_OBJECT_CLASS( vips_flatten_parent_class )->build( object ) )
		return( -1 );

	in = flatten->in; 

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

	conversion->out->Bands -= 1;

	/* Is the background black? We have a special path for this.
	 */
	black = TRUE;
	for( i = 0; i < VIPS_AREA( flatten->background )->n; i++ )
		if( vips_array_double_get( flatten->background, NULL )[i] != 
			0.0 ) {
			black = FALSE;
			break;
		}

	if( black ) {
		if( vips_image_generate( conversion->out,
			vips_start_one, vips_flatten_black_gen, vips_stop_one, 
			in, flatten ) )
			return( -1 );
	}
	else {
		/* Convert the background to the image's format.
		 */
		if( !(flatten->ink = vips__vector_to_ink( class->nickname, 
			conversion->out, 
			VIPS_AREA( flatten->background )->data, NULL, 
			VIPS_AREA( flatten->background )->n )) )
			return( -1 );

		if( vips_image_generate( conversion->out,
			vips_start_one, vips_flatten_gen, vips_stop_one, 
			in, flatten ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_flatten_class_init( VipsFlattenClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_flatten_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "flatten";
	vobject_class->description = _( "flatten alpha out of an image" );
	vobject_class->build = vips_flatten_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFlatten, in ) );

	VIPS_ARG_BOXED( class, "background", 2, 
		_( "Background" ), 
		_( "Background value" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFlatten, background ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_DOUBLE( class, "max_alpha", 115, 
		_( "Maximum alpha" ), 
		_( "Maximum value of alpha channel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFlatten, max_alpha ),
		0, 100000000, 255 );

}

static void
vips_flatten_init( VipsFlatten *flatten )
{
	flatten->background = vips_array_double_newv( 1, 0.0 );
	flatten->max_alpha= 255.0;
}

/**
 * vips_flatten:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @background: #VipsArrayDouble colour for new pixels 
 * @max_alpha: %gdouble, maximum value for alpha
 *
 * Take the last band of @in as an alpha and use it to blend the
 * remaining channels with @background. 
 *
 * The alpha channel is 0 - @max_alpha,
 * where 1 means 100% image and 0
 * means 100% background.  
 * Non-complex images only.
 * @background defaults to zero (black). 
 *
 * @max_alpha has the default value 255. You will need to set this to 65535
 * for images with a 16-bit alpha, or perhaps 1.0 for images with a float
 * alpha. 
 *
 * Useful for flattening PNG images to RGB.
 *
 * See also: vips_premultiply(), vips_pngload().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_flatten( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "flatten", ap, in, out );
	va_end( ap );

	return( result );
}
