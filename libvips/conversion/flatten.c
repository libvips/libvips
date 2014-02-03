/* flatten the alpha out of an image, replacing it with a constant background
 *
 * Author: John Cupitt
 * Written on: 18/6/12
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
	VipsArea *background;

	/* The [double] converted to the input image format.
	 */
	VipsPel *ink;

} VipsFlatten;

typedef VipsConversionClass VipsFlattenClass;

G_DEFINE_TYPE( VipsFlatten, vips_flatten, VIPS_TYPE_CONVERSION );

/* Shift A down N places, rounding to nearest.
 *
 * This calculates A / B, rounding the result to nearest, ie.
 *
 * 	(a + (b / 2)) / b
 *
 * We mustn't overflow during the add, so we actually do:
 *
 * 	((a / 2) + (b / 4)) / (b / 2)
 *
 * slightly less accurate, but safe from overflow.
 */
#define SHIFT_ROUND( A, N ) \
	((((A) >> 1) + (1 << ((N) - 2)) - 1) >> ((N) - 1))

/* Flatten with shift + round, black background.
 */
#define VIPS_FLATTEN_INT_BLACK( TYPE, N ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		TYPE alpha = p[bands - 1]; \
		int b; \
		\
		for( b = 0; b < bands - 1; b++ ) \
			q[b] = SHIFT_ROUND( p[b] * alpha, N ); \
		\
		p += bands; \
		q += bands - 1; \
	} \
}

/* Flatten with shift + round, any background.
 */
#define VIPS_FLATTEN_INT( TYPE, N ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		TYPE alpha = p[bands - 1]; \
		TYPE nalpha = ((1 << (N)) - 1) - alpha; \
		TYPE *bg = (TYPE *) flatten->ink; \
		int b; \
		\
		for( b = 0; b < bands - 1; b++ ) \
			q[b] = SHIFT_ROUND( p[b] * alpha, (N) ) + \
				SHIFT_ROUND( bg[b] * nalpha, (N) ); \
		\
		p += bands; \
		q += bands - 1; \
	} \
}

/* Flatten via float division, black background. 
 */
#define VIPS_FLATTEN_FLOAT_BLACK( TYPE, SCALE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		TYPE alpha = p[bands - 1]; \
		int b; \
		\
		for( b = 0; b < bands - 1; b++ ) \
			q[b] = ((double) p[b] * alpha) / (SCALE); \
		\
		p += bands; \
		q += bands - 1; \
	} \
}

/* Flatten via float division, any background. 
 */
#define VIPS_FLATTEN_FLOAT( TYPE, SCALE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		TYPE alpha = p[bands - 1]; \
		TYPE nalpha = (SCALE) - alpha; \
		TYPE *bg = (TYPE *) flatten->ink; \
		int b; \
		\
		for( b = 0; b < bands - 1; b++ ) \
			q[b] = ((double) p[b] * alpha) / (SCALE) + \
				((double) bg[b] * nalpha) / (SCALE); \
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

	int x, y;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *in = VIPS_REGION_ADDR( ir, r->left, r->top + y ); 
		VipsPel *out = VIPS_REGION_ADDR( or, r->left, r->top + y ); 

		switch( flatten->in->BandFmt ) { 
		case VIPS_FORMAT_UCHAR: 
			VIPS_FLATTEN_INT_BLACK( unsigned char, 8 ); 
			break; 

		case VIPS_FORMAT_CHAR: 
			/* Alpha is 0 - 127? No idea, really.
			 */
			VIPS_FLATTEN_INT_BLACK( signed char, 7 ); 
			break; 

		case VIPS_FORMAT_USHORT: 
			VIPS_FLATTEN_INT_BLACK( unsigned short, 16 ); 
			break; 

		case VIPS_FORMAT_SHORT: 
			VIPS_FLATTEN_INT_BLACK( signed short, 15 ); 
			break; 

		case VIPS_FORMAT_UINT: 
			VIPS_FLATTEN_FLOAT_BLACK( unsigned int, UINT_MAX ); 
			break; 

		case VIPS_FORMAT_INT: 
			VIPS_FLATTEN_FLOAT_BLACK( signed int, INT_MAX ); 
			break; 

		case VIPS_FORMAT_FLOAT: 
			VIPS_FLATTEN_FLOAT_BLACK( float, 1.0 ); 
			break; 

		case VIPS_FORMAT_DOUBLE: 
			VIPS_FLATTEN_FLOAT_BLACK( double, 1.0 ); 
			break; 

		case VIPS_FORMAT_COMPLEX: 
		case VIPS_FORMAT_DPCOMPLEX: 
		default: 
			g_assert( 0 ); 
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

	int x, y;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *in = VIPS_REGION_ADDR( ir, r->left, r->top + y ); 
		VipsPel *out = VIPS_REGION_ADDR( or, r->left, r->top + y ); 

		switch( flatten->in->BandFmt ) { 
		case VIPS_FORMAT_UCHAR: 
			VIPS_FLATTEN_INT( unsigned char, 8 ); 
			break; 

		case VIPS_FORMAT_CHAR: 
			/* Alpha is 0 - 127? No idea, really.
			 */
			VIPS_FLATTEN_INT( signed char, 7 ); 
			break; 

		case VIPS_FORMAT_USHORT: 
			VIPS_FLATTEN_INT( unsigned short, 16 ); 
			break; 

		case VIPS_FORMAT_SHORT: 
			VIPS_FLATTEN_INT( signed short, 15 ); 
			break; 

		case VIPS_FORMAT_UINT: 
			VIPS_FLATTEN_FLOAT( unsigned int, UINT_MAX ); 
			break; 

		case VIPS_FORMAT_INT: 
			VIPS_FLATTEN_FLOAT( signed int, INT_MAX ); 
			break; 

		case VIPS_FORMAT_FLOAT: 
			VIPS_FLATTEN_FLOAT( float, 1.0 ); 
			break; 

		case VIPS_FORMAT_DOUBLE: 
			VIPS_FLATTEN_FLOAT( double, 1.0 ); 
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
	if( flatten->in->Bands == 1 ) 
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
	for( i = 0; i < flatten->background->n; i++ )
		if( ((double *) flatten->background->data)[i] != 0.0 ) {
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
		if( !(flatten->ink = vips__vector_to_ink( 
			class->nickname, conversion->out,
			flatten->background->data, flatten->background->n )) )
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
}

static void
vips_flatten_init( VipsFlatten *flatten )
{
	flatten->background = 
		vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), 1 ); 
	((double *) (flatten->background->data))[0] = 0.0;
}

/**
 * vips_flatten:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @background: colour for new pixels
 *
 * Take the last band of @in as an alpha and use it to blend the
 * remaining channels with @background. 
 *
 * The alpha channel is 0 - 255 for
 * integer images and 0 - 1 for float images, where 255 means 100% image and 0
 * means 100% background.  Non-complex images only.
 * @background defaults to zero (black).
 *
 * Useful for flattening PNG images to RGB.
 *
 * See also: pngload().
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
