/* horizontal shrink by an integer factor
 *
 * 30/10/15
 * 	- from shrink.c
 * 22/1/16
 * 	- reorganise loops, 30% faster, vectorisable
 * 15/8/16
 * 	- rename xshrink -> hshrink for greater consistency 
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
#include <vips/debug.h>
#include <vips/internal.h>

#include "presample.h"

typedef struct _VipsShrinkh {
	VipsResample parent_instance;

	int hshrink;		/* Shrink factor */

} VipsShrinkh;

typedef VipsResampleClass VipsShrinkhClass;

G_DEFINE_TYPE( VipsShrinkh, vips_shrinkh, VIPS_TYPE_RESAMPLE );

#define INNER( BANDS ) \
	sum += p[x1]; \
	x1 += BANDS; 

/* Integer shrink. 
 */
#define ISHRINK( TYPE, BANDS ) { \
	TYPE * restrict p = (TYPE *) in; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		for( b = 0; b < BANDS; b++ ) { \
			int sum; \
			\
			sum = 0; \
			x1 = b; \
			VIPS_UNROLL( shrink->hshrink, INNER( BANDS ) ); \
			q[b] = (sum + shrink->hshrink / 2) / \
				shrink->hshrink; \
		} \
		p += ne; \
		q += BANDS; \
	} \
}

/* Float shrink. 
 */
#define FSHRINK( TYPE ) { \
	TYPE * restrict p = (TYPE *) in; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		for( b = 0; b < bands; b++ ) { \
			double sum; \
			\
			sum = 0.0; \
			x1 = b; \
			VIPS_UNROLL( shrink->hshrink, INNER( bands ) ); \
			q[b] = sum / shrink->hshrink; \
		} \
		p += ne; \
		q += bands; \
	} \
} 

/* Generate an area of @or. @ir is large enough.
 */
static void
vips_shrinkh_gen2( VipsShrinkh *shrink, VipsRegion *or, VipsRegion *ir,
	int left, int top, int width )
{
	VipsResample *resample = VIPS_RESAMPLE( shrink );
	const int bands = resample->in->Bands * 
		(vips_band_format_iscomplex( resample->in->BandFmt ) ? 
		 	2 : 1);
	const int ne = shrink->hshrink * bands; 
	VipsPel *out = VIPS_REGION_ADDR( or, left, top ); 
	VipsPel *in = VIPS_REGION_ADDR( ir, left * shrink->hshrink, top ); 

	int x;
	int x1, b;

	switch( resample->in->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	
		/* Generate a special path for 1, 3 and 4 band uchar data. The
		 * compiler will be able to vectorise these.
		 *
		 * Vectorisation doesn't help much for 16, 32-bit or float
		 * data, don't bother with them.
		 */
		switch( bands ) {
		case 1:
			ISHRINK( unsigned char, 1 ); break;
		case 3:
			ISHRINK( unsigned char, 3 ); break;
		case 4:
			ISHRINK( unsigned char, 4 ); break;
		default:
			ISHRINK( unsigned char, bands ); break;
		}
		break;

	case VIPS_FORMAT_CHAR: 	
		ISHRINK( char, bands ); break; 
	case VIPS_FORMAT_USHORT: 
		ISHRINK( unsigned short, bands ); break;
	case VIPS_FORMAT_SHORT: 	
		ISHRINK( short, bands ); break; 
	case VIPS_FORMAT_UINT: 	
		ISHRINK( unsigned int, bands ); break; 
	case VIPS_FORMAT_INT: 	
		ISHRINK( int, bands );  break; 
	case VIPS_FORMAT_FLOAT: 	
		FSHRINK( float ); break; 
	case VIPS_FORMAT_DOUBLE:	
		FSHRINK( double ); break;
	case VIPS_FORMAT_COMPLEX: 	
		FSHRINK( float ); break; 
	case VIPS_FORMAT_DPCOMPLEX:	
		FSHRINK( double ); break;

	default:
		g_assert_not_reached(); 
	}
}

static int
vips_shrinkh_gen( VipsRegion *or, void *seq, 
	void *a, void *b, gboolean *stop )
{
	VipsShrinkh *shrink = (VipsShrinkh *) b;
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &or->valid;

	int y;

	/* How do we chunk up the image? We don't want to prepare the whole of
	 * the input region corresponding to *r since it could be huge. 
	 *
	 * Request input a line at a time. 
	 *
	 * We don't chunk horizontally. We want "vips shrink x.jpg b.jpg 100
	 * 100" to run sequentially. If we chunk horizontally, we will fetch
	 * 100x100 lines from the top of the image, then 100x100 100 lines
	 * down, etc. for each thread, then when they've finished, fetch
	 * 100x100, 100 pixels across from the top of the image. This will
	 * break sequentiality. 
	 */

#ifdef DEBUG
	printf( "vips_shrinkh_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG*/

	for( y = 0; y < r->height; y ++ ) { 
		VipsRect s;

		s.left = r->left * shrink->hshrink;
		s.top = r->top + y;
		s.width = r->width * shrink->hshrink;
		s.height = 1;
#ifdef DEBUG
		printf( "shrinkh_gen: requesting line %d\n", s.top ); 
#endif /*DEBUG*/
		if( vips_region_prepare( ir, &s ) )
			return( -1 );

		VIPS_GATE_START( "vips_shrinkh_gen: work" ); 

		vips_shrinkh_gen2( shrink, or, ir, 
			r->left, r->top + y, r->width );

		VIPS_GATE_STOP( "vips_shrinkh_gen: work" ); 
	}

	VIPS_COUNT_PIXELS( or, "vips_shrinkh_gen" ); 

	return( 0 );
}

static int
vips_shrinkh_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsShrinkh *shrink = (VipsShrinkh *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 2 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_shrinkh_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	if( shrink->hshrink < 1 ) { 
		vips_error( class->nickname, 
			"%s", _( "shrink factors should be >= 1" ) );
		return( -1 );
	}

	if( shrink->hshrink == 1 ) 
		return( vips_image_write( in, resample->out ) );

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	/* We need new pixels at the right so that we don't have small chunks
	 * to average down the right edge.
	 */
	if( vips_embed( in, &t[1], 
		0, 0, 
		in->Xsize + shrink->hshrink, in->Ysize,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[1];

	/* THINSTRIP will work, anything else will break seq mode. If you 
	 * combine shrink with conv you'll need to use a line cache to maintain
	 * sequentiality.
	 */
	if( vips_image_pipelinev( resample->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Size output. We need to always round to nearest, so round(), not
	 * rint().
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true shrink factor (including the
	 * fractional part), we just see the integer part here.
	 */
	resample->out->Xsize = VIPS_ROUND_UINT( 
		(double) resample->in->Xsize / shrink->hshrink );
	if( resample->out->Xsize <= 0 ) { 
		vips_error( class->nickname, 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_shrinkh_build: shrinking %d x %d image to %d x %d\n", 
		in->Xsize, in->Ysize, 
		resample->out->Xsize, resample->out->Ysize );  
#endif /*DEBUG*/

	if( vips_image_generate( resample->out,
		vips_start_one, vips_shrinkh_gen, vips_stop_one, 
		in, shrink ) )
		return( -1 );

	return( 0 );
}

static void
vips_shrinkh_class_init( VipsShrinkhClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_shrinkh_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "shrinkh";
	vobject_class->description = _( "shrink an image horizontally" );
	vobject_class->build = vips_shrinkh_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_INT( class, "hshrink", 8, 
		_( "Hshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsShrinkh, hshrink ),
		1, 1000000, 1 );

	/* The old name .. now use h and v everywhere. 
	 */
	VIPS_ARG_INT( class, "xshrink", 8, 
		_( "Xshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsShrinkh, hshrink ),
		1, 1000000, 1 );

}

static void
vips_shrinkh_init( VipsShrinkh *shrink )
{
}

/**
 * vips_shrinkh:
 * @in: input image
 * @out: output image
 * @hshrink: horizontal shrink
 * @...: %NULL-terminated list of optional named arguments
 *
 * Shrink @in horizontally by an integer factor. Each pixel in the output is
 * the average of the corresponding line of @hshrink pixels in the input. 
 *
 * This is a very low-level operation: see vips_resize() for a more
 * convenient way to resize images. 
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_shrinkv(), vips_shrink(), vips_resize(), vips_affine().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_shrinkh( VipsImage *in, VipsImage **out, int hshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, hshrink );
	result = vips_call_split( "shrinkh", ap, in, out, hshrink );
	va_end( ap );

	return( result );
}
