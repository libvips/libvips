/* horizontal reduce by a float factor
 *
 * 30/10/15
 * 	- from reduceh.c
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

typedef struct _VipsReduceh {
	VipsResample parent_instance;

	double xreduce;		/* Reduce factor */
	VipsInterpolate *interpolate;

} VipsReduceh;

typedef VipsResampleClass VipsReducehClass;

G_DEFINE_TYPE( VipsReduceh, vips_reduceh, VIPS_TYPE_RESAMPLE );

#define INNER( BANDS ) \
	sum += p[x1]; \
	x1 += BANDS; 

/* Integer reduce. 
 */
#define IREDUCE( TYPE, BANDS ) { \
	TYPE * restrict p = (TYPE *) in; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		for( b = 0; b < BANDS; b++ ) { \
			int sum; \
			\
			sum = 0; \
			x1 = b; \
			VIPS_UNROLL( reduce->xreduce, INNER( BANDS ) ); \
			q[b] = (sum + reduce->xreduce / 2) / \
				reduce->xreduce; \
		} \
		p += ne; \
		q += BANDS; \
	} \
}

/* Float reduce. 
 */
#define FREDUCE( TYPE ) { \
	TYPE * restrict p = (TYPE *) in; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < width; x++ ) { \
		for( b = 0; b < bands; b++ ) { \
			double sum; \
			\
			sum = 0.0; \
			x1 = b; \
			VIPS_UNROLL( reduce->xreduce, INNER( bands ) ); \
			q[b] = sum / reduce->xreduce; \
		} \
		p += ne; \
		q += bands; \
	} \
} 

/* Generate an line of @or. @ir is large enough.
 */
static void
vips_reduceh_gen2( VipsReduceh *reduce, VipsRegion *or, VipsRegion *ir,
	int left, int top, int width )
{
	VipsResample *resample = VIPS_RESAMPLE( reduce );
	const int bands = resample->in->Bands * 
		(vips_band_format_iscomplex( resample->in->BandFmt ) ? 
		 	2 : 1);
	const int ne = reduce->xreduce * bands; 
	VipsPel *out = VIPS_REGION_ADDR( or, left, top ); 
	VipsPel *in = VIPS_REGION_ADDR( ir, left * reduce->xreduce, top ); 

	int x;
	int x1, b;

	switch( resample->in->BandFmt ) {
		IREDUCE( unsigned char, bands ); break;
	case VIPS_FORMAT_CHAR: 	
		IREDUCE( char, bands ); break; 
	case VIPS_FORMAT_USHORT: 
		IREDUCE( unsigned short, bands ); break;
	case VIPS_FORMAT_SHORT: 	
		IREDUCE( short, bands ); break; 
	case VIPS_FORMAT_UINT: 	
		IREDUCE( unsigned int, bands ); break; 
	case VIPS_FORMAT_INT: 	
		IREDUCE( int, bands );  break; 
	case VIPS_FORMAT_FLOAT: 	
		FREDUCE( float ); break; 
	case VIPS_FORMAT_DOUBLE:	
		FREDUCE( double ); break;
	case VIPS_FORMAT_COMPLEX: 	
		FREDUCE( float ); break; 
	case VIPS_FORMAT_DPCOMPLEX:	
		FREDUCE( double ); break;

	default:
		g_assert_not_reached(); 
	}
}

static int
vips_reduceh_gen( VipsRegion *or, void *seq, 
	void *a, void *b, gboolean *stop )
{
	VipsReduceh *reduce = (VipsReduceh *) b;
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &or->valid;

	int y;

	/* How do we chunk up the image? We don't want to prepare the whole of
	 * the input region corresponding to *r since it could be huge. 
	 *
	 * Request input a line at a time. 
	 */

#ifdef DEBUG
	printf( "vips_reduceh_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG*/

	for( y = 0; y < r->height; y ++ ) { 
		VipsRect s;

		s.left = r->left * reduce->xreduce;
		s.top = r->top + y;
		s.width = r->width * reduce->xreduce;
		s.height = 1;
#ifdef DEBUG
		printf( "reduceh_gen: requesting line %d\n", s.top ); 
#endif /*DEBUG*/
		if( vips_region_prepare( ir, &s ) )
			return( -1 );

		VIPS_GATE_START( "vips_reduceh_gen: work" ); 

		vips_reduceh_gen2( reduce, or, ir, 
			r->left, r->top + y, r->width );

		VIPS_GATE_STOP( "vips_reduceh_gen: work" ); 
	}

	return( 0 );
}

static int
vips_reduceh_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsReduceh *reduce = (VipsReduceh *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 1 );

	VipsImage *in;
	int window_size;
	int window_offset;

	if( VIPS_OBJECT_CLASS( vips_reduceh_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	/* We can't use vips_object_argument_isset(), since it may have been
	 * set to NULL, see vips_similarity().
	 */
	if( !reduceh->interpolate ) {
		VipsInterpolate *interpolate;

		interpolate = vips_interpolate_new( "cubich" );
		g_object_set( object, 
			"interpolate", interpolate,
			NULL ); 
		g_object_unref( interpolate );

		/* coverity gets confused by this, it thinks
		 * reduceh->interpolate may still be null. Assign ourselves,
		 * even though we don't need to.
		 */
		reduceh->interpolate = interpolate;
	}

	window_size = vips_interpolate_get_window_size( reduceh->interpolate );
	window_offset = 
		vips_interpolate_get_window_offset( reduceh->interpolate );

	if( reduce->xreduce < 1 ) { 
		vips_error( class->nickname, 
			"%s", _( "reduce factors should be >= 1" ) );
		return( -1 );
	}
	if( reduce->xreduce > 2 )  
		vips_warn( class->nickname, 
			"%s", _( "reduce factor greater than 2" ) );

	if( reduce->xreduce == 1 ) 
		return( vips_image_write( in, resample->out ) );

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	/* Add new pixels around the input so we can interpolate at the edges.
	 */
	if( vips_embed( in, &t[1], 
		window_offset, 0, 
		in->Xsize + window_size - 1, in->Ysize,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[1];

	/* THINSTRIP will work, anything else will break seq mode. If you 
	 * combine reduce with conv you'll need to use a line cache to maintain
	 * sequentiality.
	 */
	if( vips_image_pipelinev( resample->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Size output. Note: we round the output width down!
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true reduce factor (including the
	 * fractional part), we just see the integer part here.
	 */
	resample->out->Xsize = in->Xsize / reduce->xreduce;
	if( resample->out->Xsize <= 0 ) { 
		vips_error( class->nickname, 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_reduceh_build: reducing %d x %d image to %d x %d\n", 
		in->Xsize, in->Ysize, 
		resample->out->Xsize, resample->out->Ysize );  
#endif /*DEBUG*/

	if( vips_image_generate( resample->out,
		vips_start_one, vips_reduceh_gen, vips_stop_one, 
		in, reduce ) )
		return( -1 );

	return( 0 );
}

static void
vips_reduceh_class_init( VipsReducehClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_reduceh_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "reduceh";
	vobject_class->description = _( "reduce an image horizontally" );
	vobject_class->build = vips_reduceh_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_DOUBLE( class, "xreduce", 3, 
		_( "Xreduce" ), 
		_( "Horizontal reduce factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReduceh, xreduce ),
		1, 1000000, 1 );

	VIPS_ARG_INTERPOLATE( class, "interpolate", 4, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsReduceh, interpolate ) );

}

static void
vips_reduceh_init( VipsReduceh *reduce )
{
}

/**
 * vips_reduceh:
 * @in: input image
 * @out: output image
 * @xreduce: horizontal reduce
 * @...: %NULL-terminated list of optional named arguments
 *
 * Reduce @in horizontally by a float factor. The pixels in @out are
 * interpolated with a 1D bicubic mask. This operation will not work well for
 * a reduction of more than a factor of two.
 *
 * This is a very low-level operation: see vips_resize() for a more
 * convenient way to resize images. 
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_shrink(), vips_resize(), vips_affine().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_reduceh( VipsImage *in, VipsImage **out, double xreduce, ... )
{
	va_list ap;
	int result;

	va_start( ap, xreduce );
	result = vips_call_split( "reduceh", ap, in, out, xreduce );
	va_end( ap );

	return( result );
}
