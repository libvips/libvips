/* shrink with a box filter
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Authors: Nicos Dessipris and Kirk Martinez
 * Written on: 29/04/1991
 * Modified on: 2/11/92, 22/2/93 Kirk Martinez - Xres Yres & cleanup 
 incredibly inefficient for box filters as LUTs are used instead of + 
 Needs converting to a smoother filter: eg Gaussian!  KM
 * 15/7/93 JC
 *	- rewritten for partial v2
 *	- ANSIfied
 *	- now shrinks any non-complex type
 *	- no longer cloned from im_convsub()
 *	- could be much better! see km comments above
 * 3/8/93 JC
 *	- rounding bug fixed
 * 11/1/94 JC
 *	- problems with .000001 and round up/down ignored! Try shrink 3738
 *	  pixel image by 9.345000000001
 * 7/10/94 JC
 *	- IM_NEW and IM_ARRAY added
 *	- more typedef
 * 3/7/95 JC
 *	- IM_CODING_LABQ handling added here
 * 20/12/08
 * 	- fall back to im_copy() for 1/1 shrink
 * 2/2/11
 * 	- gtk-doc
 * 10/2/12
 * 	- shrink in chunks to reduce peak memuse for large shrinks
 * 	- simpler
 * 12/6/12
 * 	- redone as a class
 * 	- warn about non-int shrinks
 * 	- some tuning .. tried an int coordinate path, not worthwhile
 * 16/11/12
 * 	- don't change xres/yres, see comment below
 * 8/4/13
 * 	- oops demand_hint was incorrect, thanks Jan
 * 6/6/13
 * 	- don't chunk horizontally, fixes seq problems with large shrink
 * 	  factors
 * 15/8/16
 * 	- rename yshrink -> vshrink for greater consistency 
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
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

#include "presample.h"

typedef struct _VipsShrinkv {
	VipsResample parent_instance;

	int vshrink;
	size_t sizeof_line_buffer;

} VipsShrinkv;

typedef VipsResampleClass VipsShrinkvClass;

G_DEFINE_TYPE( VipsShrinkv, vips_shrinkv, VIPS_TYPE_RESAMPLE );

/* Our per-sequence parameter struct. Somewhere to sum band elements.
 */
typedef struct {
	VipsRegion *ir;

	VipsPel *sum;
} VipsShrinkvSequence;

/* Free a sequence value.
 */
static int
vips_shrinkv_stop( void *vseq, void *a, void *b )
{
	VipsShrinkvSequence *seq = (VipsShrinkvSequence *) vseq;

	VIPS_FREEF( g_object_unref, seq->ir );

	return( 0 );
}

/* Make a sequence value.
 */
static void *
vips_shrinkv_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsShrinkv *shrink = (VipsShrinkv *) b;
	VipsShrinkvSequence *seq;

	if( !(seq = VIPS_NEW( out, VipsShrinkvSequence )) )
		return( NULL );

	seq->ir = vips_region_new( in );

	/* Big enough for the largest intermediate .. a whole scanline. 
	 */
	seq->sum = VIPS_ARRAY( out, shrink->sizeof_line_buffer, VipsPel );

	return( (void *) seq );
}

#define ADD( ACC_TYPE, TYPE ) { \
	ACC_TYPE * restrict sum = (ACC_TYPE *) seq->sum; \
	TYPE * restrict p = (TYPE *) in; \
	\
	for( x = 0; x < sz; x++ ) \
		sum[x] += p[x]; \
} 

/* Add a line of pixels to sum. 
 */
static void
vips_shrinkv_add_line( VipsShrinkv *shrink, VipsShrinkvSequence *seq,
	VipsRegion *ir, int left, int top, int width )
{
	VipsResample *resample = VIPS_RESAMPLE( shrink );
	const int bands = resample->in->Bands * 
		(vips_band_format_iscomplex( resample->in->BandFmt ) ? 
		 	2 : 1);
	const int sz = bands * width; 

	int x;

	VipsPel *in = VIPS_REGION_ADDR( ir, left, top ); 
	switch( resample->in->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	
		ADD( int, unsigned char ); break;
	case VIPS_FORMAT_CHAR: 	
		ADD( int, char ); break; 
	case VIPS_FORMAT_USHORT: 
		ADD( int, unsigned short ); break;
	case VIPS_FORMAT_SHORT: 	
		ADD( int, short ); break; 
	case VIPS_FORMAT_UINT: 	
		ADD( int, unsigned int ); break; 
	case VIPS_FORMAT_INT: 	
		ADD( int, int );  break; 
	case VIPS_FORMAT_FLOAT: 	
		ADD( double, float ); break; 
	case VIPS_FORMAT_DOUBLE:	
		ADD( double, double ); break;
	case VIPS_FORMAT_COMPLEX: 	
		ADD( double, float ); break; 
	case VIPS_FORMAT_DPCOMPLEX:	
		ADD( double, double ); break;

	default:
		g_assert_not_reached(); 
	}
}

/* Integer average. 
 */
#define IAVG( TYPE ) { \
	int * restrict sum = (int *) seq->sum; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = (sum[x] + shrink->vshrink / 2) / shrink->vshrink; \
} 

/* Float average. 
 */
#define FAVG( TYPE ) { \
	double * restrict sum = (double *) seq->sum; \
	TYPE * restrict q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = sum[x] / shrink->vshrink; \
} 

/* Average the line of sums to out. 
 */
static void
vips_shrinkv_write_line( VipsShrinkv *shrink, VipsShrinkvSequence *seq,
	VipsRegion *or, int left, int top, int width )
{
	VipsResample *resample = VIPS_RESAMPLE( shrink );
	const int bands = resample->in->Bands * 
		(vips_band_format_iscomplex( resample->in->BandFmt ) ? 
		 	2 : 1);
	const int sz = bands * width; 

	int x;

	VipsPel *out = VIPS_REGION_ADDR( or, left, top ); 
	switch( resample->in->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	
		IAVG( unsigned char ); break;
	case VIPS_FORMAT_CHAR: 	
		IAVG( char ); break; 
	case VIPS_FORMAT_USHORT: 
		IAVG( unsigned short ); break;
	case VIPS_FORMAT_SHORT: 	
		IAVG( short ); break; 
	case VIPS_FORMAT_UINT: 	
		IAVG( unsigned int ); break; 
	case VIPS_FORMAT_INT: 	
		IAVG( int );  break; 
	case VIPS_FORMAT_FLOAT: 	
		FAVG( float ); break; 
	case VIPS_FORMAT_DOUBLE:	
		FAVG( double ); break;
	case VIPS_FORMAT_COMPLEX: 	
		FAVG( float ); break; 
	case VIPS_FORMAT_DPCOMPLEX:	
		FAVG( double ); break;

	default:
		g_assert_not_reached(); 
	}
}

static int
vips_shrinkv_gen( VipsRegion *or, void *vseq, 
	void *a, void *b, gboolean *stop )
{
	VipsShrinkvSequence *seq = (VipsShrinkvSequence *) vseq;
	VipsShrinkv *shrink = (VipsShrinkv *) b;
	VipsRegion *ir = seq->ir;
	VipsRect *r = &or->valid;

	int y, y1;

	/* How do we chunk up the image? We don't want to prepare the whole of
	 * the input region corresponding to *r since it could be huge. 
	 *
	 * Request input a line at a time, average to a line buffer.  
	 *
	 * We don't chunk horizontally. We want "vips shrink x.jpg b.jpg 100
	 * 100" to run sequentially. If we chunk horizontally, we will fetch
	 * 100x100 lines from the top of the image, then 100x100 100 lines
	 * down, etc. for each thread, then when they've finished, fetch
	 * 100x100, 100 pixels across from the top of the image. This will
	 * break sequentiality. 
	 */

#ifdef DEBUG
	printf( "vips_shrinkv_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG*/

	for( y = 0; y < r->height; y++ ) { 
		memset( seq->sum, 0, shrink->sizeof_line_buffer ); 

		for( y1 = 0; y1 < shrink->vshrink; y1++ ) { 
			VipsRect s;

			s.left = r->left;
			s.top = y1 + (y + r->top) * shrink->vshrink;
			s.width = r->width;
			s.height = 1;
#ifdef DEBUG
			printf( "shrink_gen: requesting line %d\n", s.top ); 
#endif /*DEBUG*/
			if( vips_region_prepare( ir, &s ) )
				return( -1 );

			VIPS_GATE_START( "vips_shrinkv_gen: work" ); 

			vips_shrinkv_add_line( shrink, seq, ir, 
				s.left, s.top, s.width );

			VIPS_GATE_STOP( "vips_shrinkv_gen: work" ); 
		}

		VIPS_GATE_START( "vips_shrinkv_gen: work" ); 

		vips_shrinkv_write_line( shrink, seq, or, 
			r->left, r->top + y, r->width );  

		VIPS_GATE_STOP( "vips_shrinkv_gen: work" ); 
	}

	VIPS_COUNT_PIXELS( or, "vips_shrinkv_gen" ); 

	return( 0 );
}

static int
vips_shrinkv_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsShrinkv *shrink = (VipsShrinkv *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 3 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_shrinkv_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	if( shrink->vshrink < 1 ) {
		vips_error( class->nickname, 
			"%s", _( "shrink factors should be >= 1" ) );
		return( -1 );
	}

	if( shrink->vshrink == 1 )
		return( vips_image_write( in, resample->out ) );

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	/* We need new pixels along the bottom so that we don't have small chunks
	 * to average along the bottom edge.
	 */
	if( vips_embed( in, &t[1], 
		0, 0, 
		in->Xsize, in->Ysize + shrink->vshrink, 
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[1];

	/* Large vshrinks will throw off sequential mode. Suppose thread1 is
	 * generating tile (0, 0), but stalls. thread2 generates tile
	 * (0, 1), 128 lines further down the output. After it has done,
	 * thread1 tries to generate (0, 0), but by then the pixels it needs
	 * have gone from the input image line cache if the vshrink is large.
	 *
	 * To fix this, cache the output of vshrink, and disable threading. Now
	 * thread1 will make the whole of tile (0, 0) and thread2 will block
	 * until it's done. 
	 *
	 * We could still get out of order if thread2 arrives here before
	 * thread1. Most images will be wide enough that many tiles will fit
	 * across the image for row0 and they would all have to be delayed
	 * behind a row1 request. This seems very unlikely, but perhaps could
	 * happen for a very tall, thin image with a very large shrink factor. 
	 */
	if( vips_image_get_typeof( in, VIPS_META_SEQUENTIAL ) ) { 
		int tile_width;
		int tile_height;
		int n_lines;

		vips_get_tile_size( in, 
			&tile_width, &tile_height, &n_lines );
		if( vips_tilecache( in, &t[2], 
			"tile_width", in->Xsize,
			"tile_height", 10,
			"max_tiles", 1 + n_lines / 10,
			"access", VIPS_ACCESS_SEQUENTIAL,
			"threaded", FALSE, 
			NULL ) )
			return( -1 );
		in = t[2];
	}

	/* We have to keep a line buffer as we sum columns.
	 */
	shrink->sizeof_line_buffer = 
		in->Xsize * in->Bands * 
		vips_format_sizeof( VIPS_FORMAT_DPCOMPLEX );

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
	resample->out->Ysize = VIPS_ROUND_UINT( 
		(double) resample->in->Ysize / shrink->vshrink );
	if( resample->out->Ysize <= 0 ) {
		vips_error( class->nickname, 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_shrinkv_build: shrinking %d x %d image to %d x %d\n", 
		in->Xsize, in->Ysize, 
		resample->out->Xsize, resample->out->Ysize );  
#endif /*DEBUG*/

	if( vips_image_generate( resample->out,
		vips_shrinkv_start, vips_shrinkv_gen, vips_shrinkv_stop, 
		in, shrink ) )
		return( -1 );

	return( 0 );
}

static void
vips_shrinkv_class_init( VipsShrinkvClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_shrinkv_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "shrinkv";
	vobject_class->description = _( "shrink an image vertically" );
	vobject_class->build = vips_shrinkv_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_INT( class, "vshrink", 9, 
		_( "Vshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsShrinkv, vshrink ),
		1, 1000000, 1 );

	/* The old name .. now use h and v everywhere. 
	 */
	VIPS_ARG_INT( class, "yshrink", 9, 
		_( "Yshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsShrinkv, vshrink ),
		1, 1000000, 1 );

}

static void
vips_shrinkv_init( VipsShrinkv *shrink )
{
}

/**
 * vips_shrinkv:
 * @in: input image
 * @out: output image
 * @vshrink: vertical shrink
 * @...: %NULL-terminated list of optional named arguments
 *
 * Shrink @in vertically by an integer factor. Each pixel in the output is
 * the average of the corresponding column of @vshrink pixels in the input. 
 *
 * This is a very low-level operation: see vips_resize() for a more
 * convenient way to resize images. 
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_shrinkh(), vips_shrink(), vips_resize(), vips_affine().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_shrinkv( VipsImage *in, VipsImage **out, int vshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, vshrink );
	result = vips_call_split( "shrinkv", ap, in, out, vshrink );
	va_end( ap );

	return( result );
}
