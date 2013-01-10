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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
 */
#define DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include "resample.h"

typedef struct _VipsShrink {
	VipsResample parent_instance;

	double xshrink;		/* Shrink factors */
	double yshrink;

	int mw;			/* Size of area we average */
	int mh;

	int np;			/* Number of pels we average */

} VipsShrink;

typedef VipsResampleClass VipsShrinkClass;

G_DEFINE_TYPE( VipsShrink, vips_shrink, VIPS_TYPE_RESAMPLE );

/* Our per-sequence parameter struct. Somewhere to sum band elements.
 */
typedef struct {
	VipsRegion *ir;

	VipsPel *sum;
} VipsShrinkSequence;

/* Free a sequence value.
 */
static int
vips_shrink_stop( void *vseq, void *a, void *b )
{
	VipsShrinkSequence *seq = (VipsShrinkSequence *) vseq;

	VIPS_FREEF( g_object_unref, seq->ir );

	return( 0 );
}

/* Make a sequence value.
 */
static void *
vips_shrink_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsShrink *shrink = (VipsShrink *) b;
	VipsShrinkSequence *seq;

	if( !(seq = IM_NEW( out, VipsShrinkSequence )) )
		return( NULL );

	/* Init!
	 */
	seq->ir = vips_region_new( in );
	if( !(seq->sum = (VipsPel *) VIPS_ARRAY( out, in->Bands, double )) ) {
		vips_shrink_stop( seq, in, shrink );
		return( NULL );
	}

	return( (void *) seq );
}

/* Integer shrink. 
 */
#define ISHRINK( TYPE ) { \
	int *sum = (int *) seq->sum; \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( b = 0; b < bands; b++ ) \
		sum[b] = 0; \
	\
	for( y1 = 0; y1 < shrink->mh; y1++ ) { \
		for( i = 0, x1 = 0; x1 < shrink->mw; x1++ ) \
			for( b = 0; b < bands; b++, i++ ) \
				sum[b] += p[i]; \
		\
		p += ls; \
	} \
	\
	for( b = 0; b < bands; b++ ) \
		q[b] = (sum[b] + shrink->np / 2) / shrink->np; \
} 

/* Float shrink. 
 */
#define FSHRINK( TYPE ) { \
	double *sum = (double *) seq->sum; \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( b = 0; b < bands; b++ ) \
		sum[b] = 0.0; \
	\
	for( y1 = 0; y1 < shrink->mh; y1++ ) { \
		for( i = 0, x1 = 0; x1 < shrink->mw; x1++ ) \
			for( b = 0; b < bands; b++, i++ ) \
				sum[b] += p[i]; \
		\
		p += ls; \
	} \
	\
	for( b = 0; b < bands; b++ ) \
		q[b] = sum[b] / shrink->np; \
} 

/* Generate an area of @or. @ir is large enough.
 */
static void
vips_shrink_gen2( VipsShrink *shrink, VipsShrinkSequence *seq,
	VipsRegion *or, VipsRegion *ir,
	int left, int top, int width, int height )
{
	VipsResample *resample = VIPS_RESAMPLE( shrink );
	const int bands = resample->in->Bands;
	const int sizeof_pixel = VIPS_IMAGE_SIZEOF_PEL( resample->in );
	const int ls = VIPS_REGION_LSKIP( ir ) / 
		VIPS_IMAGE_SIZEOF_ELEMENT( resample->in );

	int x, y, i;
	int x1, y1, b;

	for( y = 0; y < height; y++ ) { 
		VipsPel *out = VIPS_REGION_ADDR( or, left, top + y ); 

		for( x = 0; x < width; x++ ) { 
			int ix = (left + x) * shrink->xshrink; 
			int iy = (top + y) * shrink->yshrink; 
			VipsPel *in = VIPS_REGION_ADDR( ir, ix, iy ); 

			switch( resample->in->BandFmt ) {
			case VIPS_FORMAT_UCHAR: 	
				ISHRINK( unsigned char ); break;
			case VIPS_FORMAT_CHAR: 	
				ISHRINK( char ); break; 
			case VIPS_FORMAT_USHORT: 
				ISHRINK( unsigned short ); break;
			case VIPS_FORMAT_SHORT: 	
				ISHRINK( short ); break; 
			case VIPS_FORMAT_UINT: 	
				ISHRINK( unsigned int ); break; 
			case VIPS_FORMAT_INT: 	
				ISHRINK( int );  break; 
			case VIPS_FORMAT_FLOAT: 	
				FSHRINK( float ); break; 
			case VIPS_FORMAT_DOUBLE:	
				FSHRINK( double ); break;

			default:
				g_assert( 0 ); 
			}

			out += sizeof_pixel;
		}
	}
}

static int
vips_shrink_gen( VipsRegion *or, void *vseq, void *a, void *b, gboolean *stop )
{
	VipsShrinkSequence *seq = (VipsShrinkSequence *) vseq;
	VipsShrink *shrink = (VipsShrink *) b;
	VipsRegion *ir = seq->ir;
	VipsRect *r = &or->valid;

	/* How do we chunk up the image? We don't want to prepare the whole of
	 * the input region corresponding to *r since it could be huge. 
	 *
	 * Each pixel of *r will depend on roughly mw x mh
	 * pixels, so we walk *r in chunks which map to the tile size.
	 *
	 * Make sure we can't ask for a zero step.
	 */
	int xstep = shrink->mw > VIPS__TILE_WIDTH ? 
		1 : VIPS__TILE_WIDTH / shrink->mw;
	int ystep = shrink->mh > VIPS__TILE_HEIGHT ? 
		1 : VIPS__TILE_HEIGHT / shrink->mh;

	int x, y;

#ifdef DEBUG
	printf( "vips_shrink_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG*/

	for( y = 0; y < r->height; y += ystep )  
		for( x = 0; x < r->width; x += xstep ) { 
			/* Clip the this rect against the demand size.
			 */
			int width = VIPS_MIN( xstep, r->width - x );
			int height = VIPS_MIN( ystep, r->height - y );

			VipsRect s;

			s.left = (r->left + x) * shrink->xshrink;
			s.top = (r->top + y) * shrink->yshrink;
			s.width = ceil( width * shrink->xshrink );
			s.height = ceil( height * shrink->yshrink );
#ifdef DEBUG
			printf( "shrink_gen: requesting %d x %d at %d x %d\n",
				s.width, s.height, s.left, s.top ); 
#endif /*DEBUG*/
			if( vips_region_prepare( ir, &s ) )
				return( -1 );

			vips_shrink_gen2( shrink, seq, 
				or, ir, 
				r->left + x, r->top + y, width, height );
		}

	return( 0 );
}

static int
vips_shrink_build( VipsObject *object )
{
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsShrink *shrink = (VipsShrink *) object;

	if( VIPS_OBJECT_CLASS( vips_shrink_parent_class )->build( object ) )
		return( -1 );

	shrink->mw = ceil( shrink->xshrink );
	shrink->mh = ceil( shrink->yshrink );
	shrink->np = shrink->mw * shrink->mh;

	if( im_check_noncomplex( "VipsShrink", resample->in ) )
		return( -1 );

	if( shrink->xshrink < 1.0 || 
		shrink->yshrink < 1.0 ) {
		vips_error( "VipsShrink", 
			"%s", _( "shrink factors should be >= 1" ) );
		return( -1 );
	}

	if( (int) shrink->xshrink != shrink->xshrink || 
		(int) shrink->yshrink != shrink->yshrink ) 
		vips_warn( "VipsShrink", 
			"%s", _( "not integer shrink factors, "
				"expect poor results" ) ); 

	if( shrink->xshrink == 1.0 &&
		shrink->yshrink == 1.0 )
		return( vips_image_write( resample->in, resample->out ) );

	if( vips_image_copy_fields( resample->out, resample->in ) )
		return( -1 );

	/* THINSTRIP will work, FATSTRIP will break seq mode. If you combine
	 * shrink with conv you'll need to use a line cache to maintain
	 * sequentiality.
	 */
	vips_demand_hint( resample->out, 
		VIPS_DEMAND_STYLE_ANY, resample->in, NULL );

	/* Size output. Note: we round the output width down!
	 */
	resample->out->Xsize = resample->in->Xsize / shrink->xshrink;
	resample->out->Ysize = resample->in->Ysize / shrink->yshrink;
	resample->out->Xres = resample->in->Xres / shrink->xshrink;
	resample->out->Yres = resample->in->Yres / shrink->yshrink;
	if( resample->out->Xsize <= 0 || 
		resample->out->Ysize <= 0 ) {
		vips_error( "VipsShrink", 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

	if( vips_image_generate( resample->out,
		vips_shrink_start, vips_shrink_gen, vips_shrink_stop, 
		resample->in, shrink ) )
		return( -1 );

	return( 0 );
}

static void
vips_shrink_class_init( VipsShrinkClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_shrink_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "shrink";
	vobject_class->description = _( "shrink an image" );
	vobject_class->build = vips_shrink_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_DOUBLE( class, "xshrink", 8, 
		_( "Xshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsShrink, xshrink ),
		1.0, 1000000, 1 );

	VIPS_ARG_DOUBLE( class, "yshrink", 9, 
		_( "Yshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsShrink, yshrink ),
		1.0, 1000000, 1 );

}

static void
vips_shrink_init( VipsShrink *shrink )
{
}

/**
 * vips_shrink:
 * @in: input image
 * @out: output image
 * @xshrink: horizontal shrink
 * @yshrink: vertical shrink
 *
 * Shrink @in by a pair of factors with a simple box filter. 
 *
 * You will get aliasing for non-integer shrinks. In this case, shrink with
 * this function to the nearest integer size above the target shrink, then
 * downsample to the exact size with im_affinei() and your choice of
 * interpolator.
 *
 * See also: im_affinei().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_shrink( VipsImage *in, VipsImage **out, 
	double xshrink, double yshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, yshrink );
	result = vips_call_split( "shrink", ap, in, out, xshrink, yshrink );
	va_end( ap );

	return( result );
}
