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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

/* Our main parameter struct.
 */
typedef struct {
	IMAGE *in;
	IMAGE *out;
	double xshrink;		/* Shrink factors */
	double yshrink;

	int mw;			/* Size of area we average */
	int mh;
	int np;			/* Number of pels we average */
} ShrinkInfo;

/* Our per-sequence parameter struct. Somewhere to sum band elements.
 */
typedef struct {
	REGION *ir;

	VipsPel *sum;
} SeqInfo;

/* Free a sequence value.
 */
static int
shrink_stop( void *vseq, void *a, void *b )
{
	SeqInfo *seq = (SeqInfo *) vseq;

	IM_FREEF( im_region_free, seq->ir );

	return( 0 );
}

/* Make a sequence value.
 */
static void *
shrink_start( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	ShrinkInfo *st = (ShrinkInfo *) b;
	SeqInfo *seq;

	if( !(seq = IM_NEW( out, SeqInfo )) )
		return( NULL );

	/* Init!
	 */
	seq->ir = NULL;
	seq->sum = NULL;
	seq->ir = im_region_create( in );
	seq->sum = (void *) IM_ARRAY( out, in->Bands, double );
	if( !seq->sum || !seq->ir ) {
		shrink_stop( seq, in, st );
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
	for( y1 = 0; y1 < st->mh; y1++ ) { \
		for( i = 0, x1 = 0; x1 < st->mw; x1++ ) \
			for( b = 0; b < bands; b++, i++ ) \
				sum[b] += p[i]; \
		\
		p += ls; \
	} \
	\
	for( b = 0; b < bands; b++ ) \
		q[b] = (sum[b] + st->np / 2) / st->np; \
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
	for( y1 = 0; y1 < st->mh; y1++ ) { \
		for( i = 0, x1 = 0; x1 < st->mw; x1++ ) \
			for( b = 0; b < bands; b++, i++ ) \
				sum[b] += p[i]; \
		\
		p += ls; \
	} \
	\
	for( b = 0; b < bands; b++ ) \
		q[b] = sum[b] / st->np; \
} 

/* Generate an area of @or. @ir is large enough.
 */
static void
shrink_gen2( ShrinkInfo *st, SeqInfo *seq,
	REGION *or, REGION *ir,
	int left, int top, int width, int height )
{
	const int bands = st->in->Bands;
	const int sizeof_pixel = VIPS_IMAGE_SIZEOF_PEL( st->in );
	const int ls = VIPS_REGION_LSKIP( ir ) / 
		VIPS_IMAGE_SIZEOF_ELEMENT( st->in );

	int x, y, i;
	int x1, y1, b;

	for( y = 0; y < height; y++ ) { 
		VipsPel *out = IM_REGION_ADDR( or, left, top + y ); 

		for( x = 0; x < width; x++ ) { 
			int ix = (left + x) * st->xshrink; 
			int iy = (top + y) * st->yshrink; 
			VipsPel *in = IM_REGION_ADDR( ir, ix, iy ); 

			switch( st->in->BandFmt ) {
			case IM_BANDFMT_UCHAR: 	
				ISHRINK( unsigned char ); break;
			case IM_BANDFMT_CHAR: 	
				ISHRINK( char ); break; 
			case IM_BANDFMT_USHORT: 
				ISHRINK( unsigned short ); break;
			case IM_BANDFMT_SHORT: 	
				ISHRINK( short ); break; 
			case IM_BANDFMT_UINT: 	
				ISHRINK( unsigned int ); break; 
			case IM_BANDFMT_INT: 	
				ISHRINK( int );  break; 
			case IM_BANDFMT_FLOAT: 	
				FSHRINK( float ); break; 
			case IM_BANDFMT_DOUBLE:	
				FSHRINK( double ); break;

			default:
				g_assert( 0 ); 
			}

			out += sizeof_pixel;
		}
	}
}

/* Shrink a REGION.
 */
static int
shrink_gen( REGION *or, void *vseq, void *a, void *b )
{
	SeqInfo *seq = (SeqInfo *) vseq;
	ShrinkInfo *st = (ShrinkInfo *) b;
	REGION *ir = seq->ir;
	Rect *r = &or->valid;

	/* How do we chunk up the image? We don't want to prepare the whole of
	 * the input region corresponding to *r since it could be huge. 
	 *
	 * Each pixel of *r will depend on roughly mw x mh
	 * pixels, so we walk *r in chunks which map to the tile size.
	 *
	 */
	int xstep = 1 + VIPS__TILE_WIDTH / st->mw;
	int ystep = 1 + VIPS__TILE_HEIGHT / st->mh;

	int x, y;

	for( y = 0; y < r->height; y += ystep )  
		for( x = 0; x < r->width; x += xstep ) { 
			/* Clip the this rect against the demand size.
			 */
			int width = VIPS_MIN( xstep, r->width - x );
			int height = VIPS_MIN( ystep, r->height - y );

			Rect s;

			s.left = (r->left + x) * st->xshrink;
			s.top = (r->top + y) * st->yshrink;
			s.width = 1 + ceil( width * st->xshrink );
			s.height = 1 + ceil( height * st->yshrink );
			if( im_prepare( ir, &s ) )
				return( -1 );

			shrink_gen2( st, seq, 
				or, ir, 
				r->left + x, r->top + y, width, height );
		}

	return( 0 );
}

static int 
shrink( IMAGE *in, IMAGE *out, double xshrink, double yshrink )
{
	ShrinkInfo *st;

	/* Prepare output. Note: we round the output width down!
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize = in->Xsize / xshrink;
	out->Ysize = in->Ysize / yshrink;
	out->Xres = in->Xres / xshrink;
	out->Yres = in->Yres / yshrink;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_error( "im_shrink", 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

	/* Build and attach state struct.
	 */
	if( !(st = IM_NEW( out, ShrinkInfo )) )
		return( -1 );
	st->in = in;
	st->out = out;
	st->xshrink = xshrink;
	st->yshrink = yshrink;
	st->mw = ceil( xshrink );
	st->mh = ceil( yshrink );
	st->np = st->mw * st->mh;

	/* Set demand hints. We want THINSTRIP, as we will be demanding a
	 * large area of input for each output line.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Generate!
	 */
	if( im_generate( out, 
		shrink_start, shrink_gen, shrink_stop, in, st ) )
		return( -1 );

	return( 0 );
}

/**
 * im_shrink:
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
 * im_rightshift_size() is faster for factors which are integer powers of two.
 *
 * See also: im_rightshift_size(), im_affinei().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_shrink( IMAGE *in, IMAGE *out, double xshrink, double yshrink )
{
	if( im_check_noncomplex( "im_shrink", in ) ||
		im_check_coding_known( "im_shrink", in ) ||
		im_piocheck( in, out ) )
		return( -1 );
	if( xshrink < 1.0 || yshrink < 1.0 ) {
		im_error( "im_shrink", 
			"%s", _( "shrink factors should be >= 1" ) );
		return( -1 );
	}

	if( xshrink == 1 && yshrink == 1 ) {
		return( im_copy( in, out ) );
	}
	else if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *t[2];

		if( im_open_local_array( out, t, 2, "im_shrink:1", "p" ) ||
			im_LabQ2LabS( in, t[0] ) ||
			shrink( t[0], t[1], xshrink, yshrink ) ||
			im_LabS2LabQ( t[1], out ) )
			return( -1 );
	}
	else 
		if( shrink( in, out, xshrink, yshrink ) )
			return( -1 );

	return( 0 );
}
