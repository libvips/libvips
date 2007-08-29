/* @(#) Shrink any non-complex image by some x, y, factor. No interpolation!
 * @(#) Just average an area. Suitable for making quicklooks only!
 * @(#)
 * @(#) int 
 * @(#) im_shrink( in, out, xshrink, yshrink )
 * @(#) IMAGE *in, *out;
 * @(#) double xshrink, yshrink;
 * @(#)
 * @(#) Returns either 0 (success) or -1 (fail)
 * @(#)
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Our main parameter struct.
 */
typedef struct {
	double xshrink;		/* Shrink factors */
	double yshrink;
	int mw;			/* Size of area we average */
	int mh;
	int np;			/* Number of pels we average */
} ShrinkInfo;

/* Our per-sequence parameter struct. We hold an offset for each pel we
 * average.
 */
typedef struct {
	REGION *ir;
	int *off;
} SeqInfo;

/* Free a sequence value.
 */
static int
shrink_stop( SeqInfo *seq, IMAGE *in, ShrinkInfo *st )
{
	if( seq->ir ) {
		im_region_free( seq->ir );
		seq->ir = NULL;
	}

	return( 0 );
}

/* Make a sequence value.
 */
static void *
shrink_start( IMAGE *out, IMAGE *in, ShrinkInfo *st )
{
	SeqInfo *seq = IM_NEW( out, SeqInfo );

	if( !seq )
		return( NULL );

	/* Init!
	 */
	seq->ir = NULL;
	seq->off = NULL;
	seq->ir = im_region_create( in );
	seq->off = IM_ARRAY( out, st->np, int );
	if( !seq->off || !seq->ir ) {
		shrink_stop( seq, in, st );
		return( NULL );
	}

	return( (void *) seq );
}

/* Integer shrink. 
 */
#define ishrink(TYPE) \
	for( y = to; y < bo; y++ ) { \
		TYPE *q = (TYPE *) IM_REGION_ADDR( or, le, y ); \
 		\
		for( x = le; x < ri; x++ ) { \
			int ix = x * st->xshrink; \
			int iy = y * st->yshrink; \
			TYPE *p = (TYPE *) IM_REGION_ADDR( ir, ix, iy ); \
 			\
			for( b = 0; b < ir->im->Bands; b++ ) { \
				int sum = 0; \
				int *t = seq->off; \
 				\
				for( z = 0; z < st->np; z++ ) \
					sum += p[*t++]; \
				 \
				*q++ = sum / st->np; \
				p++; \
			} \
		} \
	}

/* FP shrink.
 */
#define fshrink(TYPE) \
	for( y = to; y < bo; y++ ) { \
		TYPE *q = (TYPE *) IM_REGION_ADDR( or, le, y ); \
 		\
		for( x = le; x < ri; x++ ) { \
			int ix = x * st->xshrink; \
			int iy = y * st->yshrink; \
			TYPE *p = (TYPE *) IM_REGION_ADDR( ir, ix, iy ); \
 			\
			for( b = 0; b < ir->im->Bands; b++ ) { \
				double sum = 0; \
				int *t = seq->off; \
 				\
				for( z = 0; z < st->np; z++ ) \
					sum += p[*t++]; \
				 \
				*q++ = sum / st->np; \
				p++; \
			} \
		} \
	}

/* Shrink a REGION.
 */
static int
shrink_gen( REGION *or, SeqInfo *seq, IMAGE *in, ShrinkInfo *st )
{
	REGION *ir = seq->ir;

	Rect *r = &or->valid;
	Rect s;
	int le = r->left;
	int ri = IM_RECT_RIGHT( r );
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);

	int x, y, z, b;

	/* What part of the input image do we need? Very careful: round left
	 * down, round right up.
	 */
	s.left = r->left * st->xshrink;
	s.top = r->top * st->yshrink;
	s.width = ceil( IM_RECT_RIGHT( r ) * st->xshrink ) - s.left;
	s.height = ceil( IM_RECT_BOTTOM( r ) * st->yshrink ) - s.top;
	if( im_prepare( ir, &s ) )
		return( -1 );

	/* Init offsets for pel addressing. Note that offsets must be for the
	 * type we will address the memory array with.
	 */
	for( z = 0, y = 0; y < st->mh; y++ )
		for( x = 0; x < st->mw; x++ )
			seq->off[z++] = (IM_REGION_ADDR( ir, x, y ) - IM_REGION_ADDR( ir, 0, 0 )) /
				IM_IMAGE_SIZEOF_ELEMENT( ir->im );

	switch( ir->im->BandFmt ) {
        case IM_BANDFMT_UCHAR: 		ishrink(unsigned char); break;
        case IM_BANDFMT_CHAR: 		ishrink(char); break; 
        case IM_BANDFMT_USHORT: 	ishrink(unsigned short); break;
        case IM_BANDFMT_SHORT: 		ishrink(short); break; 
        case IM_BANDFMT_UINT: 		ishrink(unsigned int); break; 
        case IM_BANDFMT_INT: 		ishrink(int);  break; 
        case IM_BANDFMT_FLOAT: 		fshrink(float); break; 
        case IM_BANDFMT_DOUBLE:		fshrink(double); break;

        default:
		im_errormsg( "im_shrink: unsupported input format" );
                return( -1 );
        }
 
	return( 0 );
}

static int 
shrink( IMAGE *in, IMAGE *out, double xshrink, double yshrink )
{
	ShrinkInfo *st;

	/* Check parameters.
	 */
	if( !in || im_iscomplex( in ) ) {
		im_errormsg( "im_shrink: non-complex input only" );
		return( -1 );
	}
	if( xshrink < 1.0 || yshrink < 1.0 ) {
		im_errormsg( "im_shrink: shrink factors should both be >1" );
		return( -1 );
	}
	if( im_piocheck( in, out ) )
		return( -1 );

	/* Prepare output. Note: we round the output width down!
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize = in->Xsize / xshrink;
	out->Ysize = in->Ysize / yshrink;
	out->Xres = in->Xres / xshrink;
	out->Yres = in->Yres / yshrink;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_errormsg( "im_shrink: image has shrunk to nothing" );
		return( -1 );
	}

	/* Build and attach state struct.
	 */
	if( !(st = IM_NEW( out, ShrinkInfo )) )
		return( -1 );
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

/* Wrap up the above: do IM_CODING_LABQ as well.
 */
int
im_shrink( IMAGE *in, IMAGE *out, double xshrink, double yshrink )
{
	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *t[2];

		if( im_open_local_array( out, t, 2, "im_shrink:1", "p" ) ||
			im_LabQ2LabS( in, t[0] ) ||
			shrink( t[0], t[1], xshrink, yshrink ) ||
			im_LabS2LabQ( t[1], out ) )
			return( -1 );
	}
	else if( in->Coding == IM_CODING_NONE ) {
		if( shrink( in, out, xshrink, yshrink ) )
			return( -1 );
	}
	else {
		im_errormsg( "im_shrink: unknown coding type" );
		return( -1 );
	}

	return( 0 );
}
