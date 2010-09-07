/* im_conv
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris & Kirk Martinez
 * Written on: 29/04/1991
 * Modified on: 19/05/1991
 * 8/7/93 JC
 *      - adapted for partial v2
 *      - memory leaks fixed
 *      - ANSIfied
 * 23/7/93 JC
 *	- inner loop unrolled with a switch - 25% speed-up!
 * 13/12/93 JC
 *	- tiny rounding error removed
 * 7/10/94 JC
 *	- new IM_ARRAY() macro
 *	- various simplifications
 *	- evalend callback added
 * 1/2/95 JC
 *	- use of IM_REGION_ADDR() updated
 *	- output size was incorrect! see comment below
 *	- bug with large non-square matricies fixed too
 *	- uses new im_embed() function
 * 13/7/98 JC
 *	- wierd bug ... im_free_imask is no longer directly called for close
 *	  callback, caused SIGKILL on solaris 2.6 ... linker bug?
 * 9/3/01 JC
 *	- reworked and simplified, about 10% faster
 *	- slightly better range clipping
 * 27/7/01 JC
 *	- reject masks with scale == 0
 * 7/4/04 
 *	- im_conv() now uses im_embed() with edge stretching on the input, not
 *	  the output
 *	- sets Xoffset / Yoffset
 * 11/11/05
 * 	- simpler inner loop avoids gcc4 bug 
 * 7/11/07
 * 	- new evalstart/end callbacks
 * 12/5/08
 * 	- int rounding was +1 too much, argh
 * 	- only rebuild the buffer offsets if bpl changes
 * 5/4/09
 * 	- tiny speedups and cleanups
 * 	- add restrict, though it doesn't seem to help gcc
 * 12/11/09
 * 	- only check for non-zero elements once
 * 	- add mask-all-zero check
 * 	- cleanups
 * 3/2/10
 * 	- gtkdoc
 * 	- more cleanups
 * 23/08/10
 * 	- add a special case for 3x3 masks, about 20% faster
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
#include <limits.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Our parameters ... we take a copy of the mask argument, plus we make a
 * smaller version with the zeros squeezed out. 
 */
typedef struct {
	IMAGE *in;
	IMAGE *out;
	INTMASK *mask;		/* Copy of mask arg */

	int nnz;		/* Number of non-zero mask elements */
	int *coeff;		/* Array of non-zero mask coefficients */
	int *coeff_pos;		/* Index of each nnz element in mask->coeff */

	int underflow;		/* Global underflow/overflow counts */
	int overflow;
} Conv;

static int
conv_close( Conv *conv )
{
	IM_FREEF( im_free_imask, conv->mask );

        return( 0 );
}

static int
conv_evalstart( Conv *conv )
{
	/* Reset underflow/overflow count.
	 */
	conv->overflow = 0;
	conv->underflow = 0;

        return( 0 );
}

static int
conv_evalend( Conv *conv )
{
	/* Print underflow/overflow count.
	 */
	if( conv->overflow || conv->underflow )
		im_warn( "im_conv", 
			_( "%d overflows and %d underflows detected" ),
			conv->overflow, conv->underflow );

        return( 0 );
}

static Conv *
conv_new( IMAGE *in, IMAGE *out, INTMASK *mask )
{
        Conv *conv = IM_NEW( out, Conv );
	const int ne = mask->xsize * mask->ysize;
        int i;

        if( !conv )
                return( NULL );

        conv->in = in;
        conv->out = out;
        conv->mask = NULL;
        conv->nnz = 0;
        conv->coeff = NULL;
        conv->coeff_pos = NULL;
        conv->underflow = 0;
        conv->overflow = 0;

        if( im_add_close_callback( out, 
		(im_callback_fn) conv_close, conv, NULL ) ||
		im_add_close_callback( out, 
			(im_callback_fn) conv_evalstart, conv, NULL ) ||
		im_add_close_callback( out, 
			(im_callback_fn) conv_evalend, conv, NULL ) ||
        	!(conv->coeff = IM_ARRAY( out, ne, int )) ||
        	!(conv->coeff_pos = IM_ARRAY( out, ne, int )) ||
        	!(conv->mask = im_dup_imask( mask, "conv_mask" )) )
                return( NULL );

        /* Find non-zero mask elements.
         */
        for( i = 0; i < ne; i++ )
                if( mask->coeff[i] ) {
			conv->coeff[conv->nnz] = mask->coeff[i];
			conv->coeff_pos[conv->nnz] = i;
			conv->nnz += 1;
		}

	/* Was the whole mask zero? We must have at least 1 element in there:
	 * set it to zero.
	 */
	if( conv->nnz == 0 ) {
		conv->coeff[0] = mask->coeff[0];
		conv->coeff_pos[0] = 0;
		conv->nnz = 1;
	}

        return( conv );
}

/* Our sequence value.
 */
typedef struct {
	Conv *conv;
	REGION *ir;		/* Input region */

	int *offsets;		/* Offsets for each non-zero matrix element */
	PEL **pts;		/* Per-non-zero mask element pointers */

	int underflow;		/* Underflow/overflow counts */
	int overflow;

	int last_bpl;		/* Avoid recalcing offsets, if we can */
} ConvSequence;

/* Free a sequence value.
 */
static int
conv_stop( void *vseq, void *a, void *b )
{
	ConvSequence *seq = (ConvSequence *) vseq;
	Conv *conv = (Conv *) b;

	/* Add local under/over counts to global counts.
	 */
	conv->overflow += seq->overflow;
	conv->underflow += seq->underflow;

	IM_FREEF( im_region_free, seq->ir );

	return( 0 );
}

/* Convolution start function.
 */
static void *
conv_start( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	Conv *conv = (Conv *) b;
	ConvSequence *seq;

	if( !(seq = IM_NEW( out, ConvSequence )) )
		return( NULL );

	/* Init!
	 */
	seq->conv = conv;
	seq->ir = NULL;
	seq->pts = NULL;
	seq->underflow = 0;
	seq->overflow = 0;
	seq->last_bpl = -1;

	/* Attach region and arrays.
	 */
	seq->ir = im_region_create( in );
	seq->offsets = IM_ARRAY( out, conv->nnz, int );
	seq->pts = IM_ARRAY( out, conv->nnz, PEL * );
	if( !seq->ir || !seq->offsets || !seq->pts ) {
		conv_stop( seq, in, conv );
		return( NULL );
	}

	return( seq );
}

#define INNER { \
	sum += t[i] * p[i][x]; \
	i += 1; \
}

/* INT inner loops.
 */
#define CONV_INT( TYPE, IM_CLIP ) { \
	TYPE ** restrict p = (TYPE **) seq->pts; \
	TYPE * restrict q = (TYPE *) IM_REGION_ADDR( or, le, y ); \
	\
	for( x = 0; x < sz; x++ ) {  \
		int sum; \
		int i; \
 		\
		sum = 0; \
		i = 0; \
		IM_UNROLL( conv->nnz, INNER ); \
 		\
		sum = ((sum + rounding) / mask->scale) + mask->offset; \
 		\
		IM_CLIP; \
		\
		q[x] = sum;  \
	}  \
} 

/* FLOAT inner loops.
 */
#define CONV_FLOAT( TYPE ) { \
	TYPE ** restrict p = (TYPE **) seq->pts; \
	TYPE * restrict q = (TYPE *) IM_REGION_ADDR( or, le, y ); \
	\
	for( x = 0; x < sz; x++ ) {  \
		double sum; \
		int i; \
 		\
		sum = 0; \
		i = 0; \
		IM_UNROLL( conv->nnz, INNER ); \
 		\
		sum = (sum / mask->scale) + mask->offset; \
		\
		q[x] = sum;  \
	}  \
} 

/* Convolve! See below for the special-case 3x3 path.
 */
static int
conv_gen( REGION *or, void *vseq, void *a, void *b )
{
	ConvSequence *seq = (ConvSequence *) vseq;
	IMAGE *in = (IMAGE *) a;
	Conv *conv = (Conv *) b;
	REGION *ir = seq->ir;
	INTMASK *mask = conv->mask;
	int * restrict t = conv->coeff; 

	/* You might think this should be (scale + 1) / 2, but then we'd be 
	 * adding one for scale == 1.
	 */
	int rounding = mask->scale / 2;

	Rect *r = &or->valid;
	Rect s;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM( r );
	int sz = IM_REGION_N_ELEMENTS( or );

	int x, y, z, i;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += mask->xsize - 1;
	s.height += mask->ysize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );

        /* Fill offset array. Only do this if the bpl has changed since the 
	 * previous im_prepare().
	 */
	if( seq->last_bpl != IM_REGION_LSKIP( ir ) ) {
		seq->last_bpl = IM_REGION_LSKIP( ir );

		for( i = 0; i < conv->nnz; i++ ) {
			z = conv->coeff_pos[i];
			x = z % conv->mask->xsize;
			y = z / conv->mask->xsize;

			seq->offsets[i] = 
				IM_REGION_ADDR( ir, x + le, y + to ) -
				IM_REGION_ADDR( ir, le, to );
		}
	}

	for( y = to; y < bo; y++ ) { 
		/* Init pts for this line of PELs.
		 */
                for( z = 0; z < conv->nnz; z++ ) 
                        seq->pts[z] = seq->offsets[z] +  
                                (PEL *) IM_REGION_ADDR( ir, le, y ); 

		switch( in->BandFmt ) {
		case IM_BANDFMT_UCHAR: 	
			CONV_INT( unsigned char, IM_CLIP_UCHAR( sum, seq ) ); 
			break;

		case IM_BANDFMT_CHAR:   
			CONV_INT( signed char, IM_CLIP_CHAR( sum, seq ) ); 
			break;

		case IM_BANDFMT_USHORT: 
			CONV_INT( unsigned short, IM_CLIP_USHORT( sum, seq ) ); 
			break;

		case IM_BANDFMT_SHORT:  
			CONV_INT( signed short, IM_CLIP_SHORT( sum, seq ) ); 
			break;

		case IM_BANDFMT_UINT:   
			CONV_INT( unsigned int, IM_CLIP_NONE( sum, seq ) ); 
			break;

		case IM_BANDFMT_INT:    
			CONV_INT( signed int, IM_CLIP_NONE( sum, seq ) ); 
			break;

		case IM_BANDFMT_FLOAT:  
			CONV_FLOAT( float ); 
			break;

		case IM_BANDFMT_DOUBLE: 
			CONV_FLOAT( double ); 
			break;

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

/* INT inner loops.
 */
#define CONV3x3_INT( TYPE, IM_CLIP ) { \
	TYPE * restrict p0 = (TYPE *) IM_REGION_ADDR( ir, le, y ); \
	TYPE * restrict p1 = (TYPE *) IM_REGION_ADDR( ir, le, y + 1 ); \
	TYPE * restrict p2 = (TYPE *) IM_REGION_ADDR( ir, le, y + 2 ); \
	TYPE * restrict q = (TYPE *) IM_REGION_ADDR( or, le, y ); \
	\
	for( x = 0; x < sz; x++ ) {  \
		int sum; \
 		\
		sum = 0; \
		sum += m[0] * p0[0]; \
		sum += m[1] * p0[bands]; \
		sum += m[2] * p0[bands * 2]; \
		sum += m[3] * p1[0]; \
		sum += m[4] * p1[bands]; \
		sum += m[5] * p1[bands * 2]; \
		sum += m[6] * p2[0]; \
		sum += m[7] * p2[bands]; \
		sum += m[8] * p2[bands * 2]; \
		\
		p0 += 1; \
		p1 += 1; \
		p2 += 1; \
 		\
		sum = ((sum + rounding) / mask->scale) + mask->offset; \
 		\
		IM_CLIP; \
		\
		q[x] = sum;  \
	}  \
} 

/* FLOAT inner loops.
 */
#define CONV3x3_FLOAT( TYPE ) { \
	TYPE * restrict p0 = (TYPE *) IM_REGION_ADDR( ir, le, y ); \
	TYPE * restrict p1 = (TYPE *) IM_REGION_ADDR( ir, le, y + 1 ); \
	TYPE * restrict p2 = (TYPE *) IM_REGION_ADDR( ir, le, y + 2 ); \
	TYPE * restrict q = (TYPE *) IM_REGION_ADDR( or, le, y ); \
	\
	for( x = 0; x < sz; x++ ) {  \
		double sum; \
 		\
		sum = 0; \
		sum += m[0] * p0[0]; \
		sum += m[1] * p0[bands]; \
		sum += m[2] * p0[bands * 2]; \
		sum += m[3] * p1[0]; \
		sum += m[4] * p1[bands]; \
		sum += m[5] * p1[bands * 2]; \
		sum += m[6] * p2[0]; \
		sum += m[7] * p2[bands]; \
		sum += m[8] * p2[bands * 2]; \
 		\
		p0 += 1; \
		p1 += 1; \
		p2 += 1; \
 		\
		sum = (sum / mask->scale) + mask->offset; \
		\
		q[x] = sum;  \
	}  \
} 

/* 3x3 masks are very common, so we have a special path for them. This is
 * about 20% faster than the general convolver above.
 */
static int
conv3x3_gen( REGION *or, void *vseq, void *a, void *b )
{
	ConvSequence *seq = (ConvSequence *) vseq;
	IMAGE *in = (IMAGE *) a;
	Conv *conv = (Conv *) b;
	REGION *ir = seq->ir;
	INTMASK *mask = conv->mask;
	int * restrict m = mask->coeff; 

	/* You might think this should be (scale + 1) / 2, but then we'd be 
	 * adding one for scale == 1.
	 */
	int rounding = mask->scale / 2;

	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM( r );
	int sz = IM_REGION_N_ELEMENTS( or );
	int bands = in->Bands;

	Rect s;
	int x, y;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += 2;
	s.height += 2;
	if( im_prepare( ir, &s ) )
		return( -1 );

	for( y = to; y < bo; y++ ) { 
		switch( in->BandFmt ) {
		case IM_BANDFMT_UCHAR: 	
			CONV3x3_INT( unsigned char, 
				IM_CLIP_UCHAR( sum, seq ) ); 
			break;

		case IM_BANDFMT_CHAR:   
			CONV3x3_INT( signed char, 
				IM_CLIP_CHAR( sum, seq ) ); 
			break;

		case IM_BANDFMT_USHORT: 
			CONV3x3_INT( unsigned short, 
				IM_CLIP_USHORT( sum, seq ) ); 
			break;

		case IM_BANDFMT_SHORT:  
			CONV3x3_INT( signed short, 
				IM_CLIP_SHORT( sum, seq ) ); 
			break;

		case IM_BANDFMT_UINT:   
			CONV3x3_INT( unsigned int, 
				IM_CLIP_NONE( sum, seq ) ); 
			break;

		case IM_BANDFMT_INT:    
			CONV3x3_INT( signed int, 
				IM_CLIP_NONE( sum, seq ) ); 
			break;

		case IM_BANDFMT_FLOAT:  
			CONV3x3_FLOAT( float ); 
			break;

		case IM_BANDFMT_DOUBLE: 
			CONV3x3_FLOAT( double ); 
			break;

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

int
im_conv_raw( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	Conv *conv;
	im_generate_fn generate;

	/* Check parameters.
	 */
	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_conv", in ) ||
		im_check_noncomplex( "im_conv", in ) ||
		im_check_imask( "im_conv", mask ) ) 
		return( -1 );
	if( mask->scale == 0 ) {
		im_error( "im_conv", "%s", "mask scale must be non-zero" );
		return( -1 );
	}
	if( !(conv = conv_new( in, out, mask )) )
		return( -1 );

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize -= mask->xsize - 1;
	out->Ysize -= mask->ysize - 1;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_error( "im_conv", "%s", _( "image too small for mask" ) );
		return( -1 );
	}

	if( mask->xsize == 3 && mask->ysize == 3 )
		generate = conv3x3_gen;
	else
		generate = conv_gen;

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) ||
		im_generate( out, conv_start, generate, conv_stop, in, conv ) )
		return( -1 );

	out->Xoffset = -mask->xsize / 2;
	out->Yoffset = -mask->ysize / 2;

	return( 0 );
}

/**
 * im_conv:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 *
 * Convolve @in with @mask using integer arithmetic. The output image 
 * always has the same #VipsBandFmt as the input image. Non-complex images
 * only.
 *
 * Each output pixel is
 * calculated as sigma[i]{pixel[i] * mask[i]} / scale + offset, where scale
 * and offset are part of @mask. For integer @in, the division by scale
 * includes round-to-nearest.
 *
 * See also: im_conv_f(), im_convsep(), im_create_imaskv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_conv( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *t1 = im_open_local( out, "im_conv intermediate", "p" );

	if( !t1 || 
		im_embed( in, t1, 1, mask->xsize / 2, mask->ysize / 2, 
			in->Xsize + mask->xsize - 1, 
			in->Ysize + mask->ysize - 1 ) ||
		im_conv_raw( t1, out, mask ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
