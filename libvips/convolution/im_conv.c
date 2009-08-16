/* @(#) Convolve an image with an INTMASK. Image can have any number of bands,
 * @(#) any non-complex type. Size and type of output image matches type of 
 * @(#) input image.
 * @(#)
 * @(#) int 
 * @(#) im_conv( in, out, mask )
 * @(#) IMAGE *in, *out;
 * @(#) INTMASK *mask;
 * @(#)
 * @(#) Also: im_conv_raw(). As above, but does not add a black border.
 * @(#)
 * @(#) Returns either 0 (success) or -1 (fail)
 * @(#) 
 * @(#) Old code, kept for use of other old code in this package: 
 * @(#) 
 * @(#)  Creates int luts for all non zero elm of the original mask;
 * @(#) which is kept in buffer of length buffersize
 * @(#) cnt is needed for freeing luts.  Called by the above.
 * @(#)
 * @(#) int im__create_int_luts( buffer, buffersize, orig_luts, luts, cnt )
 * @(#) int *buffer, buffersize;
 * @(#) int **orig_luts, **luts, *cnt;
 * @(#)
 * @(#) Returns either 0 (sucess) or -1 (fail)
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
 *	- rejects masks with scale == 0
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
#include <assert.h>

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
        conv->underflow = 0;
        conv->overflow = 0;

        if( im_add_close_callback( out, 
		(im_callback_fn) conv_close, conv, NULL ) ||
		im_add_close_callback( out, 
			(im_callback_fn) conv_evalstart, conv, NULL ) ||
		im_add_close_callback( out, 
			(im_callback_fn) conv_evalend, conv, NULL ) ||
        	!(conv->coeff = IM_ARRAY( out, ne, int )) ||
        	!(conv->mask = im_dup_imask( mask, "conv_mask" )) )
                return( NULL );

        /* Find non-zero mask elements.
         */
        for( i = 0; i < ne; i++ )
                if( mask->coeff[i] ) 
			conv->coeff[conv->nnz++] = mask->coeff[i];

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

/* INT and FLOAT inner loops.
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

/* Convolve!
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

	/* You might think this should be (scale+1)/2, but then we'd be adding
	 * one for scale == 1.
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

		z = 0;
		for( i = 0, y = 0; y < mask->ysize; y++ )
			for( x = 0; x < mask->xsize; x++, i++ )
				if( mask->coeff[i] )
					seq->offsets[z++] = 
						IM_REGION_ADDR( ir, 
							x + le, y + to ) -
						IM_REGION_ADDR( ir, le, to );
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
			assert( 0 );
		}
	}

	return( 0 );
}

int
im_conv_raw( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	Conv *conv;

	/* Check parameters.
	 */
	if( !in || in->Coding != IM_CODING_NONE || im_iscomplex( in ) ) {
		im_error( "im_conv", "%s", _( "non-complex uncoded only" ) );
		return( -1 );
	}
	if( !mask || mask->xsize > 1000 || mask->ysize > 1000 || 
		mask->xsize <= 0 || mask->ysize <= 0 || !mask->coeff ||
		mask->scale == 0 ) {
		im_error( "im_conv", "%s", _( "nonsense mask parameters" ) );
		return( -1 );
	}
	if( im_piocheck( in, out ) )
		return( -1 );
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

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
		return( -1 );

	if( im_generate( out, conv_start, conv_gen, conv_stop, in, conv ) )
		return( -1 );

	out->Xoffset = -mask->xsize / 2;
	out->Yoffset = -mask->ysize / 2;

	return( 0 );
}

/* The above, with a border to make out the same size as in.
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

/* im__create_int_luts is not used in this file. We have to keep it for the use
 * of other conv functions in this directory which have not yet been
 * rewritten.

 	FIXME ... the only one left is im_convsub() which I'm sure no one
	uses. Scrap this junk in the next version. Kill off the old gradient
	and lindetect things too.

 */

/* Create multiplication luts for all non zero elements  of the original mask;
 * which is kept in buffer of length buffersize 
 * cnt is needed for freeing luts 
 */
int
im__create_int_luts( int *buffer, int buffersize, 
	int **orig_luts, int **luts, int *cnt )
{
	int *pbuffer;
	int *buf1, *buf2, *pbuf1, *pbuf2;
	int i, j;
	int min, max;
	int mark; /* used to mark the buffer mark = max+1 */
	int counter; /* counts the no of unique elms in mask; returned in cnt*/

	buf1 = (int*)calloc( (unsigned)buffersize, sizeof(int) );
	buf2 = (int*)calloc( (unsigned)buffersize, sizeof(int) );
	if ( ( buf1 == NULL ) || ( buf2 == NULL ) )
		{
		im_errormsg("im_create_int_luts: calloc failed (1)");
		return( -1 );
		}

	pbuffer = buffer;
	pbuf1 = buf1;
	/* find max and copy mask to buf1 */
	max = *pbuffer;
	for ( i=0; i < buffersize; i++ )
		{
		if ( *pbuffer > max )
			max = *pbuffer;
		*pbuf1++ = *pbuffer++;
		}
	mark = max + 1;
	pbuf1 = buf1;
	pbuf2 = buf2;
	counter = 0;
/* find a min at a time; put it into buf2 and mark all values of
 * buf1 equal to found min, to INT_MAX
 */
	for ( i=0; i < buffersize; i++ )	
		{
		min = mark + 1; /* force min to be greater than mark */
		pbuf1 = buf1;
		/* find a min */
		for ( j=0; j < buffersize; j++ )
			{
			if ( *pbuf1 < min )
				min = *pbuf1;
			pbuf1++;
			}
		if ( min == mark )	/* all min are found */
			break;
		*pbuf2++ = min;
		counter++;
		pbuf1 = buf1;
		for ( j=0; j < buffersize; j++ ) /* mark values equal to min */
			{
			if ( *pbuf1 == min )
				*pbuf1 = mark;
			pbuf1++;
			}
		}	
/* buf2 should keep now counter unique values of the mask, descending order
 * Malloc counter luts and initialise them 
 */
	pbuf2 = buf2;
	for ( i=0; i<counter; i++)
		{
		orig_luts[i] = (int*)calloc((unsigned)256, sizeof(int));
		if (orig_luts[i] == NULL)
			{
			im_errormsg("im_create_int_luts: calloc failed (2)");
			return( -1 );
			}
		for ( j=0; j<256; j++ )
			*(orig_luts[i] + j) = j * (*pbuf2);
		pbuf2++;
		}

	pbuffer = buffer;
	for ( i=0; i<buffersize; i++ )
		{
		j = 0;
		while ( 1 )
			{
			if ( *(buf2 + j) == *pbuffer )
				{
				luts[i] = orig_luts[j];
				break;
				}
			j++;
			}
		pbuffer++;
		}
/* free buf1, buf2 */
	free((char*)buf1); free( (char*)buf2);
	*cnt = counter;
	return(0);
}
