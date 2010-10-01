/* im_convsep
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 29/04/1991
 * Modified on: 29/4/93 K.Martinez  for Sys5
 * 9/3/01 JC
 *	- rewritten using im_conv()
 * 27/7/01 JC
 *	- rejects masks with scale == 0
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the input, not
 *	  the output
 *	- sets Xoffset / Yoffset
 * 21/4/04
 *	- scale down int convolves at 1/2 way mark, much less likely to integer
 *	  overflow on intermediates
 * 12/5/08
 * 	- int rounding was +1 too much, argh
 * 3/2/10
 * 	- gtkdoc
 * 	- more cleanups
 * 1/10/10
 * 	- support complex (just double the bands)
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

/* Our parameters ... we take a copy of the mask argument.
 */
typedef struct {
	IMAGE *in;
	IMAGE *out;
	INTMASK *mask;	/* Copy of mask arg */

	int size;	/* N for our 1xN or Nx1 mask */
	int scale;	/* Our scale ... we have to square mask->scale */

	int underflow;	/* Global underflow/overflow counts */
	int overflow;
} Conv;

/* End of evaluation --- print overflows and underflows.
 */
static int
conv_destroy( Conv *conv )
{
	/* Print underflow/overflow count.
	 */
	if( conv->overflow || conv->underflow )
		im_warn( "im_convsep", _( "%d overflows and %d underflows "
			"detected" ), conv->overflow, conv->underflow );

	if( conv->mask ) {
		(void) im_free_imask( conv->mask );
		conv->mask = NULL;
	}

        return( 0 );
}

static Conv *
conv_new( IMAGE *in, IMAGE *out, INTMASK *mask )
{
        Conv *conv = IM_NEW( out, Conv );

        if( !conv )
                return( NULL );

        conv->in = in;
        conv->out = out;
        conv->mask = NULL;
	conv->size = mask->xsize * mask->ysize;
	conv->scale = mask->scale * mask->scale;
        conv->underflow = 0;
        conv->overflow = 0;

        if( im_add_close_callback( out, 
		(im_callback_fn) conv_destroy, conv, NULL ) ||
		!(conv->mask = im_dup_imask( mask, "conv_mask" )) )
                return( NULL );

        return( conv );
}

/* Our sequence value.
 */
typedef struct {
	Conv *conv;
	REGION *ir;		/* Input region */

	PEL *sum;		/* Line buffer */

	int underflow;		/* Underflow/overflow counts */
	int overflow;
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
	seq->sum = NULL;
	seq->underflow = 0;
	seq->overflow = 0;

	/* Attach region and arrays.
	 */
	seq->ir = im_region_create( in );
	if( vips_bandfmt_isint( conv->out->BandFmt ) )
		seq->sum = (PEL *) 
			IM_ARRAY( out, IM_IMAGE_N_ELEMENTS( in ), int );
	else
		seq->sum = (PEL *) 
			IM_ARRAY( out, IM_IMAGE_N_ELEMENTS( in ), double );
	if( !seq->ir || !seq->sum ) {
		conv_stop( seq, in, conv );
		return( NULL );
	}

	return( (void *) seq );
}

/* What we do for every point in the mask, for each pixel.
 */
#define VERTICAL_CONV { z -= 1; li -= lskip; sum += coeff[z] * vfrom[li]; }
#define HORIZONTAL_CONV { z -= 1; li -= bands; sum += coeff[z] * hfrom[li]; }

/* INT and FLOAT inner loops.
 */
#define CONV_INT( TYPE, IM_CLIP ) { \
	TYPE *vfrom; \
	int *vto; \
	int *hfrom; \
	TYPE *hto; \
 	\
	/* Convolve to sum array. We convolve the full width of \
	 * this input line. \
	 */ \
	vfrom = (TYPE *) IM_REGION_ADDR( ir, le, y ); \
	vto = (int *) seq->sum; \
	for( x = 0; x < isz; x++ ) {   \
		int sum; \
		 \
		z = conv->size;  \
		li = lskip * z; \
		sum = 0; \
 		\
		IM_UNROLL( z, VERTICAL_CONV ); \
 		\
		sum = ((sum + rounding) / mask->scale) + mask->offset; \
		\
		vto[x] = sum;   \
		vfrom += 1; \
	}  \
 	\
	/* Convolve sums to output. \
	 */ \
	hfrom = (int *) seq->sum; \
	hto = (TYPE *) IM_REGION_ADDR( or, le, y );  \
	for( x = 0; x < osz; x++ ) { \
		int sum; \
		 \
		z = conv->size;  \
		li = bands * z; \
		sum = 0; \
 		\
		IM_UNROLL( z, HORIZONTAL_CONV ); \
 		\
		sum = ((sum + rounding) / mask->scale) + mask->offset; \
 		\
		IM_CLIP; \
 		\
		hto[x] = sum;   \
		hfrom += 1; \
	} \
}

#define CONV_FLOAT( TYPE ) { \
	TYPE *vfrom; \
	double *vto; \
	double *hfrom; \
	TYPE *hto; \
 	\
	/* Convolve to sum array. We convolve the full width of \
	 * this input line. \
	 */ \
	vfrom = (TYPE *) IM_REGION_ADDR( ir, le, y ); \
	vto = (double *) seq->sum; \
	for( x = 0; x < isz; x++ ) {   \
		double sum; \
		 \
		z = conv->size;  \
		li = lskip * z; \
		sum = 0; \
 		\
		IM_UNROLL( z, VERTICAL_CONV ); \
 		\
		vto[x] = sum;   \
		vfrom += 1; \
	}  \
 	\
	/* Convolve sums to output. \
	 */ \
	hfrom = (double *) seq->sum; \
	hto = (TYPE *) IM_REGION_ADDR( or, le, y );  \
	for( x = 0; x < osz; x++ ) { \
		double sum; \
		 \
		z = conv->size;  \
		li = bands * z; \
		sum = 0; \
 		\
		IM_UNROLL( z, HORIZONTAL_CONV ); \
 		\
		sum = (sum / conv->scale) + mask->offset; \
 		\
		hto[x] = sum;   \
		hfrom += 1; \
	} \
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

	/* You might think this should be (scale+1)/2, but then we'd be adding
	 * one for scale == 1.
	 */
	int rounding = mask->scale / 2;

	int bands = in->Bands;
	int *coeff = conv->mask->coeff; 

	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int osz = IM_REGION_N_ELEMENTS( or ) * 
		(vips_bandfmt_iscomplex( in->BandFmt ) ? 2 : 1);

	Rect s;
	int lskip;
	int isz;
	int x, y, z, li;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += conv->size - 1;
	s.height += conv->size - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );
	lskip = IM_REGION_LSKIP( ir ) / IM_IMAGE_SIZEOF_ELEMENT( in );
	isz = IM_REGION_N_ELEMENTS( ir );

	for( y = to; y < bo; y++ ) { 
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
		case IM_BANDFMT_COMPLEX:  
			CONV_FLOAT( float ); 
			break;
		case IM_BANDFMT_DOUBLE: 
		case IM_BANDFMT_DPCOMPLEX:  
			CONV_FLOAT( double ); 
			break;

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

int
im_convsep_raw( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	Conv *conv;

	/* Check parameters.
	 */
	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_convsep", in ) ||
		im_check_imask( "im_convsep", mask ) ) 
		return( -1 );
	if( mask->xsize != 1 && mask->ysize != 1 ) {
                im_error( "im_convsep", 
			"%s", _( "expect 1xN or Nx1 input mask" ) );
                return( -1 );
	}
	if( mask->scale == 0 ) {
		im_error( "im_convsep", "%s", "mask scale must be non-zero" );
		return( -1 );
	}
	if( !(conv = conv_new( in, out, mask )) )
		return( -1 );

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize -= conv->size - 1;
	out->Ysize -= conv->size - 1;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_error( "im_convsep", "%s", _( "image too small for mask" ) );
		return( -1 );
	}

	/* SMALLTILE seems the fastest in benchmarks.
	 */
	if( im_demand_hint( out, IM_SMALLTILE, in, NULL ) ||
		im_generate( out, conv_start, conv_gen, conv_stop, in, conv ) )
		return( -1 );

	out->Xoffset = -mask->xsize / 2;
	out->Yoffset = -mask->ysize / 2;

	return( 0 );
}


/**
 * im_convsep:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 *
 * Perform a separable convolution of @in with @mask using integer arithmetic. 
 *
 * The mask must be 1xn or nx1 elements. 
 * The output image 
 * always has the same #VipsBandFmt as the input image. 
 *
 * The image is convolved twice: once with @mask and then again with @mask 
 * rotated by 90 degrees. This is much faster for certain types of mask
 * (gaussian blur, for example) than doing a full 2D convolution.
 *
 * Each output pixel is
 * calculated as sigma[i]{pixel[i] * mask[i]} / scale + offset, where scale
 * and offset are part of @mask. For integer @in, the division by scale
 * includes round-to-nearest.
 *
 * See also: im_convsep_f(), im_conv(), im_create_imaskv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_convsep( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *t1 = im_open_local( out, "im_convsep intermediate", "p" );
	int size = mask->xsize * mask->ysize;

	if( !t1 || 
		im_embed( in, t1, 1, size / 2, size / 2, 
			in->Xsize + size - 1, 
			in->Ysize + size - 1 ) ||
		im_convsep_raw( t1, out, mask ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
