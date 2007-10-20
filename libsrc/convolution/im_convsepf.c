/* @(#) Convolve an image with a DOUBLEMASK. Image can have any number of bands,
 * @(#) any non-complex type. Output is IM_BANDFMT_FLOAT for all non-complex inputs
 * @(#) except IM_BANDFMT_DOUBLE, which gives IM_BANDFMT_DOUBLE.
 * @(#) Separable mask of sizes 1xN or Nx1 
 * @(#)
 * @(#) int im_convsepf( in, out, mask )
 * @(#) IMAGE *in, *out;
 * @(#) DOUBLEMASK *mask;		details in mask.h
 * @(#)
 * @(#) Returns either 0 (sucess) or -1 (fail)
 * @(#) Picture can have any number of channels (max 64).
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 29/04/1991
 * Modified on: 29/4/93 K.Martinez for sys5
 * 9/3/01 JC
 *	- rewritten using im_conv()
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the input, not
 *	  the output
 *	- sets Xoffset / Yoffset
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

/* Our parameters ... we take a copy of the mask argument.
 */
typedef struct {
	IMAGE *in;
	IMAGE *out;
	DOUBLEMASK *mask;	/* Copy of mask arg */

	int size;		/* N for our 1xN or Nx1 mask */
	int scale;		/* Our scale ... we have to ^2 mask->scale */
} Conv;

/* End of evaluation.
 */
static int
conv_destroy( Conv *conv )
{
	if( conv->mask ) {
		(void) im_free_dmask( conv->mask );
		conv->mask = NULL;
	}

        return( 0 );
}

static Conv *
conv_new( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
        Conv *conv = IM_NEW( out, Conv );

        if( !conv )
                return( NULL );

        conv->in = in;
        conv->out = out;
        conv->mask = NULL;
	conv->size = mask->xsize * mask->ysize;
	conv->scale = mask->scale * mask->scale;

        if( im_add_close_callback( out, 
		(im_callback_fn) conv_destroy, conv, NULL ) ||
		!(conv->mask = im_dup_dmask( mask, "conv_mask" )) )
                return( NULL );

        return( conv );
}

/* Our sequence value.
 */
typedef struct {
	Conv *conv;
	REGION *ir;		/* Input region */

	PEL *sum;		/* Line buffer */
} ConvSequence;

/* Free a sequence value.
 */
static int
conv_stop( void *vseq, void *a, void *b )
{
	ConvSequence *seq = (ConvSequence *) vseq;

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

	/* Attach region and arrays.
	 */
	seq->ir = im_region_create( in );
	if( im_isint( conv->out ) )
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

#define CONV_FLOAT( ITYPE, OTYPE ) { \
	ITYPE *vfrom; \
	double *vto; \
	double *hfrom; \
	OTYPE *hto; \
 	\
	/* Convolve to sum array. We convolve the full width of \
	 * this input line. \
	 */ \
	vfrom = (ITYPE *) IM_REGION_ADDR( ir, le, y ); \
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
	hto = (OTYPE *) IM_REGION_ADDR( or, le, y );  \
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
	DOUBLEMASK *mask = conv->mask;
	double *coeff = conv->mask->coeff; 
	int bands = in->Bands;

	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int osz = IM_REGION_N_ELEMENTS( or );

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
			CONV_FLOAT( unsigned char, float ); break;
		case IM_BANDFMT_CHAR:   
			CONV_FLOAT( signed char, float ); break;
		case IM_BANDFMT_USHORT: 
			CONV_FLOAT( unsigned short, float ); break;
		case IM_BANDFMT_SHORT:  
			CONV_FLOAT( signed short, float ); break;
		case IM_BANDFMT_UINT:   
			CONV_FLOAT( unsigned int, float ); break;
		case IM_BANDFMT_INT:    
			CONV_FLOAT( signed int, float ); break;
		case IM_BANDFMT_FLOAT:  
			CONV_FLOAT( float, float ); break;
		case IM_BANDFMT_DOUBLE: 
			CONV_FLOAT( double, double ); break;

		default:
			assert( 0 );
		}
	}

	return( 0 );
}

int
im_convsepf_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	Conv *conv;

	/* Check parameters.
	 */
	if( !in || in->Coding != IM_CODING_NONE || im_iscomplex( in ) ) {
		im_error( "im_convsepf", _( "non-complex uncoded only" ) );
		return( -1 );
	}
	if( !mask || mask->xsize > 1000 || mask->ysize > 1000 || 
		mask->xsize <= 0 || mask->ysize <= 0 || !mask->coeff ||
		mask->scale == 0 ) {
		im_error( "im_convsepf", _( "bad mask parameters" ) );
		return( -1 );
	}
	if( mask->xsize != 1 && mask->ysize != 1 ) {
                im_error( "im_convsepf", _( "expect 1xN or Nx1 input mask" ) );
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
	if( im_isint( in ) ) {
		out->Bbits = IM_BBITS_FLOAT;
		out->BandFmt = IM_BANDFMT_FLOAT;
	}
	out->Xsize -= conv->size - 1;
	out->Ysize -= conv->size - 1;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_error( "im_convsepf", _( "image too small for mask" ) );
		return( -1 );
	}

	/* SMALLTILE seems fastest.
	 */
	if( im_demand_hint( out, IM_SMALLTILE, in, NULL ) ||
		im_generate( out, conv_start, conv_gen, conv_stop, in, conv ) )
		return( -1 );

	out->Xoffset = -conv->size / 2;
	out->Yoffset = -conv->size / 2;

	return( 0 );
}

/* The above, with a border to make out the same size as in.
 */
int 
im_convsepf( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	IMAGE *t1 = im_open_local( out, "im_convsepf intermediate", "p" );
	int size = mask->xsize * mask->ysize;

	if( !t1 || 
		im_embed( in, t1, 1, size / 2, size / 2, 
			in->Xsize + size - 1, 
			in->Ysize + size - 1 ) ||
		im_convsepf_raw( t1, out, mask ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
