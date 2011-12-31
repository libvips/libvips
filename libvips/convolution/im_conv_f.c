/* im_conv_f
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
 * 12/7/93 JC
 *	- adapted im_convbi() to im_convbf()
 * 7/10/94 JC
 *	- new IM_ARRAY() macro
 *	- evalend callbacks
 *	- more typedef
 * 9/3/01 JC
 *	- redone from im_conv() 
 * 27/7/01 JC
 *	- rejects masks with scale == 0
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the input, not
 *	  the output
 *	- sets Xoffset / Yoffset
 * 11/11/05
 * 	- simpler inner loop avoids gcc4 bug 
 * 12/11/09
 * 	- only rebuild the buffer offsets if bpl changes
 * 	- tiny speedups and cleanups
 * 	- add restrict, though it doesn't seem to help gcc
 * 	- add mask-all-zero check
 * 13/11/09
 * 	- rename as im_conv_f() to make it easier for vips.c to make the
 * 	  overloaded version
 * 3/2/10
 * 	- gtkdoc
 * 	- more cleanups
 * 1/10/10
 * 	- support complex (just double the bands)
 * 29/10/10
 * 	- get rid of im_convsep_f(), just call this twice, no longer worth
 * 	  keeping two versions
 * 15/10/11 Nicolas
 * 	- handle offset correctly in seperable convolutions
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

/* Our parameters ... we take a copy of the mask argument, plus we make a
 * smaller version with the zeros squeezed out. 
 */
typedef struct {
	IMAGE *in;
	IMAGE *out;
	DOUBLEMASK *mask;	/* Copy of mask arg */

	int nnz;		/* Number of non-zero mask elements */
	double *coeff;		/* Array of non-zero mask coefficients */
	int *coeff_pos;		/* Index of each nnz element in mask->coeff */
} Conv;

static int
conv_close( Conv *conv )
{
	IM_FREEF( im_free_dmask, conv->mask );

        return( 0 );
}

static Conv *
conv_new( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
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

        if( im_add_close_callback( out, 
		(im_callback_fn) conv_close, conv, NULL ) ||
        	!(conv->coeff = IM_ARRAY( out, ne, double )) ||
        	!(conv->coeff_pos = IM_ARRAY( out, ne, int )) ||
        	!(conv->mask = im_dup_dmask( mask, "conv_mask" )) )
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
	VipsPel **pts;		/* Per-non-zero mask element image pointers */

	int last_bpl;		/* Avoid recalcing offsets, if we can */
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
	seq->pts = NULL;
	seq->last_bpl = -1;

	/* Attach region and arrays.
	 */
	seq->ir = im_region_create( in );
	seq->offsets = IM_ARRAY( out, conv->nnz, int );
	seq->pts = IM_ARRAY( out, conv->nnz, VipsPel * );
	if( !seq->ir || !seq->offsets || !seq->pts ) {
		conv_stop( seq, in, conv );
		return( NULL );
	}

	return( (void *) seq );
}

#define INNER { \
	sum += t[i] * p[i][x]; \
	i += 1; \
}

#define CONV_FLOAT( ITYPE, OTYPE ) { \
	ITYPE ** restrict p = (ITYPE **) seq->pts; \
	OTYPE * restrict q = (OTYPE *) IM_REGION_ADDR( or, le, y ); \
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
	DOUBLEMASK *mask = conv->mask;
	double * restrict t = conv->coeff; 

	Rect *r = &or->valid;
	Rect s;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int sz = IM_REGION_N_ELEMENTS( or ) * 
		(vips_bandfmt_iscomplex( in->BandFmt ) ? 2 : 1);

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
				IM_REGION_ADDR( ir, le, y ); 

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
		case IM_BANDFMT_COMPLEX:  
			CONV_FLOAT( float, float ); break;
		case IM_BANDFMT_DOUBLE: 
		case IM_BANDFMT_DPCOMPLEX:  
			CONV_FLOAT( double, double ); break;

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

int
im_conv_f_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	Conv *conv;

	/* Check parameters.
	 */
	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_conv", in ) ||
		im_check_dmask( "im_conv", mask ) ) 
		return( -1 );
	if( mask->scale == 0 ) {
		im_error( "im_conv_f", "%s", "mask scale must be non-zero" );
		return( -1 );
	}
	if( !(conv = conv_new( in, out, mask )) )
		return( -1 );

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	if( vips_bandfmt_isint( in->BandFmt ) ) 
		out->BandFmt = IM_BANDFMT_FLOAT;
	out->Xsize -= mask->xsize - 1;
	out->Ysize -= mask->ysize - 1;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_error( "im_conv_f", "%s", _( "image too small for mask" ) );
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

/**
 * im_conv_f:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 *
 * Convolve @in with @mask using floating-point arithmetic. The output image 
 * is always %IM_BANDFMT_FLOAT unless @in is %IM_BANDFMT_DOUBLE, in which case
 * @out is also %IM_BANDFMT_DOUBLE. 
 *
 * Each output pixel is
 * calculated as sigma[i]{pixel[i] * mask[i]} / scale + offset, where scale
 * and offset are part of @mask. 
 *
 * See also: im_conv(), im_convsep_f(), im_create_dmaskv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_conv_f( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	IMAGE *t1 = im_open_local( out, "im_conv_f intermediate", "p" );

	if( !t1 || 
		im_embed( in, t1, 1, mask->xsize / 2, mask->ysize / 2, 
			in->Xsize + mask->xsize - 1, 
			in->Ysize + mask->ysize - 1 ) ||
		im_conv_f_raw( t1, out, mask ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}

int
im_convsep_f_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	IMAGE *t;
	DOUBLEMASK *rmask;

	if( mask->xsize != 1 && mask->ysize != 1 ) {
                im_error( "im_convsep_f", 
			"%s", _( "expect 1xN or Nx1 input mask" ) );
                return( -1 );
	}

	if( !(t = im_open_local( out, "im_convsep_f", "p" )) ||
		!(rmask = (DOUBLEMASK *) im_local( out, 
		(im_construct_fn) im_dup_dmask,
		(im_callback_fn) im_free_dmask, mask, mask->filename, NULL )) )
		return( -1 );

	rmask->xsize = mask->ysize;
	rmask->ysize = mask->xsize;
        rmask->offset = 0.;

	if( im_conv_f_raw( in, t, rmask ) ||
		im_conv_f_raw( t, out, mask ) )
		return( -1 );

	return( 0 );
}

/**
 * im_convsep_f:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 *
 * Perform a separable convolution of @in with @mask using floating-point 
 * arithmetic. 
 *
 * The mask must be 1xn or nx1 elements. 
 * The output image 
 * is always %IM_BANDFMT_FLOAT unless @in is %IM_BANDFMT_DOUBLE, in which case
 * @out is also %IM_BANDFMT_DOUBLE. 
 *
 * The image is convolved twice: once with @mask and then again with @mask 
 * rotated by 90 degrees. This is much faster for certain types of mask
 * (gaussian blur, for example) than doing a full 2D convolution.
 *
 * Each output pixel is
 * calculated as sigma[i]{pixel[i] * mask[i]} / scale + offset, where scale
 * and offset are part of @mask. 
 *
 * See also: im_convsep(), im_conv(), im_create_dmaskv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_convsep_f( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	IMAGE *t1 = im_open_local( out, "im_convsep intermediate", "p" );
	int size = mask->xsize * mask->ysize;

	if( !t1 || 
		im_embed( in, t1, 1, size / 2, size / 2, 
			in->Xsize + size - 1, 
			in->Ysize + size - 1 ) ||
		im_convsep_f_raw( t1, out, mask ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
