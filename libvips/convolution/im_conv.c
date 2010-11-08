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
 * 1/10/10
 * 	- support complex (just double the bands)
 * 18/10/10
 * 	- add experimental Orc path
 * 29/10/10
 * 	- use VipsVector
 * 	- get rid of im_convsep(), just call this twice, no longer worth
 * 	  keeping two versions
 * 8/11/10
 * 	- add array tiling
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

/* Show sample pixels as they are transformed.
#define DEBUG_PIXELS
 */

/*
#define DEBUG
 */

/* 

 	TODO

	- will this change make much difference to the vips benchmark?

	- try a path with a 32-bit sum for larger matrices / scale / offset, 

	- make up a signed 8-bit code path?

	- try a 16-bit path

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/vector.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* We can't run more than this many passes. Larger than this and we
 * fall back to C.
 */
#define MAX_PASS (10)

/* A pass with a vector. 
 */
typedef struct {
	int first;		/* The index of the first mask coff we use */
	int last;		/* The index of the last mask coff we use */

        /* The code we generate for this section of this mask. 
	 */
        VipsVector *vector;
} Pass;

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

	/* The convolver we generate for this mask. We have to split the
	 * convolve and clip into two phases.
	 */
	int n_pass;	
	Pass pass[MAX_PASS];
	VipsVector *clip;
} Conv;

static void
conv_vector_free( Conv *conv )
{
	int i;

	for( i = 0; i < conv->n_pass; i++ )
		IM_FREEF( vips_vector_free, conv->pass[i].vector );
	conv->n_pass = 0;

	IM_FREEF( vips_vector_free, conv->clip );
}

static int
conv_close( Conv *conv )
{
	IM_FREEF( im_free_imask, conv->mask );
	conv_vector_free( conv );

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

#define TEMP( N, S ) vips_vector_temporary( v, N, S )
#define SCANLINE( N, P, S ) vips_vector_source_scanline( v, N, P, S )
#define CONST( N, V, S ) vips_vector_constant( v, N, V, S )
#define ASM2( OP, A, B ) vips_vector_asm2( v, OP, A, B )
#define ASM3( OP, A, B, C ) vips_vector_asm3( v, OP, A, B, C )

/* Generate code for a section of the mask.
 *
 * 0 for success, -1 on error.
 */
static int
conv_compile_convolution_u8s16_section( Pass *pass, Conv *conv )
{
	INTMASK *mask = conv->mask;
	const int n_mask = mask->xsize * mask->ysize; 

	int i;
	VipsVector *v;
	char zero[256];
	char offset[256];
	char source[256];
	char coeff[256];

	pass->vector = v = vips_vector_new( "conv", 2 );

	/* The value we fetch from the image, the product with the matrix
	 * value, the accumulated sum.
	 */
	TEMP( "value", 1 );
	TEMP( "product", 2 );
	TEMP( "sum", 2 );

	CONST( zero, 0, 2 );
	ASM2( "copyw", "sum", zero );

	for( i = pass->first; i < n_mask; i++ ) {
		int x = i % mask->xsize;
		int y = i / mask->xsize;

		if( !mask->coeff[i] )
			/* Exclude zero elements.
			 */
			continue;

		/* The source. sl0 is the first scanline in the mask.
		 */
		SCANLINE( source, y, 1 );

		/* The offset, only for non-first-columns though.
		 */
		if( x > 0 ) 
			CONST( offset, conv->in->Bands * x, 1 );

		/* The coefficient. Only for non-1 coeffs though, we skip the
		 * mul for them.
		 *
		 * We need to do 8-bit unsigned pixel * signed mask, so we
		 * have to cast the pixel up to 16-bit then do a mult against a
		 * 16-bit constant. We know the result will fit in the botom
		 * 16 bits.
		 */
		if( mask->coeff[i] != 1 ) 
			CONST( coeff, mask->coeff[i], 2 );

		/* Two factors: 
		 * - element is in the first column, ie. has a zero offset
		 * - mask coeff is 1, ie. we can skip the multiply
		 *
		 * We could combine some of these cases, but it's simpler
		 * and safer to spell them all out.
		 */
		if( x == 0 ) 
			ASM2( "loadb", "value", source );
		else 
			ASM3( "loadoffb", "value", source, offset );

		ASM2( "convubw", "product", "value" );

		if( mask->coeff[i] != 1 ) 
			ASM3( "mullw", "product", "product", coeff );

		ASM3( "addssw", "sum", "sum", "product" );

		if( vips_vector_full( v ) )
			break;
	}

	pass->last = i;

	ASM2( "copyw", "d1", "sum" );

	if( !vips_vector_compile( v ) ) 
		return( -1 );

#ifdef DEBUG
	vips_vector_print( v );
#endif /*DEBUG*/

	return( 0 );
}

/* Generate the convolution pass for u8 data with an s16 accumulator.
 *
 * 0 for success, -1 on error.
 */
static int
conv_compile_convolution_u8s16( Conv *conv )
{
	INTMASK *mask = conv->mask;
	const int n_mask = mask->xsize * mask->ysize; 

	double min, max;
	int i;

	if( conv->in->BandFmt != IM_BANDFMT_UCHAR )
		return( -1 );

	/* Can the accumulator overflow or underflow at any stage? Since
	 * matrix elements are signed, we need to calculate a running 
	 * possible min and max.
	 */
	min = 0;
	max = 0;
	for( i = 0; i < n_mask; i++ ) {
		int v = 255 * mask->coeff[i];

		if( min + v < min )
			min += v;
		else if( min + v > max )
			max += v;

		if( max > SHRT_MAX )
			return( -1 );
		if( min < SHRT_MIN )
			return( -1 );
	}

	/* Generate passes until we've used up the whole mask.
	 */
	for( i = 0;;) {
		Pass *pass;

		/* Skip any zero coefficients at the start of the mask 
		 * region.
		 */
		for( ; i < n_mask && !mask->coeff[i]; i++ )
			;
		if( i == n_mask )
			break;

		/* Allocate space for another pass.
		 */
		if( conv->n_pass == MAX_PASS ) 
			return( -1 );
		pass = &conv->pass[conv->n_pass];
		conv->n_pass += 1;

		pass->first = i;
		pass->last = i;

		if( conv_compile_convolution_u8s16_section( pass, conv ) )
			return( -1 );
		i = pass->last + 1;

#ifdef DEBUG
		printf( "conv_compile_convolution_u8s16: "
			"first = %d, last = %d\n", 
			pass->first, pass->last ); 
#endif /*DEBUG*/

		if( i >= n_mask )
			break;
	}

	return( 0 );
}

/* Generate the program that does (sum(passes) + rounding) / scale + offset 
 * from a s16 intermediate back to a u8 output.
 */
static int
conv_compile_scale_s16u8( Conv *conv )
{
	INTMASK *mask = conv->mask;

	int i;
	VipsVector *v;
	char scale[256];
	char offset[256];
	char zero[256];

	/* Scale and offset must be in range.
	 */
	if( mask->scale > 255 ||
		mask->scale < 0 ||
		mask->offset > SHRT_MAX ||
		mask->offset < SHRT_MIN ) 
		return( -1 );

	conv->clip = v = vips_vector_new( "clip", 1 );
	for( i = 0; i < conv->n_pass; i++ ) {
		char source[10];

		im_snprintf( source, 10, "s%d", i );
		vips_vector_source_name( v, source, 2 );
	}

	TEMP( "t1", 2 );
	TEMP( "t2", 2 );

	/* We can only do unsigned divide, so we must add the offset before
	 * dividing by the scale. We need to scale the offset up.
	 *
	 * We can build the rounding into the offset as well.
	 * You might think this should be (scale + 1) / 2, but then we'd be 
	 * adding one for scale == 1.
	 */
	CONST( scale, mask->scale, 1 );
	CONST( offset, mask->offset * mask->scale + mask->scale / 2, 2 );
	CONST( zero, 0, 2 );

	/* Sum the passes into t1.
	 */
	ASM2( "loadw", "t1", "s0" );
	for( i = 1; i < conv->n_pass; i++ ) {
		char source[10];

		im_snprintf( source, 10, "s%d", i );
		ASM3( "addssw", "t1", "t1", source );
	}

	/* Offset and scale. 
	 */
	ASM3( "addssw", "t1", "t1", offset );

	/* We need to convert the signed result of the
	 * offset to unsigned for the div, ie. we want to set anything <0 to 0.
	 */
	ASM3( "cmpgtsw", "t2", "t1", zero );
	ASM3( "andw", "t1", "t1", "t2" );

	ASM3( "divluw", "t1", "t1", scale );
	ASM2( "convuuswb", "d1", "t1" );

	if( vips_vector_full( v ) ||
		!vips_vector_compile( v ) ) 
		return( -1 );

#ifdef DEBUG
	vips_vector_print( v );
#endif /*DEBUG*/

	return( 0 );
}

static Conv *
conv_new( IMAGE *in, IMAGE *out, INTMASK *mask )
{
        Conv *conv = IM_NEW( out, Conv );
	const int n_mask = mask->xsize * mask->ysize;
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

	conv->n_pass = 0;
	conv->clip = NULL;

        if( im_add_close_callback( out, 
		(im_callback_fn) conv_close, conv, NULL ) ||
		im_add_close_callback( out, 
			(im_callback_fn) conv_evalstart, conv, NULL ) ||
		im_add_close_callback( out, 
			(im_callback_fn) conv_evalend, conv, NULL ) ||
        	!(conv->coeff = IM_ARRAY( out, n_mask, int )) ||
        	!(conv->coeff_pos = IM_ARRAY( out, n_mask, int )) ||
        	!(conv->mask = im_dup_imask( mask, "conv_mask" )) )
                return( NULL );

        /* Find non-zero mask elements.
         */
        for( i = 0; i < n_mask; i++ )
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

	/* Generate code for this mask / image, if possible.
	 */
	if( vips_vector_get_enabled() ) {
		if( conv_compile_convolution_u8s16( conv ) ||
			conv_compile_scale_s16u8( conv ) ) 
			conv_vector_free( conv );
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

	/* We need a set of intermediate buffers to keep the result of the 
	 * conv in before we clip it.
	 */
	void **sum;
} ConvSequence;

/* Free a sequence value.
 */
static int
conv_stop( void *vseq, void *a, void *b )
{
	ConvSequence *seq = (ConvSequence *) vseq;
	Conv *conv = (Conv *) b;

	int i;

	/* Add local under/over counts to global counts.
	 */
	conv->overflow += seq->overflow;
	conv->underflow += seq->underflow;

	IM_FREEF( im_region_free, seq->ir );

	for( i = 0; i < conv->n_pass; i++ )
		IM_FREE( seq->sum[i] );
	IM_FREE( seq->sum );

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
	int i;

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
	seq->sum = NULL;

	/* Attach region and arrays.
	 */
	seq->ir = im_region_create( in );
	seq->offsets = IM_ARRAY( out, conv->nnz, int );
	seq->pts = IM_ARRAY( out, conv->nnz, PEL * );
	if( !seq->ir || !seq->offsets || !seq->pts ) {
		conv_stop( seq, in, conv );
		return( NULL );
	}

	if( vips_vector_get_enabled() && conv->n_pass ) {
		if( !(seq->sum = IM_ARRAY( NULL, conv->n_pass, void * )) ) {
			conv_stop( seq, in, conv );
			return( NULL );
		}
		for( i = 0; i < conv->n_pass; i++ )
			seq->sum[i] = NULL;

		for( i = 0; i < conv->n_pass; i++ )
			if( !(seq->sum[i] = IM_ARRAY( NULL, 
				IM_IMAGE_N_ELEMENTS( in ), short )) ) {
				conv_stop( seq, in, conv );
				return( NULL );
			}
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
	int sz = IM_REGION_N_ELEMENTS( or ) * (im_iscomplex( in ) ? 2 : 1);

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
	int sz = IM_REGION_N_ELEMENTS( or ) * (im_iscomplex( in ) ? 2 : 1);
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
		case IM_BANDFMT_COMPLEX:  
			CONV3x3_FLOAT( float ); 
			break;

		case IM_BANDFMT_DOUBLE: 
		case IM_BANDFMT_DPCOMPLEX: 
			CONV3x3_FLOAT( double ); 
			break;

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

/* The VipsVector codepath.
 */
static int
convvec_gen( REGION *or, void *vseq, void *a, void *b )
{
	ConvSequence *seq = (ConvSequence *) vseq;
	IMAGE *in = (IMAGE *) a;
	Conv *conv = (Conv *) b;
	INTMASK *mask = conv->mask;
	REGION *ir = seq->ir;

	Rect *r = &or->valid;
	int sz = IM_REGION_N_ELEMENTS( or ) * (im_iscomplex( in ) ? 2 : 1);

	Rect s;
	int j, y;
	VipsExecutor convolve[MAX_PASS];
	VipsExecutor clip;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += mask->xsize - 1;
	s.height += mask->ysize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );

	for( j = 0; j < conv->n_pass; j++ ) 
		vips_executor_set_program( &convolve[j], 
			conv->pass[j].vector, sz );
	vips_executor_set_program( &clip, conv->clip, sz );

	/* Link the conv output to the intermediate buffer, and to the
	 * clipper's input.
	 */
	for( j = 0; j < conv->n_pass; j++ ) {
		vips_executor_set_destination( &convolve[j], seq->sum[j] );
		vips_executor_set_array( &clip, conv->clip->s[j], seq->sum[j] );
	}

	for( y = 0; y < r->height; y++ ) { 
#ifdef DEBUG_PIXELS
{
		int h, v;

		printf( "before convolve: %d, %d\n", r->left, r->top + y );
		for( v = 0; v < mask->ysize; v++ ) {
			for( h = 0; h < mask->xsize; h++ )
				printf( "%3d ", *((PEL *) IM_REGION_ADDR( ir, 
					r->left + h, r->top + y + v )) );
			printf( "\n" );
		}
}
#endif /*DEBUG_PIXELS*/

		for( j = 0; j < conv->n_pass; j++ ) {
			vips_executor_set_scanline( &convolve[j], 
				ir, r->left, r->top + y );
			vips_executor_run( &convolve[j] );
		}

#ifdef DEBUG_PIXELS
		printf( "before clip:\n" );
		for( j = 0; j < conv->n_pass; j++ ) 
			printf( "  %d) %3d\n", 
				j, ((signed short *) seq->sum[j])[0] );
#endif /*DEBUG_PIXELS*/

		vips_executor_set_destination( &clip, 
			IM_REGION_ADDR( or, r->left, r->top + y ) );
		vips_executor_run( &clip );

#ifdef DEBUG_PIXELS
		printf( "after clip: %d\n", 
			*((PEL *) IM_REGION_ADDR( or, r->left, r->top + y )) );
#endif /*DEBUG_PIXELS*/
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

	if( conv->n_pass ) {
		generate = convvec_gen;

#ifdef DEBUG
		printf( "im_conv_raw: using vector path\n" );
#endif /*DEBUG*/
	}
	else if( mask->xsize == 3 && mask->ysize == 3 )
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
 * always has the same #VipsBandFmt as the input image. 
 *
 * Each output pixel is
 * calculated as sigma[i]{pixel[i] * mask[i]} / scale + offset, where scale
 * and offset are part of @mask. For integer @in, the division by scale
 * includes round-to-nearest.
 *
 * Small convolutions on unsigned 8-bit images are performed using the 
 * processor's vector unit,
 * if possible. Disable this with --vips-novector or IM_NOVECTOR.
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

int
im_convsep_raw( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *t;
	INTMASK *rmask;

	if( mask->xsize != 1 && mask->ysize != 1 ) {
                im_error( "im_convsep", 
			"%s", _( "expect 1xN or Nx1 input mask" ) );
                return( -1 );
	}

	if( !(t = im_open_local( out, "im_convsep", "p" )) ||
		!(rmask = (INTMASK *) im_local( out, 
		(im_construct_fn) im_dup_imask,
		(im_callback_fn) im_free_imask, mask, mask->filename, NULL )) )
		return( -1 );

	rmask->xsize = mask->ysize;
	rmask->ysize = mask->xsize;

	if( im_conv_raw( in, t, mask ) ||
		im_conv_raw( t, out, rmask ) )
		return( -1 );

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
	int n_mask = mask->xsize * mask->ysize;

	if( !t1 || 
		im_embed( in, t1, 1, n_mask / 2, n_mask / 2, 
			in->Xsize + n_mask - 1, 
			in->Ysize + n_mask - 1 ) ||
		im_convsep_raw( t1, out, mask ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
