/* convi
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
 * 9/5/11
 * 	- argh typo in overflow estimation could cause errors
 * 15/10/11 Nicolas
 * 	- handle offset correctly in seperable convolutions
 * 26/1/16 Lovell Fuller
 * 	- remove Duff for a 25% speedup
 * 23/6/16
 * 	- rewritten as a class
 * 	- new fixed-point vector path, up to 2x faster
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
#define DEBUG_PIXELS
#define DEBUG_COMPILE
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <vips/vips.h>

#include "pconvolution.h"

/* We do the 8-bit vector path with fixed-point arithmetic. We use 2.6 bits
 * for the mask coefficients, so our range is -2 to +1.99, after using scale
 * on the mask.
 */
#define FIXED_BITS (6)
#define FIXED_SCALE (1 << FIXED_BITS)

/* Larger than this and we fall back to C.
 */
#define MAX_PASS (20)

/* A pass with a vector. 
 */
typedef struct {
	int first;		/* The index of the first mask coff we use */
	int last;		/* The index of the last mask coff we use */

	int r;			/* Set previous result in this var */

        /* The code we generate for this section of the mask. 
	 */
        VipsVector *vector;
} Pass;

typedef struct {
	VipsConvolution parent_instance;

	/* An int version of M.
	 */
	VipsImage *iM;

	/* We make a smaller version of the mask with the zeros squeezed out.
	 */
	int nnz;		/* Number of non-zero mask elements */
	int *coeff;		/* Array of non-zero mask coefficients */
	int *coeff_pos;		/* Index of each nnz element in mask->coeff */

	/* And a fixed-point version for a vector path.
	 */
	int *fixed;
	int n_point;		/* Number of points in fixed-point array */

	/* The set of passes we need for this mask.
	 */
	int n_pass;	
	Pass pass[MAX_PASS];

	/* Code for the final clip back to 8 bits.
	 */
	int r;			
        VipsVector *vector;
} VipsConvi;

typedef VipsConvolutionClass VipsConviClass;

G_DEFINE_TYPE( VipsConvi, vips_convi, VIPS_TYPE_CONVOLUTION );

/* Our sequence value.
 */
typedef struct {
	VipsConvi *convi;
	VipsRegion *ir;		/* Input region */

	int *offsets;		/* Offsets for each non-zero matrix element */
	VipsPel **pts;		/* Per-non-zero mask element image pointers */

	int last_bpl;		/* Avoid recalcing offsets, if we can */

	/* We need a pair of intermediate buffers to keep the results of each
	 * vector conv pass. 
	 */
	short *t1;
	short *t2;
} VipsConviSequence;

/* Free a sequence value.
 */
static int
vips_convi_stop( void *vseq, void *a, void *b )
{
	VipsConviSequence *seq = (VipsConviSequence *) vseq;

	VIPS_UNREF( seq->ir );
	VIPS_FREE( seq->offsets );
	VIPS_FREE( seq->pts );
	VIPS_FREE( seq->t1 );
	VIPS_FREE( seq->t2 );

	return( 0 );
}

/* Convolution start function.
 */
static void *
vips_convi_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsConvi *convi = (VipsConvi *) b;
	VipsConviSequence *seq;

	if( !(seq = VIPS_NEW( out, VipsConviSequence )) )
		return( NULL );

	seq->convi = convi;
	seq->ir = NULL;
	seq->offsets = NULL;
	seq->pts = NULL;
	seq->last_bpl = -1;
	seq->t1 = NULL;
	seq->t2 = NULL;

	seq->ir = vips_region_new( in );

	/* C mode.
	 */
	if( convi->nnz ) {
		seq->offsets = VIPS_ARRAY( NULL, convi->nnz, int );
		seq->pts = VIPS_ARRAY( NULL, convi->nnz, VipsPel * );

		if( !seq->offsets ||
			!seq->pts ) { 
			vips_convi_stop( seq, in, convi );
			return( NULL );
		}
	}

	/* Vector mode.
	 */
	if( convi->n_pass ) {
		seq->t1 = VIPS_ARRAY( NULL, VIPS_IMAGE_N_ELEMENTS( in ), short );
		seq->t2 = VIPS_ARRAY( NULL, VIPS_IMAGE_N_ELEMENTS( in ), short );

		if( !seq->t1 || 
			!seq->t2 ) {
			vips_convi_stop( seq, in, convi );
			return( NULL );
		}
	}

	return( (void *) seq );
}

static void
vips_convi_compile_free( VipsConvi *convi )
{
	int i;

	for( i = 0; i < convi->n_pass; i++ )
		VIPS_FREEF( vips_vector_free, convi->pass[i].vector );
	convi->n_pass = 0;
	VIPS_FREEF( vips_vector_free, convi->vector );
}

#define TEMP( N, S ) vips_vector_temporary( v, (char *) N, S )
#define PARAM( N, S ) vips_vector_parameter( v, (char *) N, S )
#define SCANLINE( N, P, S ) vips_vector_source_scanline( v, (char *) N, P, S )
#define CONST( N, V, S ) vips_vector_constant( v, (char *) N, V, S )
#define ASM2( OP, A, B ) vips_vector_asm2( v, (char *) OP, A, B )
#define ASM3( OP, A, B, C ) vips_vector_asm3( v, (char *) OP, A, B, C )

/* Generate code for a section of the mask. first is the index we start
 * at, we set last to the index of the last one we use before we run 
 * out of intermediates / constants / parameters / sources or mask
 * coefficients.
 *
 * 0 for success, -1 on error.
 */
static int
vips_convi_compile_section( VipsConvi *convi, VipsImage *in, Pass *pass )
{
	VipsConvolution *convolution = (VipsConvolution *) convi;
	VipsImage *M = convolution->M;

	VipsVector *v;
	int i;

#ifdef DEBUG_COMPILE
	printf( "starting pass %d\n", pass->first ); 
#endif /*DEBUG_COMPILE*/

	pass->vector = v = vips_vector_new( "convi", 2 );

	/* "r" is the array of sums from the previous pass (if any).
	 */
	pass->r = vips_vector_source_name( v, "r", 2 );

	/* The value we fetch from the image, the accumulated sum.
	 */
	TEMP( "value", 2 );
	TEMP( "valueb", 1 );
	TEMP( "sum", 2 );

	/* Init the sum. If this is the first pass, it's a constant. If this
	 * is a later pass, we have to init the sum from the result 
	 * of the previous pass. 
	 */
	if( pass->first == 0 ) {
		char c0[256];

		CONST( c0, 0, 2 );
		ASM2( "loadpw", "sum", c0 );
	}
	else 
		ASM2( "loadw", "sum", "r" );

	for( i = pass->first; i < convi->n_point; i++ ) {
		int x = i % M->Xsize;
		int y = i / M->Xsize;

		char source[256];
		char off[256];
		char coeff[256];

		/* Exclude zero elements.
		 */
		if( !convi->fixed[i] )
			continue;

		/* The source. sl0 is the first scanline in the mask.
		 */
		SCANLINE( source, y, 1 );

		/* Load with an offset. Only for non-first-columns though.
		 */
		if( x == 0 ) 
			ASM2( "convubw", "value", source );
		else {
			CONST( off, in->Bands * x, 1 );
			ASM3( "loadoffb", "valueb", source, off );
			ASM2( "convubw", "value", "valueb" );
		}

		/* Mask coefficients are 2.6 bits fixed point, so -2 to +1.99.
		 *
		 * We need a signed multiply, so the image pixel needs to
		 * become a signed 16-bit value. We know only the bottom 8 bits
		 * of the image and coefficient are interesting, so we can take
		 * the bottom half of a 16x16->32 multiply. 
		 */
		CONST( coeff, convi->fixed[i], 2 );
		ASM3( "mullw", "value", "value", coeff );

		/* We accumulate the signed 16-bit result in sum. Saturated
		 * add. 
		 */
		ASM3( "addssw", "sum", "sum", "value" );

		if( vips_vector_full( v ) )
			break;
	}

	pass->last = i;

	/* And write to our intermediate buffer.
	 */
	ASM2( "copyw", "d1", "sum" );

	if( !vips_vector_compile( v ) ) 
		return( -1 );

#ifdef DEBUG_COMPILE
	printf( "done coeffs %d to %d\n", pass->first, pass->last );
	vips_vector_print( v );
#endif /*DEBUG_COMPILE*/

	return( 0 );
}

/* Generate code for the final 16->8 conversion. 
 *
 * 0 for success, -1 on error.
 */
static int
vips_convi_compile_clip( VipsConvi *convi )
{
	VipsConvolution *convolution = (VipsConvolution *) convi;
	VipsImage *M = convolution->M;
	int offset = VIPS_RINT( vips_image_get_offset( M ) );

	VipsVector *v;
	char c32[256];
	char c6[256];
	char c0[256];
	char c255[256];
	char off[256];

	convi->vector = v = vips_vector_new( "convi", 1 );

	/* "r" is the array of sums we clip down. 
	 */
	convi->r = vips_vector_source_name( v, "r", 2 );

	/* The value we fetch from the image.
	 */
	TEMP( "value", 2 );

	CONST( c32, 32, 2 );
	ASM3( "addw", "value", "r", c32 );
	CONST( c6, 6, 2 );
	ASM3( "shrsw", "value", "value", c6 );

	CONST( off, offset, 2 ); 
	ASM3( "addw", "value", "value", off );

	/* You'd think "convsuswb" (convert signed 16-bit to unsigned
	 * 8-bit with saturation) would be quicker, but it's a lot
	 * slower.
	 */
	CONST( c0, 0, 2 );
	ASM3( "maxsw", "value", c0, "value" ); 
	CONST( c255, 255, 2 );
	ASM3( "minsw", "value", c255, "value" ); 

	ASM2( "convwb", "d1", "value" );

	if( !vips_vector_compile( v ) ) 
		return( -1 );

	return( 0 );
}

static int
vips_convi_compile( VipsConvi *convi, VipsImage *in )
{
	int i;
	Pass *pass;

	/* Generate passes until we've used up the whole mask.
	 */
	for( i = 0;; ) {
		/* Allocate space for another pass.
		 */
		if( convi->n_pass == MAX_PASS ) 
			return( -1 );
		pass = &convi->pass[convi->n_pass];
		convi->n_pass += 1;

		pass->first = i;
		pass->r = -1;

		if( vips_convi_compile_section( convi, in, pass ) )
			return( -1 );
		i = pass->last + 1;

		if( i >= convi->n_point )
			break;
	}

	if( vips_convi_compile_clip( convi ) )
		return( -1 );

	return( 0 );
}

static int
vips_convi_generate_vector( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsConviSequence *seq = (VipsConviSequence *) vseq;
	VipsConvi *convi = (VipsConvi *) b;
	VipsConvolution *convolution = (VipsConvolution *) convi;
	VipsImage *M = convolution->M;
	VipsImage *in = (VipsImage *) a;
	VipsRegion *ir = seq->ir;
	VipsRect *r = &or->valid;
	int ne = r->width * in->Bands;

	VipsRect s;
	int i, y;
	VipsExecutor executor[MAX_PASS];
	VipsExecutor clip;

#ifdef DEBUG_PIXELS
	printf( "vips_convi_generate_vector: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG_PIXELS*/

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += M->Xsize - 1;
	s.height += M->Ysize - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	for( i = 0; i < convi->n_pass; i++ ) 
		vips_executor_set_program( &executor[i], 
			convi->pass[i].vector, ne );
	vips_executor_set_program( &clip, convi->vector, ne );

	VIPS_GATE_START( "vips_convi_generate_vector: work" ); 

	for( y = 0; y < r->height; y ++ ) { 
		VipsPel *q = VIPS_REGION_ADDR( or, r->left, r->top + y );
	
#ifdef DEBUG_PIXELS
{
		int h, v;

		printf( "before convolve: x = %d, y = %d\n", 
			r->left, r->top + y );
		for( v = 0; v < M->Ysize; v++ ) {
			for( h = 0; h < M->Xsize; h++ )
				printf( "%3d ", *VIPS_REGION_ADDR( ir, 
					r->left + h, r->top + y + v ) );
			printf( "\n" );
		}
}
#endif /*DEBUG_PIXELS*/

		/* We run our n passes to generate this scanline.
		 */
		for( i = 0; i < convi->n_pass; i++ ) {
			Pass *pass = &convi->pass[i]; 

			vips_executor_set_scanline( &executor[i], 
				ir, r->left, r->top + y );
			vips_executor_set_array( &executor[i],
				pass->r, seq->t1 );
			vips_executor_set_destination( &executor[i], seq->t2 );
			vips_executor_run( &executor[i] );

			VIPS_SWAP( signed short *, seq->t1, seq->t2 );
		}

#ifdef DEBUG_PIXELS
		printf( "before clip: %d\n", ((signed short *) seq->t1)[0] );
#endif /*DEBUG_PIXELS*/

		vips_executor_set_array( &clip, convi->r, seq->t1 );
		vips_executor_set_destination( &clip, q ); 
		vips_executor_run( &clip );

#ifdef DEBUG_PIXELS
		printf( "after clip: %d\n", 
			*VIPS_REGION_ADDR( or, r->left, r->top + y ) );
#endif /*DEBUG_PIXELS*/
	}

	VIPS_GATE_STOP( "vips_convi_generate_vector: work" ); 

	VIPS_COUNT_PIXELS( or, "vips_convi_generate_vector" ); 

	return( 0 );
}

/* INT inner loops.
 */
#define CONV_INT( TYPE, CLIP ) { \
	TYPE ** restrict p = (TYPE **) seq->pts; \
	TYPE * restrict q = (TYPE *) VIPS_REGION_ADDR( or, le, y ); \
	\
	for( x = 0; x < sz; x++ ) {  \
		int sum; \
		int i; \
		\
		sum = 0; \
		for ( i = 0; i < nnz; i++ ) \
			sum += t[i] * p[i][x]; \
		\
		sum = ((sum + rounding) / scale) + offset; \
		\
		CLIP; \
		\
		q[x] = sum;  \
	}  \
} 

/* FLOAT inner loops.
 */
#define CONV_FLOAT( TYPE ) { \
	TYPE ** restrict p = (TYPE **) seq->pts; \
	TYPE * restrict q = (TYPE *) VIPS_REGION_ADDR( or, le, y ); \
	\
	for( x = 0; x < sz; x++ ) {  \
		double sum; \
		int i; \
		\
		sum = 0; \
		for ( i = 0; i < nnz; i++ ) \
			sum += t[i] * p[i][x]; \
 		\
		sum = (sum / scale) + offset; \
		\
		q[x] = sum;  \
	}  \
} 

/* Various integer range clips. Record over/under flows.
 */
#define CLIP_UCHAR( V ) \
G_STMT_START { \
	if( (V) < 0 ) \
		(V) = 0; \
	else if( (V) > UCHAR_MAX ) \
		(V) = UCHAR_MAX; \
} G_STMT_END

#define CLIP_CHAR( V ) \
G_STMT_START { \
	if( (V) < SCHAR_MIN ) \
		(V) = SCHAR_MIN; \
	else if( (V) > SCHAR_MAX ) \
		(V) = SCHAR_MAX; \
} G_STMT_END

#define CLIP_USHORT( V ) \
G_STMT_START { \
	if( (V) < 0 ) \
		(V) = 0; \
	else if( (V) > USHRT_MAX ) \
		(V) = USHRT_MAX; \
} G_STMT_END

#define CLIP_SHORT( V ) \
G_STMT_START { \
	if( (V) < SHRT_MIN ) \
		(V) = SHRT_MIN; \
	else if( (V) > SHRT_MAX ) \
		(V) = SHRT_MAX; \
} G_STMT_END

#define CLIP_NONE( V ) {}

/* Convolve!
 */
static int
vips_convi_generate( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsConviSequence *seq = (VipsConviSequence *) vseq;
	VipsConvi *convi = (VipsConvi *) b;
	VipsConvolution *convolution = (VipsConvolution *) convi;
	VipsImage *M = convolution->M;
	int scale = VIPS_RINT( vips_image_get_scale( M ) ); 
	int rounding = scale / 2;
	int offset = VIPS_RINT( vips_image_get_offset( M ) ); 
	VipsImage *in = (VipsImage *) a;
	VipsRegion *ir = seq->ir;
	int * restrict t = convi->coeff; 
	const int nnz = convi->nnz;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );
	int sz = VIPS_REGION_N_ELEMENTS( or ) * 
		(vips_band_format_iscomplex( in->BandFmt ) ? 2 : 1);

	VipsRect s;
	int x, y, z, i;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += M->Xsize - 1;
	s.height += M->Ysize - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

        /* Fill offset array. Only do this if the bpl has changed since the 
	 * previous vips_region_prepare().
	 */
	if( seq->last_bpl != VIPS_REGION_LSKIP( ir ) ) {
		seq->last_bpl = VIPS_REGION_LSKIP( ir );

		for( i = 0; i < nnz; i++ ) {
			z = convi->coeff_pos[i];
			x = z % M->Xsize;
			y = z / M->Xsize;

			seq->offsets[i] = 
				VIPS_REGION_ADDR( ir, x + le, y + to ) -
				VIPS_REGION_ADDR( ir, le, to );
		}
	}

	for( y = to; y < bo; y++ ) { 
		/* Init pts for this line of PELs.
		 */
		for( z = 0; z < nnz; z++ )
			seq->pts[z] = seq->offsets[z] +
				VIPS_REGION_ADDR( ir, le, y ); 

		switch( in->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			CONV_INT( unsigned char, CLIP_UCHAR( sum ) ); 
			break;

		case VIPS_FORMAT_CHAR:   
			CONV_INT( signed char, CLIP_CHAR( sum ) ); 
			break;

		case VIPS_FORMAT_USHORT: 
			CONV_INT( unsigned short, CLIP_USHORT( sum ) ); 
			break;

		case VIPS_FORMAT_SHORT:  
			CONV_INT( signed short, CLIP_SHORT( sum ) ); 
			break;

		case VIPS_FORMAT_UINT:   
			CONV_INT( unsigned int, CLIP_NONE( sum ) ); 
			break;

		case VIPS_FORMAT_INT:    
			CONV_INT( signed int, CLIP_NONE( sum ) ); 
			break;

		case VIPS_FORMAT_FLOAT:  
		case VIPS_FORMAT_COMPLEX:  
			CONV_FLOAT( float ); 
			break;

		case VIPS_FORMAT_DOUBLE: 
		case VIPS_FORMAT_DPCOMPLEX:  
			CONV_FLOAT( double ); 
			break;

		default:
			g_assert_not_reached();
		}
	}

	return( 0 );
}

/* Make an int version of a mask.
 *
 * We rint() everything, then adjust the scale try to match the overall
 * effect.
 */
static int
intize( VipsImage *in, VipsImage **out )
{
	VipsImage *t;
	int x, y;
	double double_result;
	double out_scale;
	double out_offset;
	int int_result;

	if( vips_check_matrix( "vips2imask", in, &t ) )
		return( -1 ); 
	if( !(*out = vips_image_new_matrix( t->Xsize, t->Ysize )) ) {
		g_object_unref( t ); 
		return( -1 ); 
	}

	/* We want to make an intmask which has the same input to output ratio
	 * as the double image.
	 *
	 * Imagine convolving with the double image, what's the ratio of
	 * brightness between input and output? We want the same ratio for the
	 * int version, if we can.
	 *
	 * Imagine an input image where every pixel is 1, what will the output
	 * be?
	 */
	double_result = 0;
	for( y = 0; y < t->Ysize; y++ )
		for( x = 0; x < t->Xsize; x++ )
			double_result += *VIPS_MATRIX( t, x, y ); 
	double_result /= vips_image_get_scale( t );

	for( y = 0; y < t->Ysize; y++ )
		for( x = 0; x < t->Xsize; x++ )
			*VIPS_MATRIX( *out, x, y ) = 
				VIPS_RINT( *VIPS_MATRIX( t, x, y ) );

	out_scale = VIPS_RINT( vips_image_get_scale( t ) );
	if( out_scale == 0 )
		out_scale = 1;
	out_offset = VIPS_RINT( vips_image_get_offset( t ) );

	/* Now convolve a 1 everywhere image with the int version we've made,
	 * what do we get?
	 */
	int_result = 0;
	for( y = 0; y < t->Ysize; y++ )
		for( x = 0; x < t->Xsize; x++ )
			int_result += *VIPS_MATRIX( *out, x, y ); 
	int_result /= out_scale;

	/* And adjust the scale to get as close to a match as we can. 
	 */
	out_scale = VIPS_RINT( out_scale + (int_result - double_result) );
	if( out_scale == 0 ) 
		out_scale = 1;

	vips_image_set_double( *out, "scale", out_scale );
	vips_image_set_double( *out, "offset", out_offset );

	g_object_unref( t ); 

	return( 0 );
}

/* Make an int version of a mask.
 *
 * This makes a fixed-point version ready for the vector path: instead of an 
 * output scale, we have x.y for each element.
 *
 * @out is a w x h int array.
 */
static int
intize_to_fixed_point( VipsImage *in, int *out )
{
	VipsImage *t;
	double scale;
	int ne;
	double *scaled;
	int i;

	if( vips_check_matrix( "vips2imask", in, &t ) )
		return( -1 ); 

	/* Bake the scale into the mask.
	 */
	scale = vips_image_get_scale( t );
	ne = t->Xsize * t->Ysize; 
        if( !(scaled = VIPS_ARRAY( in, ne, double )) ) {
		g_object_unref( t ); 
		return( -1 );
	}
	for( i = 0; i < ne; i++ ) 
		scaled[i] = VIPS_MATRIX( t, 0, 0 )[i] / scale;
	g_object_unref( t ); 

	/* The scaled mask must fit in 2.6 bits, so we can handle -2 to +1.99
	 */
	for( i = 0; i < ne; i++ ) 
		if( scaled[i] >= 2.0 ||
			scaled[i] < -2 ) {
#ifdef DEBUG_COMPILE
			printf( "intize_to_fixed_point: out of range\n" );
#endif /*DEBUG_COMPILE*/

			return( -1 ); 
		}

	/* The smallest coefficient we can manage is 1/64th, we'll just turn
	 * that into zero.
	 */
	for( i = 0; i < ne; i++ ) 
		if( scaled[i] != 0.0 &&
			VIPS_FABS( scaled[i] ) < 1.0 / FIXED_SCALE ) {
#ifdef DEBUG_COMPILE
			printf( "intize_to_fixed_point: underflow\n" );
#endif /*DEBUG_COMPILE*/

			return( -1 ); 
		}

	vips_vector_to_fixed_point( scaled, out, ne, FIXED_SCALE );

#ifdef DEBUG_COMPILE
{
	int x, y;

	printf( "intize_to_fixed_point:\n" ); 
	for( y = 0; y < t->Ysize; y++ ) {
		printf( "\t" ); 
		for( x = 0; x < t->Xsize; x++ ) 
			printf( "%4d ", out[y * t->Xsize + x] ); 
		printf( "\n" ); 
	}
}
#endif /*DEBUG_COMPILE*/

	return( 0 );
}

static int
vips_convi_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConvolution *convolution = (VipsConvolution *) object;
	VipsConvi *convi = (VipsConvi *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	VipsImage *in;
	VipsImage *M;
	int n_point;
	VipsGenerateFn generate;
	double *coeff;
        int i;

	if( VIPS_OBJECT_CLASS( vips_convi_parent_class )->build( object ) )
		return( -1 );

	in = convolution->in;
	M = convolution->M;
	convi->n_point = n_point = M->Xsize * M->Ysize;

	if( vips_embed( in, &t[0], 
		M->Xsize / 2, M->Ysize / 2, 
		in->Xsize + M->Xsize - 1, in->Ysize + M->Ysize - 1,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[0]; 

	/* For uchar input, try to make a vector path.
	 */
	if( vips_vector_isenabled() &&
		in->BandFmt == VIPS_FORMAT_UCHAR ) {
		if( (convi->fixed = VIPS_ARRAY( object, n_point, int )) &&
			!intize_to_fixed_point( M, convi->fixed ) &&
			!vips_convi_compile( convi, in ) ) {
			generate = vips_convi_generate_vector;
			vips_info( class->nickname, "using vector path" ); 
		}
		else
			vips_convi_compile_free( convi );
	}

	/* If there's no vector path, fall back to C.
	 */
	if( !convi->n_pass ) {
		/* Make an int version of our mask.
		 */
		if( intize( M, &t[1] ) )
			return( -1 ); 
		convi->iM = M = t[1];

		coeff = VIPS_MATRIX( M, 0, 0 ); 
		if( !(convi->coeff = VIPS_ARRAY( object, n_point, int )) ||
			!(convi->coeff_pos = VIPS_ARRAY( object, n_point, int )) )
			return( -1 );

		/* Squeeze out zero mask elements. 
		 */
		for( i = 0; i < n_point; i++ )
			if( coeff[i] ) {
				convi->coeff[convi->nnz] = coeff[i];
				convi->coeff_pos[convi->nnz] = i;
				convi->nnz += 1;
			}

		/* Was the whole mask zero? We must have at least 1 element 
		 * in there: set it to zero.
		 */
		if( convi->nnz == 0 ) {
			convi->coeff[0] = 0;
			convi->coeff_pos[0] = 0;
			convi->nnz = 1;
		}

		generate = vips_convi_generate;
		vips_info( class->nickname, "using C path" ); 
	}

	g_object_set( convi, "out", vips_image_new(), NULL ); 
	if( vips_image_pipelinev( convolution->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, in, NULL ) )
		return( -1 );

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	convolution->out->Xsize -= M->Xsize - 1;
	convolution->out->Ysize -= M->Ysize - 1;

	if( vips_image_generate( convolution->out, 
		vips_convi_start, generate, vips_convi_stop, in, convi ) )
		return( -1 );

	convolution->out->Xoffset = -M->Xsize / 2;
	convolution->out->Yoffset = -M->Ysize / 2;

	return( 0 );
}

static void
vips_convi_class_init( VipsConviClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "convi";
	object_class->description = _( "int convolution operation" );
	object_class->build = vips_convi_build;
}

static void
vips_convi_init( VipsConvi *convi )
{
        convi->nnz = 0;
        convi->coeff = NULL;
        convi->coeff_pos = NULL;
}

/**
 * vips_convi:
 * @in: input image
 * @out: output image
 * @mask: convolve with this mask
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convolution. This is a low-level operation, see vips_conv() for something
 * more convenient. 
 *
 * Perform a convolution of @in with @mask.
 * Each output pixel is
 * calculated as rint(sigma[i]{pixel[i] * mask[i]} / scale) + offset, where 
 * scale and offset are part of @mask. 
 *
 * The convolution is performed with integer arithmetic. The output image 
 * always has the same #VipsBandFormat as the input image. 
 *
 * See also: vips_conv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_convi( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
{
	va_list ap;
	int result;

	va_start( ap, mask );
	result = vips_call_split( "convi", ap, in, out, mask );
	va_end( ap );

	return( result );
}

