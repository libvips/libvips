/* horizontal reduce by a float factor with a kernel
 *
 * 29/1/16
 * 	- from shrinkh.c
 * 10/3/16
 * 	- add other kernels
 * 15/8/16
 * 	- rename xshrink as hshrink for consistency
 * 9/9/16
 * 	- add @centre option
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
#define DEBUG_COMPILE
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>
#include <vips/vector.h>

#include "presample.h"
#include "templates.h"

/* We can't run more than this many passes. Larger than this and we
 * fall back to C.
 */
#define MAX_PASS (10)

/* The number of params we pass for coeffs. Orc limits this rather. 
 */
#define MAX_PARAM (8)

/* A pass with a vector. 
 */
typedef struct {
	int first;		/* The index of the first mask coff we use */
	int last;		/* The index of the last mask coff we use */

	int r;			/* Set previous result in this var */
	int d2;			/* Write new temp result here */

	int p[MAX_PARAM];	/* Mask coeffs passed in these */
	int n_param;

        /* The code we generate for this section of this mask. 
	 */
        VipsVector *vector;
} Pass;

typedef struct _VipsReduceh {
	VipsResample parent_instance;

	double hshrink;		/* Reduce factor */

	/* The thing we use to make the kernel.
	 */
	VipsKernel kernel;

	/* Use centre rather than corner sampling convention.
	 */
	gboolean centre;

	/* Number of points in kernel.
	 */
	int n_point;

	/* Precalculated interpolation matrices. int (used for pel
	 * sizes up to short), and double (for all others). We go to
	 * scale + 1 so we can round-to-nearest safely.
	 */
	int *matrixi[VIPS_TRANSFORM_SCALE + 1];
	double *matrixf[VIPS_TRANSFORM_SCALE + 1];

	/* And another set for orc: we want 2.6 precision.
	 */
	int *matrixo[VIPS_TRANSFORM_SCALE + 1];

	/* The passes we generate for this mask.
	 */
	int n_pass;	
	Pass pass[MAX_PASS];

} VipsReduceh;

typedef VipsResampleClass VipsReducehClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsReduceh, vips_reduceh, VIPS_TYPE_RESAMPLE );
}

static void
vips_reduceh_finalize( GObject *gobject )
{
	VipsReduceh *reduceh = (VipsReduceh *) gobject; 

	for( int i = 0; i < reduceh->n_pass; i++ )
		VIPS_FREEF( vips_vector_free, reduceh->pass[i].vector );
	reduceh->n_pass = 0;
	for( int i = 0; i < VIPS_TRANSFORM_SCALE + 1; i++ ) {
		VIPS_FREE( reduceh->matrixf[i] );
		VIPS_FREE( reduceh->matrixi[i] );
		VIPS_FREE( reduceh->matrixo[i] );
	}

	G_OBJECT_CLASS( vips_reduceh_parent_class )->finalize( gobject );
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
vips_reduceh_compile_section( VipsReduceh *reduceh, 
	VipsImage *in, Pass *pass, gboolean first )
{
	VipsVector *v;
	char source[256];
	int i;

#ifdef DEBUG_COMPILE
	printf( "starting pass %d\n", pass->first ); 
#endif /*DEBUG_COMPILE*/

	pass->vector = v = vips_vector_new( "reduceh", 1 );

	/* We have two destinations: the final output image (8-bit) and the
	 * intermediate buffer if this is not the final pass (16-bit).
	 */
	pass->d2 = vips_vector_destination( v, "d2", 2 );

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
	if( first ) {
		char c0[256];

		CONST( c0, 0, 2 );
		ASM2( "loadpw", "sum", c0 );
	}
	else 
		ASM2( "loadw", "sum", "r" );

	SCANLINE( source, 0, 1 );

	for( i = pass->first; i < reduceh->n_point; i++ ) {
		char coeff[256];
		char off[256];

		/* Load with an offset. Only for non-first-columns though.
		 */
		if( i == 0 ) 
			ASM2( "convubw", "value", source );
		else {
			CONST( off, in->Bands * i, 1 );
			ASM3( "loadoffb", "valueb", source, off );
			ASM2( "convubw", "value", "valueb" );
		}

		/* This mask coefficient.
		 */
		vips_snprintf( coeff, 256, "p%d", i );
		pass->p[pass->n_param] = PARAM( coeff, 2 );
		pass->n_param += 1;
		if( pass->n_param >= MAX_PARAM )
			return( -1 );

		/* Mask coefficients are 2.6 bits fixed point. We need to hold
		 * about -0.5 to 1.0, so -2 to +1.999 is as close as we can
		 * get. 
		 *
		 * We need a signed multiply, so the image pixel needs to
		 * become a signed 16-bit value. We know only the bottom 8 bits
		 * of the image and coefficient are interesting, so we can take
		 * the bottom bits of a 16x16->32 multiply. 
		 *
		 * We accumulate the signed 16-bit result in sum.
		 */
		ASM3( "mullw", "value", "value", coeff );
		ASM3( "addssw", "sum", "sum", "value" );

		/* We've used this coeff.
		 */
		pass->last = i;

		if( vips_vector_full( v ) )
			break;

		/* orc 0.4.24 and earlier hate more than about five lines at
		 * once :( 
		 */
		if( i - pass->first > 3 )
			break;
	}

	/* If this is the end of the mask, we write the 8-bit result to the
	 * image, otherwise write the 16-bit intermediate to our temp buffer. 
	 */
	if( pass->last >= reduceh->n_point - 1 ) {
		char c32[256];
		char c6[256];
		char c0[256];
		char c255[256];

		CONST( c32, 32, 2 );
		ASM3( "addw", "sum", "sum", c32 );
		CONST( c6, 6, 2 );
		ASM3( "shrsw", "sum", "sum", c6 );

		/* You'd think "convsuswb", convert signed 16-bit to unsigned
		 * 8-bit with saturation, would be quicker, but it's a lot
		 * slower.
		 */
		CONST( c0, 0, 2 );
		ASM3( "maxsw", "sum", c0, "sum" ); 
		CONST( c255, 255, 2 );
		ASM3( "minsw", "sum", c255, "sum" ); 

		ASM2( "convwb", "d1", "sum" );
	}
	else 
		ASM2( "copyw", "d2", "sum" );

	if( !vips_vector_compile( v ) ) 
		return( -1 );

#ifdef DEBUG_COMPILE
	printf( "done coeffs %d to %d\n", pass->first, pass->last );
	vips_vector_print( v );
#endif /*DEBUG_COMPILE*/

	return( 0 );
}

static int
vips_reduceh_compile( VipsReduceh *reduceh, VipsImage *in )
{
	Pass *pass;

	/* Generate passes until we've used up the whole mask.
	 */
	for( int i = 0;; ) {
		/* Allocate space for another pass.
		 */
		if( reduceh->n_pass == MAX_PASS ) 
			return( -1 );
		pass = &reduceh->pass[reduceh->n_pass];
		reduceh->n_pass += 1;

		pass->first = i;
		pass->r = -1;
		pass->d2 = -1;
		pass->n_param = 0;

		if( vips_reduceh_compile_section( reduceh, in, 
			pass, reduceh->n_pass == 1 ) )
			return( -1 );
		i = pass->last + 1;

		if( i >= reduceh->n_point )
			break;
	}

	return( 0 );
}

/* Get n points. @shrink is the shrink factor, so 2 for a 50% reduction. 
 */
int
vips_reduce_get_points( VipsKernel kernel, double shrink ) 
{
	switch( kernel ) {
	case VIPS_KERNEL_NEAREST:
		return( 1 ); 

	case VIPS_KERNEL_LINEAR:
		return( rint( 2 * shrink ) + 1 ); 

	case VIPS_KERNEL_CUBIC:
		return( rint( 4 * shrink ) + 1 ); 

	case VIPS_KERNEL_LANCZOS2:
		/* Needs to be in sync with calculate_coefficients_lanczos().
		 */
		return( rint( 2 * 2 * shrink ) + 1 ); 

	case VIPS_KERNEL_LANCZOS3:
		return( rint( 2 * 3 * shrink ) + 1 ); 

	default:
		g_assert_not_reached();
		return( 0 ); 
	}
}

/* Calculate a mask element. 
 */
void
vips_reduce_make_mask( double *c, VipsKernel kernel, double shrink, double x )
{
	switch( kernel ) {
	case VIPS_KERNEL_NEAREST:
		c[0] = 1.0;
		break;

	case VIPS_KERNEL_LINEAR:
		calculate_coefficients_triangle( c, shrink, x ); 
		break;

	case VIPS_KERNEL_CUBIC:
		calculate_coefficients_adaptive_catmull( c, shrink, x ); 
		break;

	case VIPS_KERNEL_LANCZOS2:
		calculate_coefficients_lanczos( c, 2, shrink, x ); 
		break;

	case VIPS_KERNEL_LANCZOS3:
		calculate_coefficients_lanczos( c, 3, shrink, x ); 
		break;

	default:
		g_assert_not_reached();
		break;
	}
}

/* Our sequence value.
 */
typedef struct {
	VipsReduceh *reduceh;
	VipsRegion *ir;		/* Input region */

	/* In vector mode we need a pair of intermediate buffers to keep the 
	 * results of each pass in.
	 */
	signed short *t1;
	signed short *t2;
} Sequence;

static int
vips_reduceh_stop( void *vseq, void *a, void *b )
{
	Sequence *seq = (Sequence *) vseq;

	VIPS_UNREF( seq->ir );
	VIPS_FREE( seq->t1 );
	VIPS_FREE( seq->t2 );

	return( 0 );
}

static void *
vips_reduceh_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsReduceh *reduceh = (VipsReduceh *) b;

	Sequence *seq;

	if( !(seq = VIPS_NEW( out, Sequence )) )
		return( NULL );

	/* Init!
	 */
	seq->reduceh = reduceh;
	seq->ir = NULL;
	seq->t1 = NULL;
	seq->t2 = NULL;

	/* Attach region and arrays.
	 */
	seq->ir = vips_region_new( in );
	seq->t1 = VIPS_ARRAY( NULL, 2 * in->Bands, signed short );
	seq->t2 = VIPS_ARRAY( NULL, 2 * in->Bands, signed short );
	if( !seq->ir || 
		!seq->t1 || 
		!seq->t2  ) {
		vips_reduceh_stop( seq, NULL, NULL );
		return( NULL );
	}

	return( seq );
}

template <typename T, int max_value>
static void inline
reduceh_unsigned_int_tab( VipsReduceh *reduceh,
	VipsPel *pout, const VipsPel *pin,
	const int bands, const int * restrict cx )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;
	const int n = reduceh->n_point;

	for( int z = 0; z < bands; z++ ) {
		int sum;
	       
		sum = reduce_sum<T, int>( in + z, bands, cx, n );
		sum = unsigned_fixed_round( sum ); 
		sum = VIPS_CLIP( 0, sum, max_value ); 

		out[z] = sum;
	}
}

template <typename T, int min_value, int max_value>
static void inline
reduceh_signed_int_tab( VipsReduceh *reduceh,
	VipsPel *pout, const VipsPel *pin,
	const int bands, const int * restrict cx )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;
	const int n = reduceh->n_point;

	for( int z = 0; z < bands; z++ ) {
		int sum;

		sum = reduce_sum<T, int>( in, bands, cx, n );
		sum = signed_fixed_round( sum ); 
		sum = VIPS_CLIP( min_value, sum, max_value ); 

		out[z] = sum;

		in += 1;
	}
}

/* Floating-point version.
 */
template <typename T>
static void inline
reduceh_float_tab( VipsReduceh *reduceh,
	VipsPel *pout, const VipsPel *pin,
	const int bands, const double *cx )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;
	const int n = reduceh->n_point;

	for( int z = 0; z < bands; z++ ) {
		out[z] = reduce_sum<T, double>( in, bands, cx, n );
		in += 1;
	}
}

/* 32-bit int output needs a double intermediate.
 */

template <typename T, int max_value>
static void inline
reduceh_unsigned_int32_tab( VipsReduceh *reduceh,
	VipsPel *pout, const VipsPel *pin,
	const int bands, const double * restrict cx )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;
	const int n = reduceh->n_point;

	for( int z = 0; z < bands; z++ ) {
		double sum;

		sum = reduce_sum<T, double>( in, bands, cx, n );
		out[z] = VIPS_CLIP( 0, sum, max_value ); 

		in += 1;
	}
}

template <typename T, int min_value, int max_value>
static void inline
reduceh_signed_int32_tab( VipsReduceh *reduceh,
	VipsPel *pout, const VipsPel *pin,
	const int bands, const double * restrict cx )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;
	const int n = reduceh->n_point;

	for( int z = 0; z < bands; z++ ) {
		double sum;

		sum = reduce_sum<T, double>( in, bands, cx, n );
		sum = VIPS_CLIP( min_value, sum, max_value ); 
		out[z] = sum;

		in += 1;
	}
}

/* Ultra-high-quality version for double images.
 */
template <typename T>
static void inline
reduceh_notab( VipsReduceh *reduceh,
	VipsPel *pout, const VipsPel *pin,
	const int bands, double x )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;
	const int n = reduceh->n_point;

	double cx[MAX_POINT];

	vips_reduce_make_mask( cx, reduceh->kernel, reduceh->hshrink, x ); 

	for( int z = 0; z < bands; z++ ) {
		out[z] = reduce_sum<T, double>( in, bands, cx, n );

		in += 1;
	}
}

/* Tried a vector path (see reducev) but it was slower. The vectors for
 * horizontal reduce are just too small to get a useful speedup.
 */

static int
vips_reduceh_gen( VipsRegion *out_region, void *vseq, 
	void *a, void *b, gboolean *stop )
{
	VipsImage *in = (VipsImage *) a;
	VipsReduceh *reduceh = (VipsReduceh *) b;
	const int ps = VIPS_IMAGE_SIZEOF_PEL( in );
	Sequence *seq = (Sequence *) vseq;
	VipsRegion *ir = seq->ir;
	VipsRect *r = &out_region->valid;

	/* Double bands for complex.
	 */
	const int bands = in->Bands * 
		(vips_band_format_iscomplex( in->BandFmt ) ?  2 : 1);

	VipsRect s;

#ifdef DEBUG
	printf( "vips_reduceh_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG*/

	s.left = r->left * reduceh->hshrink;
	s.top = r->top;
	s.width = r->width * reduceh->hshrink + reduceh->n_point;
	s.height = r->height;
	if( reduceh->centre )
		s.width += 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	VIPS_GATE_START( "vips_reduceh_gen: work" ); 

	for( int y = 0; y < r->height; y ++ ) { 
		VipsPel *p0;
		VipsPel *q;

		double X;

		q = VIPS_REGION_ADDR( out_region, r->left, r->top + y );

		X = r->left * reduceh->hshrink;
		if( reduceh->centre )
			X += 0.5;

		/* We want p0 to be the start (ie. x == 0) of the input 
		 * scanline we are reading from. We can then calculate the p we
		 * need for each pixel with a single mul and avoid calling ADDR
		 * for each pixel. 
		 *
		 * We can't get p0 directly with ADDR since it could be outside
		 * valid, so get the leftmost pixel in valid and subtract a
		 * bit.
		 */
		p0 = VIPS_REGION_ADDR( ir, ir->valid.left, r->top + y ) - 
			ir->valid.left * ps;

		for( int x = 0; x < r->width; x++ ) {
			int ix = (int) X;
			VipsPel *p = p0 + ix * ps;
			const int sx = X * VIPS_TRANSFORM_SCALE * 2;
			const int six = sx & (VIPS_TRANSFORM_SCALE * 2 - 1);
			const int tx = (six + 1) >> 1;
			const int *cxi = reduceh->matrixi[tx];
			const double *cxf = reduceh->matrixf[tx];

			switch( in->BandFmt ) {
			case VIPS_FORMAT_UCHAR:
				reduceh_unsigned_int_tab
					<unsigned char, UCHAR_MAX>(
					reduceh,
					q, p, bands, cxi );
				break;

			case VIPS_FORMAT_CHAR:
				reduceh_signed_int_tab
					<signed char, SCHAR_MIN, SCHAR_MAX>(
					reduceh,
					q, p, bands, cxi );
				break;

			case VIPS_FORMAT_USHORT:
				reduceh_unsigned_int_tab
					<unsigned short, USHRT_MAX>(
					reduceh,
					q, p, bands, cxi );
				break;

			case VIPS_FORMAT_SHORT:
				reduceh_signed_int_tab
					<signed short, SHRT_MIN, SHRT_MAX>(
					reduceh,
					q, p, bands, cxi );
				break;

			case VIPS_FORMAT_UINT:
				reduceh_unsigned_int32_tab
					<unsigned int, INT_MAX>(
					reduceh,
					q, p, bands, cxf );
				break;

			case VIPS_FORMAT_INT:
				reduceh_signed_int32_tab
					<signed int, INT_MIN, INT_MAX>(
					reduceh,
					q, p, bands, cxf );
				break;

			case VIPS_FORMAT_FLOAT:
			case VIPS_FORMAT_COMPLEX:
				reduceh_float_tab<float>( reduceh,
					q, p, bands, cxf );
				break;

			case VIPS_FORMAT_DOUBLE:
			case VIPS_FORMAT_DPCOMPLEX:
				reduceh_notab<double>( reduceh,
					q, p, bands, X - ix );
				break;

			default:
				g_assert_not_reached();
				break;
			}

			X += reduceh->hshrink;
			q += ps;
		}
	}

	VIPS_GATE_STOP( "vips_reduceh_gen: work" ); 

	VIPS_COUNT_PIXELS( out_region, "vips_reduceh_gen" ); 

	return( 0 );
}

/* Process uchar images with a vector path.
 */
static int
vips_reduceh_vector_gen( VipsRegion *out_region, void *vseq, 
	void *a, void *b, gboolean *stop )
{
	VipsImage *in = (VipsImage *) a;
	const int ps = VIPS_IMAGE_SIZEOF_PEL( in );
	VipsReduceh *reduceh = (VipsReduceh *) b;
	Sequence *seq = (Sequence *) vseq;
	VipsRegion *ir = seq->ir;
	VipsRect *r = &out_region->valid;

	VipsExecutor executor[MAX_PASS];
	VipsRect s;

#ifdef DEBUG_PIXELS
	printf( "vips_reduceh_vector_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG_PIXELS*/

	s.left = r->left * reduceh->hshrink;
	s.top = r->top;
	s.width = r->width * reduceh->hshrink + reduceh->n_point;
	s.height = r->height;
	if( reduceh->centre )
		s.width += 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

#ifdef DEBUG_PIXELS
	printf( "vips_reduceh_vector_gen: preparing %d x %d at %d x %d\n",
		s.width, s.height, s.left, s.top ); 
#endif /*DEBUG_PIXELS*/

	for( int i = 0; i < reduceh->n_pass; i++ ) {
		Pass *pass = &reduceh->pass[i]; 

		vips_executor_set_program( &executor[i], pass->vector, in->Bands );
		vips_executor_set_array( &executor[i], pass->r, seq->t1 );
		vips_executor_set_array( &executor[i], pass->d2, seq->t2 );
	}

	VIPS_GATE_START( "vips_reduceh_vector_gen: work" ); 

	for( int y = 0; y < r->height; y ++ ) { 
		VipsPel *p0;
		VipsPel *q;

		double X;

		q = VIPS_REGION_ADDR( out_region, r->left, r->top + y );

		X = r->left * reduceh->hshrink;
		if( reduceh->centre )
			X += 0.5;

		/* We want p0 to be the start (ie. x == 0) of the input 
		 * scanline we are reading from. We can then calculate the p we
		 * need for each pixel with a single mul and avoid calling ADDR
		 * for each pixel. 
		 *
		 * We can't get p0 directly with ADDR since it could be outside
		 * valid, so get the leftmost pixel in valid and subtract a
		 * bit.
		 */
		p0 = VIPS_REGION_ADDR( ir, ir->valid.left, r->top + y ) - 
			ir->valid.left * ps;

		for( int x = 0; x < r->width; x++ ) {
			int ix = (int) X;
			VipsPel *p = p0 + ix * ps;
			const int sx = X * VIPS_TRANSFORM_SCALE * 2;
			const int six = sx & (VIPS_TRANSFORM_SCALE * 2 - 1);
			const int tx = (six + 1) >> 1;
			const int *cxo = reduceh->matrixo[tx];

			if( reduceh->n_pass == 1 ) {
				Pass *pass = &reduceh->pass[0]; 

				orc_executor_set_array( &executor[0].executor, 
					pass->vector->sl[0], p );
				for( int j = 0; j < pass->n_param; j++ ) 
					orc_executor_set_param( 
						&executor[0].executor, 
						pass->p[j], 
						cxo[j] ); 
				orc_executor_set_array( &executor[0].executor, 
					pass->vector->d1, q );
				orc_executor_run( &executor[0].executor );
			}
			else {
				for( int i = 0; i < reduceh->n_pass; i++ ) {
					Pass *pass = &reduceh->pass[i]; 

					vips_executor_set_array( &executor[i],
						pass->r, seq->t1 );
					vips_executor_set_array( &executor[i],
						pass->d2, seq->t2 );
					vips_executor_set_array( &executor[i], 
						pass->vector->sl[0], p );
					for( int j = 0; j < pass->n_param; j++ ) 
						vips_executor_set_parameter( 
							&executor[i],
							pass->p[j], 
							cxo[j + pass->first] ); 
					vips_executor_set_destination( &executor[i], q );
					vips_executor_run( &executor[i] );

					VIPS_SWAP( signed short *, seq->t1, seq->t2 );
				}
			}

			X += reduceh->hshrink;
			q += ps;
		}
	}

	VIPS_GATE_STOP( "vips_reduceh_vector_gen: work" ); 

	VIPS_COUNT_PIXELS( out_region, "vips_reduceh_vector_gen" ); 

	return( 0 );
}

static int
vips_reduceh_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsReduceh *reduceh = (VipsReduceh *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 2 );

	VipsImage *in;
	int width;
	VipsGenerateFn generate;

	if( VIPS_OBJECT_CLASS( vips_reduceh_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	if( reduceh->hshrink < 1 ) { 
		vips_error( object_class->nickname, 
			"%s", _( "reduce factors should be >= 1" ) );
		return( -1 );
	}

	if( reduceh->hshrink == 1 ) 
		return( vips_image_write( in, resample->out ) );

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	/* Build the tables of pre-computed coefficients.
	 */
	reduceh->n_point = 
		vips_reduce_get_points( reduceh->kernel, reduceh->hshrink ); 
	g_info( "reduceh: %d point mask", reduceh->n_point );
	if( reduceh->n_point > MAX_POINT ) {
		vips_error( object_class->nickname, 
			"%s", _( "reduce factor too large" ) );
		return( -1 );
	}
	for( int x = 0; x < VIPS_TRANSFORM_SCALE + 1; x++ ) {
		reduceh->matrixf[x] = 
			VIPS_ARRAY( NULL, reduceh->n_point, double ); 
		reduceh->matrixi[x] = 
			VIPS_ARRAY( NULL, reduceh->n_point, int ); 
		if( !reduceh->matrixf[x] ||
			!reduceh->matrixi[x] )
			return( -1 ); 

		vips_reduce_make_mask( reduceh->matrixf[x], 
			reduceh->kernel, reduceh->hshrink, 
			(float) x / VIPS_TRANSFORM_SCALE );

		for( int i = 0; i < reduceh->n_point; i++ )
			reduceh->matrixi[x][i] = reduceh->matrixf[x][i] * 
				VIPS_INTERPOLATE_SCALE;

#ifdef DEBUG
		printf( "vips_reduceh_build: mask %d\n    ", x ); 
		for( int i = 0; i < reduceh->n_point; i++ )
			printf( "%d ", reduceh->matrixi[x][i] );
		printf( "\n" ); 
#endif /*DEBUG*/
	}

	/* And we need an 2.6 version if we will use the vector path.
	 */
	if( in->BandFmt == VIPS_FORMAT_UCHAR &&
		vips_vector_isenabled() ) 
		for( int x = 0; x < VIPS_TRANSFORM_SCALE + 1; x++ ) {
			reduceh->matrixo[x] = 
				VIPS_ARRAY( NULL, reduceh->n_point, int ); 
			if( !reduceh->matrixo[x] )
				return( -1 ); 

			vips_vector_to_fixed_point( 
				reduceh->matrixf[x], reduceh->matrixo[x], 
				reduceh->n_point, 64 );
		}

	/* Try to build a vector version, if we can.
	 */
	generate = vips_reduceh_gen;
	if( in->BandFmt == VIPS_FORMAT_UCHAR &&
		vips_vector_isenabled() &&
		!vips_reduceh_compile( reduceh, in ) ) {
		g_info( "reduceh: using vector path" ); 
		generate = vips_reduceh_vector_gen;
	}

	/* Add new pixels around the input so we can interpolate at the edges.
	 * In centre mode, we read 0.5 pixels more to the right, so we must
	 * enlarge a little further.
	 */
	width = in->Xsize + reduceh->n_point - 1;
	if( reduceh->centre )
		width += 1;
	if( vips_embed( in, &t[1], 
		reduceh->n_point / 2 - 1, 0, 
		width, in->Ysize,
		"extend", VIPS_EXTEND_COPY,
		(void *) NULL ) )
		return( -1 );
	in = t[1];

	if( vips_image_pipelinev( resample->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, (void *) NULL ) )
		return( -1 );

	/* Size output. We need to always round to nearest, so round(), not
	 * rint().
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true reduce factor (including the
	 * fractional part), we just see the integer part here.
	 */
	resample->out->Xsize = VIPS_ROUND_UINT( 
		resample->in->Xsize / reduceh->hshrink );
	if( resample->out->Xsize <= 0 ) { 
		vips_error( object_class->nickname, 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_reduceh_build: reducing %d x %d image to %d x %d\n", 
		in->Xsize, in->Ysize, 
		resample->out->Xsize, resample->out->Ysize );  
#endif /*DEBUG*/

	if( vips_image_generate( resample->out,
		vips_reduceh_start, generate, vips_reduceh_stop, 
		in, reduceh ) )
		return( -1 );

	vips_reorder_margin_hint( resample->out, reduceh->n_point ); 

	return( 0 );
}

static void
vips_reduceh_class_init( VipsReducehClass *reduceh_class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( reduceh_class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( reduceh_class );
	VipsOperationClass *operation_class = 
		VIPS_OPERATION_CLASS( reduceh_class );

	VIPS_DEBUG_MSG( "vips_reduceh_class_init\n" );

	gobject_class->finalize = vips_reduceh_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "reduceh";
	vobject_class->description = _( "shrink an image horizontally" );
	vobject_class->build = vips_reduceh_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_DOUBLE( reduceh_class, "hshrink", 3, 
		_( "Hshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReduceh, hshrink ),
		1, 1000000, 1 );

	VIPS_ARG_ENUM( reduceh_class, "kernel", 3, 
		_( "Kernel" ), 
		_( "Resampling kernel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsReduceh, kernel ),
		VIPS_TYPE_KERNEL, VIPS_KERNEL_LANCZOS3 );

	VIPS_ARG_BOOL( reduceh_class, "centre", 7, 
		_( "Centre" ), 
		_( "Use centre sampling convention" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsReduceh, centre ),
		FALSE );

	/* Old name.
	 */
	VIPS_ARG_DOUBLE( reduceh_class, "xshrink", 3, 
		_( "Xshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsReduceh, hshrink ),
		1, 1000000, 1 );

}

static void
vips_reduceh_init( VipsReduceh *reduceh )
{
	reduceh->kernel = VIPS_KERNEL_LANCZOS3;
}

/**
 * vips_reduceh: (method)
 * @in: input image
 * @out: (out): output image
 * @hshrink: horizontal reduce
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @kernel: #VipsKernel to use to interpolate (default: lanczos3)
 * * @centre: %gboolean use centre rather than corner sampling convention
 *
 * Reduce @in horizontally by a float factor. The pixels in @out are
 * interpolated with a 1D mask generated by @kernel.
 *
 * Set @centre to use centre rather than corner sampling convention. Centre
 * convention can be useful to match the behaviour of other systems. 
 *
 * This is a very low-level operation: see vips_resize() for a more
 * convenient way to resize images. 
 *
 * This operation does not change xres or yres. The image resolution needs to
 * be updated by the application. 
 *
 * See also: vips_shrink(), vips_resize(), vips_affine().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_reduceh( VipsImage *in, VipsImage **out, double hshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, hshrink );
	result = vips_call_split( "reduceh", ap, in, out, hshrink );
	va_end( ap );

	return( result );
}
