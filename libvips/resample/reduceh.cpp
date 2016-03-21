/* horizontal reduce by a float factor with lanczos3
 *
 * 29/1/16
 * 	- from shrinkh.c
 * 10/3/16
 * 	- add other kernels
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

#include "presample.h"
#include "templates.h"

/**
 * VipsKernel: 
 * @VIPS_KERNEL_NEAREST: nearest-neighbour
 * @VIPS_KERNEL_LINEAR: linear interpolation
 * @VIPS_KERNEL_CUBIC: cubic interpolation
 * @VIPS_KERNEL_LANCZOS2: lanczos2 interpolation
 * @VIPS_KERNEL_LANCZOS3: lanczos3 interpolation
 *
 * 1D resampling kernels. 
 */

typedef struct _VipsReduceh {
	VipsResample parent_instance;

	double xshrink;		/* Reduce factor */

	/* The thing we use to make the kernel.
	 */
	VipsKernel kernel;

	/* Number of points in kernel.
	 */
	int n_point;

	/* Precalculated interpolation matrices. int (used for pel
	 * sizes up to short), and double (for all others). We go to
	 * scale + 1 so we can round-to-nearest safely.
	 */
	int *matrixi[VIPS_TRANSFORM_SCALE + 1];
	double *matrixf[VIPS_TRANSFORM_SCALE + 1];

} VipsReduceh;

typedef VipsResampleClass VipsReducehClass;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsReduceh, vips_reduceh, VIPS_TYPE_RESAMPLE );
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
		return( 2 ); 

	case VIPS_KERNEL_CUBIC:
		return( 4 ); 

	case VIPS_KERNEL_LANCZOS2:
		/* Needs to be in sync with calculate_coefficients_lanczos().
		 */
		return( ceil( 2 * 2 * shrink ) + 2 ); 

	case VIPS_KERNEL_LANCZOS3:
		return( ceil( 2 * 3 * shrink ) + 2 ); 

	default:
		g_assert_not_reached();
		return( 0 ); 
	}
}

/* Calculate a mask element. 
 */
void
vips_reduce_make_mask( VipsKernel kernel, double shrink, double x, double *c )
{
	switch( kernel ) {
	case VIPS_KERNEL_NEAREST:
		c[0] = 1.0;
		break;

	case VIPS_KERNEL_LINEAR:
		c[0] = 1.0 - x;
		c[1] = x;
		break;

	case VIPS_KERNEL_CUBIC:
		calculate_coefficients_catmull( x, c ); 
		break;

	case VIPS_KERNEL_LANCZOS2:
		calculate_coefficients_lanczos( 2, shrink, x, c ); 
		break;

	case VIPS_KERNEL_LANCZOS3:
		calculate_coefficients_lanczos( 3, shrink, x, c ); 
		break;

	default:
		g_assert_not_reached();
		break;
	}
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

	vips_reduce_make_mask( reduceh->kernel, reduceh->xshrink, x, cx ); 

	for( int z = 0; z < bands; z++ ) {
		out[z] = reduce_sum<T, double>( in, bands, cx, n );

		in += 1;
	}
}

static int
vips_reduceh_gen( VipsRegion *out_region, void *seq, 
	void *a, void *b, gboolean *stop )
{
	VipsImage *in = (VipsImage *) a;
	VipsReduceh *reduceh = (VipsReduceh *) b;
	const int ps = VIPS_IMAGE_SIZEOF_PEL( in );
	VipsRegion *ir = (VipsRegion *) seq;
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

	s.left = r->left * reduceh->xshrink;
	s.top = r->top;
	s.width = r->width * reduceh->xshrink + reduceh->n_point;
	s.height = r->height;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	VIPS_GATE_START( "vips_reduceh_gen: work" ); 

	for( int y = 0; y < r->height; y ++ ) { 
		VipsPel *q;
		double X;

		q = VIPS_REGION_ADDR( out_region, r->left, r->top + y );
		X = r->left * reduceh->xshrink;

		for( int x = 0; x < r->width; x++ ) {
			int ix = (int) X;
			VipsPel *p = VIPS_REGION_ADDR( ir, ix, r->top + y );
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

			X += reduceh->xshrink;
			q += ps;
		}
	}

	VIPS_GATE_STOP( "vips_reduceh_gen: work" ); 

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

	if( VIPS_OBJECT_CLASS( vips_reduceh_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	if( reduceh->xshrink < 1 ) { 
		vips_error( object_class->nickname, 
			"%s", _( "reduce factors should be >= 1" ) );
		return( -1 );
	}

	if( reduceh->xshrink == 1 ) 
		return( vips_image_write( in, resample->out ) );

	/* Build the tables of pre-computed coefficients.
	 */
	reduceh->n_point = 
		vips_reduce_get_points( reduceh->kernel, reduceh->xshrink ); 
	vips_info( object_class->nickname, "%d point mask", reduceh->n_point );
	if( reduceh->n_point > MAX_POINT ) {
		vips_error( object_class->nickname, 
			"%s", _( "reduce factor too large" ) );
		return( -1 );
	}
	for( int x = 0; x < VIPS_TRANSFORM_SCALE + 1; x++ ) {
		reduceh->matrixf[x] = 
			VIPS_ARRAY( object, reduceh->n_point, double ); 
		reduceh->matrixi[x] = 
			VIPS_ARRAY( object, reduceh->n_point, int ); 
		if( !reduceh->matrixf[x] ||
			!reduceh->matrixi[x] )
			return( -1 ); 

		vips_reduce_make_mask( reduceh->kernel, reduceh->xshrink,
			(float) x / VIPS_TRANSFORM_SCALE,
			reduceh->matrixf[x] );

		for( int i = 0; i < reduceh->n_point; i++ )
			reduceh->matrixi[x][i] = reduceh->matrixf[x][i] * 
				VIPS_INTERPOLATE_SCALE;
	}

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	/* Add new pixels around the input so we can interpolate at the edges.
	 */
	if( vips_embed( in, &t[1], 
		reduceh->n_point / 2 - 1, 0, 
		in->Xsize + reduceh->n_point - 1, in->Ysize,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[1];

	if( vips_image_pipelinev( resample->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Size output. Note: we round to nearest to hide rounding errors. 
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true reduce factor (including the
	 * fractional part), we just see the integer part here.
	 */
	resample->out->Xsize = VIPS_RINT( 
		(in->Xsize - reduceh->n_point + 1) / reduceh->xshrink );
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
		vips_start_one, vips_reduceh_gen, vips_stop_one, 
		in, reduceh ) )
		return( -1 );

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

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "reduceh";
	vobject_class->description = _( "shrink an image horizontally" );
	vobject_class->build = vips_reduceh_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_DOUBLE( reduceh_class, "xshrink", 3, 
		_( "Xshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReduceh, xshrink ),
		1, 1000000, 1 );

	VIPS_ARG_ENUM( reduceh_class, "kernel", 3, 
		_( "Kernel" ), 
		_( "Resampling kernel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsReduceh, kernel ),
		VIPS_TYPE_KERNEL, VIPS_KERNEL_LANCZOS3 );

}

static void
vips_reduceh_init( VipsReduceh *reduceh )
{
	reduceh->kernel = VIPS_KERNEL_LANCZOS3;
}

/**
 * vips_reduceh:
 * @in: input image
 * @out: output image
 * @xshrink: horizontal reduce
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @kernel: #VipsKernel to use to interpolate (default: lanczos3)
 *
 * Reduce @in horizontally by a float factor. The pixels in @out are
 * interpolated with a 1D mask. This operation will not work well for
 * a reduction of more than a factor of two.
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
vips_reduceh( VipsImage *in, VipsImage **out, double xshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, xshrink );
	result = vips_call_split( "reduceh", ap, in, out, xshrink );
	va_end( ap );

	return( result );
}
