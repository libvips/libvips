/* vertical reduce by a float factor
 *
 * 29/1/16
 * 	- from shrinkv.c
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

typedef struct _VipsReducev {
	VipsResample parent_instance;

	double yshrink;		/* Shrink factor */

} VipsReducev;

typedef VipsResampleClass VipsReducevClass;

/* Precalculated interpolation matrices. int (used for pel
 * sizes up to short), and double (for all others). We go to
 * scale + 1 so we can round-to-nearest safely.
 */

static int vips_reducev_matrixi[VIPS_TRANSFORM_SCALE + 1][4];
static double vips_reducev_matrixf[VIPS_TRANSFORM_SCALE + 1][4];

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsReducev, vips_reducev, VIPS_TYPE_RESAMPLE );
}

template <typename T, int max_value>
static void inline
reducev_unsigned_int_tab( VipsPel *pout, const VipsPel *pin,
	const int ne, const int lskip,
	const int *cy )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

	const int c0 = cy[0];
	const int c1 = cy[1];
	const int c2 = cy[2];
	const int c3 = cy[3];

	for( int z = 0; z < ne; z++ ) {
		int cubicv = unsigned_fixed_round( 
			c0 * in[0] +
			c1 * in[l1] +
			c2 * in[l2] +
			c3 * in[l3] ); 

		cubicv = VIPS_CLIP( 0, cubicv, max_value ); 

		out[z] = cubicv;

		in += 1;
	}
}

template <typename T, int min_value, int max_value>
static void inline
reducev_signed_int_tab( VipsPel *pout, const VipsPel *pin,
	const int ne, const int lskip,
	const int *cy )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

	const int c0 = cy[0];
	const int c1 = cy[1];
	const int c2 = cy[2];
	const int c3 = cy[3];

	for( int z = 0; z < ne; z++ ) {
		int cubicv = signed_fixed_round( 
			c0 * in[0] +
			c1 * in[l1] +
			c2 * in[l2] +
			c3 * in[l3] ); 

		cubicv = VIPS_CLIP( min_value, cubicv, max_value ); 

		out[z] = cubicv;

		in += 1;
	}
}

/* Floating-point version, for int/float types.
 */
template <typename T>
static void inline
reducev_float_tab( VipsPel *pout, const VipsPel *pin,
	const int ne, const int lskip,
	const double *cy )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

	const double c0 = cy[0];
	const double c1 = cy[1];
	const double c2 = cy[2];
	const double c3 = cy[3];

	for( int z = 0; z < ne; z++ ) {
		out[z] = 
			c0 * in[0] +
			c1 * in[l1] +
			c2 * in[l2] +
			c3 * in[l3]; 

		in += 1;
	}
}

/* Ultra-high-quality version for double images.
 */
template <typename T>
static void inline
reducev_notab( VipsPel *pout, const VipsPel *pin,
	const int ne, const int lskip,
	double y )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	const int l1 = lskip / sizeof( T );
	const int l2 = l1 + l1;
	const int l3 = l1 + l2;

	double cy[4];

	calculate_coefficients_catmull( y, cy );

	const double c0 = cy[0];
	const double c1 = cy[1];
	const double c2 = cy[2];
	const double c3 = cy[3];

	for( int z = 0; z < ne; z++ ) {
		out[z] = 
			c0 * in[0] +
			c1 * in[l1] +
			c2 * in[l2] +
			c3 * in[l3]; 

		in += 1;
	}
}

static int
vips_reducev_gen( VipsRegion *out_region, void *seq, 
	void *a, void *b, gboolean *stop )
{
	VipsImage *in = (VipsImage *) a;
	VipsReducev *reducev = (VipsReducev *) b;
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &out_region->valid;

	/* Double bands for complex.
	 */
	const int bands = in->Bands * 
		(vips_band_format_iscomplex( in->BandFmt ) ?  2 : 1);
	int ne = r->width * bands;

	VipsRect s;

#ifdef DEBUG
	printf( "vips_reducev_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG*/

	s.left = r->left;
	s.top = r->top * reducev->yshrink;
	s.width = r->width;
	s.height = r->height * reducev->yshrink + 3;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	VIPS_GATE_START( "vips_reducev_gen: work" ); 

	for( int y = 0; y < r->height; y ++ ) { 
		VipsPel *q = VIPS_REGION_ADDR( out_region, r->left, r->top + y );
		const double Y = (r->top + y) * reducev->yshrink; 
		VipsPel *p = VIPS_REGION_ADDR( ir, r->left, (int) Y ); 
		const int sy = Y * VIPS_TRANSFORM_SCALE * 2;
		const int siy = sy & (VIPS_TRANSFORM_SCALE * 2 - 1);
		const int ty = (siy + 1) >> 1;
		const int *cyi = vips_reducev_matrixi[ty];
		const double *cyf = vips_reducev_matrixf[ty];
		const int lskip = VIPS_REGION_LSKIP( ir );

		switch( in->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			reducev_unsigned_int_tab
				<unsigned char, UCHAR_MAX>(
				q, p, ne, lskip, cyi );
			break;

		case VIPS_FORMAT_CHAR:
			reducev_signed_int_tab
				<signed char, SCHAR_MIN, SCHAR_MAX>(
				q, p, ne, lskip, cyi );
			break;

		case VIPS_FORMAT_USHORT:
			reducev_unsigned_int_tab
				<unsigned short, USHRT_MAX>(
				q, p, ne, lskip, cyi );
			break;

		case VIPS_FORMAT_SHORT:
			reducev_signed_int_tab
				<signed short, SHRT_MIN, SHRT_MAX>(
				q, p, ne, lskip, cyi );
			break;

		case VIPS_FORMAT_UINT:
			reducev_float_tab<unsigned int>( q, p, ne, lskip, cyf );
			break;

		case VIPS_FORMAT_INT:
			reducev_float_tab<signed int>( q, p, ne, lskip, cyf );
			break;

		case VIPS_FORMAT_FLOAT:
		case VIPS_FORMAT_COMPLEX:
			reducev_float_tab<float>( q, p, ne, lskip, cyf );
			break;

		case VIPS_FORMAT_DPCOMPLEX:
		case VIPS_FORMAT_DOUBLE:
			reducev_notab<double>( q, p, ne, lskip, Y - (int) Y );
			break;

		default:
			g_assert_not_reached();
			break;
		}
	}

	VIPS_GATE_STOP( "vips_reducev_gen: work" ); 

	return( 0 );
}

static int
vips_reducev_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsReducev *reducev = (VipsReducev *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_reducev_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	if( reducev->yshrink < 1 ) { 
		vips_error( object_class->nickname, 
			"%s", _( "reduce factors should be >= 1" ) );
		return( -1 );
	}
	if( reducev->yshrink > 2 )  
		vips_warn( object_class->nickname, 
			"%s", _( "reduce factor greater than 2" ) );

	if( reducev->yshrink == 1 ) 
		return( vips_image_write( in, resample->out ) );

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	/* Add new pixels around the input so we can interpolate at the edges.
	 */
	if( vips_embed( in, &t[1], 
		0, 1, 
		in->Xsize, in->Ysize + 3, 
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[1];

	if( vips_image_pipelinev( resample->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, in, NULL ) )
		return( -1 );

	/* Size output. Note: we round the output width down!
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true reduce factor (including the
	 * fractional part), we just see the integer part here.
	 */
	resample->out->Ysize = (in->Ysize - 3) / reducev->yshrink;
	if( resample->out->Ysize <= 0 ) { 
		vips_error( object_class->nickname, 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_reducev_build: reducing %d x %d image to %d x %d\n", 
		in->Xsize, in->Ysize, 
		resample->out->Xsize, resample->out->Ysize );  
#endif /*DEBUG*/

	if( vips_image_generate( resample->out,
		vips_start_one, vips_reducev_gen, vips_stop_one, 
		in, reducev ) )
		return( -1 );

	return( 0 );
}

static void
vips_reducev_class_init( VipsReducevClass *reducev_class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( reducev_class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( reducev_class );
	VipsOperationClass *operation_class = 
		VIPS_OPERATION_CLASS( reducev_class );

	VIPS_DEBUG_MSG( "vips_reducev_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "reducev";
	vobject_class->description = _( "shrink an image vertically" );
	vobject_class->build = vips_reducev_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_DOUBLE( reducev_class, "yshrink", 3, 
		_( "Xshrink" ), 
		_( "Vertical shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReducev, yshrink ),
		1, 1000000, 1 );

	/* Build the tables of pre-computed coefficients.
	 */
	for( int y = 0; y < VIPS_TRANSFORM_SCALE + 1; y++ ) {
		calculate_coefficients_catmull(
			(float) y / VIPS_TRANSFORM_SCALE,
			vips_reducev_matrixf[y] );

		for( int i = 0; i < 4; i++ )
			vips_reducev_matrixi[y][i] =
				vips_reducev_matrixf[y][i] * 
				VIPS_INTERPOLATE_SCALE;
	}

}

static void
vips_reducev_init( VipsReducev *reducev )
{
}

/**
 * vips_reducev:
 * @in: input image
 * @out: output image
 * @yshrink: horizontal reduce
 * @...: %NULL-terminated list of optional named arguments
 *
 * Reduce @in vertically by a float factor. The pixels in @out are
 * interpolated with a 1D cubic mask. This operation will not work well for
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
vips_reducev( VipsImage *in, VipsImage **out, double yshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, yshrink );
	result = vips_call_split( "reducev", ap, in, out, yshrink );
	va_end( ap );

	return( result );
}
