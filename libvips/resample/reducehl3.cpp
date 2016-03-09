/* horizontal reduce by a float factor with lanczos3
 *
 * 29/1/16
 * 	- from shrinkh.c
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

/* The max size of the vector we use.
 */
#define MAX_POINTS (6)

typedef struct _VipsReducehl3 {
	VipsResample parent_instance;

	double xshrink;		/* Reduce factor */

	/* The thing we use to make the kernel.
	 */
	VipsKernel kernel;

	/* Number of points in kernel.
	 */
	int n_points;

	/* Precalculated interpolation matrices. int (used for pel
	 * sizes up to short), and double (for all others). We go to
	 * scale + 1 so we can round-to-nearest safely.
	 */
	int matrixi[VIPS_TRANSFORM_SCALE + 1][MAX_POINTS];
	double matrixf[VIPS_TRANSFORM_SCALE + 1][MAX_POINTS];

} VipsReducehl3;

typedef VipsResampleClass VipsReducehl3Class;

/* We need C linkage for this.
 */
extern "C" {
G_DEFINE_TYPE( VipsReducehl3, vips_reducehl3, VIPS_TYPE_RESAMPLE );
}

/* Get n points.
 */
int
vips_reducehl3_get_points( VipsKernel kernel ) 
{
	switch( kernel ) {
	case VIPS_KERNEL_NEAREST:
		return( 1 ); 

	case VIPS_KERNEL_LINEAR:
		return( 2 ); 

	case VIPS_KERNEL_CUBIC:
		return( 4 ); 

	case VIPS_KERNEL_LANCZOS2:
		return( 4 ); 

	case VIPS_KERNEL_LANCZOS3:
		return( 6 ); 

	default:
		g_assert_not_reached();
		return( 0 ); 
	}
}

/* Calculate a mask.
 */
void
vips_reducehl3_make_mask( VipsKernel kernel, double x, double *c )
{
	switch( kernel ) {
	case VIPS_KERNEL_NEAREST:
		c[0] = 1.0;
		break;

	case VIPS_KERNEL_LINEAR:
		c[0] = x;
		c[1] = 1.0 - x;
		break;

	case VIPS_KERNEL_CUBIC:
		calculate_coefficients_catmull( x, c ); 
		break;

	case VIPS_KERNEL_LANCZOS2:
		calculate_coefficients_lanczos( 2, x, c ); 
		break;

	case VIPS_KERNEL_LANCZOS3:
		calculate_coefficients_lanczos( 3, x, c ); 
		break;

	default:
		g_assert_not_reached();
		break;
	}
}

template <typename T, int max_value>
static void inline
reducehl3_unsigned_int_tab( VipsReducehl3 *reducehl3,
	VipsPel *pout, const VipsPel *pin,
	const int bands, const int * restrict cx )
{
	T* restrict out = (T *) pout;
	const T* restrict in = (T *) pin;

	for( int z = 0; z < bands; z++ ) {
		int sum;

		sum = 0;
		for( int i = 0; i < reducehl3->n_points; i++ )
			sum += cx[i] * in[i * bands];

		sum = unsigned_fixed_round( sum ); 

		sum = VIPS_CLIP( 0, sum, max_value ); 
		
		out[z] = sum;

		in += 1;
	}
}

static int
vips_reducehl3_gen( VipsRegion *out_region, void *seq, 
	void *a, void *b, gboolean *stop )
{
	VipsImage *in = (VipsImage *) a;
	VipsReducehl3 *reducehl3 = (VipsReducehl3 *) b;
	const int ps = VIPS_IMAGE_SIZEOF_PEL( in );
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &out_region->valid;

	/* Double bands for complex.
	 */
	const int bands = in->Bands * 
		(vips_band_format_iscomplex( in->BandFmt ) ?  2 : 1);

	VipsRect s;

#ifdef DEBUG
	printf( "vips_reducehl3_gen: generating %d x %d at %d x %d\n",
		r->width, r->height, r->left, r->top ); 
#endif /*DEBUG*/

	s.left = r->left * reducehl3->xshrink;
	s.top = r->top;
	s.width = r->width * reducehl3->xshrink + reducehl3->n_points;
	s.height = r->height;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	VIPS_GATE_START( "vips_reducehl3_gen: work" ); 

	for( int y = 0; y < r->height; y ++ ) { 
		VipsPel *q;
		double X;

		q = VIPS_REGION_ADDR( out_region, r->left, r->top + y );
		X = r->left * reducehl3->xshrink;

		for( int x = 0; x < r->width; x++ ) {
			int ix = (int) X;
			VipsPel *p = VIPS_REGION_ADDR( ir, ix, r->top + y );
			const int sx = X * VIPS_TRANSFORM_SCALE * 2;
			const int six = sx & (VIPS_TRANSFORM_SCALE * 2 - 1);
			const int tx = (six + 1) >> 1;
			const int *cxi = reducehl3->matrixi[tx];
			const double *cxf = reducehl3->matrixf[tx];

			switch( in->BandFmt ) {
			case VIPS_FORMAT_UCHAR:
				reducehl3_unsigned_int_tab
					<unsigned char, UCHAR_MAX>(
					reducehl3,
					q, p, bands, cxi );
				break;

			default:
				g_assert_not_reached();
				break;
			}

			X += reducehl3->xshrink;
			q += ps;
		}
	}

	VIPS_GATE_STOP( "vips_reducehl3_gen: work" ); 

	return( 0 );
}

static int
vips_reducehl3_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsReducehl3 *reducehl3 = (VipsReducehl3 *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 2 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_reducehl3_parent_class )->build( object ) )
		return( -1 );

	in = resample->in; 

	if( reducehl3->xshrink < 1 ) { 
		vips_error( object_class->nickname, 
			"%s", _( "reduce factors should be >= 1" ) );
		return( -1 );
	}
	if( reducehl3->xshrink > 3 )  
		vips_warn( object_class->nickname, 
			"%s", _( "reduce factor greater than 3" ) );

	if( reducehl3->xshrink == 1 ) 
		return( vips_image_write( in, resample->out ) );

	/* Build the tables of pre-computed coefficients.
	 */
	reducehl3->n_points = vips_reducehl3_get_points( reducehl3->kernel ); 
	for( int x = 0; x < VIPS_TRANSFORM_SCALE + 1; x++ ) {
		vips_reducehl3_make_mask( reducehl3->kernel, 
			(float) x / VIPS_TRANSFORM_SCALE,
			reducehl3->matrixf[x] );

		for( int i = 0; i < reducehl3->n_points; i++ )
			reducehl3->matrixi[x][i] = reducehl3->matrixf[x][i] * 
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
		reducehl3->n_points / 2, 0, 
		in->Xsize + reducehl3->n_points - 1, in->Ysize,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[1];

	if( vips_image_pipelinev( resample->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Size output. Note: we round the output width down!
	 *
	 * Don't change xres/yres, leave that to the application layer. For
	 * example, vipsthumbnail knows the true reduce factor (including the
	 * fractional part), we just see the integer part here.
	 */
	resample->out->Xsize = (in->Xsize - reducehl3->n_points + 1) / 
		reducehl3->xshrink;
	if( resample->out->Xsize <= 0 ) { 
		vips_error( object_class->nickname, 
			"%s", _( "image has shrunk to nothing" ) );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_reducehl3_build: reducing %d x %d image to %d x %d\n", 
		in->Xsize, in->Ysize, 
		resample->out->Xsize, resample->out->Ysize );  
#endif /*DEBUG*/

	if( vips_image_generate( resample->out,
		vips_start_one, vips_reducehl3_gen, vips_stop_one, 
		in, reducehl3 ) )
		return( -1 );

	return( 0 );
}

static void
vips_reducehl3_class_init( VipsReducehl3Class *reducehl3_class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( reducehl3_class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( reducehl3_class );
	VipsOperationClass *operation_class = 
		VIPS_OPERATION_CLASS( reducehl3_class );

	VIPS_DEBUG_MSG( "vips_reducehl3_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "reducehl3";
	vobject_class->description = _( "shrink an image horizontally" );
	vobject_class->build = vips_reducehl3_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_DOUBLE( reducehl3_class, "xshrink", 3, 
		_( "Xshrink" ), 
		_( "Horizontal shrink factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReducehl3, xshrink ),
		1, 1000000, 1 );

	VIPS_ARG_ENUM( reducehl3_class, "kernel", 3, 
		_( "Kernel" ), 
		_( "Resamling kernel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsReducehl3, kernel ),
		VIPS_TYPE_KERNEL, VIPS_KERNEL_CUBIC );

}

static void
vips_reducehl3_init( VipsReducehl3 *reducehl3 )
{
	reducehl3->kernel = VIPS_KERNEL_CUBIC;
}

/**
 * vips_reducehl3:
 * @in: input image
 * @out: output image
 * @xshrink: horizontal reduce
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @kernel: #VipsKernel to use to interpolate (default: cubic)
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
vips_reducehl3( VipsImage *in, VipsImage **out, double xshrink, ... )
{
	va_list ap;
	int result;

	va_start( ap, xshrink );
	result = vips_call_split( "reducehl3", ap, in, out, xshrink );
	va_end( ap );

	return( result );
}
