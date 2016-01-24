/* Resample an image with a quadratic transform.
 *
 * Original code from Reimar Lenz,
 * Adapted by Lars Raffelt for many bands,
 * VIPSified by JC ... other numeric types, partial output
 *
 * 7/11/12
 * 	- rewritten again for vips8
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
#define DEBUG_GEOMETRY
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include "presample.h"

/* The transform we compute:

x',y'  = coordinates of srcim
x,y    = coordinates of dstim
a .. l = coefficients

x = x' + a              : order 0     image shift only
  + b x' + c y'   	: order 1     + affine transf.
  + d x' y'             : order 2     + bilinear transf.
  + e x' x' + f y' y'   : order 3     + quadratic transf.

y = y' + g            
  + h y' + i x'   
  + j y' x'             
  + k y' y' + l x' x'  

input matrix:

  a g
  --
  b h
  c i
  --
  d j
  --
  e k
  f l

matrix height may be 1, 3, 4, 6

 */

typedef struct _VipsQuadratic {
	VipsResample parent_instance;

	VipsImage *coeff;
	VipsInterpolate *interpolate;

	/* The coeff array argment, made into an in-memory double.
	 */
	VipsImage *mat;

	/* Transform order.
	 */
	int order;
} VipsQuadratic;

typedef VipsResampleClass VipsQuadraticClass;

G_DEFINE_TYPE( VipsQuadratic, vips_quadratic, VIPS_TYPE_RESAMPLE );

static void
vips_quadratic_dispose( GObject *gobject )
{
	VipsQuadratic *quadratic = (VipsQuadratic *) gobject;

	VIPS_UNREF( quadratic->mat ); 

	G_OBJECT_CLASS( vips_quadratic_parent_class )->dispose( gobject );
}

static int
vips_quadratic_gen( VipsRegion *or, void *vseq, 
	void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsQuadratic *quadratic = (VipsQuadratic *) b;
	VipsResample *resample = VIPS_RESAMPLE( quadratic );
	VipsInterpolateMethod interpolate_fn = 
		vips_interpolate_get_method( quadratic->interpolate );

	/* @in is the enlarged image (borders on, after vips_embed()). Use
	 * @resample->in for the original, not-expanded image. 
	 */
	const VipsImage *in = (VipsImage *) a;

	const int ps = VIPS_IMAGE_SIZEOF_PEL( in );

	double *vec = VIPS_MATRIX( quadratic->mat, 0, 0 );

	int clip_width = resample->in->Xsize;
	int clip_height = resample->in->Ysize;

	int xlow = or->valid.left;
	int ylow = or->valid.top;
	int xhigh = VIPS_RECT_RIGHT( &or->valid );
	int yhigh = VIPS_RECT_BOTTOM( &or->valid );

	VipsPel *q;

	int xo, yo;		/* output coordinates, dstimage */
	int z;
	double fxi, fyi; 	/* input coordinates */
	double dx, dy;        	/* xo derivative of input coord. */
	double ddx, ddy;      	/* 2nd xo derivative of input coord. */

	VipsRect image;

	image.left = 0;
	image.top = 0;
	image.width = in->Xsize;
	image.height = in->Ysize;
	if( vips_region_image( ir, &image ) )
		return( -1 );

	for( yo = ylow; yo < yhigh; yo++ ) {
		fxi = 0.0;
		fyi = 0.0;
		dx = 0.0;
		dy = 0.0;
		ddx = 0.0;
		ddy = 0.0;

		switch( quadratic->order ) {
		case 3: 
			fxi += vec[10] * yo * yo + vec[8] * xlow * xlow;
			fyi += vec[11] * yo * yo + vec[9] * xlow * xlow;
			dx += vec[8];
			ddx += vec[8] * 2.0;
			dy += vec[9];
			ddy += vec[9] * 2.0;

		case 2: 
			fxi += vec[6] * xlow * yo;
			fyi += vec[7] * xlow * yo;
			dx += vec[6] * yo;
			dy += vec[7] * yo;

		case 1: 
			fxi += vec[4] * yo + vec[2] * xlow;
			fyi += vec[5] * yo + vec[3] * xlow;
			dx += vec[2];
			dy += vec[3];

		case 0: 
			fxi += vec[0];
			fyi += vec[1];    
			break;

		default:
		    	g_assert_not_reached();
		}

		printf( "dx = %g, dy = %g\n", dx, dy );

		q = VIPS_REGION_ADDR( or, xlow, yo );

		for( xo = xlow; xo < xhigh; xo++ ) {
			int xi, yi; 	

			xi = fxi;
			yi = fyi;

			/* Clipping! 
			 */
			if( xi < 0 || 
				yi < 0 || 
				xi >= clip_width || 
				yi >= clip_height ) {
				for( z = 0; z < ps; z++ ) 
					q[z] = 0;
			}
			else 
				interpolate_fn( quadratic->interpolate, 
					q, ir, fxi, fyi );

			q += ps;

			fxi += dx;
			fyi += dy;

			if( quadratic->order > 2 ) {
				dx += ddx;
				dy += ddy;
			}
		}
	}

	return( 0 );
}

static int
vips_quadratic_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsQuadratic *quadratic = (VipsQuadratic *) object;

	VipsInterpolate *interpolate;
	int window_size;
	int window_offset;
	VipsImage *in;
	VipsImage *t;

	if( VIPS_OBJECT_CLASS( vips_quadratic_parent_class )->build( object ) )
		return( -1 );

	/* We have the whole of the input in memory, so we can generate any
	 * output.
	 */
	if( vips_image_pipelinev( resample->out, 
		VIPS_DEMAND_STYLE_ANY, resample->in, NULL ) )
		return( -1 );

	in = resample->in;

        if( vips_check_uncoded( class->nickname, in ) ||
		vips_check_noncomplex( class->nickname, in ) ||
		vips_check_matrix( class->nickname, 
			quadratic->coeff, &quadratic->mat  ) )
                return( -1 );

	if( quadratic->mat->Xsize != 2 ) {
		vips_error( class->nickname, 
			"%s", _( "coefficient matrix must have width 2" ) ); 
		return( -1 );
	} 
        switch( quadratic->mat->Ysize ) {
	case 1: 
		quadratic->order = 0; 
		break;

	case 3: 
		quadratic->order = 1; 
		break;

	case 4: 
		quadratic->order = 2; 
		break;

	case 6: 
		quadratic->order = 3; 
		break;

	default:
		vips_error( class->nickname, 
			"%s", _( "coefficient matrix must have height "
				"1, 3, 4 or 6" ) );
		return( -1 );
	} 

	if( !vips_object_argument_isset( object, "interpolator" ) )
		quadratic->interpolate = vips_interpolate_new( "bilinear" );
	interpolate = quadratic->interpolate;

	window_size = vips_interpolate_get_window_size( interpolate );
	window_offset = vips_interpolate_get_window_offset( interpolate );

	/* Enlarge the input image. 
	 */
	if( vips_embed( in, &t, 
		window_offset, window_offset, 
		in->Xsize + window_size, in->Ysize + window_size,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	vips_object_local( object, t );
	in = t;

        /* We need random access to our input.
         */
        if( !(t = vips_image_copy_memory( in )) )
                return( -1 );
	vips_object_local( object, t );
	in = t;

	if( vips_image_generate( resample->out,
		vips_start_one, vips_quadratic_gen, vips_stop_one, 
			in, quadratic ) )
		return( -1 );

        return( 0 );
}

static void
vips_quadratic_class_init( VipsQuadraticClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_quadratic_class_init\n" );

	gobject_class->dispose = vips_quadratic_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "quadratic";
	vobject_class->description = 
		_( "resample an image with a quadratic transform" );
	vobject_class->build = vips_quadratic_build;

	VIPS_ARG_IMAGE( class, "coeff", 8, 
		_( "Coeff" ), 
		_( "Coefficient matrix" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsQuadratic, coeff ) );

	VIPS_ARG_INTERPOLATE( class, "interpolate", 9, 
		_( "Interpolate" ), 
		_( "Interpolate values with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsQuadratic, interpolate ) );
}

static void
vips_quadratic_init( VipsQuadratic *quadratic )
{
}

/**
 * vips_quadratic:
 * @in: input image
 * @out: output image
 * @coeff: horizontal quadratic
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @interpolate: use this interpolator (default bilinear)
 *
 * This operation is unfinished and unusable, sorry. 
 *
 * See also: vips_affine().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_quadratic( VipsImage *in, VipsImage **out, VipsImage *coeff, ... )
{
	va_list ap;
	int result;

	va_start( ap, coeff );
	result = vips_call_split( "quadratic", ap, in, out, coeff );
	va_end( ap );

	return( result );
}
