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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include "resample.h"

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

/* Inner bilinear interpolation loop. Integer types.
 */
#define IPOL_INNERI( TYPE ) { \
	TYPE *from = (TYPE *) p; \
	TYPE *to = (TYPE *) q; \
	int i; \
	\
	for( i = 0; i < bands; i++ ) { \
		double value = \
			f1 * from[t2 + t4 + i] + \
			f2 * from[t2 + t5 + i] + \
			f3 * from[t3 + t4 + i] + \
			f4 * from[t3 + t5 + i]; \
		to[i] = (int) (value + 0.5); \
	} \
}

/* Inner bilinear interpolation loop. Float types.
 */
#define IPOL_INNERF( TYPE ) { \
	TYPE *from = (TYPE *) p; \
	TYPE *to = (TYPE *) q; \
	int i; \
	\
	for( i = 0; i < bands; i++ ) { \
		double value = \
			f1 * from[t2 + t4 + i] + \
			f2 * from[t2 + t5 + i] + \
			f3 * from[t3 + t4 + i] + \
			f4 * from[t3 + t5 + i]; \
		to[i] = value; \
	} \
}

#define TYPE_SWITCH_IPOL \
	switch( bandfmt ) { \
	case IM_BANDFMT_UCHAR:	IPOL_INNERI( unsigned char ); break; \
	case IM_BANDFMT_USHORT:	IPOL_INNERI( unsigned short ); break; \
	case IM_BANDFMT_UINT:	IPOL_INNERI( unsigned int ); break; \
	case IM_BANDFMT_CHAR:	IPOL_INNERI( signed char ); break; \
	case IM_BANDFMT_SHORT:	IPOL_INNERI( signed short ); break; \
	case IM_BANDFMT_INT:	IPOL_INNERI( signed int ); break; \
	case IM_BANDFMT_FLOAT:	IPOL_INNERF( float ); break; \
	case IM_BANDFMT_DOUBLE:	IPOL_INNERF( double ); break; \
 	\
	default: \
		g_assert( 0 ); \
		/*NOTREACHED*/ \
	}

static int
vips_quadratic_gen( VipsRegion *or, void *vseq, 
	void *a, void *b, gboolean *stop )
{
	const VipsImage *in = (VipsImage *) a;
	VipsQuadratic *quadratic = (VipsQuadratic *) b;
	const int ps = VIPS_IMAGE_SIZEOF_PEL( in );

	double *vec = (double *) VIPS_IMAGE_ADDR( quadratic->mat, 0, 0 );

	int sizex = in->Xsize;
	int sizey = in->Ysize;
	int bands = in->Bands;
	int bandfmt = in->BandFmt;

	const int sizex1 = sizex - 1;
	const int sizey1 = sizey - 1;

	int xlow = or->valid.left;
	int ylow = or->valid.top;
	int xhigh = IM_RECT_RIGHT( &or->valid );
	int yhigh = IM_RECT_BOTTOM( &or->valid );

	PEL *p = VIPS_IMAGE_ADDR( in, 0, 0 );
	PEL *q;

	int xi1, yi1;		/* 1 + input coordinates */
	int xo, yo;		/* output coordinates, dstimage */
	int z;
	double fxi, fyi; 	/* input coordinates */
	double frx, fry;      	/* fractinal part of input coord. */
	double frx1, fry1; 	/* 1.0 - fract. part of input coord. */
	double dx, dy;        	/* xo derivative of input coord. */
	double ddx, ddy;      	/* 2nd xo derivative of input coord. */

	for( yo = ylow; yo < yhigh; yo++ ) {
		fxi = xlow + vec[0];                /* order 0 */
		fyi = yo + vec[1];    
		dx = 1.0;
		dy = 0.0;

		switch( quadratic->order ) {
		case 3: 
			fxi += vec[10] * yo * yo + vec[8] * xlow * xlow;
			fyi += vec[11] * yo * yo + vec[9] * xlow * xlow;
			dx += vec[8];
			ddx = vec[8] * 2.0;
			dy += vec[9];
			ddy = vec[9] * 2.0;

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
			/* See above for order 0.
			 */
			break;

		default:
		    	g_assert( 0 );
		    	return(-7);
		}

		q = (PEL *) IM_REGION_ADDR( or, xlow, yo );

		for( xo = xlow; xo < xhigh; xo++ ) {
			int t1, t2, t3, t4, t5;
			double f1, f2, f3, f4;
			int xi, yi; 	

			xi = fxi;
			yi = fyi;

			/* Clipping! 
			 */
			if( xi < 0 || xi >= sizex1 || yi < 0 || yi >= sizey1 ) {
				for( z = 0; z < ps; z++ ) 
					q[z] = 0;
			}
			else {
				/*
				interpolate( affine->interpolate, 
					q, ir, fxi, fyi );
				 */
				frx = fxi - xi;
				frx1 = 1.0 - frx;
				fry = fyi - yi;
				fry1 = 1.0 - fry;
				xi1 = xi + 1;
				yi1 = yi + 1;

				t1 = sizex * bands;
				t2 = yi * t1;
				t3 = yi1 * t1;
				t4 = xi * bands;
				t5 = xi1 * bands;
				f1 = frx1 * fry1;
				f2 = frx * fry1;
				f3 = frx1 * fry;
				f4 = frx * fry;

				TYPE_SWITCH_IPOL;
			}

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

	/* Default to "bilinear".
	 */
	if( !vips_object_argument_isset( object, "interpolate" ) )
		g_object_set( object, 
			"interpolate", vips_interpolate_new( "bilinear" ), 
			NULL ); 

	if( VIPS_OBJECT_CLASS( vips_quadratic_parent_class )->build( object ) )
		return( -1 );

        /* We need random access to our input.
         */
        if( vips_image_wio_input( resample->in ) )
                return( -1 );
        if( vips_check_uncoded( class->nickname, resample->in ) ||
		vips_check_noncomplex( class->nickname, resample->in ) ||
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

	/* We have the whole of the input in memory, so we can generate any
	 * output.
	 */
	vips_demand_hint( resample->out, 
		VIPS_DEMAND_STYLE_ANY, resample->in, NULL );

	if( vips_image_generate( resample->out,
		NULL, vips_quadratic_gen, NULL, 
		resample->in, quadratic ) )
		return( -1 );

        return( 0 );
}

static void
vips_quadratic_class_init( VipsQuadraticClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_quadratic_class_init\n" );

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
 *
 * Optional arguments:
 *
 * @interpolate: use this interpolator (default bilinear)
 *
 * See also: im_affinei().
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
