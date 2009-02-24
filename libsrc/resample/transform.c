/* affine transforms
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
 */
#define DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/transform.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Calculate the inverse transformation.
 */
int
im__transform_calc_inverse( Transformation *trn )
{
	DOUBLEMASK *msk, *msk2;

	if( !(msk = im_create_dmaskv( "boink", 2, 2, 
		trn->a, trn->b, trn->c, trn->d )) )
		return( -1 );
	if( !(msk2 = im_matinv( msk, "boink2" )) ) {
		(void) im_free_dmask( msk );
		return( -1 );
	}
	trn->ia = msk2->coeff[0];
	trn->ib = msk2->coeff[1];
	trn->ic = msk2->coeff[2];
	trn->id = msk2->coeff[3];
	(void) im_free_dmask( msk );
	(void) im_free_dmask( msk2 );

	return( 0 );
}

/* Init a Transform.
 */
void
im__transform_init( Transformation *trn )
{
	trn->oarea.left = 0;
	trn->oarea.top = 0;
	trn->oarea.width = -1;
	trn->oarea.height = -1;
	trn->iarea.left = 0;
	trn->iarea.top = 0;
	trn->iarea.width = -1;
	trn->iarea.height = -1;
	trn->a = 1.0;	/* Identity transform */
	trn->b = 0.0;
	trn->c = 0.0;
	trn->d = 1.0;
	trn->dx = 0.0;
	trn->dy = 0.0;

	(void) im__transform_calc_inverse( trn );
}

/* Test for transform is identity function.
 */
int
im__transform_isidentity( const Transformation *trn )
{
	if( trn->a == 1.0 && trn->b == 0.0 && trn->c == 0.0 &&
		trn->d == 1.0 && trn->dx == 0.0 && trn->dy == 0.0 )
		return( 1 );
	else
		return( 0 );
}

/* Combine two transformations. out can be one of the ins.
 */
int
im__transform_add( const Transformation *in1, const Transformation *in2, 
	Transformation *out )
{
	out->a = in1->a * in2->a + in1->c * in2->b;
	out->b = in1->b * in2->a + in1->d * in2->b;
	out->c = in1->a * in2->c + in1->c * in2->d;
	out->d = in1->b * in2->c + in1->d * in2->d;

	out->dx = in1->dx * in2->a + in1->dy * in2->b + in2->dx;
	out->dy = in1->dx * in2->c + in1->dy * in2->d + in2->dy;

	if( im__transform_calc_inverse( out ) )
		return( -1 );

	return( 0 );
}

void 
im__transform_print( const Transformation *trn )
{
	printf( "im__transform_print:\n" );
	printf( " iarea: left=%d, top=%d, width=%d, height=%d\n",
		trn->iarea.left,
		trn->iarea.top,
		trn->iarea.width,
		trn->iarea.height );
	printf( " oarea: left=%d, top=%d, width=%d, height=%d\n",
		trn->oarea.left,
		trn->oarea.top,
		trn->oarea.width,
		trn->oarea.height );
	printf( " mat: a=%g, b=%g, c=%g, d=%g\n",
		trn->a, trn->b, trn->c, trn->d );
	printf( " off: dx=%g, dy=%g\n",
		trn->dx, trn->dy );
}

/* Map a pixel coordinate through the transform. 
 */
void
im__transform_forward_point( const Transformation *trn, 
	const double x, const double y,		/* In input space */
	double *ox, double *oy )	/* In output space */
{
	*ox = trn->a * x + trn->b * y + trn->dx;
	*oy = trn->c * x + trn->d * y + trn->dy;
}

/* Map a pixel coordinate through the inverse transform. 
 */
void
im__transform_invert_point( const Transformation *trn, 
	const double x, const double y,		/* In output space */
	double *ox, double *oy )	/* In input space */
{
	double mx = x - trn->dx;
	double my = y - trn->dy;

	*ox = trn->ia * mx + trn->ib * my;
	*oy = trn->ic * mx + trn->id * my;
}

typedef void (*transform_fn)( const Transformation *, 
	const double, const double, double*, double* );

/* Transform a rect using a point transformer.
 */
static void
transform_rect( const Transformation *trn, transform_fn transform,
	const Rect *in, 		/* In input space */
	Rect *out )		/* In output space */
{
	double x1, y1;		/* Map corners */
	double x2, y2;
	double x3, y3;
	double x4, y4;
	double left, right, top, bottom;

	/* Map input Rect.
	 */
	transform( trn, in->left, in->top, &x1, &y1 );
	transform( trn, in->left, IM_RECT_BOTTOM( in ), &x3, &y3 );
	transform( trn, IM_RECT_RIGHT( in ), in->top, &x2, &y2 );
	transform( trn, IM_RECT_RIGHT( in ), IM_RECT_BOTTOM( in ), &x4, &y4 );

	/* Find bounding box for these four corners.
	 */
	left = IM_MIN( x1, IM_MIN( x2, IM_MIN( x3, x4 ) ) );
	right = IM_MAX( x1, IM_MAX( x2, IM_MAX( x3, x4 ) ) );
	top = IM_MIN( y1, IM_MIN( y2, IM_MIN( y3, y4 ) ) );
	bottom = IM_MAX( y1, IM_MAX( y2, IM_MAX( y3, y4 ) ) );

	out->left = floor( left );
	out->top = floor( top );
	out->width = ceil( right ) - out->left;
	out->height = ceil( bottom ) - out->top;
}

/* Given an area in the input image, calculate the bounding box for those
 * pixels in the output image.
 */
void
im__transform_forward_rect( const Transformation *trn,
	const Rect *in, 	/* In input space */
	Rect *out )		/* In output space */
{
	transform_rect( trn, im__transform_forward_point, in, out );
}

/* Given an area in the output image, calculate the bounding box for the 
 * corresponding pixels in the input image.
 */
void
im__transform_invert_rect( const Transformation *trn, 
	const Rect *in,		/* In output space */
	Rect *out )		/* In input space */
{
	transform_rect( trn, im__transform_invert_point, in, out );
}

/* Set output area of trn so that it just holds all of our input pels.
 */
void
im__transform_set_area( Transformation *trn )
{
	im__transform_forward_rect( trn, &trn->iarea, &trn->oarea );
}
