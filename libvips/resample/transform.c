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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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

/* Calculate the inverse transformation.
 */
int
vips__transform_calc_inverse( VipsTransformation *trn )
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

/* Init a VipsTransform.
 */
void
vips__transform_init( VipsTransformation *trn )
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
	trn->idx = 0.0;
	trn->idy = 0.0;
	trn->odx = 0.0;
	trn->ody = 0.0;

	(void) vips__transform_calc_inverse( trn );
}

/* Test for transform is identity function.
 */
int
vips__transform_isidentity( const VipsTransformation *trn )
{
	if( trn->a == 1.0 && trn->b == 0.0 && 
		trn->c == 0.0 && trn->d == 1.0 && 
		trn->idx == 0.0 && trn->idy == 0.0 &&
		trn->odx == 0.0 && trn->ody == 0.0 )
		return( 1 );
	else
		return( 0 );
}

/* Combine two transformations. out can be one of the ins.
 */
int
vips__transform_add( const VipsTransformation *in1, 
	const VipsTransformation *in2, VipsTransformation *out )
{
	out->a = in1->a * in2->a + in1->c * in2->b;
	out->b = in1->b * in2->a + in1->d * in2->b;
	out->c = in1->a * in2->c + in1->c * in2->d;
	out->d = in1->b * in2->c + in1->d * in2->d;

	// fixme: do idx/idy as well

	out->odx = in1->odx * in2->a + in1->ody * in2->b + in2->odx;
	out->ody = in1->odx * in2->c + in1->ody * in2->d + in2->ody;

	if( vips__transform_calc_inverse( out ) )
		return( -1 );

	return( 0 );
}

void 
vips__transform_print( const VipsTransformation *trn )
{
	printf( "vips__transform_print:\n" );
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
	printf( " off: odx=%g, ody=%g, idx=%g, idy=%g\n",
		trn->odx, trn->ody, trn->idx, trn->idy );
}

/* Map a pixel coordinate through the transform. 
 */
void
vips__transform_forward_point( const VipsTransformation *trn, 
	double x, double y,	/* In input space */
	double *ox, double *oy )/* In output space */
{
	x += trn->idx;
	y += trn->idy;

	*ox = trn->a * x + trn->b * y + trn->odx;
	*oy = trn->c * x + trn->d * y + trn->ody;
}

/* Map a pixel coordinate through the inverse transform. 
 */
void
vips__transform_invert_point( const VipsTransformation *trn, 
	double x, double y,	/* In output space */
	double *ox, double *oy )/* In input space */
{
	x -= trn->odx;
	y -= trn->ody;

	*ox = trn->ia * x + trn->ib * y - trn->idx;
	*oy = trn->ic * x + trn->id * y - trn->idy;
}

typedef void (*transform_fn)( const VipsTransformation *, 
	const double, const double, double*, double* );

/* Transform a rect using a point transformer.
 */
static void
transform_rect( const VipsTransformation *trn, transform_fn transform,
	const VipsRect *in,	/* In input space */
	VipsRect *out )		/* In output space */
{
	double x1, y1;		/* Map corners */
	double x2, y2;
	double x3, y3;
	double x4, y4;
	double left, right, top, bottom;

	/* Map input VipsRect.
	 */
	transform( trn, in->left, in->top, 
		&x1, &y1 );
	transform( trn, in->left, VIPS_RECT_BOTTOM( in ), 
		&x3, &y3 );
	transform( trn, VIPS_RECT_RIGHT( in ), in->top, 
		&x2, &y2 );
	transform( trn, VIPS_RECT_RIGHT( in ), VIPS_RECT_BOTTOM( in ), 
		&x4, &y4 );

	/* Find bounding box for these four corners. Round-to-nearest to try
	 * to stop rounding errors growing images.
	 */
	left = VIPS_MIN( x1, VIPS_MIN( x2, VIPS_MIN( x3, x4 ) ) );
	right = VIPS_MAX( x1, VIPS_MAX( x2, VIPS_MAX( x3, x4 ) ) );
	top = VIPS_MIN( y1, VIPS_MIN( y2, VIPS_MIN( y3, y4 ) ) );
	bottom = VIPS_MAX( y1, VIPS_MAX( y2, VIPS_MAX( y3, y4 ) ) );

	out->left = VIPS_ROUND_INT( left );
	out->top = VIPS_ROUND_INT( top );
	out->width = VIPS_ROUND_INT( right - left );
	out->height = VIPS_ROUND_INT( bottom - top );
}

/* Given an area in the input image, calculate the bounding box for those
 * pixels in the output image.
 */
void
vips__transform_forward_rect( const VipsTransformation *trn,
	const VipsRect *in, 	/* In input space */
	VipsRect *out )		/* In output space */
{
	transform_rect( trn, vips__transform_forward_point, in, out );
}

/* Given an area in the output image, calculate the bounding box for the 
 * corresponding pixels in the input image.
 */
void
vips__transform_invert_rect( const VipsTransformation *trn, 
	const VipsRect *in,	/* In output space */
	VipsRect *out )		/* In input space */
{
	transform_rect( trn, vips__transform_invert_point, in, out );
}

/* Set output area of trn so that it just holds all of our input pels.
 */
void
vips__transform_set_area( VipsTransformation *trn )
{
	vips__transform_forward_rect( trn, &trn->iarea, &trn->oarea );
}
