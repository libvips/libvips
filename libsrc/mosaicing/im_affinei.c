/* @(#) im_affine() ... affine transform with a supplied interpolator.
 * @(#)
 * @(#) int im_affinei(in, out, interpolate, a, b, c, d, dx, dy, w, h, x, y)
 * @(#)
 * @(#) IMAGE *in, *out;
 * @(#) VipsInterpolate *interpolate;
 * @(#) double a, b, c, d, dx, dy;
 * @(#) int w, h, x, y;
 * @(#)
 * @(#) Forward transform
 * @(#) X = a * x + b * y + dx
 * @(#) Y = c * x + d * y + dy
 * @(#)
 * @(#) x and y are the coordinates in input image.  
 * @(#) X and Y are the coordinates in output image.
 * @(#) (0,0) is the upper left corner.
 * 
 * Copyright N. Dessipris
 * Written on: 01/11/1991
 * Modified on: 12/3/92 JC
 *	- rounding error in interpolation routine fixed
 *	- test for scale=1, angle=0 case fixed
 *	- clipping of output removed: redundant
 *	- various little tidies
 *	- problems remain with scale>20, size<10
 *
 * Re-written on: 20/08/92, J.Ph Laurent
 *
 * 21/02/93, JC
 *	- speed-ups
 * 	- simplifications
 *	- im_similarity now calculates a window and calls this routine
 * 6/7/93 JC
 *	- rewritten for partials
 *	- ANSIfied
 *	- now rotates any non-complex type
 * 3/6/94 JC
 *	- C revised in bug search
 * 9/6/94 JC
 *	- im_prepare() was preparing too small an area! oops
 * 22/5/95 JC
 *	- added code to detect all-black output area case - helps lazy ip
 * 3/7/95 JC
 *	- IM_CODING_LABQ handling moved to here
 * 31/7/97 JC
 * 	- dx/dy sign reversed to be less confusing ... now follows comment at
 * 	  top ... ax - by + dx etc.
 *	- tiny speed up, replaced the *++ on interpolation with [z]
 *	- im_similarity() moved in here
 *	- args swapped: was whxy, now xywh
 *	- didn't agree with dispatch fns before :(
 * 3/3/98 JC
 *	- im_demand_hint() added
 * 20/12/99 JC
 *	- im_affine() made from im_similarity_area()
 *	- transform stuff cleaned up a bit
 * 14/4/01 JC
 *	- oops, invert_point() had a rounding problem
 * 23/2/02 JC
 *	- pre-calculate interpolation matricies
 *	- integer interpolation for int8/16 types, double for
 *	  int32/float/double
 *	- faster transformation 
 * 15/8/02 JC
 *	- records Xoffset/Yoffset
 * 14/4/04
 *	- rounding, clipping and transforming revised, now pixel-perfect (or 
 *	  better than gimp, anyway)
 * 22/6/05
 *	- all revised again, simpler and more reliable now
 * 30/3/06
 * 	- gah, still an occasional clipping problem
 * 12/7/06
 * 	- still more tweaking, gah again
 * 7/10/06
 * 	- set THINSTRIP for no-rotate affines
 * 20/10/08
 * 	- version with interpolate parameter, from im_affine()
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
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "merge.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* "fast" floor() ... on my laptop, anyway.
 */
#define FLOOR( V ) ((V) >= 0 ? (int)(V) : (int)((V) - 1))

/* Map a point through the inverse transform. Used for clipping calculations,
 * so it takes account of iarea and oarea.
 */
static void
invert_point( Transformation *trn, 
	double x, double y,		/* In output space */
	double *ox, double *oy )	/* In input space */
{
	double xin = x - trn->oarea.left - trn->dx;
	double yin = y - trn->oarea.top - trn->dy;

	/* Find the inverse transform of current (x, y) 
	 */
	*ox = trn->ia * xin + trn->ib * yin;
	*oy = trn->ic * xin + trn->id * yin;
}

/* Given a bounding box for an area in the output image, set the bounding box
 * for the corresponding pixels in the input image.
 */
static void
invert_rect( Transformation *trn, 
	Rect *in, 		/* In output space */
	Rect *out )		/* In input space */
{	
	double x1, y1;		/* Map corners */
	double x2, y2;
	double x3, y3;
	double x4, y4;
	double left, right, top, bottom;

	/* Map input Rect.
	 */
	invert_point( trn, in->left, in->top, &x1, &y1 );
	invert_point( trn, in->left, IM_RECT_BOTTOM(in), &x2, &y2 );
	invert_point( trn, IM_RECT_RIGHT(in), in->top, &x3, &y3 );
	invert_point( trn, IM_RECT_RIGHT(in), IM_RECT_BOTTOM(in), &x4, &y4 );

	/* Find bounding box for these four corners.
	 */
	left = IM_MIN( x1, IM_MIN( x2, IM_MIN( x3, x4 ) ) );
	right = IM_MAX( x1, IM_MAX( x2, IM_MAX( x3, x4 ) ) );
	top = IM_MIN( y1, IM_MIN( y2, IM_MIN( y3, y4 ) ) );
	bottom = IM_MAX( y1, IM_MAX( y2, IM_MAX( y3, y4 ) ) );

	/* Set output Rect.
	 */
	out->left = left;
	out->top = top;
	out->width = right - left + 1;
	out->height = bottom - top + 1;

}

/* Per-call state.
 */
typedef struct _Affine {
	IMAGE *in;
	IMAGE *out;
	VipsInterpolate *interpolate;
	Transformation trn;
} Affine;

static int
affine_free( Affine *affine )
{
	IM_FREEF( g_object_unref, affine->interpolate );

	return( 0 );
}

static int
affinei_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE *in = (IMAGE *) a;
	Affine *affine = (Affine *) b;
	const int window_size = 
		vips_interpolate_get_window_size( affine->interpolate );
	const int half_window_size = window_size / 2;
	VipsInterpolateMethod interpolate = 
		vips_interpolate_get_method( affine->interpolate );

	/* Output area for this call.
	 */
	Rect *r = &or->valid;
	int le = r->left;
	int ri = IM_RECT_RIGHT(r);
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	Rect *iarea = &affine->trn.iarea;
	Rect *oarea = &affine->trn.oarea;
	int ps = IM_IMAGE_SIZEOF_PEL( in );
	int x, y, z;
	
	/* Clipping Rects.
	 */
	Rect image, need, clipped;

	/* Find the area of the input image we need.
	 */
	image.left = 0;
	image.top = 0;
	image.width = in->Xsize;
	image.height = in->Ysize;
	invert_rect( &affine->trn, r, &need );

	/* Add a border for interpolation. You'd think +1 would do it, but 
	 * we need to allow for rounding clipping as well.
	 */
	im_rect_marginadjust( &need, window_size );

	im_rect_intersectrect( &need, &image, &clipped );

	/* Outside input image? All black.
	 */
	if( im_rect_isempty( &clipped ) ) {
		im__black_region( or );
		return( 0 );
	}

	/* We do need some pixels from the input image to make our output -
	 * ask for them.
	 */
	if( im_prepare( ir, &clipped ) )
		return( -1 );

#ifdef DEBUG
	printf( "affine: preparing left=%d, top=%d, width=%d, height=%d\n", 
		clipped.left,
		clipped.top,
		clipped.width,
		clipped.height );
#endif /*DEBUG*/

	/* Resample!
	 */
	for( y = to; y < bo; y++ ) {
		/* Continuous cods in output space.
		 */
		double oy = y - oarea->top - affine->trn.dy;
		double ox;

		/* Input clipping rectangle.
		 */
		int ile = iarea->left;
		int ito = iarea->top;
		int iri = iarea->left + iarea->width;
		int ibo = iarea->top + iarea->height;
	
		/* Derivative of matrix.
		 */
		double dx = affine->trn.ia;
		double dy = affine->trn.ic;

		/* Continuous cods in input space.
		 */
		double ix, iy;

		PEL *q;

		ox = le - oarea->left - affine->trn.dx;

		ix = affine->trn.ia * ox + affine->trn.ib * oy;
		iy = affine->trn.ic * ox + affine->trn.id * oy;

		/* Offset ix/iy input by iarea.left/top ... so we skip the
		 * image edges we added for interpolation. 
		 */
		ix += iarea->left;
		iy += iarea->top;

		q = (PEL *) IM_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			int fx, fy; 	

			fx = FLOOR( ix );
			fy = FLOOR( iy );

			/* Clipping! Use >= for right/bottom, since IPOL needs
			 * to see one pixel more each way.
			 */
			if( fx <= ile - half_window_size || 
				fx >= iri + half_window_size || 
				fy <= ito - half_window_size || 
				fy >= ibo + half_window_size ) {
				for( z = 0; z < ps; z++ ) 
					q[z] = 0;
			}
			else {
				interpolate( affine->interpolate, 
					or, ir, 
					x, y, ix, iy );
			}

			ix += dx;
			iy += dy;
			q += ps;
		}
	}

	return( 0 );
}

static int 
affinei( IMAGE *in, IMAGE *out, 
	VipsInterpolate *interpolate, Transformation *trn )
{
	Affine *affine;
	double edge;

	if( im_iscomplex( in ) ) {
		im_error( "im_affinei", 
			"%s", _( "complex input not supported" ) );
		return( -1 );
	}

	/* Make output image.
	 */
	if( im_piocheck( in, out ) ) 
		return( -1 );
	if( im_cp_desc( out, in ) ) 
		return( -1 );

	/* Need a copy of the params for the lifetime of out.
	 */
	if( !(affine = IM_NEW( out, Affine )) )
		return( -1 );
	affine->interpolate = NULL;
	if( im_add_close_callback( out, 
		(im_callback_fn) affine_free, affine, NULL ) )
		return( -1 );
	affine->in = in;
	affine->out = out;
	affine->interpolate = interpolate;
	g_object_ref( interpolate );
	affine->trn = *trn;

	/* We output at (0,0), so displace output by that amount -ve to get
	 * output at (ox,oy). Alter our copy of trn.
	 */
	affine->trn.oarea.left = -affine->trn.oarea.left;
	affine->trn.oarea.top = -affine->trn.oarea.top;

	if( im__transform_calc_inverse( &affine->trn ) )
		return( -1 );

	out->Xsize = affine->trn.oarea.width;
	out->Ysize = affine->trn.oarea.height;

	/* Normally SMALLTILE ... except if this is a size up/down affine.
	 */
	if( affine->trn.b == 0.0 && affine->trn.c == 0.0 ) {
		if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
			return( -1 );
	}
	else {
		if( im_demand_hint( out, IM_SMALLTILE, in, NULL ) )
			return( -1 );
	}

	/* Check for coordinate overflow ... we want to be able to hold the
	 * output space inside INT_MAX / TRANSFORM_SCALE.
	 */
	edge = INT_MAX / VIPS_TRANSFORM_SCALE;
	if( affine->trn.oarea.left < -edge || affine->trn.oarea.top < -edge ||
		IM_RECT_RIGHT( &affine->trn.oarea ) > edge || 
		IM_RECT_BOTTOM( &affine->trn.oarea ) > edge ) {
		im_error( "im_affinei", 
			"%s", _( "output coordinates out of range" ) );
		return( -1 );
	}

	/* Generate!
	 */
	if( im_generate( out, 
		im_start_one, affinei_gen, im_stop_one, in, affine ) )
		return( -1 );

	return( 0 );
}

/* As above, but do IM_CODING_LABQ too. And embed the input.
 */
int 
im__affinei( IMAGE *in, IMAGE *out, 
	VipsInterpolate *interpolate, Transformation *trn )
{
	IMAGE *t3 = im_open_local( out, "im_affine:3", "p" );
	const int window_size = vips_interpolate_get_window_size( interpolate );
	Transformation trn2;

#ifdef DEBUG_GEOMETRY
	printf( "im__affinei: %s\n", in->filename );
	im__transform_print( trn );
#endif /*DEBUG_GEOMETRY*/

	/* Add new pixels around the input so we can interpolate at the edges.
	 */
	if( !t3 ||
		im_embed( in, t3, 1, 
			window_size / 2, window_size / 2, 
			in->Xsize + window_size, in->Ysize + window_size ) )
		return( -1 );

	/* Set iarea so we know what part of the input we can take.
	 */
	trn2 = *trn;
	trn2.iarea.left += window_size / 2;
	trn2.iarea.top += window_size / 2;

	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *t1 = im_open_local( out, "im_affine:1", "p" );
		IMAGE *t2 = im_open_local( out, "im_affine:2", "p" );

		if( !t1 || !t2 ||
			im_LabQ2LabS( t3, t1 ) ||
			affinei( t1, t2, interpolate, &trn2 ) ||
			im_LabS2LabQ( t2, out ) )
			return( -1 );
	}
	else if( in->Coding == IM_CODING_NONE ) {
		if( affinei( t3, out, interpolate, &trn2 ) )
			return( -1 );
	}
	else {
		im_error( "im_affinei", "%s", _( "unknown coding type" ) );
		return( -1 );
	}

	/* Finally: can now set Xoffset/Yoffset.
	 */
	out->Xoffset = trn->dx - trn->oarea.left;
	out->Yoffset = trn->dy - trn->oarea.top;

	return( 0 );
}

int 
im_affinei( IMAGE *in, IMAGE *out, VipsInterpolate *interpolate,
	double a, double b, double c, double d, 
	double dx, double dy, 
	int ox, int oy, int ow, int oh )
{
	Transformation trn;

	trn.iarea.left = 0;
	trn.iarea.top = 0;
	trn.iarea.width = in->Xsize;
	trn.iarea.height = in->Ysize;

	trn.oarea.left = ox;
	trn.oarea.top = oy;
	trn.oarea.width = ow;
	trn.oarea.height = oh;

	trn.a = a;
	trn.b = b;
	trn.c = c;
	trn.d = d;
	trn.dx = dx;
	trn.dy = dy;

	return( im__affinei( in, out, interpolate, &trn ) );
}
