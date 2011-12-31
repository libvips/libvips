/* im_affine() ... affine transform with a supplied interpolator.
 *
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
 * 30/10/08
 * 	- allow complex image types
 * 4/11/08
 * 	- take an interpolator as a param
 * 	- replace im_affine with this, provide an im_affine() compat wrapper
 * 	- break transform stuff out to transform.c
 * 	- revise clipping / transform stuff, again
 * 	- now do corner rather than centre: this way the identity transform
 * 	  returns the input exactly
 * 12/8/10
 * 	- revise window_size / window_offset stuff again, see also
 * 	  interpolate.c
 * 2/2/11
 * 	- gtk-doc
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
#include <vips/transform.h>

/*
 * FAST_PSEUDO_FLOOR is a floor and floorf replacement which has been
 * found to be faster on several linux boxes than the library
 * version. It returns the floor of its argument unless the argument
 * is a negative integer, in which case it returns one less than the
 * floor. For example:
 *
 * FAST_PSEUDO_FLOOR(0.5) = 0
 *
 * FAST_PSEUDO_FLOOR(0.) = 0
 *
 * FAST_PSEUDO_FLOOR(-.5) = -1
 *
 * as expected, but
 *
 * FAST_PSEUDO_FLOOR(-1.) = -2
 *
 * The locations of the discontinuities of FAST_PSEUDO_FLOOR are the
 * same as floor and floorf; it is just that at negative integers the
 * function is discontinuous on the right instead of the left.
 */
#define FAST_PSEUDO_FLOOR(x) ( (int)(x) - ( (x) < 0. ) )

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

/* We have five (!!) coordinate systems. Working forward through them, these
 * are:
 *
 * 1. The original input image
 *
 * 2. This is embedded in a larger image to provide borders for the
 * interpolator. iarea->left/top give the offset. These are the coordinates we
 * pass to IM_REGION_ADDR()/im_prepare() for the input image. 
 *
 * The borders are sized by the interpolator's window_size property and offset 
 * by the interpolator's window_offset property. For example,
 * for bilinear (window_size 2, window_offset 0) we add a single line 
 * of extra pixels along the bottom and right (window_size - 1). For 
 * bicubic (window_size 4, window_offset 1) we add a single line top and left 
 * (window_offset), and two lines bottom and right (window_size - 1 -
 * window_offset).
 *
 * 3. We need point (0, 0) in (1) to be at (0, 0) for the transformation. So
 * shift everything up and left to make the displaced input image. This is the
 * space that the transformation maps from, and can have negative pixels 
 * (up and left of the image, for interpolation).
 *
 * 4. Output transform space. This is the where the transform maps to. Pixels
 * can be negative, since a rotated image can go up and left of the origin.
 *
 * 5. Output image space. This is the wh of the xywh passed to im_affine()
 * below. These are the coordinates we pass to IM_REGION_ADDR() for the 
 * output image, and that affinei_gen() is asked for.
 */

static int
affinei_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	const IMAGE *in = (IMAGE *) a;
	const Affine *affine = (Affine *) b;
	const int window_size = 
		vips_interpolate_get_window_size( affine->interpolate );
	const int window_offset = 
		vips_interpolate_get_window_offset( affine->interpolate );
	const VipsInterpolateMethod interpolate = 
		vips_interpolate_get_method( affine->interpolate );

	/* Area we generate in the output image.
	 */
	const Rect *r = &or->valid;
	const int le = r->left;
	const int ri = IM_RECT_RIGHT( r );
	const int to = r->top;
	const int bo = IM_RECT_BOTTOM( r );

	const Rect *iarea = &affine->trn.iarea;
	const Rect *oarea = &affine->trn.oarea;

	int ps = IM_IMAGE_SIZEOF_PEL( in );
	int x, y, z;
	
	Rect image, want, need, clipped;

#ifdef DEBUG
	printf( "affine: generating left=%d, top=%d, width=%d, height=%d\n", 
		r->left,
		r->top,
		r->width,
		r->height );
#endif /*DEBUG*/

	/* We are generating this chunk of the transformed image.
	 */
	want = *r;
	want.left += oarea->left;
	want.top += oarea->top;

	/* Find the area of the input image we need.
	 */
	im__transform_invert_rect( &affine->trn, &want, &need );

	/* That does round-to-nearest, because it has to stop rounding errors
	 * growing images unexpectedly. We need round-down, so we must
	 * add half a pixel along the left and top. But we are int :( so add 1
	 * pixel. 
	 *
	 * Add an extra line along the right and bottom as well, for rounding.
	 */
	im_rect_marginadjust( &need, 1 );

	/* Now go to space (2) above.
	 */
	need.left += iarea->left;
	need.top += iarea->top;

	/* Add a border for interpolation. 
	 */
	need.width += window_size - 1;
	need.height += window_size - 1;
	need.left -= window_offset; 
	need.top -= window_offset;

	/* Clip against the size of (2).
	 */
	image.left = 0;
	image.top = 0;
	image.width = in->Xsize;
	image.height = in->Ysize;
	im_rect_intersectrect( &need, &image, &clipped );

	/* Outside input image? All black.
	 */
	if( im_rect_isempty( &clipped ) ) {
		im_region_black( or );
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

	/* Resample! x/y loop over pixels in the output image (5).
	 */
	for( y = to; y < bo; y++ ) {
		/* Input clipping rectangle. 
		 */
		const int ile = iarea->left;
		const int ito = iarea->top;
		const int iri = iarea->left + iarea->width;
		const int ibo = iarea->top + iarea->height;

		/* Derivative of matrix.
		 */
		const double ddx = affine->trn.ia;
		const double ddy = affine->trn.ic;

		/* Continuous cods in transformed space.
		 */
		const double ox = le + oarea->left - affine->trn.dx;
		const double oy = y + oarea->top - affine->trn.dy;

		/* Continuous cods in input space.
		 */
		double ix, iy;

		VipsPel *q;

		/* To (3).
		 */
		ix = affine->trn.ia * ox + affine->trn.ib * oy;
		iy = affine->trn.ic * ox + affine->trn.id * oy;

		/* Now move to (2).
		 */
		ix += iarea->left;
		iy += iarea->top;

		q = IM_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			int fx, fy; 	

			fx = FAST_PSEUDO_FLOOR( ix );
			fy = FAST_PSEUDO_FLOOR( iy );

			/* Clipping! 
			 */
			if( fx < ile || fx >= iri || fy < ito || fy >= ibo ) {
				for( z = 0; z < ps; z++ ) 
					q[z] = 0;
			}
			else {
				interpolate( affine->interpolate, 
					q, ir, ix, iy );
			}

			ix += ddx;
			iy += ddy;
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

	/* Make output image.
	 */
	if( im_piocheck( in, out ) || 
		im_cp_desc( out, in ) ) 
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
static int 
im__affinei( IMAGE *in, IMAGE *out, 
	VipsInterpolate *interpolate, Transformation *trn )
{
	IMAGE *t3 = im_open_local( out, "im_affine:3", "p" );
	const int window_size = 
		vips_interpolate_get_window_size( interpolate );
	const int window_offset = 
		vips_interpolate_get_window_offset( interpolate );
	Transformation trn2;

	/* Add new pixels around the input so we can interpolate at the edges.
	 */
	if( !t3 ||
		im_embed( in, t3, 1, 
			window_offset, window_offset, 
			in->Xsize + window_size, in->Ysize + window_size ) )
		return( -1 );

	/* Set iarea so we know what part of the input we can take.
	 */
	trn2 = *trn;
	trn2.iarea.left += window_offset;
	trn2.iarea.top += window_offset;

#ifdef DEBUG_GEOMETRY
	printf( "im__affinei: %s\n", in->filename );
	im__transform_print( &trn2 );
#endif /*DEBUG_GEOMETRY*/

	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *t[2];

		if( im_open_local_array( out, t, 2, "im_affine:2", "p" ) ||
			im_LabQ2LabS( t3, t[0] ) ||
			affinei( t[0], t[1], interpolate, &trn2 ) ||
			im_LabS2LabQ( t[1], out ) )
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

/**
 * im_affinei:
 * @in: input image
 * @out: output image
 * @interpolate: interpolation method
 * @a: transformation matrix
 * @b: transformation matrix
 * @c: transformation matrix
 * @d: transformation matrix
 * @dx: output offset
 * @dy: output offset
 * @ox: output region
 * @oy: output region
 * @ow: output region
 * @oh: output region
 *
 * This operator performs an affine transform on an image using @interpolate.
 *
 * The transform is:
 *
 *   X = @a * x + @b * y + @dx
 *   Y = @c * x + @d * y + @dy
 * 
 *   x and y are the coordinates in input image.  
 *   X and Y are the coordinates in output image.
 *   (0,0) is the upper left corner.
 *
 * The section of the output space defined by @ox, @oy, @ow, @oh is written to
 * @out. See im_affinei_all() for a function which outputs all the transformed 
 * pixels.
 *
 * See also: im_affinei_all(), #VipsInterpolate.
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_affinei( IMAGE *in, IMAGE *out, VipsInterpolate *interpolate,
	double a, double b, double c, double d, double dx, double dy, 
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


/**
 * im_affinei_all:
 * @in: input image
 * @out: output image
 * @interpolate: interpolation method
 * @a: transformation matrix
 * @b: transformation matrix
 * @c: transformation matrix
 * @d: transformation matrix
 * @dx: output offset
 * @dy: output offset
 *
 * As im_affinei(), but the entire image is output.
 *
 * See also: im_affinei(), #VipsInterpolate.
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_affinei_all( IMAGE *in, IMAGE *out, VipsInterpolate *interpolate,
	double a, double b, double c, double d, double dx, double dy ) 
{
	Transformation trn;

	trn.iarea.left = 0;
	trn.iarea.top = 0;
	trn.iarea.width = in->Xsize;
	trn.iarea.height = in->Ysize;
	trn.a = a;
	trn.b = b;
	trn.c = c;
	trn.d = d;
	trn.dx = dx;
	trn.dy = dy;

	im__transform_set_area( &trn );

	return( im__affinei( in, out, interpolate, &trn ) );
}

/* Still needed by some parts of mosaic.
 */
int 
im__affine( IMAGE *in, IMAGE *out, Transformation *trn )
{
	return( im__affinei( in, out, 
		vips_interpolate_bilinear_static(), trn ) );
}
