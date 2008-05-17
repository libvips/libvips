/* @(#) im_affine() ... affine transform, bi-linear interpolation.
 * @(#)
 * @(#) int im_affine(in, out, a, b, c, d, dx, dy, w, h, x, y)
 * @(#)
 * @(#) IMAGE *in, *out;
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

/* Precalculate a whole bunch of interpolation matricies. int (used for pel
 * sizes up to short), and double (for all others). We go to scale + 1, so
 * we can round-to-nearest safely.

 	FIXME ... should use seperable tables really

 */
static int im_affine_linear_int
	[TRANSFORM_SCALE + 1][TRANSFORM_SCALE + 1][4];
static double im_affine_linear_double
	[TRANSFORM_SCALE + 1][TRANSFORM_SCALE + 1][4];

/* Make sure the interpolation tables are built.
 */
static void
affine_interpol_calc( void )
{
	static int calced = 0;
	int x, y;

	if( calced )
		return;

	for( x = 0; x < TRANSFORM_SCALE + 1; x++ )
		for( y = 0; y < TRANSFORM_SCALE + 1; y++ ) {
			double X, Y, Xd, Yd;
			double c1, c2, c3, c4;

			/* Interpolation errors.
			 */
			X = (double) x / TRANSFORM_SCALE;
			Y = (double) y / TRANSFORM_SCALE;
			Xd = 1.0 - X;	
			Yd = 1.0 - Y;

			/* Weights.
			 */
			c1 = Xd*Yd;
			c2 = X*Yd;
			c3 = X*Y;
			c4 = Xd*Y;

			im_affine_linear_double[x][y][0] = c1;
			im_affine_linear_double[x][y][1] = c2;
			im_affine_linear_double[x][y][2] = c3;
			im_affine_linear_double[x][y][3] = c4;

			im_affine_linear_int[x][y][0] = c1 * INTERPOL_SCALE;
			im_affine_linear_int[x][y][1] = c2 * INTERPOL_SCALE;
			im_affine_linear_int[x][y][2] = c3 * INTERPOL_SCALE;
			im_affine_linear_int[x][y][3] = c4 * INTERPOL_SCALE;
		}

	calced = 1;
}

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
im__transform_isidentity( Transformation *trn )
{
	if( trn->a == 1.0 && trn->b == 0.0 && trn->c == 0.0 &&
		trn->d == 1.0 && trn->dx == 0.0 && trn->dy == 0.0 )
		return( 1 );
	else
		return( 0 );
}

/* Map a pixel coordinate through the transform. 
 */
void
im__transform_forward( Transformation *trn, 
	double x, double y,		/* In input space */
	double *ox, double *oy )	/* In output space */
{
	*ox = trn->a * x + trn->b * y + trn->dx;
	*oy = trn->c * x + trn->d * y + trn->dy;
}

/* Map a pixel coordinate through the inverse transform. 
 */
void
im__transform_inverse( Transformation *trn, 
	double x, double y,		/* In output space */
	double *ox, double *oy )	/* In input space */
{
	double mx = x - trn->dx;
	double my = y - trn->dy;

	*ox = trn->ia * mx + trn->ib * my;
	*oy = trn->ic * mx + trn->id * my;
}

/* Combine two transformations. out can be one of the ins.
 */
int
im__transform_add( Transformation *in1, Transformation *in2, 
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
im__transform_print( Transformation *trn )
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

	/* Add a border for interpolation. You'd think +1 would do it, but 
	 * we need to allow for rounding clipping as well.

		FIXME ... will need adjusting when we add bicubic

	 */
	im_rect_marginadjust( out, 2 );
}

/* Interpolate a section ... int8/16 types.
 */
#define DO_IPEL(TYPE) { \
	TYPE *tq = (TYPE *) q; \
 	\
	int c1 = im_affine_linear_int[xi][yi][0]; \
	int c2 = im_affine_linear_int[xi][yi][1]; \
	int c3 = im_affine_linear_int[xi][yi][2]; \
	int c4 = im_affine_linear_int[xi][yi][3]; \
 	\
	/* p1 points to location (x_int, y_int) \
	 * p2  "      "   "      (x_int+1, y_int) \
	 * p4  "      "   "      (x_int+1, y_int+1) \
	 * p3  "      "   "      (x_int, y_int+1) \
	 */ \
	PEL *p1 = (PEL *) IM_REGION_ADDR( ir, x_int, y_int ); \
	PEL *p2 = p1 + ofs2; \
	PEL *p3 = p1 + ofs3; \
	PEL *p4 = p1 + ofs4; \
	TYPE *tp1 = (TYPE *) p1; \
	TYPE *tp2 = (TYPE *) p2; \
	TYPE *tp3 = (TYPE *) p3; \
	TYPE *tp4 = (TYPE *) p4; \
	\
	/* Interpolate each band. \
	 */ \
	for( z = 0; z < in->Bands; z++ )  \
		tq[z] = (c1*tp1[z] + c2*tp2[z] +  \
			c3*tp3[z] + c4*tp4[z]) >> INTERPOL_SHIFT; \
}

/* Interpolate a pel ... int32 and float types.
 */
#define DO_FPEL(TYPE) { \
	TYPE *tq = (TYPE *) q; \
 	\
	double c1 = im_affine_linear_double[xi][yi][0]; \
	double c2 = im_affine_linear_double[xi][yi][1]; \
	double c3 = im_affine_linear_double[xi][yi][2]; \
	double c4 = im_affine_linear_double[xi][yi][3]; \
	\
	/* p1 points to location (x_int, y_int) \
	 * p2  "      "   "      (x_int+1, y_int) \
	 * p4  "      "   "      (x_int+1, y_int+1) \
	 * p3  "      "   "      (x_int, y_int+1) \
	 */ \
	PEL *p1 = (PEL *) IM_REGION_ADDR( ir, x_int, y_int ); \
	PEL *p2 = p1 + ofs2; \
	PEL *p3 = p1 + ofs3; \
	PEL *p4 = p1 + ofs4; \
	TYPE *tp1 = (TYPE *) p1; \
	TYPE *tp2 = (TYPE *) p2; \
	TYPE *tp3 = (TYPE *) p3; \
	TYPE *tp4 = (TYPE *) p4; \
	\
	/* Interpolate each band. \
	 */ \
	for( z = 0; z < in->Bands; z++ )  \
		tq[z] = c1*tp1[z] + c2*tp2[z] +  \
			c3*tp3[z] + c4*tp4[z]; \
}

static int
affine_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE *in = (IMAGE *) a;
	Transformation *trn = (Transformation *) b;

	/* Output area for this call.
	 */
	Rect *r = &or->valid;
	int le = r->left;
	int ri = IM_RECT_RIGHT(r);
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	Rect *iarea = &trn->iarea;
	Rect *oarea = &trn->oarea;
	int ps = IM_IMAGE_SIZEOF_PEL( in );
	int x, y, z;
	
	/* Interpolation variables. 
	 */
	int ofs2, ofs3, ofs4;

	/* Clipping Rects.
	 */
	Rect image, need, clipped;

	/* Find the area of the input image we need.
	 */
	image.left = 0;
	image.top = 0;
	image.width = in->Xsize;
	image.height = in->Ysize;
	invert_rect( trn, r, &need );
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

	/* Calculate pel offsets.
	 */
	ofs2 = IM_IMAGE_SIZEOF_PEL( in );
	ofs3 = ofs2 + IM_REGION_LSKIP( ir ); 
	ofs4 = IM_REGION_LSKIP( ir );

	/* Resample!
	 */
	for( y = to; y < bo; y++ ) {
		/* Continuous cods in output space.
		 */
		double oy = y - oarea->top - trn->dy;
		double ox;

		/* Input clipping rectangle.
		 */
		int ile = iarea->left;
		int ito = iarea->top;
		int iri = iarea->left + iarea->width;
		int ibo = iarea->top + iarea->height;
	
		/* Derivative of matrix.
		 */
		double dx = trn->ia;
		double dy = trn->ic;

		/* Continuous cods in input space.
		 */
		double ix, iy;

		PEL *q;
		
		q = (PEL *) IM_REGION_ADDR( or, le, y );
		ox = le - oarea->left - trn->dx;

		ix = trn->ia * ox + trn->ib * oy;
		iy = trn->ic * ox + trn->id * oy;

		/* Offset ix/iy input by iarea.left/top ... so we skip the
		 * image edges we added for interpolation. 
		 */
		ix += iarea->left;
		iy += iarea->top;

		for( x = le; x < ri; x++ ) {
			int fx, fy; 	

			fx = FLOOR( ix );
			fy = FLOOR( iy );

			/* Clipping! Use >= for right/bottom, since IPOL needs
			 * to see one pixel more each way.
			 */
			if( fx < ile || fx >= iri || fy < ito || fy >= ibo ) {
				for( z = 0; z < ps; z++ ) 
					q[z] = 0;
			}
			else {
				double sx, sy;
				int x_int, y_int;
				int xi, yi;

				/* Subtract 0.5 to centre the bilinear.

				 	FIXME ... need to adjust for bicubic.

				 */
				sx = ix - 0.5;
				sy = iy - 0.5;

				/* Now go to scaled int. 
				 */
				sx *= TRANSFORM_SCALE;
				sy *= TRANSFORM_SCALE;
				x_int = FLOOR( sx );
				y_int = FLOOR( sy );

				/* Get index into interpolation table and 
				 * unscaled integer position.
				 */
				xi = x_int & (TRANSFORM_SCALE - 1);
				yi = y_int & (TRANSFORM_SCALE - 1);
				x_int = x_int >> TRANSFORM_SHIFT;
				y_int = y_int >> TRANSFORM_SHIFT;

				/* Interpolate for each input type.
				 */
				switch( in->BandFmt ) {
				case IM_BANDFMT_UCHAR: 	
					DO_IPEL( unsigned char ); 
					break;
				case IM_BANDFMT_CHAR: 	
					DO_IPEL( char ); 
					break; 
				case IM_BANDFMT_USHORT: 
					DO_IPEL( unsigned short ); 
					break; 
				case IM_BANDFMT_SHORT: 	
					DO_IPEL( short ); 
					break; 
				case IM_BANDFMT_UINT: 	
					DO_FPEL( unsigned int ); 
					break; 
				case IM_BANDFMT_INT: 	
					DO_FPEL( int );  
					break; 
				case IM_BANDFMT_FLOAT: 	
					DO_FPEL( float ); 
					break; 
				case IM_BANDFMT_DOUBLE:	
					DO_FPEL( double ); 
					break; 

				default:
					error_exit( "im_affine: panic!");
					/*NOTREACHED*/
				}
			}

			ix += dx;
			iy += dy;
			q += ps;
		}
	}

	return( 0 );
}

static int 
affine( IMAGE *in, IMAGE *out, Transformation *trn )
{
	Transformation *trn2;
	double edge;

	if( im_iscomplex( in ) ) {
		im_errormsg( "im_affine: complex input not supported" );
		return( -1 );
	}

	/* We output at (0,0), so displace output by that amount -ve to get
	 * output at (ox,oy). Alter our copy of trn.
	 */
	if( !(trn2 = IM_NEW( out, Transformation )) )
		return( -1 );
	*trn2 = *trn;
	trn2->oarea.left = -trn->oarea.left;
	trn2->oarea.top = -trn->oarea.top;

	if( im__transform_calc_inverse( trn2 ) )
		return( -1 );

	/* Make output image.
	 */
	if( im_piocheck( in, out ) ) 
		return( -1 );
	if( im_cp_desc( out, in ) ) 
		return( -1 );
	out->Xsize = trn2->oarea.width;
	out->Ysize = trn2->oarea.height;

	/* Normally SMALLTILE ... except if this is a size up/down affine.
	 */
	if( trn->b == 0.0 && trn->c == 0.0 ) {
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
	edge = INT_MAX / TRANSFORM_SCALE;
	if( trn2->oarea.left < -edge || trn2->oarea.top < -edge ||
		IM_RECT_RIGHT( &trn2->oarea ) > edge || 
		IM_RECT_BOTTOM( &trn2->oarea ) > edge ) {
		im_errormsg( "im_affine: output coordinates out of range" );
		return( -1 );
	}

	/* Generate!
	 */
	if( im_generate( out, 
		im_start_one, affine_gen, im_stop_one, in, trn2 ) )
		return( -1 );

	return( 0 );
}

/* As above, but do IM_CODING_LABQ too. And embed the input.
 */
int 
im__affine( IMAGE *in, IMAGE *out, Transformation *trn )
{
	IMAGE *t3 = im_open_local( out, "im_affine:3", "p" );
	Transformation trn2;

#ifdef DEBUG_GEOMETRY
	printf( "im__affine: %s\n", in->filename );
	im__transform_print( trn );
#endif /*DEBUG_GEOMETRY*/

	/* Add new pixels around the input so we can interpolate at the edges.
	 * Bilinear needs 0.5 pixels on all edges.

	 	FIXME ... will need to fiddle with this when we add bicubic

	 */
	if( !t3 ||
		im_embed( in, t3, 1, 
			1, 1, in->Xsize + 2, in->Ysize + 2 ) )
		return( -1 );

	/* Set iarea so we know what part of the input we can take.
	 */
	trn2 = *trn;
	trn2.iarea.left += 1;
	trn2.iarea.top += 1;

	affine_interpol_calc();

	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *t1 = im_open_local( out, "im_affine:1", "p" );
		IMAGE *t2 = im_open_local( out, "im_affine:2", "p" );

		if( !t1 || !t2 ||
			im_LabQ2LabS( t3, t1 ) ||
			affine( t1, t2, &trn2 ) ||
			im_LabS2LabQ( t2, out ) )
			return( -1 );
	}
	else if( in->Coding == IM_CODING_NONE ) {
		if( affine( t3, out, &trn2 ) )
			return( -1 );
	}
	else {
		im_errormsg( "im_affine: unknown coding type" );
		return( -1 );
	}

	/* Finally: can now set Xoffset/Yoffset.
	 */
	out->Xoffset = trn->dx - trn->oarea.left;
	out->Yoffset = trn->dy - trn->oarea.top;

	return( 0 );
}

int 
im_affine( IMAGE *in, IMAGE *out, 
	double a, double b, double c, double d, double dx, double dy, 
	int ox, int oy, int ow, int oh )
{
	Transformation trn;

	trn.oarea.left = ox;
	trn.oarea.top = oy;
	trn.oarea.width = ow;
	trn.oarea.height = oh;
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

	return( im__affine( in, out, &trn ) );
}
