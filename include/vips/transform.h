/* Affine transforms.
 */

/*

    Copyright (C) 1991-2003 The National Gallery

    This program is free software; you can redistribute it and/or modify
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

/* Params for an affine transformation.
 */
typedef struct {
	/* Area of input we can use. This can be smaller than the real input 
	 * image: we expand the input to add extra pixels for interpolation. 
	 */
	Rect iarea;			

	/* The area of the output we've been asked to generate. left/top can
	 * be negative.
	 */
	Rect oarea;

	/* The transform.
	 */
	double a, b, c, d;		
	double dx, dy;

	double ia, ib, ic, id;		/* Inverse of matrix abcd */
} Transformation;

void im__transform_init( Transformation *trn );
int im__transform_calc_inverse( Transformation *trn );
int im__transform_isidentity( const Transformation *trn );
int im__transform_add( const Transformation *in1, const Transformation *in2, 
	Transformation *out );
void im__transform_print( const Transformation *trn );

void im__transform_forward_point( const Transformation *trn, 
	const double x, const double y, double *ox, double *oy );
void im__transform_invert_point( const Transformation *trn, 
	const double x, const double y, double *ox, double *oy );
void im__transform_forward_rect( const Transformation *trn,
	const Rect *in, Rect *out );
void im__transform_invert_rect( const Transformation *trn, 
	const Rect *in, Rect *out );

void im__transform_set_area( Transformation * );

int im__affine( IMAGE *in, IMAGE *out, Transformation *trn );
