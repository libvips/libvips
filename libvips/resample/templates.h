/* various interpolation templates
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

/*
 * FAST_MINMOD is an implementation of the minmod function which only
 * needs two conditional moves.  (Nicolas: I think that this may be
 * the very first two branch minmod.) The product of the two arguments
 * and a useful difference involving them are precomputed as far ahead
 * of branching as possible.
 */
#define FAST_MINMOD(a,b,ab,abminusaa) \
        ( (ab)>=0. ? ( (abminusaa)>=0. ? (a) : (b) ) : 0. )

/*
 * Various casts which assume that the data is already in range. (That
 * is, they are to be used with monotone samplers.)
 */
template <typename T> static T inline
to_fptypes( const double val )
{
  const T newval = val;
  return( newval );
}

template <typename T> static T inline
to_withsign( const double val )
{
  const int sign_of_val = 2 * ( val >= 0. ) - 1;
  const int rounded_abs_val = .5 + sign_of_val * val;
  const T newval = sign_of_val * rounded_abs_val;
  return( newval );
}

template <typename T> static T inline
to_nosign( const double val )
{
  const T newval = .5 + val;
  return( newval );
}

/*
 * Various bilinear implementation templates. Note that no clampling
 * is used: There is an assumption that the data is such that
 * over/underflow is not an issue:
 */
/*
 * Bilinear interpolation for float and double types. The first four
 * inputs are weights, the last four are the corresponding pixel
 * values:
 */
template <typename T> static T inline
bilinear_fptypes(
	const double w_times_z,
	const double x_times_z,
	const double w_times_y,
	const double x_times_y,
	const double tre_thr,
	const double tre_thrfou,
	const double trequa_thr,
	const double trequa_thrfou )
{
	const T newval =
		w_times_z * tre_thr +
		x_times_z * tre_thrfou +
		w_times_y * trequa_thr +
		x_times_y * trequa_thrfou;

	return( newval );
}

/*
 * Bilinear interpolation for signed integer types:
 */
template <typename T> static T inline
bilinear_withsign(
	const double w_times_z,
	const double x_times_z,
	const double w_times_y,
	const double x_times_y,
	const double tre_thr,
	const double tre_thrfou,
	const double trequa_thr,
	const double trequa_thrfou )
{
	const double val =
		w_times_z * tre_thr +
		x_times_z * tre_thrfou +
		w_times_y * trequa_thr +
		x_times_y * trequa_thrfou;

	const int sign_of_val = 2 * ( val >= 0. ) - 1;

	const int rounded_abs_val = .5 + sign_of_val * val;

	const T newval = sign_of_val * rounded_abs_val;

	return( newval );
}

/*
 * Bilinear Interpolation for unsigned integer types:
 */
template <typename T> static T inline
bilinear_nosign(
	const double w_times_z,
	const double x_times_z,
	const double w_times_y,
	const double x_times_y,
	const double tre_thr,
	const double tre_thrfou,
	const double trequa_thr,
	const double trequa_thrfou )
{
	const T newval =
		w_times_z * tre_thr +
		x_times_z * tre_thrfou +
		w_times_y * trequa_thr +
		x_times_y * trequa_thrfou +
		0.5;

	return( newval );
}

/*
 * Bicubic (Catmull-Rom) interpolation templates:
 */

/* Fixed-point integer bicubic, used for 8 and 16-bit types.
 */
template <typename T> static int inline
bicubic_int(
	const T uno_one, const T uno_two, const T uno_thr, const T uno_fou,
	const T dos_one, const T dos_two, const T dos_thr, const T dos_fou,
	const T tre_one, const T tre_two, const T tre_thr, const T tre_fou,
	const T qua_one, const T qua_two, const T qua_thr, const T qua_fou,
	const int* restrict cx, const int* restrict cy )
{
	const int r0 =
		(cx[0] * uno_one +
		 cx[1] * uno_two +
		 cx[2] * uno_thr +
		 cx[3] * uno_fou) >> VIPS_INTERPOLATE_SHIFT;

	const int r1 =
		(cx[0] * dos_one +
		 cx[1] * dos_two +
		 cx[2] * dos_thr +
		 cx[3] * dos_fou) >> VIPS_INTERPOLATE_SHIFT;

	const int r2 =
		(cx[0] * tre_one +
		 cx[1] * tre_two +
		 cx[2] * tre_thr +
		 cx[3] * tre_fou) >> VIPS_INTERPOLATE_SHIFT;

	const int r3 =
		(cx[0] * qua_one +
		 cx[1] * qua_two +
		 cx[2] * qua_thr +
		 cx[3] * qua_fou) >> VIPS_INTERPOLATE_SHIFT;

	return( (cy[0] * r0 +
		 cy[1] * r1 +
		 cy[2] * r2 +
		 cy[3] * r3) >> VIPS_INTERPOLATE_SHIFT );
}

/* Floating-point bicubic, used for int/float/double types.
 */
template <typename T> static T inline
bicubic_float(
	const T uno_one, const T uno_two, const T uno_thr, const T uno_fou,
	const T dos_one, const T dos_two, const T dos_thr, const T dos_fou,
	const T tre_one, const T tre_two, const T tre_thr, const T tre_fou,
	const T qua_one, const T qua_two, const T qua_thr, const T qua_fou,
	const double* restrict cx, const double* restrict cy )
{
	return(
		cy[0] * (cx[0] * uno_one +
			 cx[1] * uno_two +
			 cx[2] * uno_thr +
			 cx[3] * uno_fou)
                +
		cy[1] * (cx[0] * dos_one +
			 cx[1] * dos_two +
			 cx[2] * dos_thr +
			 cx[3] * dos_fou)
                +
		cy[2] * (cx[0] * tre_one +
			 cx[1] * tre_two +
			 cx[2] * tre_thr +
			 cx[3] * tre_fou)
                +
		cy[3] * (cx[0] * qua_one +
			 cx[1] * qua_two +
			 cx[2] * qua_thr +
			 cx[3] * qua_fou) );
}

/* Given an offset in [0,1] (we can have x == 1 when building tables),
 * calculate c0, c1, c2, c3, the catmull-rom coefficients. This is called
 * from the interpolator as well as from the table builder.
 */
static void inline
calculate_coefficients_catmull( const double x, double c[4] )
{
	const double dx = 1. - x;
	const double x2 = dx * x;
	const double mx2 = -.5 * x2;

	g_assert( x >= 0 && x <= 1 );

	c[0] = mx2 * dx;
	c[1] = x2 * (-1.5 * x + 1.) + dx;
	c[2] = 1. - (mx2 + c[1]);
	c[3] = mx2 * x;
}
