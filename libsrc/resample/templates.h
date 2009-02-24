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

/* "fast" floor() ... on my laptop, anyway.
 */
#define FLOOR( V ) ((V) >= 0 ? (int)(V) : (int)((V) - 1))

#ifndef restrict
#ifdef __restrict
#define restrict __restrict
#else
#ifdef __restrict__
#define restrict __restrict__
#else
#define restrict
#endif
#endif
#endif

/* Bilinear for float and double types.
 */
template <typename T> static T inline
bilinear_float( 
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

/* Interpolate for signed integer types.
 */
template <typename T> static T inline
bilinear_signed( 
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

/* Interpolate for unsigned integer types.
 */
template <typename T> static T inline
bilinear_unsigned( 
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

/* Fixed-point integer bicubic, used for 8 and 16-bit types.
 */
template <typename T> static int inline
bicubic_int( 
	const T uno_one, const T uno_two, const T uno_thr, const T uno_fou,
	const T dos_one, const T dos_two, const T dos_thr, const T dos_fou,
	const T tre_one, const T tre_two, const T tre_thr, const T tre_fou,
	const T qua_one, const T qua_two, const T qua_thr, const T qua_fou,
	const int *cx, const int *cy )
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
	const double *cx, const double *cy )
{
	return( 
		cy[0] * (cx[0] * uno_one +
			 cx[1] * uno_two +
			 cx[2] * uno_thr +
			 cx[3] * uno_fou) +

		cy[1] * (cx[0] * dos_one +
			 cx[1] * dos_two +
			 cx[2] * dos_thr +
			 cx[3] * dos_fou) +

		cy[2] * (cx[0] * tre_one +
			 cx[1] * tre_two +
			 cx[2] * tre_thr +
			 cx[3] * tre_fou) +

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
	const double dx = 1.f - x;
	const double x2 = dx * x;
	const double mx2 = -.5f * x2;

	g_assert( x >= 0 && x <= 1 );

	c[0] = mx2 * dx;
	c[1] = x2 * (-1.5f * x + 1.f) + dx;
	c[2] = 1.f - (mx2 + c[1]);
	c[3] = mx2 * x;
}
