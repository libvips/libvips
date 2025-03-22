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
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
	02110-1301  USA

 */

/*

	These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#include <cstdint>

/*
 * Various casts which assume that the data is already in range. (That
 * is, they are to be used with monotone samplers.)
 */
template <typename T>
static T inline to_fptypes(const double val)
{
	const T newval = val;

	return newval;
}

template <typename T>
static T inline to_withsign(const double val)
{
	const int sign_of_val = 2 * (val >= 0.) - 1;
	const int rounded_abs_val = .5 + sign_of_val * val;
	const T newval = sign_of_val * rounded_abs_val;

	return newval;
}

template <typename T>
static T inline to_nosign(const double val)
{
	const T newval = .5 + val;

	return newval;
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
template <typename T>
static T inline bilinear_fptypes(
	const double w_times_z,
	const double x_times_z,
	const double w_times_y,
	const double x_times_y,
	const double tre_thr,
	const double tre_thrfou,
	const double trequa_thr,
	const double trequa_thrfou)
{
	const T newval =
		w_times_z * tre_thr +
		x_times_z * tre_thrfou +
		w_times_y * trequa_thr +
		x_times_y * trequa_thrfou;

	return newval;
}

/*
 * Bilinear interpolation for signed integer types:
 */
template <typename T>
static T inline bilinear_withsign(
	const double w_times_z,
	const double x_times_z,
	const double w_times_y,
	const double x_times_y,
	const double tre_thr,
	const double tre_thrfou,
	const double trequa_thr,
	const double trequa_thrfou)
{
	const double val =
		w_times_z * tre_thr +
		x_times_z * tre_thrfou +
		w_times_y * trequa_thr +
		x_times_y * trequa_thrfou;

	const int sign_of_val = 2 * (val >= 0.) - 1;

	const int rounded_abs_val = .5 + sign_of_val * val;

	const T newval = sign_of_val * rounded_abs_val;

	return newval;
}

/*
 * Bilinear Interpolation for unsigned integer types:
 */
template <typename T>
static T inline bilinear_nosign(
	const double w_times_z,
	const double x_times_z,
	const double w_times_y,
	const double x_times_y,
	const double tre_thr,
	const double tre_thrfou,
	const double trequa_thr,
	const double trequa_thrfou)
{
	const T newval =
		w_times_z * tre_thr +
		x_times_z * tre_thrfou +
		w_times_y * trequa_thr +
		x_times_y * trequa_thrfou +
		0.5;

	return newval;
}

/*
 * Bicubic (Catmull-Rom) interpolation templates:
 */

template <typename T>
static T inline unsigned_fixed_round(T v)
{
	const int round_by = VIPS_INTERPOLATE_SCALE >> 1;

	return (v + round_by) >> VIPS_INTERPOLATE_SHIFT;
}

/* Fixed-point integer bicubic, used for 8-bit types.
 */
template <typename T>
static int inline bicubic_unsigned_int(
	const T uno_one, const T uno_two, const T uno_thr, const T uno_fou,
	const T dos_one, const T dos_two, const T dos_thr, const T dos_fou,
	const T tre_one, const T tre_two, const T tre_thr, const T tre_fou,
	const T qua_one, const T qua_two, const T qua_thr, const T qua_fou,
	const int *restrict cx, const int *restrict cy)
{
	const int c0 = cx[0];
	const int c1 = cx[1];
	const int c2 = cx[2];
	const int c3 = cx[3];

	const int r0 = unsigned_fixed_round(
		c0 * uno_one +
		c1 * uno_two +
		c2 * uno_thr +
		c3 * uno_fou);
	const int r1 = unsigned_fixed_round(
		c0 * dos_one +
		c1 * dos_two +
		c2 * dos_thr +
		c3 * dos_fou);
	const int r2 = unsigned_fixed_round(
		c0 * tre_one +
		c1 * tre_two +
		c2 * tre_thr +
		c3 * tre_fou);
	const int r3 = unsigned_fixed_round(
		c0 * qua_one +
		c1 * qua_two +
		c2 * qua_thr +
		c3 * qua_fou);

	return unsigned_fixed_round(
		cy[0] * r0 +
		cy[1] * r1 +
		cy[2] * r2 +
		cy[3] * r3);
}

template <typename T>
static T inline signed_fixed_round(T v)
{
	const int sign_of_v = 2 * (v >= 0) - 1;
	const int round_by = sign_of_v * (VIPS_INTERPOLATE_SCALE >> 1);

	return (v + round_by) >> VIPS_INTERPOLATE_SHIFT;
}

/* Fixed-point integer bicubic, used for 8-bit types.
 */
template <typename T>
static int inline bicubic_signed_int(
	const T uno_one, const T uno_two, const T uno_thr, const T uno_fou,
	const T dos_one, const T dos_two, const T dos_thr, const T dos_fou,
	const T tre_one, const T tre_two, const T tre_thr, const T tre_fou,
	const T qua_one, const T qua_two, const T qua_thr, const T qua_fou,
	const int *restrict cx, const int *restrict cy)
{
	const int c0 = cx[0];
	const int c1 = cx[1];
	const int c2 = cx[2];
	const int c3 = cx[3];

	const int r0 = signed_fixed_round(
		c0 * uno_one +
		c1 * uno_two +
		c2 * uno_thr +
		c3 * uno_fou);
	const int r1 = signed_fixed_round(
		c0 * dos_one +
		c1 * dos_two +
		c2 * dos_thr +
		c3 * dos_fou);
	const int r2 = signed_fixed_round(
		c0 * tre_one +
		c1 * tre_two +
		c2 * tre_thr +
		c3 * tre_fou);
	const int r3 = signed_fixed_round(
		c0 * qua_one +
		c1 * qua_two +
		c2 * qua_thr +
		c3 * qua_fou);

	return signed_fixed_round(
		cy[0] * r0 +
		cy[1] * r1 +
		cy[2] * r2 +
		cy[3] * r3);
}

template <typename T>
static T inline cubic_float(
	const T one, const T two, const T thr, const T fou,
	const double *restrict cx)
{
	return cx[0] * one +
		cx[1] * two +
		cx[2] * thr +
		cx[3] * fou;
}

/* Floating-point bicubic, used for int/float/double types.
 */
template <typename T>
static T inline bicubic_float(
	const T uno_one, const T uno_two, const T uno_thr, const T uno_fou,
	const T dos_one, const T dos_two, const T dos_thr, const T dos_fou,
	const T tre_one, const T tre_two, const T tre_thr, const T tre_fou,
	const T qua_one, const T qua_two, const T qua_thr, const T qua_fou,
	const double *restrict cx, const double *restrict cy)
{
	const double r0 = cubic_float<T>(
		uno_one, uno_two, uno_thr, uno_fou, cx);
	const double r1 = cubic_float<T>(
		dos_one, dos_two, dos_thr, dos_fou, cx);
	const double r2 = cubic_float<T>(
		tre_one, tre_two, tre_thr, tre_fou, cx);
	const double r3 = cubic_float<T>(
		qua_one, qua_two, qua_thr, qua_fou, cx);

	return cubic_float<T>(r0, r1, r2, r3, cy);
}

/* Given an offset in [0,1] (we can have x == 1 when building tables),
 * calculate c0, c1, c2, c3, the catmull-rom coefficients. This is called
 * from the interpolator as well as from the table builder.
 */
static void inline calculate_coefficients_catmull(double c[4], const double x)
{
	/* Nicolas believes that the following is an hitherto unknown
	 * hyper-efficient method of computing Catmull-Rom coefficients. It
	 * only uses 4* & 1+ & 5- for a total of only 10 flops to compute
	 * four coefficients.
	 */
	const double cr1 = 1. - x;
	const double cr2 = -.5 * x;
	const double cr3 = cr1 * cr2;
	const double cone = cr1 * cr3;
	const double cfou = x * cr3;
	const double cr4 = cfou - cone;
	const double ctwo = cr1 - cone + cr4;
	const double cthr = x - cfou - cr4;

	g_assert(x >= 0. && x <= 1.);

	c[0] = cone;
	c[3] = cfou;
	c[1] = ctwo;
	c[2] = cthr;
}

/* Generate a cubic filter. See:
 *
 * Mitchell and Netravali, Reconstruction Filters in Computer Graphics
 * Computer Graphics, Volume 22, Number 4, August 1988.
 *
 * B = 1,   C = 0   - cubic B-spline
 * B = 1/3, C = 1/3 - Mitchell
 * B = 0,   C = 1/2 - Catmull-Rom spline
 */
static double inline cubic_filter(double x, double B, double C)
{
	const double ax = fabs(x);
	const double ax2 = ax * ax;
	const double ax3 = ax2 * ax;

	if (ax <= 1)
		return ((12 - 9 * B - 6 * C) * ax3 +
				   (-18 + 12 * B + 6 * C) * ax2 +
				   (6 - 2 * B)) /
			6;

	if (ax <= 2)
		return ((-B - 6 * C) * ax3 +
				   (6 * B + 30 * C) * ax2 +
				   (-12 * B - 48 * C) * ax +
				   (8 * B + 24 * C)) /
			6;

	return 0.0;
}

static double inline sinc_filter(double x)
{
	if (x == 0.0)
		return 1.0;

	x = x * VIPS_PI;

	return sin(x) / x;
}

using VipsFilterFn = double (*)(double);

template <VipsKernel K>
static double inline filter(double x);

template <>
double inline filter<VIPS_KERNEL_LINEAR>(double x)
{
	x = fabs(x);

	if (x < 1.0)
		return 1.0 - x;

	return 0.0;
}

/* Catmull-Rom.
 */
template <>
double inline filter<VIPS_KERNEL_CUBIC>(double x)
{
	return cubic_filter(x, 0.0, 0.5);
}

template <>
double inline filter<VIPS_KERNEL_MITCHELL>(double x)
{
	return cubic_filter(x, 1.0 / 3.0, 1.0 / 3.0);
}

template <>
double inline filter<VIPS_KERNEL_LANCZOS2>(double x)
{
	if (x >= -2 && x <= 2)
		return sinc_filter(x) * sinc_filter(x / 2);

	return 0.0;
}

template <>
double inline filter<VIPS_KERNEL_LANCZOS3>(double x)
{
	if (x >= -3 && x <= 3)
		return sinc_filter(x) * sinc_filter(x / 3);

	return 0.0;
}

template <>
double inline filter<VIPS_KERNEL_MKS2013>(double x)
{
	x = fabs(x);

	if (x >= 2.5)
		return 0.0;

	if (x >= 1.5)
		return (x - 5.0 / 2.0) * (x - 5.0 / 2.0) / -8.0;

	if (x >= 0.5)
		return (4.0 * x * x - 11.0 * x + 7.0) / 4.0;

	return 17.0 / 16.0 - 7.0 * x * x / 4.0;
}

template <>
double inline filter<VIPS_KERNEL_MKS2021>(double x)
{
	x = fabs(x);

	if (x >= 4.5)
		return 0.0;

	if (x >= 3.5)
		return (4.0 * x * x - 36.0 * x + 81.0) / -1152.0;

	if (x >= 2.5)
		return (4.0 * x * x - 27.0 * x + 45.0) / 144.0;

	if (x >= 1.5)
		return (24.0 * x * x - 113.0 * x + 130.0) / -144.0;

	if (x >= 0.5)
		return (140.0 * x * x - 379.0 * x + 239.0) / 144.0;

	return 577.0 / 576.0 - 239.0 * x * x / 144.0;
}

/* Given an x in [0,1] (we can have x == 1 when building tables),
 * calculate c0 .. c(@n_points), the coefficients. This is called
 * from the interpolator as well as from the table builder.
 *
 * @shrink is the reduction factor, so 1 for interpolation, 2 for a
 * x2 reduction, etc.
 */
template <typename T>
static void
calculate_coefficients(T *c, const int n_points,
	VipsFilterFn filter_fn, const double shrink, const double x)
{
	const double half = x + n_points / 2.0 - 1;

	int i;
	T sum;

	sum = 0.0;
	for (i = 0; i < n_points; i++) {
		const double xp = (i - half) / shrink;
		double l = filter_fn(xp);

		c[i] = l;
		sum += l;
	}

	for (i = 0; i < n_points; i++)
		c[i] /= sum;
}

/* Calculate a mask element.
 */
template <typename T>
static void
vips_reduce_make_mask(T *c, VipsKernel kernel, const int n_points,
	const double shrink, const double x)
{
	switch (kernel) {
	case VIPS_KERNEL_NEAREST:
		c[0] = 1.0;
		break;

	case VIPS_KERNEL_LINEAR:
		calculate_coefficients(c, n_points,
			filter<VIPS_KERNEL_LINEAR>, shrink, x);
		break;

	case VIPS_KERNEL_CUBIC:
		calculate_coefficients(c, n_points,
			filter<VIPS_KERNEL_CUBIC>, shrink, x);
		break;

	case VIPS_KERNEL_MITCHELL:
		calculate_coefficients(c, n_points,
			filter<VIPS_KERNEL_MITCHELL>, shrink, x);
		break;

	case VIPS_KERNEL_LANCZOS2:
		calculate_coefficients(c, n_points,
			filter<VIPS_KERNEL_LANCZOS2>, shrink, x);
		break;

	case VIPS_KERNEL_LANCZOS3:
		calculate_coefficients(c, n_points,
			filter<VIPS_KERNEL_LANCZOS3>, shrink, x);
		break;

	case VIPS_KERNEL_MKS2013:
		calculate_coefficients(c, n_points,
			filter<VIPS_KERNEL_MKS2013>, shrink, x);
		break;

	case VIPS_KERNEL_MKS2021:
		calculate_coefficients(c, n_points,
			filter<VIPS_KERNEL_MKS2021>, shrink, x);
		break;

	default:
		g_assert_not_reached();
		break;
	}
}

/* Machinery to promote type T to a larger data type, prevents an
 * overflow in reduce_sum(). Defaults to a 32-bit integral type.
 */
template <typename T>
struct LongT {
	typedef int32_t type;
};

/* 32-bit integral types needs a 64-bits intermediate.
 */
template <>
struct LongT<int32_t> {
	typedef int64_t type;
};

template <>
struct LongT<uint32_t> {
	typedef int64_t type;
};

/* 32-bit floating-point types needs a 64-bits intermediate.
 */
template <>
struct LongT<float> {
	typedef double type;
};

/* 64-bit floating-point types needs a 128-bits intermediate.
 */
template <>
struct LongT<double> {
	typedef long double type;
};

/* Our inner loop for resampling with a convolution of type CT. Operate on
 * elements of type T, gather results in an intermediate of type IT.
 */
template <typename T, typename CT, typename IT = typename LongT<T>::type>
static IT inline reduce_sum(const T *restrict in, int stride,
	const CT *restrict c, int n)
{
	IT sum;

	sum = 0;
	for (int i = 0; i < n; i++) {
		sum += (IT) c[i] * in[0];
		in += stride;
	}

	return sum;
}
