/* base class for all colour operations
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

#ifndef VIPS_PCOLOUR_H
#define VIPS_PCOLOUR_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vips.h>

#define VIPS_TYPE_COLOUR (vips_colour_get_type())
#define VIPS_COLOUR(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_COLOUR, VipsColour))
#define VIPS_COLOUR_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		VIPS_TYPE_COLOUR, VipsColourClass))
#define VIPS_IS_COLOUR(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), VIPS_TYPE_COLOUR))
#define VIPS_IS_COLOUR_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), VIPS_TYPE_COLOUR))
#define VIPS_COLOUR_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
		VIPS_TYPE_COLOUR, VipsColourClass))

struct _VipsColour;
typedef void (*VipsColourProcessFn)(struct _VipsColour *colour,
	VipsPel *out, VipsPel **in, int width);

typedef struct _VipsColour {
	VipsOperation parent_instance;

	/* Null-terminated array of input arguments, set these from a
	 * subclass.
	 */
	VipsImage **in;
	int n;

	/* If this is >0, only process this many bands from the input. Extra
	 * bands are removed and reattached after processing.
	 */
	int input_bands;

	VipsImage *out;

	/* Set fields on ->out from these.
	 */
	VipsCoding coding;
	VipsInterpretation interpretation;
	VipsBandFormat format;
	int bands;

	/* Attach this profile, if set.
	 */
	char *profile_filename;
} VipsColour;

typedef struct _VipsColourClass {
	VipsOperationClass parent_class;

	/* The buffer processor.
	 */
	VipsColourProcessFn process_line;

} VipsColourClass;

GType vips_colour_get_type(void);

/* A float in, float out colourspace transformation.
 */

#define VIPS_TYPE_COLOUR_TRANSFORM (vips_colour_transform_get_type())
#define VIPS_COLOUR_TRANSFORM(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_COLOUR_TRANSFORM, VipsColourTransform))
#define VIPS_COLOUR_TRANSFORM_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		VIPS_TYPE_COLOUR_TRANSFORM, VipsColourTransformClass))
#define VIPS_IS_COLOUR_TRANSFORM(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), VIPS_TYPE_COLOUR_TRANSFORM))
#define VIPS_IS_COLOUR_TRANSFORM_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), VIPS_TYPE_COLOUR_TRANSFORM))
#define VIPS_COLOUR_TRANSFORM_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
		VIPS_TYPE_COLOUR_TRANSFORM, VipsColourTransformClass))

typedef struct _VipsColourTransform {
	VipsColour parent_instance;

	VipsImage *in;

} VipsColourTransform;

typedef struct _VipsColourTransformClass {
	VipsColourClass parent_class;

} VipsColourTransformClass;

GType vips_colour_transform_get_type(void);

/* Change colour encoding ... either in or out is not three-band float.
 */

#define VIPS_TYPE_COLOUR_CODE (vips_colour_code_get_type())
#define VIPS_COLOUR_CODE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_COLOUR_CODE, VipsColourCode))
#define VIPS_COLOUR_CODE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		VIPS_TYPE_COLOUR_CODE, VipsColourCodeClass))
#define VIPS_IS_COLOUR_CODE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), VIPS_TYPE_COLOUR_CODE))
#define VIPS_IS_COLOUR_CODE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), VIPS_TYPE_COLOUR_CODE))
#define VIPS_COLOUR_CODE_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
		VIPS_TYPE_COLOUR_CODE, VipsColourCodeClass))

typedef struct _VipsColourCode {
	VipsColour parent_instance;

	VipsImage *in;

	/* Test in against these.
	 */
	VipsCoding input_coding;
	VipsBandFormat input_format;
	VipsInterpretation input_interpretation;

} VipsColourCode;

typedef struct _VipsColourCodeClass {
	VipsColourClass parent_class;

} VipsColourCodeClass;

GType vips_colour_code_get_type(void);

/* Difference between two colour images.
 */

#define VIPS_TYPE_COLOUR_DIFFERENCE (vips_colour_difference_get_type())
#define VIPS_COLOUR_DIFFERENCE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_COLOUR_DIFFERENCE, VipsColourDifference))
#define VIPS_COLOUR_DIFFERENCE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		VIPS_TYPE_COLOUR_DIFFERENCE, VipsColourDifferenceClass))
#define VIPS_IS_COLOUR_DIFFERENCE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), VIPS_TYPE_COLOUR_DIFFERENCE))
#define VIPS_IS_COLOUR_DIFFERENCE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), VIPS_TYPE_COLOUR_DIFFERENCE))
#define VIPS_COLOUR_DIFFERENCE_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
		VIPS_TYPE_COLOUR_DIFFERENCE, VipsColourDifferenceClass))

typedef struct _VipsColourDifference {
	VipsColour parent_instance;

	VipsImage *left;
	VipsImage *right;

	/* Both get converted to this space.
	 */
	VipsInterpretation interpretation;

} VipsColourDifference;

typedef struct _VipsColourDifferenceClass {
	VipsColourClass parent_class;

} VipsColourDifferenceClass;

GType vips_colour_difference_get_type(void);

void vips__pythagoras_line(VipsColour *colour,
	VipsPel *out, VipsPel **in, int width);

/* Colour tables for Y<->v conversion. Call vips_col_make_tables_RGB_8() and
 * vips_col_make_tables_RGB_16() before use to initialize.
 */
extern float vips_v2Y_8[256];

void vips_col_make_tables_RGB_8(void);

/* A colour-transforming function.
 */
typedef int (*VipsColourTransformFn)(VipsImage *in, VipsImage **out, ...);

int vips__colourspace_process_n(const char *domain,
	VipsImage *in, VipsImage **out, int n, VipsColourTransformFn fn);

#define SDR_WHITE 80.0f

/* Identity matrix (BT.709 -> BT.709). */
static const float BT709_to_BT709[9] = {
	1.0f, 0.0f, 0.0f,
	0.0f, 1.0f, 0.0f,
	0.0f, 0.0f, 1.0f
};

/* Luminance coefficients (Y row of primaries-to-XYZ matrix) for
 * each set of colour primaries. Used by HLG OOTF / inverse OOTF
 * to compute luminance in the source/target primaries' colour space.
 *
 * These are the normalised Y chromaticities scaled so that the
 * white point has Y = 1. In practice these come from the second
 * row of the 3x3 chromaticity-to-XYZ matrix, normalised to sum
 * to 1.
 *
 * Derived from H.273 Table 2 chromaticities.
 */

/* BT.709 / sRGB (value 1) */
static const float BT709_luminance[3] = { 0.2126f, 0.7152f, 0.0722f };

/* BT.2020 / BT.2100 (value 9) */
static const float BT2020_luminance[3] = { 0.2627f, 0.6780f, 0.0593f };

/* DCI-P3 / SMPTE 431 (value 11, Illuminant DCI ~0.314/0.351) */
static const float DCI_P3_luminance[3] = { 0.2095f, 0.7216f, 0.0689f };

/* Display P3 / SMPTE 432 (value 12, D65 white) */
static const float Display_P3_luminance[3] = { 0.2290f, 0.6917f, 0.0793f };

/* BT.470M (value 4, Illuminant C) */
static const float BT470M_luminance[3] = { 0.2990f, 0.5864f, 0.1146f };

/* BT.470BG (value 5) */
static const float BT470BG_luminance[3] = { 0.2220f, 0.7067f, 0.0713f };

/* BT.601 / SMPTE 170M / SMPTE 240M (values 6, 7) */
static const float BT601_luminance[3] = { 0.2124f, 0.7011f, 0.0866f };

/* Generic Film (value 8, Illuminant C) */
static const float GenericFilm_luminance[3] = { 0.2536f, 0.6783f, 0.0681f };

/* EBU 3213 (value 22) */
static const float EBU3213_luminance[3] = { 0.2318f, 0.6723f, 0.0960f };

/* Look up luminance coefficients for a CICP colour primaries code. */
static inline const float *
vips_cicp_get_luminance(int colour_primaries)
{
	switch (colour_primaries) {
	case VIPS_CICP_COLOUR_PRIMARIES_BT709:
		return BT709_luminance;
	case VIPS_CICP_COLOUR_PRIMARIES_BT2020:
		return BT2020_luminance;
	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE431:
		return DCI_P3_luminance;
	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE432:
		return Display_P3_luminance;
	case VIPS_CICP_COLOUR_PRIMARIES_BT470M:
		return BT470M_luminance;
	case VIPS_CICP_COLOUR_PRIMARIES_BT470BG:
		return BT470BG_luminance;
	case VIPS_CICP_COLOUR_PRIMARIES_BT601:
	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE240:
		return BT601_luminance;
	case VIPS_CICP_COLOUR_PRIMARIES_GENERIC_FILM:
		return GenericFilm_luminance;
	case VIPS_CICP_COLOUR_PRIMARIES_EBU3213:
		return EBU3213_luminance;
	default:
		return BT709_luminance;
	}
}

/* LUT size for CICP transfer / OOTF tables.
 */
#define VIPS_CICP_LUT_SIZE 4096

/* Build a LUT for f(t) = scale * t^exponent, t in [0, 1].
 * Used by HLG forward OOTF (exponent=0.2, scale=1000/80)
 * and HLG inverse OOTF (exponent=1/1.2, scale=1).
 */
static inline float *
vips_cicp_build_power_lut(float exponent, float scale)
{
	float *lut = g_new(float, VIPS_CICP_LUT_SIZE);

	lut[0] = 0.0f;
	for (int i = 1; i < VIPS_CICP_LUT_SIZE; i++)
		lut[i] = scale *
			powf((float) i / (VIPS_CICP_LUT_SIZE - 1), exponent);

	return lut;
}

/* Linearly interpolate a LUT on the domain [0, 1].
 * Returns lut[0] for t <= 0; extrapolates from the last
 * segment for t slightly above 1.
 */
static inline float
vips_cicp_lut_interpolate(const float *lut, float t)
{
	float idx = t * (VIPS_CICP_LUT_SIZE - 1);

	if (idx <= 0.0f)
		return lut[0];

	int lo = (int) idx;

	if (lo >= VIPS_CICP_LUT_SIZE - 1)
		lo = VIPS_CICP_LUT_SIZE - 2;

	float frac = idx - lo;

	return lut[lo] + frac * (lut[lo + 1] - lut[lo]);
}

static inline void
vips_cicp_apply_matrix(const float *matrix, float r, float g, float b,
	float *out_r, float *out_g, float *out_b)
{
	*out_r = matrix[0] * r + matrix[1] * g + matrix[2] * b;
	*out_g = matrix[3] * r + matrix[4] * g + matrix[5] * b;
	*out_b = matrix[6] * r + matrix[7] * g + matrix[8] * b;
}

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PCOLOUR_H*/
