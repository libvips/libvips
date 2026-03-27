/* Turn image with CICP metadata to scRGB colourspace.
 *
 * 26/11/25 [Starbix]
 * 	- from uhdr2scRGB.c
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

	These files are distributed with VIPS - https://github.com/libvips/libvips

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#include "pcolour.h"

typedef struct _VipsCICP2scRGB {
	VipsColour parent;

	VipsImage *in;

	VipsCICPColourPrimaries colour_primaries;
	VipsCICPTransferCharacteristics transfer_characteristics;

	VipsCICPMatrixCoefficients matrix_coefficients; // unused
	int full_range_flag; // unused

	/* Conversion matrix from source primaries to BT.709 (scRGB)
	 */
	float conversion_matrix[9];

	/* Luminance coefficients for source primaries (Y row of
	 * primaries-to-XYZ matrix), used by HLG OOTF.
	 */
	float luminance_coeffs[3];

	/* Pre-computed transfer function LUT. Maps integer sample
	 * values directly to linear-light floats, combining
	 * normalisation and inverse transfer in one lookup.
	 * 256 entries for uchar, 65536 for ushort.
	 */
	float *transfer_lut;
	int lut_size;

	/* LUT for HLG OOTF: maps Y_s in [0,1] to
	 * scale * Y_s^(gamma-1), with linear interpolation.
	 */
	float *ootf_lut;

} VipsCICP2scRGB;

typedef VipsColourClass VipsCICP2scRGBClass;

G_DEFINE_TYPE(VipsCICP2scRGB, vips_CICP2scRGB, VIPS_TYPE_COLOUR);

static const float BT2020_to_BT709[9] = {
	1.660491f, -0.58764114f, -0.07284986f,
	-0.12455047f, 1.1328999f, -0.00834942f,
	-0.01815076f, -0.1005789f, 1.11872966f
};

/* Bradford chromatic adaptation
 */
static const float DCI_P3_to_BT709[9] = {
	1.15751641f, -0.15496238f, -0.00255403f,
	-0.04150007f, 1.04556792f, -0.00406785f,
	-0.01805004f, -0.07857827f, 1.09662831f
};

static const float Display_P3_to_BT709[9] = {
	1.22494018f, -0.224940176f, -6.95071840e-17f,
	-0.0420569547f, 1.04205695f, 3.05868274e-17f,
	-0.0196375546f, -0.0786360456f, 1.09827360f
};

/* Bradford chromatic adaptation (Illuminant C -> D65)
 */
static const float BT470M_to_BT709[9] = {
	1.48615685f, -0.40355491f, -0.08260194f,
	-0.02510111f, 0.95402469f, 0.07107642f,
	-0.02722400f, -0.04409523f, 1.07131924f
};

static const float BT470BG_to_BT709[9] = {
	1.04404321f, -0.04404321f, 0.0f,
	0.0f, 1.0f, 0.0f,
	0.0f, 0.01179338f, 0.98820662f
};

/* BT.601 / SMPTE 170M / SMPTE 240M share the same primaries
 */
static const float BT601_to_BT709[9] = {
	0.93954206f, 0.05018136f, 0.01027658f,
	0.01777222f, 0.96579286f, 0.01643491f,
	-0.00162160f, -0.00436975f, 1.00599135f
};

/* Bradford chromatic adaptation (Illuminant C -> D65)
 */
static const float GenericFilm_to_BT709[9] = {
	1.34617592f, -0.33919507f, -0.00698084f,
	-0.04735102f, 1.06605153f, -0.01870051f,
	-0.02166498f, -0.06131310f, 1.08297808f
};

static const float EBU3213_to_BT709[9] = {
	1.02525246f, -0.02654753f, 0.00129508f,
	0.01939351f, 0.94802801f, 0.03257848f,
	-0.00176953f, -0.00144232f, 1.00321185f
};

static const float *
vips_CICP2scRGB_get_matrix(VipsCICPColourPrimaries primaries)
{
	switch (primaries) {
	case VIPS_CICP_COLOUR_PRIMARIES_BT2020:
		return BT2020_to_BT709;
	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE431:
		return DCI_P3_to_BT709;
	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE432:
		return Display_P3_to_BT709;
	case VIPS_CICP_COLOUR_PRIMARIES_BT470M:
		return BT470M_to_BT709;
	case VIPS_CICP_COLOUR_PRIMARIES_BT470BG:
		return BT470BG_to_BT709;
	case VIPS_CICP_COLOUR_PRIMARIES_BT601:
	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE240:
		return BT601_to_BT709;
	case VIPS_CICP_COLOUR_PRIMARIES_GENERIC_FILM:
		return GenericFilm_to_BT709;
	case VIPS_CICP_COLOUR_PRIMARIES_EBU3213:
		return EBU3213_to_BT709;
	default:
		return BT709_to_BT709;
	}
}

static inline float
vips_pq_eotf(float E)
{
	const float m1 = 2610.0f / 16384.0f;
	const float m2 = 2523.0f / 4096.0f * 128.0f;
	const float c1 = 3424.0f / 4096.0f;
	const float c2 = 2413.0f / 4096.0f * 32.0f;
	const float c3 = 2392.0f / 4096.0f * 32.0f;

	if (E <= 0.0f)
		return 0.0f;

	float Em2 = powf(E, 1.0f / m2);
	float numerator = fmaxf(Em2 - c1, 0.0f);
	float denominator = c2 - c3 * Em2;

	if (denominator <= 0.0f)
		return 0.0f;

	float linear = powf(numerator / denominator, 1.0f / m1);

	/* linear is in [0, 1] representing [0, 10000] nits.
	 * scRGB: 1.0 = 80 nits, so multiply by 10000/80.
	 */
	return linear * (10000.0f / SDR_WHITE);
}

static inline float
vips_hlg_inverse_oetf(float E)
{
	/* Constants from H.273 Table 3, value 18 (ARIB STD-B67).
	 * This is only the inverse OETF (signal -> scene-linear).
	 * The full HLG EOTF also requires the OOTF, applied separately
	 * via vips_hlg_ootf() since it is a cross-channel operation.
	 */
	const float a = 0.17883277f;
	const float b = 0.28466892f;
	const float c = 0.55991073f;

	if (E <= 0.0f)
		return 0.0f;

	if (E <= 0.5f)
		return E * E / 3.0f;
	else
		return (expf((E - c) / a) + b) / 12.0f;
}

/* BT.2100-2 Table 5: HLG OOTF for a 1000-nit reference display.
 * Converts scene-linear RGB to display-linear, scaled to scRGB units.
 *
 * OOTF: F_d = alpha * Y_s^(gamma-1) * E_s
 *   alpha = L_W = 1000 nits (HLG nominal peak luminance)
 *   gamma = 1.2 (for L_W = 1000 nits)
 *   Y_s = luminance using source primaries' coefficients
 *
 * Output scaled by 1/SDR_WHITE so that 1.0 = 80 nits.
 *
 * Uses a pre-computed LUT for powf(Y_s, gamma-1) with linear
 * interpolation. Y_s is in [0, 1] (scene-linear after inverse OETF).
 */
static inline void
vips_hlg_ootf(float *r, float *g, float *b,
	const float *luminance, const float *ootf_lut)
{
	float Y_s = luminance[0] * *r + luminance[1] * *g + luminance[2] * *b;

	if (Y_s <= 0.0f) {
		*r = 0.0f;
		*g = 0.0f;
		*b = 0.0f;
		return;
	}

	float factor = vips_cicp_lut_interpolate(ootf_lut, Y_s);

	*r *= factor;
	*g *= factor;
	*b *= factor;
}

static inline float
vips_bt709_inverse_oetf(float E)
{
	/* BT.709 / BT.601 / BT.2020 share the same curve.
	 * Analytical constants for C0/C1 continuity.
	 */
	const float alpha = 1.09929682680944f;
	const float linear_beta = 0.018053968510807f;
	const float signal_beta = 4.5f * linear_beta;

	if (E < 0.0f)
		return 0.0f;

	if (E < signal_beta)
		return E / 4.5f;
	else
		return powf((E + (alpha - 1.0f)) / alpha, 1.0f / 0.45f);
}

static inline float
vips_sRGB_inverse_oetf(float E)
{
	const float linear_beta = 0.003041282560128f;
	const float slope = 12.92f;
	const float signal_beta = slope * linear_beta;
	const float alpha = 1.05501071894759f;
	const float gamma = 2.4f;

	if (E < 0.0f)
		return 0.0f;

	if (E <= signal_beta)
		return E / slope;
	else
		return powf((E + (alpha - 1.0f)) / alpha, gamma);
}

static inline float
vips_CICP2scRGB_transfer(VipsCICPTransferCharacteristics transfer, float in)
{
	switch (transfer) {
	case VIPS_CICP_TRANSFER_PQ:
		return vips_pq_eotf(in);
	case VIPS_CICP_TRANSFER_HLG:
		return vips_hlg_inverse_oetf(in);
	case VIPS_CICP_TRANSFER_BT709:
	case VIPS_CICP_TRANSFER_BT601:
	case VIPS_CICP_TRANSFER_BT2020_10BIT:
	case VIPS_CICP_TRANSFER_BT2020_12BIT:
		return vips_bt709_inverse_oetf(in);
	case VIPS_CICP_TRANSFER_SMPTE240: {
		const float alpha = 1.11157219592173f;
		const float linear_beta = 0.022821585529445f;
		const float slope = 4.0f;

		if (in < slope * linear_beta)
			return in / slope;
		else
			return powf((in + (alpha - 1.0f)) / alpha, 1.0f / 0.45f);
	}
	case VIPS_CICP_TRANSFER_SRGB:
		return vips_sRGB_inverse_oetf(in);
	case VIPS_CICP_TRANSFER_BT470M:
		return powf(fmaxf(in, 0.0f), 2.2f); /* Gamma 2.2 */
	case VIPS_CICP_TRANSFER_BT470BG:
		return powf(fmaxf(in, 0.0f), 2.8f); /* Gamma 2.8 */
	case VIPS_CICP_TRANSFER_LINEAR:
		return in;
	case VIPS_CICP_TRANSFER_LOG_100:
		/* V = 1.0 + Log10(Lc) / 2.0 for Lc >= 0.01, else 0.
		 * Inverse: Lc = 10^(2*(V-1)) for V > 0, else 0.
		 */
		return in > 0.0f ? powf(10.0f, 2.0f * (in - 1.0f)) : 0.0f;
	case VIPS_CICP_TRANSFER_LOG_100_SQRT10:
		/* V = 1.0 + Log10(Lc) / 2.5 for Lc >= Sqrt(10)/1000, else 0.
		 * Inverse: Lc = 10^(2.5*(V-1)) for V > 0, else 0.
		 */
		return in > 0.0f ? powf(10.0f, 2.5f * (in - 1.0f)) : 0.0f;
	case VIPS_CICP_TRANSFER_IEC61966:
	case VIPS_CICP_TRANSFER_BT1361: {
		/* BT.709 curve extended to negative values via odd symmetry.
		 * IEC 61966-2-4 (xvYCC) and BT.1361 both use this form.
		 */
		if (in >= 0.0f)
			return vips_bt709_inverse_oetf(in);
		else
			return -vips_bt709_inverse_oetf(-in);
	}
	case VIPS_CICP_TRANSFER_SMPTE428: {
		/* SMPTE ST 428-1: V = (48 * Lo / 52.37)^(1/2.6)
		 * Inverse: Lo = (52.37/48) * V^2.6
		 * Lo is display-referred (48 cd/m² reference projector).
		 * Scale to scRGB: 1.0 = 80 nits -> multiply by 48/80.
		 */
		float Lo = (52.37f / 48.0f) * powf(fmaxf(in, 0.0f), 2.6f);
		return Lo * (48.0f / SDR_WHITE);
	}
	default:
		/* Unknown transfer -- pass through unchanged.
		 */
		return in;
	}
}

/* Build a transfer function LUT that maps integer sample values
 * directly to linear-light floats. Combines normalisation (divide
 * by max_val) and inverse transfer into one table lookup.
 */
static float *
vips_CICP2scRGB_build_lut(VipsCICPTransferCharacteristics transfer, int n)
{
	float *lut = g_new(float, n);
	const float scale = 1.0f / (n - 1);

	for (int i = 0; i < n; i++)
		lut[i] = vips_CICP2scRGB_transfer(transfer, i * scale);

	return lut;
}

#define CICP2SCRGB_LOOP(TYPE) \
{ \
	TYPE *restrict p = (TYPE *) in[0]; \
	float *restrict q = (float *) out; \
	const float *restrict lut = cicp->transfer_lut; \
	const float *matrix = cicp->conversion_matrix; \
	const float *luminance = cicp->luminance_coeffs; \
	const gboolean is_hlg = \
		cicp->transfer_characteristics == VIPS_CICP_TRANSFER_HLG; \
\
	for (int i = 0; i < width; i++) { \
		float r = lut[p[0]]; \
		float g = lut[p[1]]; \
		float b = lut[p[2]]; \
		p += 3; \
\
		if (is_hlg) \
			vips_hlg_ootf(&r, &g, &b, luminance, cicp->ootf_lut); \
\
		vips_cicp_apply_matrix(matrix, r, g, b, &q[0], &q[1], &q[2]); \
\
		q += 3; \
	} \
}

static void
vips_CICP2scRGB_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	VipsCICP2scRGB *cicp = (VipsCICP2scRGB *) colour;

	if (cicp->in->BandFmt == VIPS_FORMAT_UCHAR)
		CICP2SCRGB_LOOP(VipsPel)
	else
		CICP2SCRGB_LOOP(unsigned short)
}

static int
vips_CICP2scRGB_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsColour *colour = VIPS_COLOUR(object);
	VipsCICP2scRGB *cicp = (VipsCICP2scRGB *) object;
	int colour_primaries;
	int transfer_characteristics;
	int matrix_coefficients;

	/* Don't process alpha
	 */
	colour->input_bands = 3;
	colour->n = 1;
	colour->in = (VipsImage **) vips_object_local_array(object, 1);

	if (cicp->in) {

		if (vips_check_u8or16(class->nickname, cicp->in))
			return -1;

		if (vips_image_get_int(cicp->in, "cicp-colour-primaries", &colour_primaries) ||
			vips_image_get_int(cicp->in, "cicp-transfer-characteristics", &transfer_characteristics) ||
			vips_image_get_int(cicp->in, "cicp-matrix-coefficients", &matrix_coefficients) ||
			vips_image_get_int(cicp->in, "cicp-full-range-flag", &cicp->full_range_flag))
			return -1;

		cicp->colour_primaries = colour_primaries;
		cicp->transfer_characteristics = transfer_characteristics;
		cicp->matrix_coefficients = matrix_coefficients;

		memcpy(cicp->conversion_matrix,
			vips_CICP2scRGB_get_matrix(cicp->colour_primaries),
			9 * sizeof(float));
		memcpy(cicp->luminance_coeffs,
			vips_cicp_get_luminance(cicp->colour_primaries),
			3 * sizeof(float));

		cicp->lut_size = cicp->in->BandFmt == VIPS_FORMAT_UCHAR
			? 256 : 65536;
		cicp->transfer_lut = vips_CICP2scRGB_build_lut(
			cicp->transfer_characteristics, cicp->lut_size);

		if (cicp->transfer_characteristics == VIPS_CICP_TRANSFER_HLG)
			cicp->ootf_lut = vips_cicp_build_power_lut(
				0.2f, 1000.0f / SDR_WHITE);

		colour->in[0] = cicp->in;
		g_object_ref(cicp->in);
	}

	if (VIPS_OBJECT_CLASS(vips_CICP2scRGB_parent_class)->build(object))
		return -1;

	/* Strip CICP metadata from the output - it no longer describes
	 * the pixel values after linearization to scRGB.
	 */
	vips_image_remove(colour->out, "cicp-colour-primaries");
	vips_image_remove(colour->out, "cicp-transfer-characteristics");
	vips_image_remove(colour->out, "cicp-matrix-coefficients");
	vips_image_remove(colour->out, "cicp-full-range-flag");

	return 0;
}

static void
vips_CICP2scRGB_dispose(GObject *gobject)
{
	VipsCICP2scRGB *cicp = (VipsCICP2scRGB *) gobject;

	VIPS_FREE(cicp->transfer_lut);
	VIPS_FREE(cicp->ootf_lut);

	G_OBJECT_CLASS(vips_CICP2scRGB_parent_class)->dispose(gobject);
}

static void
vips_CICP2scRGB_class_init(VipsCICP2scRGBClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->dispose = vips_CICP2scRGB_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "CICP2scRGB";
	object_class->description = _("transform CICP to scRGB");
	object_class->build = vips_CICP2scRGB_build;

	colour_class->process_line = vips_CICP2scRGB_line;

	VIPS_ARG_IMAGE(class, "in", 1,
		_("Input"),
		_("Input image"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsColourTransform, in));
}

static void
vips_CICP2scRGB_init(VipsCICP2scRGB *cicp)
{
	VipsColour *colour = VIPS_COLOUR(cicp);

	colour->interpretation = VIPS_INTERPRETATION_scRGB;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;
}

/**
 * vips__image_is_cicp_hdr:
 * @image: image to check
 *
 * Check if @image has CICP metadata indicating an HDR transfer
 * function (PQ or HLG).
 *
 * Returns: %TRUE if the image has HDR CICP metadata.
 */
gboolean
vips__image_is_cicp_hdr(VipsImage *image)
{
	int transfer;

	if (vips_image_get_typeof(image, "cicp-transfer-characteristics") &&
		!vips_image_get_int(image,
			"cicp-transfer-characteristics", &transfer))
		return transfer == VIPS_CICP_TRANSFER_PQ ||
			transfer == VIPS_CICP_TRANSFER_HLG;

	return FALSE;
}

/**
 * vips_CICP2scRGB: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Transform an image with CICP signal to scRGB.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_CICP2scRGB(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("CICP2scRGB", ap, in, out);
	va_end(ap);

	return result;
}
