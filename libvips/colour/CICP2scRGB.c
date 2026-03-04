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
	VipsCICPMatrixCoefficients matrix_coefficients;

	int full_range_flag; // unused

	/* Conversion matrix from source primaries to BT.709 (scRGB) */
	float conversion_matrix[9];

} VipsCICP2scRGB;

#define SDR_WHITE 80.0f

typedef VipsColourClass VipsCICP2scRGBClass;

G_DEFINE_TYPE(VipsCICP2scRGB, vips_CICP2scRGB, VIPS_TYPE_COLOUR);

static const float BT709_to_BT709[9] = {
	1.0f, 0.0f, 0.0f,
	0.0f, 1.0f, 0.0f,
	0.0f, 0.0f, 1.0f
};

static const float BT2020_to_BT709[9] = {
    1.660491f, -0.58764114f, -0.07284986f,
    -0.12455047f, 1.1328999f, -0.00834942f,
    -0.01815076f, -0.1005789f, 1.11872966f
};

// Bradford chromatic adaptation
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

static void
vips_CICP2scRGB_init_matrix(VipsCICP2scRGB *cicp)
{
	const float *matrix;

	switch (cicp->colour_primaries) {
	case VIPS_CICP_COLOUR_PRIMARIES_BT709:
		matrix = BT709_to_BT709;
		break;

	case VIPS_CICP_COLOUR_PRIMARIES_BT2020:
		matrix = BT2020_to_BT709;
		break;

	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE431:
		matrix = DCI_P3_to_BT709;
		break;

	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE432:
		matrix = Display_P3_to_BT709;
		break;

	default:
		/* For unspecified or unimplemented primaries, use identity */
		matrix = BT709_to_BT709;
		break;
	}

	memcpy(cicp->conversion_matrix, matrix, 9 * sizeof(float));
}

static inline void
vips_apply_matrix(const float *matrix, float r, float g, float b,
	float *out_r, float *out_g, float *out_b)
{
	*out_r = matrix[0] * r + matrix[1] * g + matrix[2] * b;
	*out_g = matrix[3] * r + matrix[4] * g + matrix[5] * b;
	*out_b = matrix[6] * r + matrix[7] * g + matrix[8] * b;
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
 *   Y_s = BT.2020 luminance = 0.2627*R + 0.6780*G + 0.0593*B
 *
 * Output scaled by 1/SDR_WHITE so that 1.0 = 80 nits.
 */
static inline void
vips_hlg_ootf(float *r, float *g, float *b)
{
	const float gamma_minus_1 = 0.2f;
	const float scale = 1000.0f / SDR_WHITE;

	float Y_s = 0.2627f * *r + 0.6780f * *g + 0.0593f * *b;

	if (Y_s <= 0.0f) {
		*r = 0.0f;
		*g = 0.0f;
		*b = 0.0f;
		return;
	}

	float factor = scale * powf(Y_s, gamma_minus_1);

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
	const float signal_beta = 0.04045f;
	const float slope = 12.92f;
	const float alpha = 1.055f;
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
		const float alpha = 1.1115f;
		const float linear_beta = 0.0228f;
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
	default:
		/* Unknown transfer -- pass through unchanged */
		return in;
	}
}

/* Process 8-bit RGB image with CICP transfer function.
 */
static void
vips_CICP2scRGB_uchar(VipsCICP2scRGB *cicp,
	VipsPel *out, VipsPel **in, int width)
{
	VipsPel *restrict p = in[0];
	float *restrict q = (float *) out;
	const VipsCICPTransferCharacteristics transfer = cicp->transfer_characteristics;
	const float *matrix = cicp->conversion_matrix;

	for (int i = 0; i < width; i++) {
		float r = p[0] / 255.0f;
		float g = p[1] / 255.0f;
		float b = p[2] / 255.0f;

		p += 3;

		r = vips_CICP2scRGB_transfer(transfer, r);
		g = vips_CICP2scRGB_transfer(transfer, g);
		b = vips_CICP2scRGB_transfer(transfer, b);

		if (transfer == VIPS_CICP_TRANSFER_HLG)
			vips_hlg_ootf(&r, &g, &b);

		vips_apply_matrix(matrix, r, g, b, &q[0], &q[1], &q[2]);

		q += 3;
	}
}

static void
vips_CICP2scRGB_ushort(VipsCICP2scRGB *cicp,
	VipsPel *out, VipsPel **in, int width)
{
	unsigned short *restrict p = (unsigned short *) in[0];
	float *restrict q = (float *) out;
	const VipsCICPTransferCharacteristics transfer = cicp->transfer_characteristics;
	const float *matrix = cicp->conversion_matrix;

	for (int i = 0; i < width; i++) {
		float r = p[0] / 65535.0f;
		float g = p[1] / 65535.0f;
		float b = p[2] / 65535.0f;
		p += 3;

		r = vips_CICP2scRGB_transfer(transfer, r);
		g = vips_CICP2scRGB_transfer(transfer, g);
		b = vips_CICP2scRGB_transfer(transfer, b);

		if (transfer == VIPS_CICP_TRANSFER_HLG)
			vips_hlg_ootf(&r, &g, &b);

		vips_apply_matrix(matrix, r, g, b, &q[0], &q[1], &q[2]);

		q += 3;
	}
}

static void
vips_CICP2scRGB_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	VipsCICP2scRGB *cicp = (VipsCICP2scRGB *) colour;

	if (cicp->in->BandFmt == VIPS_FORMAT_UCHAR) {
		vips_CICP2scRGB_uchar(cicp, out, in, width);
	}
	else if (cicp->in->BandFmt == VIPS_FORMAT_USHORT) {
		vips_CICP2scRGB_ushort(cicp, out, in, width);
	}
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

		if (cicp->in->BandFmt != VIPS_FORMAT_UCHAR &&
			cicp->in->BandFmt != VIPS_FORMAT_USHORT) {
			vips_error(class->nickname, "%s", _("image must be uchar or ushort"));
			return -1;
		}

		if (vips_image_get_int(cicp->in, "cicp-colour-primaries", &colour_primaries) ||
			vips_image_get_int(cicp->in, "cicp-transfer-characteristics", &transfer_characteristics) ||
			vips_image_get_int(cicp->in, "cicp-matrix-coefficients", &matrix_coefficients) ||
			vips_image_get_int(cicp->in, "cicp-full-range-flag", &cicp->full_range_flag))
			return -1;

		cicp->colour_primaries = colour_primaries;
		cicp->transfer_characteristics = transfer_characteristics;
		cicp->matrix_coefficients = matrix_coefficients;

		vips_CICP2scRGB_init_matrix(cicp);

		colour->in[0] = cicp->in;
		g_object_ref(cicp->in);
	}

	if (VIPS_OBJECT_CLASS(vips_CICP2scRGB_parent_class)->build(object))
		return -1;

	return 0;
}

static void
vips_CICP2scRGB_class_init(VipsCICP2scRGBClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

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
