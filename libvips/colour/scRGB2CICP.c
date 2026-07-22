/* Turn scRGB image to CICP signal.
 *
 * 27/3/26
 * 	- from CICP2scRGB.c
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

typedef struct _VipsscRGB2CICP {
	VipsColourCode parent_instance;

	int depth;

	VipsCICPColourPrimaries colour_primaries;
	VipsCICPTransferCharacteristics transfer_characteristics;
	VipsCICPMatrixCoefficients matrix_coefficients;

	/* Conversion matrix from BT.709 (scRGB) to target primaries.
	 */
	float conversion_matrix[9];

	/* Luminance coefficients for target primaries (Y row of
	 * primaries-to-XYZ matrix), used by HLG inverse OOTF.
	 */
	float luminance_coeffs[3];

} VipsscRGB2CICP;

typedef VipsColourCodeClass VipsscRGB2CICPClass;

G_DEFINE_TYPE(VipsscRGB2CICP, vips_scRGB2CICP, VIPS_TYPE_COLOUR_CODE);

/* Inverse matrices: BT.709 -> target primaries.
 * Computed as the matrix inverse of the X_to_BT709 matrices in CICP2scRGB.c.
 */

static const float BT709_to_BT2020[9] = {
	0.62740390f, 0.32928304f, 0.04331306f,
	0.06909729f, 0.91954039f, 0.01136231f,
	0.01639144f, 0.08801331f, 0.89559525f
};

static const float BT709_to_DCI_P3[9] = {
	0.86857974f, 0.12891914f, 0.00250112f,
	0.03454041f, 0.96181139f, 0.00364820f,
	0.01677143f, 0.07104000f, 0.91218857f
};

static const float BT709_to_Display_P3[9] = {
	0.82246197f, 0.17753803f, 0.00000000f,
	0.03319420f, 0.96680581f, 0.00000000f,
	0.01708263f, 0.07239744f, 0.91051993f
};

/* Bradford chromatic adaptation (D65 -> Illuminant C)
 */
static const float BT709_to_BT470M[9] = {
	0.67835640f, 0.28847937f, 0.03316423f,
	0.01651316f, 1.05200891f, -0.06852207f,
	0.01791784f, 0.05063116f, 0.93145099f
};

static const float BT709_to_BT470BG[9] = {
	0.95781476f, 0.04218524f, 0.00000000f,
	0.00000000f, 1.00000000f, 0.00000000f,
	0.00000000f, -0.01193412f, 1.01193412f
};

/* BT.601 / SMPTE 170M / SMPTE 240M share the same primaries
 */
static const float BT709_to_BT601[9] = {
	1.06537904f, -0.05540088f, -0.00997816f,
	-0.01963255f, 1.03636310f, -0.01673054f,
	0.00163205f, 0.00441237f, 0.99395558f
};

/* Bradford chromatic adaptation (D65 -> Illuminant C)
 */
static const float BT709_to_GenericFilm[9] = {
	0.75141736f, 0.23960166f, 0.00898097f,
	0.03367299f, 0.94971067f, 0.01661635f,
	0.01693851f, 0.05856136f, 0.92450013f
};

static const float BT709_to_EBU3213[9] = {
	0.97484950f, 0.02729535f, -0.00214486f,
	-0.02000029f, 1.05420904f, -0.03420875f,
	0.00169075f, 0.00156378f, 0.99674547f
};

static const float *
vips_scRGB2CICP_get_matrix(VipsCICPColourPrimaries primaries)
{
	switch (primaries) {
	case VIPS_CICP_COLOUR_PRIMARIES_BT2020:
		return BT709_to_BT2020;
	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE431:
		return BT709_to_DCI_P3;
	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE432:
		return BT709_to_Display_P3;
	case VIPS_CICP_COLOUR_PRIMARIES_BT470M:
		return BT709_to_BT470M;
	case VIPS_CICP_COLOUR_PRIMARIES_BT470BG:
		return BT709_to_BT470BG;
	case VIPS_CICP_COLOUR_PRIMARIES_BT601:
	case VIPS_CICP_COLOUR_PRIMARIES_SMPTE240:
		return BT709_to_BT601;
	case VIPS_CICP_COLOUR_PRIMARIES_GENERIC_FILM:
		return BT709_to_GenericFilm;
	case VIPS_CICP_COLOUR_PRIMARIES_EBU3213:
		return BT709_to_EBU3213;
	default:
		return BT709_to_BT709;
	}
}

/* Forward OETFs: linear-light -> signal.
 * These are the mathematical inverses of the EOTF/inverse-OETF
 * functions in CICP2scRGB.c, per ITU-T H.273 Table 3.
 */

/* BT.709 / BT.601 / BT.2020 OETF (H.273 Table 3, values 1, 6, 14, 15).
 * V = alpha * Lc^0.45 - (alpha - 1), for Lc >= beta
 * V = 4.5 * Lc, for Lc < beta
 */
static inline float
vips_bt709_oetf(float L)
{
	const float alpha = 1.09929682680944f;
	const float beta = 0.018053968510807f;

	if (L < 0.0f)
		return 0.0f;

	if (L < beta)
		return 4.5f * L;
	else
		return alpha * powf(L, 0.45f) - (alpha - 1.0f);
}

/* sRGB OETF (H.273 Table 3, value 13 with MatrixCoefficients == 0).
 * V = alpha * Lc^(1/2.4) - (alpha - 1), for Lc >= beta
 * V = 12.92 * Lc, for Lc < beta
 */
static inline float
vips_sRGB_oetf(float L)
{
	const float alpha = 1.05501071894759f;
	const float beta = 0.003041282560128f;

	if (L < 0.0f)
		return 0.0f;

	if (L < beta)
		return 12.92f * L;
	else
		return alpha * powf(L, 1.0f / 2.4f) - (alpha - 1.0f);
}

/* PQ inverse EOTF (H.273 Table 3, value 16).
 * V = ((c1 + c2 * Lo^n) / (1 + c3 * Lo^n))^m
 * Lo = L * SDR_WHITE / 10000 (normalize scRGB to [0, 1] display luminance)
 */
static inline float
vips_pq_oetf(float L)
{
	const float m1 = 2610.0f / 16384.0f;
	const float m2 = 2523.0f / 4096.0f * 128.0f;
	const float c1 = 3424.0f / 4096.0f;
	const float c2 = 2413.0f / 4096.0f * 32.0f;
	const float c3 = 2392.0f / 4096.0f * 32.0f;

	float Lo = fmaxf(L * (SDR_WHITE / 10000.0f), 0.0f);

	float Lo_m1 = powf(Lo, m1);
	float numerator = c1 + c2 * Lo_m1;
	float denominator = 1.0f + c3 * Lo_m1;

	return powf(numerator / denominator, m2);
}

/* HLG OETF (H.273 Table 3, value 18).
 * V = a * Ln(12 * Lc - b) + c, for 1 >= Lc > 1/12
 * V = Sqrt(3) * Lc^0.5, for 1/12 >= Lc >= 0
 */
static inline float
vips_hlg_oetf(float L)
{
	const float a = 0.17883277f;
	const float b = 0.28466892f;
	const float c = 0.55991073f;

	if (L <= 0.0f)
		return 0.0f;

	if (L <= 1.0f / 12.0f)
		return sqrtf(3.0f * L);
	else
		return a * logf(12.0f * L - b) + c;
}

/* HLG inverse OOTF: display-linear -> scene-linear.
 * Inverts the OOTF F_d = alpha * Y_s^(gamma-1) * E_s from BT.2100-2.
 *
 * The luminance transforms as Y_d = alpha * Y_s^gamma, so:
 *   Y_s = (Y_d / alpha)^(1/gamma)
 *   E_s = F_d * Y_s / Y_d
 *
 * Input/output are in target primaries (after BT.709 -> target matrix).
 */
static inline void
vips_hlg_inverse_ootf(float *r, float *g, float *b,
	const float *luminance)
{
	const float alpha = 1000.0f / SDR_WHITE;
	const float inv_gamma = 1.0f / 1.2f;

	float Y_d = luminance[0] * *r + luminance[1] * *g + luminance[2] * *b;

	if (Y_d <= 0.0f) {
		*r = 0.0f;
		*g = 0.0f;
		*b = 0.0f;
		return;
	}

	float Y_s = powf(Y_d / alpha, inv_gamma);
	float factor = Y_s / Y_d;

	*r *= factor;
	*g *= factor;
	*b *= factor;
}

/* Dispatch to the appropriate forward OETF for the given transfer
 * characteristic. Input is linear-light, output is signal in [0, 1].
 */
static inline float
vips_scRGB2CICP_transfer(VipsCICPTransferCharacteristics transfer, float L)
{
	switch (transfer) {
	case VIPS_CICP_TRANSFER_PQ:
		return vips_pq_oetf(L);
	case VIPS_CICP_TRANSFER_HLG:
		return vips_hlg_oetf(L);
	case VIPS_CICP_TRANSFER_BT709:
	case VIPS_CICP_TRANSFER_BT601:
	case VIPS_CICP_TRANSFER_BT2020_10BIT:
	case VIPS_CICP_TRANSFER_BT2020_12BIT:
		return vips_bt709_oetf(L);
	case VIPS_CICP_TRANSFER_SMPTE240: {
		const float alpha = 1.11157219592173f;
		const float beta = 0.022821585529445f;

		if (L < 0.0f)
			return 0.0f;
		if (L < beta)
			return 4.0f * L;
		return alpha * powf(L, 0.45f) - (alpha - 1.0f);
	}
	case VIPS_CICP_TRANSFER_SRGB:
		return vips_sRGB_oetf(L);
	case VIPS_CICP_TRANSFER_BT470M:
		return powf(fmaxf(L, 0.0f), 1.0f / 2.2f);
	case VIPS_CICP_TRANSFER_BT470BG:
		return powf(fmaxf(L, 0.0f), 1.0f / 2.8f);
	case VIPS_CICP_TRANSFER_LINEAR:
		return L;
	case VIPS_CICP_TRANSFER_LOG_100:
		/* V = 1.0 + Log10(Lc) / 2 for Lc >= 0.01, else 0.
		 */
		return L >= 0.01f ? 1.0f + log10f(L) / 2.0f : 0.0f;
	case VIPS_CICP_TRANSFER_LOG_100_SQRT10:
		/* V = 1.0 + Log10(Lc) / 2.5 for Lc >= Sqrt(10)/1000, else 0.
		 */
		return L >= 3.16227766e-3f
			? 1.0f + log10f(L) / 2.5f
			: 0.0f;
	case VIPS_CICP_TRANSFER_IEC61966:
	case VIPS_CICP_TRANSFER_BT1361:
		/* BT.709 curve extended to negative values via odd symmetry.
		 */
		if (L >= 0.0f)
			return vips_bt709_oetf(L);
		else
			return -vips_bt709_oetf(-L);
	case VIPS_CICP_TRANSFER_SMPTE428:
		/* V = (48 * Lo / 52.37)^(1/2.6)
		 * Lo = L * SDR_WHITE / 48 (scRGB to 48 cd/m² reference)
		 * Simplifies to V = (L * SDR_WHITE / 52.37)^(1/2.6)
		 */
		return powf(fmaxf(L, 0.0f) * (SDR_WHITE / 52.37f),
			1.0f / 2.6f);
	default:
		return L;
	}
}

#define SCRGB2CICP_LOOP(TYPE, MAX_VAL) \
{ \
	float *restrict p = (float *) in[0]; \
	TYPE *restrict q = (TYPE *) out; \
	const float *matrix = cicp->conversion_matrix; \
	const float *luminance = cicp->luminance_coeffs; \
	const VipsCICPTransferCharacteristics transfer = \
		cicp->transfer_characteristics; \
	const gboolean is_hlg = (transfer == VIPS_CICP_TRANSFER_HLG); \
	const float scale = (float) MAX_VAL; \
\
	for (int i = 0; i < width; i++) { \
		float r = p[0]; \
		float g = p[1]; \
		float b = p[2]; \
		p += 3; \
\
		float tr, tg, tb; \
		vips_cicp_apply_matrix(matrix, r, g, b, &tr, &tg, &tb); \
\
		if (is_hlg) \
			vips_hlg_inverse_ootf(&tr, &tg, &tb, luminance); \
\
		float vr = vips_scRGB2CICP_transfer(transfer, tr); \
		float vg = vips_scRGB2CICP_transfer(transfer, tg); \
		float vb = vips_scRGB2CICP_transfer(transfer, tb); \
\
		int ir = (int) (vr * scale + 0.5f); \
		int ig = (int) (vg * scale + 0.5f); \
		int ib = (int) (vb * scale + 0.5f); \
\
		q[0] = (TYPE) VIPS_CLIP(0, ir, MAX_VAL); \
		q[1] = (TYPE) VIPS_CLIP(0, ig, MAX_VAL); \
		q[2] = (TYPE) VIPS_CLIP(0, ib, MAX_VAL); \
		q += 3; \
	} \
}

static void
vips_scRGB2CICP_line(VipsColour *colour, VipsPel *out, VipsPel **in, int width)
{
	VipsscRGB2CICP *cicp = (VipsscRGB2CICP *) colour;

	if (cicp->depth == 16)
		SCRGB2CICP_LOOP(unsigned short, 65535)
	else
		SCRGB2CICP_LOOP(unsigned char, 255)
}

static int
vips_scRGB2CICP_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsscRGB2CICP *cicp = (VipsscRGB2CICP *) object;
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;

	code->input_format = VIPS_FORMAT_FLOAT;
	colour->input_bands = 3;

	switch (cicp->depth) {
	case 16:
		colour->interpretation = VIPS_INTERPRETATION_RGB16;
		colour->format = VIPS_FORMAT_USHORT;
		break;

	case 8:
		colour->interpretation = VIPS_INTERPRETATION_sRGB;
		colour->format = VIPS_FORMAT_UCHAR;
		break;

	default:
		vips_error(class->nickname, "%s", _("depth must be 8 or 16"));
		return -1;
	}

	colour->bands = 3;

	/* TODO: implement matrix coefficients and narrow-range
	 * quantization. For now, only identity matrix (0) with
	 * full range is supported.
	 */
	if (cicp->matrix_coefficients != VIPS_CICP_MATRIX_RGB) {
		vips_error(class->nickname, "%s",
			_("only matrix-coefficients 0 (identity/RGB) "
			  "is currently supported"));
		return -1;
	}

	memcpy(cicp->conversion_matrix,
		vips_scRGB2CICP_get_matrix(cicp->colour_primaries),
		9 * sizeof(float));
	memcpy(cicp->luminance_coeffs,
		vips_cicp_get_luminance(cicp->colour_primaries),
		3 * sizeof(float));

	if (VIPS_OBJECT_CLASS(vips_scRGB2CICP_parent_class)->build(object))
		return -1;

	vips_image_set_int(colour->out,
		"cicp-colour-primaries", cicp->colour_primaries);
	vips_image_set_int(colour->out,
		"cicp-transfer-characteristics", cicp->transfer_characteristics);
	vips_image_set_int(colour->out,
		"cicp-matrix-coefficients", cicp->matrix_coefficients);
	vips_image_set_int(colour->out, "cicp-full-range-flag", 1);
	vips_image_remove(colour->out, "clli-max-content-light-level");
	vips_image_remove(colour->out, "clli-max-frame-average-light-level");

	return 0;
}

static void
vips_scRGB2CICP_class_init(VipsscRGB2CICPClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "scRGB2CICP";
	object_class->description = _("transform scRGB to CICP");
	object_class->build = vips_scRGB2CICP_build;

	colour_class->process_line = vips_scRGB2CICP_line;

	VIPS_ARG_ENUM(class, "colour_primaries", 2,
		_("Colour primaries"),
		_("CICP colour primaries (H.273 Table 2)"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsscRGB2CICP, colour_primaries),
		VIPS_TYPE_CICP_COLOUR_PRIMARIES,
		VIPS_CICP_COLOUR_PRIMARIES_BT709);

	VIPS_ARG_ENUM(class, "transfer_characteristics", 3,
		_("Transfer characteristics"),
		_("CICP transfer characteristics (H.273 Table 3)"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsscRGB2CICP, transfer_characteristics),
		VIPS_TYPE_CICP_TRANSFER_CHARACTERISTICS,
		VIPS_CICP_TRANSFER_SRGB);

	VIPS_ARG_ENUM(class, "matrix_coefficients", 4,
		_("Matrix coefficients"),
		_("CICP matrix coefficients (H.273 Table 4)"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsscRGB2CICP, matrix_coefficients),
		VIPS_TYPE_CICP_MATRIX_COEFFICIENTS,
		VIPS_CICP_MATRIX_RGB);

	VIPS_ARG_INT(class, "depth", 130,
		_("Depth"),
		_("Output device space depth in bits"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsscRGB2CICP, depth),
		8, 16, 8);
}

static void
vips_scRGB2CICP_init(VipsscRGB2CICP *cicp)
{
	cicp->depth = 8;
	cicp->colour_primaries = VIPS_CICP_COLOUR_PRIMARIES_BT709;
	cicp->transfer_characteristics = VIPS_CICP_TRANSFER_SRGB;
	cicp->matrix_coefficients = VIPS_CICP_MATRIX_RGB;
}

/**
 * vips_scRGB2CICP: (method)
 * @in: input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Transform an scRGB image to CICP signal. The target colour encoding
 * is specified via the optional CICP arguments.
 *
 * Currently only @matrix_coefficients %VIPS_CICP_MATRIX_RGB and
 * full-range output is supported.
 *
 * ::: tip "Optional arguments"
 *     * @colour_primaries: #VipsCICPColourPrimaries, target primaries (default %VIPS_CICP_COLOUR_PRIMARIES_BT709)
 *     * @transfer_characteristics: #VipsCICPTransferCharacteristics, target transfer (default %VIPS_CICP_TRANSFER_SRGB)
 *     * @matrix_coefficients: #VipsCICPMatrixCoefficients, target matrix (default %VIPS_CICP_MATRIX_RGB)
 *     * @depth: `gint`, output depth in bits, 8 or 16 (default 8)
 *
 * ::: seealso
 *     [method@Image.CICP2scRGB], [method@Image.scRGB2sRGB].
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_scRGB2CICP(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("scRGB2CICP", ap, in, out);
	va_end(ap);

	return result;
}
