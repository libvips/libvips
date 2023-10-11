/* Transform images with little cms
 *
 * 26/4/02 JC
 * 26/8/05
 * 	- attach profiles and intents to output images
 * 	- added im_icc_import_embedded() to import with an embedded profile
 * 12/5/06
 * 	- lock around cmsDoTransform
 * 23/1/07
 * 	- set RGB16 on 16-bit RGB export
 * 6/4/09
 * 	- catch lcms error messages
 * 2/11/09
 * 	- gtkdoc
 * 	- small cleanups
 * 	- call attach_profile() before im_wrapone() so the profile will get
 * 	  written if we are wrinting to a file
 * 2/8/10
 * 	- add lcms2
 * 12/7/11
 * 	- import and export cast @in to an appropriate format for you
 * 25/9/12
 * 	- redo as a class
 * 14/5/13
 * 	- import and export would segv on very wide images
 * 12/11/13
 * 	- support XYZ as an alternative PCS
 * 10/9/14
 * 	- support GRAY as an input and output space
 * 29/9/14
 * 	- check input profiles for compatibility with the input image, thanks
 * 	  James
 * 26/6/15
 *	- better profile sanity checking for icc import
 * 2/8/17
 * 	- remove lcms1 support, it was untested
 * 10/10/17
 * 	- more input profile sanity tests
 * 8/3/18
 * 	- attach fallback profile on import if we used it
 * 28/12/18
 * 	- remove warning messages from vips_icc_is_compatible_profile() since
 * 	  they can be triggered under normal circumstances
 * 17/4/19 kleisauke
 * 	- better rejection of broken embedded profiles
 * 29/3/21 [hanssonrickard]
 * 	- add black_point_compensation
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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#ifdef HAVE_LCMS2

#include <stdio.h>
#include <math.h>

/* Has to be before VIPS to avoid nameclashes.
 */
#include <lcms2.h>

#include <vips/vips.h>

#include "pcolour.h"

/* Call lcms with up to this many pixels at once.
 */
#define PIXEL_BUFFER_SIZE (10000)

/**
 * VipsIntent:
 * @VIPS_INTENT_PERCEPTUAL: perceptual rendering intent
 * @VIPS_INTENT_RELATIVE: relative colorimetric rendering intent
 * @VIPS_INTENT_SATURATION: saturation rendering intent
 * @VIPS_INTENT_ABSOLUTE: absolute colorimetric rendering intent
 *
 * The rendering intent. #VIPS_INTENT_ABSOLUTE is best for
 * scientific work, #VIPS_INTENT_RELATIVE is usually best for
 * accurate communication with other imaging libraries.
 */

/**
 * VipsPCS:
 * @VIPS_PCS_LAB: use CIELAB D65 as the Profile Connection Space
 * @VIPS_PCS_XYZ: use XYZ as the Profile Connection Space
 *
 * Pick a Profile Connection Space for vips_icc_import() and
 * vips_icc_export(). LAB is usually best, XYZ can be more convenient in some
 * cases.
 */

/**
 * vips_icc_present:
 *
 * VIPS can optionally be built without the ICC library. Use this function to
 * test for its availability.
 *
 * Returns: non-zero if the ICC library is present.
 */
int
vips_icc_present(void)
{
	return 1;
}

#define VIPS_TYPE_ICC (vips_icc_get_type())
#define VIPS_ICC(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_ICC, VipsIcc))
#define VIPS_ICC_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		VIPS_TYPE_ICC, VipsIccClass))
#define VIPS_IS_ICC(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), VIPS_TYPE_ICC))
#define VIPS_IS_ICC_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), VIPS_TYPE_ICC))
#define VIPS_ICC_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
		VIPS_TYPE_ICC, VipsIccClass))

typedef struct _VipsIcc {
	VipsColourCode parent_instance;

	VipsIntent intent;
	VipsPCS pcs;
	int depth;
	gboolean black_point_compensation;

	VipsBlob *in_blob;
	cmsHPROFILE in_profile;
	VipsBlob *out_blob;
	cmsHPROFILE out_profile;
	cmsUInt32Number in_icc_format;
	cmsUInt32Number out_icc_format;
	cmsHTRANSFORM trans;
	gboolean non_standard_input_profile;
} VipsIcc;

typedef VipsColourCodeClass VipsIccClass;

G_DEFINE_ABSTRACT_TYPE(VipsIcc, vips_icc, VIPS_TYPE_COLOUR_CODE);

/* Error from lcms.
 */

static void
icc_error(cmsContext context, cmsUInt32Number code, const char *text)
{
	vips_error("VipsIcc", "%s", text);
}

static void
vips_icc_dispose(GObject *gobject)
{
	VipsIcc *icc = (VipsIcc *) gobject;

	VIPS_FREEF(cmsDeleteTransform, icc->trans);
	VIPS_FREEF(cmsCloseProfile, icc->in_profile);
	VIPS_FREEF(cmsCloseProfile, icc->out_profile);

	if (icc->in_blob) {
		vips_area_unref((VipsArea *) icc->in_blob);
		icc->in_blob = NULL;
	}

	if (icc->out_blob) {
		vips_area_unref((VipsArea *) icc->out_blob);
		icc->out_blob = NULL;
	}

	G_OBJECT_CLASS(vips_icc_parent_class)->dispose(gobject);
}

/* Is a profile just a pcs stub.
 */
static gboolean
is_pcs(cmsHPROFILE profile)
{
	return cmsGetColorSpace(profile) == cmsSigLabData ||
		cmsGetColorSpace(profile) == cmsSigXYZData;
}

/* Info for all supported lcms profile signatures.
 */
typedef struct _VipsIccInfo {
	int signature;
	int bands;
	guint lcms_type8;
	guint lcms_type16;
} VipsIccInfo;

static VipsIccInfo vips_icc_info_table[] = {
	{ cmsSigGrayData, 1, TYPE_GRAY_8, TYPE_GRAY_16 },

	{ cmsSigRgbData, 3, TYPE_RGB_8, TYPE_RGB_16 },
	{ cmsSigLabData, 3, TYPE_Lab_FLT, TYPE_Lab_16 },
	{ cmsSigXYZData, 3, TYPE_XYZ_FLT, TYPE_XYZ_16 },

	{ cmsSigCmykData, 4, TYPE_CMYK_8, TYPE_CMYK_16 },
	{ cmsSig4colorData, 4, TYPE_CMYK_8, TYPE_CMYK_16 },
	{ cmsSig5colorData, 5, TYPE_CMYK5_8, TYPE_CMYK5_16 },
	{ cmsSig6colorData, 6, TYPE_CMYK6_8, TYPE_CMYK6_16 },
	{ cmsSig7colorData, 7, TYPE_CMYK7_8, TYPE_CMYK7_16 },
	{ cmsSig8colorData, 8, TYPE_CMYK8_8, TYPE_CMYK8_16 },
	{ cmsSig9colorData, 9, TYPE_CMYK9_8, TYPE_CMYK9_16 },
	{ cmsSig10colorData, 10, TYPE_CMYK10_8, TYPE_CMYK10_16 },
	{ cmsSig11colorData, 11, TYPE_CMYK11_8, TYPE_CMYK11_16 },
	{ cmsSig12colorData, 12, TYPE_CMYK12_8, TYPE_CMYK12_16 },
};

static VipsIccInfo *
vips_icc_info(int signature)
{
	int i;

	for (i = 0; i < VIPS_NUMBER(vips_icc_info_table); i++)
		if (vips_icc_info_table[i].signature == signature)
			return &vips_icc_info_table[i];

	return NULL;
}

static int
vips_icc_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;
	VipsIcc *icc = (VipsIcc *) object;

	cmsUInt32Number flags;

	if (icc->depth != 8 &&
		icc->depth != 16) {
		vips_error(class->nickname,
			"%s", _("depth must be 8 or 16"));
		return -1;
	}

	if (icc->in_profile &&
		code->in) {
		int signature;
		VipsIccInfo *info;

		signature = cmsGetColorSpace(icc->in_profile);
		if (!(info = vips_icc_info(signature))) {
			vips_error(class->nickname,
				_("unimplemented input color space 0x%x"),
				signature);
			return -1;
		}

		colour->input_bands = info->bands;

		switch (signature) {
		case cmsSigGrayData:
			code->input_format = code->in->BandFmt == VIPS_FORMAT_USHORT
				? VIPS_FORMAT_USHORT
				: VIPS_FORMAT_UCHAR;
			icc->in_icc_format = code->in->BandFmt == VIPS_FORMAT_USHORT
				? info->lcms_type16
				: info->lcms_type8;
			break;

		case cmsSigRgbData:
			code->input_format = code->in->BandFmt == VIPS_FORMAT_USHORT
				? VIPS_FORMAT_USHORT
				: VIPS_FORMAT_UCHAR;
			icc->in_icc_format = code->in->BandFmt == VIPS_FORMAT_USHORT
				? info->lcms_type16
				: info->lcms_type8;
			break;

		case cmsSigLabData:
			code->input_format = VIPS_FORMAT_FLOAT;
			code->input_interpretation =
				VIPS_INTERPRETATION_LAB;
			icc->in_icc_format = info->lcms_type8;
			break;

		case cmsSigXYZData:
			code->input_format = VIPS_FORMAT_FLOAT;
			code->input_interpretation =
				VIPS_INTERPRETATION_XYZ;
			icc->in_icc_format = info->lcms_type8;
			break;

		case cmsSigCmykData:
		case cmsSig5colorData:
		case cmsSig6colorData:
		case cmsSig7colorData:
		case cmsSig8colorData:
		case cmsSig9colorData:
		case cmsSig10colorData:
		case cmsSig11colorData:
		case cmsSig12colorData:
			/* Treat as forms of CMYK.
			 */
			info = vips_icc_info(
				cmsGetColorSpace(icc->in_profile));

			code->input_format = code->in->BandFmt == VIPS_FORMAT_USHORT
				? VIPS_FORMAT_USHORT
				: VIPS_FORMAT_UCHAR;
			icc->in_icc_format =
				code->in->BandFmt == VIPS_FORMAT_USHORT
				? info->lcms_type16
				: info->lcms_type8;
			break;

		default:
			g_assert_not_reached();
			return -1;
		}
	}

	if (icc->out_profile) {
		int signature;
		VipsIccInfo *info;

		signature = cmsGetColorSpace(icc->out_profile);
		if (!(info = vips_icc_info(signature))) {
			vips_error(class->nickname,
				_("unimplemented output color space 0x%x"),
				signature);
			return -1;
		}

		colour->bands = info->bands;

		switch (signature) {
		case cmsSigGrayData:
			colour->interpretation = icc->depth == 8
				? VIPS_INTERPRETATION_B_W
				: VIPS_INTERPRETATION_GREY16;
			colour->format = icc->depth == 8
				? VIPS_FORMAT_UCHAR
				: VIPS_FORMAT_USHORT;
			icc->out_icc_format = icc->depth == 16
				? info->lcms_type16
				: info->lcms_type8;
			break;

		case cmsSigRgbData:
			colour->interpretation = icc->depth == 8
				? VIPS_INTERPRETATION_sRGB
				: VIPS_INTERPRETATION_RGB16;
			colour->format = icc->depth == 8
				? VIPS_FORMAT_UCHAR
				: VIPS_FORMAT_USHORT;
			icc->out_icc_format = icc->depth == 16
				? info->lcms_type16
				: info->lcms_type8;
			break;

		case cmsSigLabData:
			colour->interpretation = VIPS_INTERPRETATION_LAB;
			colour->format = VIPS_FORMAT_FLOAT;
			icc->out_icc_format = info->lcms_type16;
			break;

		case cmsSigXYZData:
			colour->interpretation = VIPS_INTERPRETATION_XYZ;
			colour->format = VIPS_FORMAT_FLOAT;
			icc->out_icc_format = info->lcms_type16;
			break;

		case cmsSigCmykData:
		case cmsSig5colorData:
		case cmsSig6colorData:
		case cmsSig7colorData:
		case cmsSig8colorData:
		case cmsSig9colorData:
		case cmsSig10colorData:
		case cmsSig11colorData:
		case cmsSig12colorData:
			/* Treat as forms of CMYK.
			 */
			colour->interpretation = VIPS_INTERPRETATION_CMYK;
			colour->format = icc->depth == 8
				? VIPS_FORMAT_UCHAR
				: VIPS_FORMAT_USHORT;
			icc->out_icc_format = icc->depth == 16
				? info->lcms_type16
				: info->lcms_type8;
			break;

		default:
			g_assert_not_reached();
			return -1;
		}
	}

	/* At least one must be a device profile.
	 */
	if (icc->in_profile &&
		icc->out_profile &&
		is_pcs(icc->in_profile) &&
		is_pcs(icc->out_profile)) {
		vips_error(class->nickname,
			"%s", _("no device profile"));
		return -1;
	}

	/* Use cmsFLAGS_NOCACHE to disable the 1-pixel cache and make
	 * calling cmsDoTransform() from multiple threads safe.
	 */
	flags = cmsFLAGS_NOCACHE;

	if (icc->black_point_compensation)
		flags |= cmsFLAGS_BLACKPOINTCOMPENSATION;

	if (!(icc->trans = cmsCreateTransform(
			  icc->in_profile, icc->in_icc_format,
			  icc->out_profile, icc->out_icc_format,
			  icc->intent, flags)))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_icc_parent_class)->build(object))
		return -1;

	return 0;
}

/* Get from an image.
 */
static VipsBlob *
vips_icc_get_profile_image(VipsImage *image)
{
	const void *data;
	size_t size;

	if (!vips_image_get_typeof(image, VIPS_META_ICC_NAME))
		return NULL;
	if (vips_image_get_blob(image, VIPS_META_ICC_NAME, &data, &size))
		return NULL;

	return vips_blob_new(NULL, data, size);
}

#ifdef DEBUG
static void
vips_icc_print_profile(const char *name, cmsHPROFILE profile)
{
	static const cmsInfoType info_types[] = {
		cmsInfoDescription,
		cmsInfoManufacturer,
		cmsInfoModel,
		cmsInfoCopyright
	};
	static const char *info_names[] = {
		"description",
		"manufacturer",
		"model",
		"copyright"
	};

	int i;
	cmsUInt32Number n_bytes;
	cmsUInt32Number n_intents;
	cmsUInt32Number *intent_codes;
	char **intent_descriptions;

	printf("icc profile %s: %p\n", name, profile);
	for (i = 0; i < VIPS_NUMBER(info_types); i++) {
		if ((n_bytes = cmsGetProfileInfoASCII(profile,
				 info_types[i], "en", "US",
				 NULL, 0))) {
			char *buffer;

			buffer = VIPS_ARRAY(NULL, n_bytes, char);
			(void) cmsGetProfileInfoASCII(profile,
				info_types[i], "en", "US",
				buffer, n_bytes);
			printf("%s: %s\n", info_names[i], buffer);
			g_free(buffer);
		}
	}

	printf("intent: %d\n", cmsGetHeaderRenderingIntent(profile));

	printf("profile class: %#x\n", cmsGetDeviceClass(profile));
	{
		cmsColorSpaceSignature pcs = cmsGetPCS(profile);
		guint pcs_as_be = GUINT_TO_BE(pcs);

		char name[5];

		vips_strncpy(name, (const char *) &pcs_as_be, 5);
		printf("PCS: %#x (%s)\n", pcs, name);
	}

	printf("matrix shaper: %d\n", cmsIsMatrixShaper(profile));
	printf("version: %g\n", cmsGetProfileVersion(profile));

	n_intents = cmsGetSupportedIntents(0, NULL, NULL);
	printf("n_intents = %u\n", n_intents);
	intent_codes = VIPS_ARRAY(NULL, n_intents, cmsUInt32Number);
	intent_descriptions = VIPS_ARRAY(NULL, n_intents, char *);
	(void) cmsGetSupportedIntents(n_intents,
		intent_codes, intent_descriptions);
	for (i = 0; i < n_intents; i++) {
		printf("  %#x: %s, in CLUT = %d, out CLUT = %d\n",
			intent_codes[i], intent_descriptions[i],
			cmsIsCLUT(profile,
				intent_codes[i], LCMS_USED_AS_INPUT),
			cmsIsCLUT(profile,
				intent_codes[i], LCMS_USED_AS_OUTPUT));
	}
	g_free(intent_codes);
	g_free(intent_descriptions);
}
#endif /*DEBUG*/

/* TRUE if the number of bands in the ICC profile is compatible with the
 * image.
 */
static gboolean
vips_image_is_profile_compatible(VipsImage *image, int profile_bands)
{
	switch (image->Type) {
	case VIPS_INTERPRETATION_B_W:
	case VIPS_INTERPRETATION_GREY16:
		/* The ICC profile needs to be monochrome.
		 */
		return profile_bands == 1;

	case VIPS_INTERPRETATION_XYZ:
	case VIPS_INTERPRETATION_LAB:
	case VIPS_INTERPRETATION_LABQ:
	case VIPS_INTERPRETATION_RGB:
	case VIPS_INTERPRETATION_CMC:
	case VIPS_INTERPRETATION_LCH:
	case VIPS_INTERPRETATION_LABS:
	case VIPS_INTERPRETATION_sRGB:
	case VIPS_INTERPRETATION_YXY:
	case VIPS_INTERPRETATION_RGB16:
	case VIPS_INTERPRETATION_scRGB:
	case VIPS_INTERPRETATION_HSV:
		/* The band count in the ICC profile must correspond to that of
		 * the image, with a maximum of 3 bands allowed.
		 */
		return VIPS_MIN(3, image->Bands) == profile_bands;

	case VIPS_INTERPRETATION_CMYK:
		/* CMYK images can only be imported if the ICC-profile has at
		 * least 4 bands thereby blocking the usage of RGB profiles.
		 */
		return profile_bands >= 4;

	case VIPS_INTERPRETATION_MULTIBAND:
	case VIPS_INTERPRETATION_HISTOGRAM:
	case VIPS_INTERPRETATION_MATRIX:
	case VIPS_INTERPRETATION_FOURIER:
	default:
		return image->Bands >= profile_bands;
	}
}

/* Load a profile from a blob and check compatibility with image, intent and
 * direction.
 *
 * Don't set any errors since this is used to test compatibility.
 */
static cmsHPROFILE
vips_icc_load_profile_blob(VipsBlob *blob,
	VipsImage *image, VipsIntent intent, int direction)
{
	const void *data;
	size_t size;
	cmsHPROFILE profile;
	VipsIccInfo *info;

#ifdef DEBUG
	printf("loading %s profile, intent %s, from blob %p\n",
		direction == LCMS_USED_AS_INPUT ? _("input") : _("output"),
		vips_enum_nick(VIPS_TYPE_INTENT, intent),
		blob);
#endif /*DEBUG*/

	data = vips_blob_get(blob, &size);
	if (!(profile = cmsOpenProfileFromMem(data, size))) {
		g_warning("%s", _("corrupt profile"));
		return NULL;
	}

#ifdef DEBUG
	vips_icc_print_profile("loaded from blob to make", profile);
#endif /*DEBUG*/

	if (!(info = vips_icc_info(cmsGetColorSpace(profile)))) {
		VIPS_FREEF(cmsCloseProfile, profile);
		g_warning("%s", _("unsupported profile"));
		return NULL;
	}

	if (image &&
		!vips_image_is_profile_compatible(image, info->bands)) {
		VIPS_FREEF(cmsCloseProfile, profile);
		g_warning("%s", _("profile incompatible with image"));
		return NULL;
	}

	if (!cmsIsIntentSupported(profile, intent, direction)) {
		VIPS_FREEF(cmsCloseProfile, profile);
		g_warning(_("profile does not support %s %s intent"),
			vips_enum_nick(VIPS_TYPE_INTENT, intent),
			direction == LCMS_USED_AS_INPUT ? _("input") : _("output"));
		return NULL;
	}

	return profile;
}

/* Verify that a blob is not corrupt and is compatible with this image.
 *
 * unref the blob if it's useless.
 */
static cmsHPROFILE
vips_icc_verify_blob(VipsBlob **blob, VipsImage *image, VipsIntent intent)
{
	if (*blob) {
		cmsHPROFILE profile;

		if (!(profile = vips_icc_load_profile_blob(*blob,
				  image, intent, LCMS_USED_AS_INPUT))) {
			vips_area_unref((VipsArea *) *blob);
			*blob = NULL;
		}

		return profile;
	}

	return NULL;
}

/* Try to set the import profile. We read the input profile like this:
 *
 *	embedded	filename	action
 *	0		0 		image
 *	1		0		image
 *	0		1		file
 *	1		1		image, then fall back to file
 *
 * If averything fails, we fall back to our built-in profiles, either
 * srgb or cmyk, depending on the input image.
 *
 * We set attach_input_profile if we used a non-emdedded profile. The profile
 * in in_blob will need to be attached to the output image in some way.
 */
static int
vips_icc_set_import(VipsIcc *icc,
	gboolean embedded, const char *input_profile_filename)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(icc);
	VipsColourCode *code = (VipsColourCode *) icc;

	icc->non_standard_input_profile = FALSE;

	/* Try embedded profile.
	 */
	if (code->in &&
		(embedded || !input_profile_filename)) {
		icc->in_blob = vips_icc_get_profile_image(code->in);
		icc->in_profile = vips_icc_verify_blob(&icc->in_blob,
			code->in, icc->intent);
	}

	/* Try profile from filename.
	 */
	if (code->in &&
		!icc->in_blob &&
		input_profile_filename) {
		if (
			!vips_profile_load(input_profile_filename,
				&icc->in_blob, NULL) &&
			(icc->in_profile = vips_icc_verify_blob(&icc->in_blob,
				 code->in, icc->intent)))
			icc->non_standard_input_profile = TRUE;
	}

	/* Try built-in profile.
	 */
	if (code->in &&
		!icc->in_profile) {
		const char *name;

		switch (code->in->Type) {
		case VIPS_INTERPRETATION_B_W:
		case VIPS_INTERPRETATION_GREY16:
			name = "sgrey";
			break;

		case VIPS_INTERPRETATION_CMYK:
			name = "cmyk";
			break;

		default:
			name = "srgb";
			break;
		}

		if (
			!vips_profile_load(name, &icc->in_blob, NULL) &&
			(icc->in_profile = vips_icc_verify_blob(&icc->in_blob,
				 code->in, icc->intent)))
			icc->non_standard_input_profile = TRUE;
	}

	if (!icc->in_profile) {
		vips_error(class->nickname, "%s",
			_("unable to load or find any compatible input profile"));
		return -1;
	}

	return 0;
}

static void
vips_icc_class_init(VipsIccClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->dispose = vips_icc_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "icc";
	object_class->description = _("transform using ICC profiles");
	object_class->build = vips_icc_build;

	VIPS_ARG_ENUM(class, "intent", 6,
		_("Intent"),
		_("Rendering intent"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIcc, intent),
		VIPS_TYPE_INTENT, VIPS_INTENT_RELATIVE);

	VIPS_ARG_ENUM(class, "pcs", 6,
		_("PCS"),
		_("Set Profile Connection Space"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIcc, pcs),
		VIPS_TYPE_PCS, VIPS_PCS_LAB);

	VIPS_ARG_BOOL(class, "black_point_compensation", 7,
		_("Black point compensation"),
		_("Enable black point compensation"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIcc, black_point_compensation),
		FALSE);

	cmsSetLogErrorHandler(icc_error);
}

static void
vips_icc_init(VipsIcc *icc)
{
	icc->intent = VIPS_INTENT_RELATIVE;
	icc->pcs = VIPS_PCS_LAB;
	icc->depth = 8;
}

typedef struct _VipsIccImport {
	VipsIcc parent_instance;

	gboolean embedded;
	char *input_profile_filename;

} VipsIccImport;

typedef VipsIccClass VipsIccImportClass;

G_DEFINE_TYPE(VipsIccImport, vips_icc_import, VIPS_TYPE_ICC);

static int
vips_icc_import_build(VipsObject *object)
{
	VipsColour *colour = (VipsColour *) object;
	VipsIcc *icc = (VipsIcc *) object;
	VipsIccImport *import = (VipsIccImport *) object;

	if (vips_icc_set_import(icc,
			import->embedded, import->input_profile_filename))
		return -1;

	if (icc->pcs == VIPS_PCS_LAB) {
		cmsCIExyY white;
		cmsWhitePointFromTemp(&white, 6504);

		icc->out_profile = cmsCreateLab4Profile(&white);
	}
	else
		icc->out_profile = cmsCreateXYZProfile();

	if (VIPS_OBJECT_CLASS(vips_icc_import_parent_class)->build(object))
		return -1;

	/* If we used the fallback profile, we need to attach it to the PCS
	 * image, since the PCS image needs a route back to device space.
	 *
	 * In the same way, we don't remove the embedded input profile on
	 * import.
	 */
	if (icc->non_standard_input_profile &&
		icc->in_blob) {
		const void *data;
		size_t size;

		data = vips_blob_get(icc->in_blob, &size);
		vips_image_set_blob(colour->out, VIPS_META_ICC_NAME,
			NULL, data, size);
	}

	return 0;
}

static void
decode_lab(guint16 *fixed, float *lab, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		/* cmsLabEncoded2Float inlined.
		 */
		lab[0] = (double) fixed[0] / 655.35;
		lab[1] = ((double) fixed[1] / 257.0) - 128.0;
		lab[2] = ((double) fixed[2] / 257.0) - 128.0;

		lab += 3;
		fixed += 3;
	}
}

/* The matrix already includes the D65 channel weighting, so we just scale by
 * Y.
 */
#define SCALE (VIPS_D65_Y0)

static void
decode_xyz(guint16 *fixed, float *xyz, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		/* cmsXYZEncoded2Float inlined.
		 */
		float X = fixed[0] / 32768.0;
		float Y = fixed[1] / 32768.0;
		float Z = fixed[2] / 32768.0;

		X *= SCALE;
		Y *= SCALE;
		Z *= SCALE;

		/* Transform XYZ D50 to D65, chromatic adaption is done with the
		 * Bradford transformation.
		 * See: https://fujiwaratko.sakura.ne.jp/infosci/colorspace/bradford_e.html
		 */
		xyz[0] = 0.955513 * X +
			-0.023073 * Y +
			0.063309 * Z;
		xyz[1] = -0.028325 * X +
			1.009942 * Y +
			0.021055 * Z;
		xyz[2] = 0.012329 * X +
			-0.020536 * Y +
			1.330714 * Z;

		xyz += 3;
		fixed += 3;
	}
}

/* Process a buffer of data.
 */
static void
vips_icc_import_line(VipsColour *colour,
	VipsPel *out, VipsPel **in, int width)
{
	VipsIcc *icc = (VipsIcc *) colour;

	VipsPel *p;
	float *q;
	int i;

	/* Buffer of encoded 16-bit pixels we transform.
	 */
	guint16 encoded[3 * PIXEL_BUFFER_SIZE];

	p = (VipsPel *) in[0];
	q = (float *) out;
	for (i = 0; i < width; i += PIXEL_BUFFER_SIZE) {
		const int chunk = VIPS_MIN(width - i, PIXEL_BUFFER_SIZE);

		cmsDoTransform(icc->trans, p, encoded, chunk);

		if (icc->pcs == VIPS_PCS_LAB)
			decode_lab(encoded, q, chunk);
		else
			decode_xyz(encoded, q, chunk);

		// use input_bands, since in[0] may have had alpha removed,
		// and can have 1, 3 or 4 bands
		p += PIXEL_BUFFER_SIZE *
			colour->input_bands *
			VIPS_IMAGE_SIZEOF_ELEMENT(colour->in[0]);
		q += PIXEL_BUFFER_SIZE * 3;
	}
}

static void
vips_icc_import_class_init(VipsIccImportClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "icc_import";
	object_class->description = _("import from device with ICC profile");
	object_class->build = vips_icc_import_build;

	colour_class->process_line = vips_icc_import_line;

	VIPS_ARG_BOOL(class, "embedded", 110,
		_("Embedded"),
		_("Use embedded input profile, if available"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIccImport, embedded),
		FALSE);

	VIPS_ARG_STRING(class, "input_profile", 120,
		_("Input profile"),
		_("Filename to load input profile from"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIccImport, input_profile_filename),
		NULL);
}

static void
vips_icc_import_init(VipsIccImport *import)
{
}

typedef struct _VipsIccExport {
	VipsIcc parent_instance;

	char *output_profile_filename;

} VipsIccExport;

typedef VipsIccClass VipsIccExportClass;

G_DEFINE_TYPE(VipsIccExport, vips_icc_export, VIPS_TYPE_ICC);

static int
vips_icc_export_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;
	VipsIcc *icc = (VipsIcc *) object;
	VipsIccExport *export = (VipsIccExport *) object;

	/* If icc->pcs hasn't been set and this image is tagged as XYZ, swap
	 * to XYZ pcs. This will save a XYZ->LAB conversion when we chain up.
	 */
	if (!vips_object_argument_isset(object, "pcs") &&
		code->in &&
		code->in->Type == VIPS_INTERPRETATION_XYZ)
		icc->pcs = VIPS_PCS_XYZ;

	if (icc->pcs == VIPS_PCS_LAB) {
		cmsCIExyY white;
		cmsWhitePointFromTemp(&white, 6504);

		icc->in_profile = cmsCreateLab4Profile(&white);
	}
	else
		icc->in_profile = cmsCreateXYZProfile();

	if (code->in &&
		!export->output_profile_filename)
		icc->out_blob = vips_icc_get_profile_image(code->in);

	if (!icc->out_blob &&
		export->output_profile_filename) {
		if (vips_profile_load(export->output_profile_filename,
				&icc->out_blob, NULL))
			return -1;
		colour->profile_filename = export->output_profile_filename;
	}

	if (icc->out_blob &&
		!(icc->out_profile = vips_icc_load_profile_blob(icc->out_blob,
			  NULL, icc->intent, LCMS_USED_AS_OUTPUT))) {
		vips_error(class->nickname, "%s", _("no output profile"));
		return -1;
	}

	if (VIPS_OBJECT_CLASS(vips_icc_export_parent_class)->build(object))
		return -1;

	return 0;
}

static void
encode_xyz(float *in, float *out, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		float X = in[0] / SCALE;
		float Y = in[1] / SCALE;
		float Z = in[2] / SCALE;

		/* Transform XYZ D65 to D50, chromatic adaption is done with the
		 * Bradford transformation.
		 * See: https://fujiwaratko.sakura.ne.jp/infosci/colorspace/bradford_e.html
		 */
		out[0] = 1.047886 * X +
			0.022919 * Y +
			-0.050216 * Z;
		out[1] = 0.029582 * X +
			0.990484 * Y +
			-0.017079 * Z;
		out[2] = -0.009252 * X +
			0.015073 * Y +
			0.751678 * Z;

		in += 3;
		out += 3;
	}
}

static void
vips_icc_export_line_xyz(VipsColour *colour,
	VipsPel *out, VipsPel **in, int width)
{
	VipsIcc *icc = (VipsIcc *) colour;

	float *p;
	VipsPel *q;
	int x;

	/* Buffer of encoded float pixels we transform to device space.
	 */
	float encoded[3 * PIXEL_BUFFER_SIZE];

	p = (float *) in[0];
	q = (VipsPel *) out;
	for (x = 0; x < width; x += PIXEL_BUFFER_SIZE) {
		const int chunk = VIPS_MIN(width - x, PIXEL_BUFFER_SIZE);

		encode_xyz(p, encoded, chunk);
		cmsDoTransform(icc->trans, encoded, q, chunk);

		p += PIXEL_BUFFER_SIZE * 3;
		// use colour->bands, since out may have had alpha reattached
		// and can have extra bands
		q += PIXEL_BUFFER_SIZE *
			colour->bands *
			VIPS_IMAGE_SIZEOF_ELEMENT(colour->out);
	}
}

/* Process a buffer of data.
 */
static void
vips_icc_export_line(VipsColour *colour,
	VipsPel *out, VipsPel **in, int width)
{
	VipsIcc *icc = (VipsIcc *) colour;

	if (icc->pcs == VIPS_PCS_LAB)
		cmsDoTransform(icc->trans, in[0], out, width);
	else
		vips_icc_export_line_xyz(colour, out, in, width);
}

static void
vips_icc_export_class_init(VipsIccExportClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "icc_export";
	object_class->description = _("output to device with ICC profile");
	object_class->build = vips_icc_export_build;

	colour_class->process_line = vips_icc_export_line;

	VIPS_ARG_STRING(class, "output_profile", 110,
		_("Output profile"),
		_("Filename to load output profile from"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIccExport, output_profile_filename),
		NULL);

	VIPS_ARG_INT(class, "depth", 130,
		_("Depth"),
		_("Output device space depth in bits"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIcc, depth),
		8, 16, 8);
}

static void
vips_icc_export_init(VipsIccExport *export)
{
}

typedef struct _VipsIccTransform {
	VipsIcc parent_instance;

	gboolean embedded;
	char *input_profile_filename;
	char *output_profile_filename;

} VipsIccTransform;

typedef VipsIccClass VipsIccTransformClass;

G_DEFINE_TYPE(VipsIccTransform, vips_icc_transform, VIPS_TYPE_ICC);

static int
vips_icc_transform_build(VipsObject *object)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(object);
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;
	VipsIcc *icc = (VipsIcc *) object;
	VipsIccTransform *transform = (VipsIccTransform *) object;

	/* Depth defaults to 16 for 16 bit images.
	 */
	if (!vips_object_argument_isset(object, "depth") &&
		code->in &&
		(code->in->Type == VIPS_INTERPRETATION_RGB16 ||
			code->in->Type == VIPS_INTERPRETATION_GREY16))
		icc->depth = 16;

	if (vips_icc_set_import(icc,
			transform->embedded, transform->input_profile_filename))
		return -1;

	if (transform->output_profile_filename) {
		if (vips_profile_load(transform->output_profile_filename,
				&icc->out_blob, NULL))
			return -1;
		colour->profile_filename = transform->output_profile_filename;
	}

	if (icc->out_blob)
		icc->out_profile = vips_icc_load_profile_blob(icc->out_blob,
			NULL, icc->intent, LCMS_USED_AS_OUTPUT);

	if (!icc->out_profile) {
		vips_error(class->nickname, "%s", _("no output profile"));
		return -1;
	}

	if (VIPS_OBJECT_CLASS(vips_icc_transform_parent_class)->build(object))
		return -1;

	return 0;
}

/* Process a buffer of data.
 */
static void
vips_icc_transform_line(VipsColour *colour,
	VipsPel *out, VipsPel **in, int width)
{
	VipsIcc *icc = (VipsIcc *) colour;

	cmsDoTransform(icc->trans, in[0], out, width);
}

static void
vips_icc_transform_class_init(VipsIccImportClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "icc_transform";
	object_class->description =
		_("transform between devices with ICC profiles");
	object_class->build = vips_icc_transform_build;

	colour_class->process_line = vips_icc_transform_line;

	VIPS_ARG_STRING(class, "output_profile", 110,
		_("Output profile"),
		_("Filename to load output profile from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsIccTransform, output_profile_filename),
		NULL);

	VIPS_ARG_BOOL(class, "embedded", 120,
		_("Embedded"),
		_("Use embedded input profile, if available"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIccTransform, embedded),
		FALSE);

	VIPS_ARG_STRING(class, "input_profile", 130,
		_("Input profile"),
		_("Filename to load input profile from"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIccTransform, input_profile_filename),
		NULL);

	VIPS_ARG_INT(class, "depth", 140,
		_("Depth"),
		_("Output device space depth in bits"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsIcc, depth),
		8, 16, 8);
}

static void
vips_icc_transform_init(VipsIccTransform *transform)
{
}

/**
 * vips_icc_ac2rc: (method)
 * @in: input image
 * @out: (out): output image
 * @profile_filename: use this profile
 *
 * Transform an image from absolute to relative colorimetry using the
 * MediaWhitePoint stored in the ICC profile.
 *
 * See also: vips_icc_transform(), vips_icc_import().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_icc_ac2rc(VipsImage *in, VipsImage **out, const char *profile_filename)
{
	VipsImage *t;
	cmsHPROFILE profile;
	cmsCIEXYZ *media;
	double X, Y, Z;
	double *add;
	double *mul;
	int i;

#ifdef G_OS_WIN32
	if (!(profile = cmsOpenProfileFromFile(profile_filename, "r")))
#else  /*!G_OS_WIN32*/
	if (!(profile = cmsOpenProfileFromFile(profile_filename, "re")))
#endif /*G_OS_WIN32*/
		return -1;

#ifdef DEBUG
	vips_icc_print_profile(profile_filename, profile);
#endif /*DEBUG*/

	if (!(media = cmsReadTag(profile, cmsSigMediaWhitePointTag))) {
		vips_error("vips_icc_ac2rc",
			"%s", _("unable to get media white point"));
		return -1;
	}

	X = media->X;
	Y = media->Y;
	Z = media->Z;

	cmsCloseProfile(profile);

	/* We need XYZ so we can adjust the white balance.
	 */
	if (vips_colourspace(in, &t, VIPS_INTERPRETATION_XYZ, NULL))
		return -1;
	in = t;

	if (!(add = VIPS_ARRAY(in, in->Bands, double)) ||
		!(mul = VIPS_ARRAY(in, in->Bands, double)))
		return -1;

	/* There might be extra bands off to the right somewhere.
	 */
	for (i = 0; i < in->Bands; i++)
		add[i] = 0.0;

	mul[0] = VIPS_D50_X0 / (X * 100.0);
	mul[1] = VIPS_D50_Y0 / (Y * 100.0);
	mul[2] = VIPS_D50_Z0 / (Z * 100.0);

	for (i = 3; i < in->Bands; i++)
		mul[i] = 1.0;

	if (vips_linear(in, &t, add, mul, in->Bands, NULL)) {
		g_object_unref(in);
		return -1;
	}
	g_object_unref(in);
	in = t;

	*out = in;

	return 0;
}

/* TRUE if a profile is sane and is compatible with an image.
 */
gboolean
vips_icc_is_compatible_profile(VipsImage *image,
	const void *data, size_t data_length)
{
	cmsHPROFILE profile;
	VipsIccInfo *info;

	if (!(profile = cmsOpenProfileFromMem(data, data_length)))
		/* Corrupt profile.
		 */
		return FALSE;

#ifdef DEBUG
	vips_icc_print_profile("from memory", profile);
#endif /*DEBUG*/

	if (!(info = vips_icc_info(cmsGetColorSpace(profile)))) {
		/* Unsupported profile.
		 */
		VIPS_FREEF(cmsCloseProfile, profile);
		return FALSE;
	}

	if (!vips_image_is_profile_compatible(image, info->bands)) {
		/* Bands mismatch.
		 */
		VIPS_FREEF(cmsCloseProfile, profile);
		return FALSE;
	}

	VIPS_FREEF(cmsCloseProfile, profile);

	return TRUE;
}

#else /*!HAVE_LCMS2*/

#include <vips/vips.h>

int
vips_icc_present(void)
{
	return 0;
}

int
vips_icc_ac2rc(VipsImage *in, VipsImage **out, const char *profile_filename)
{
	vips_error("VipsIcc", "%s",
		_("libvips configured without lcms support"));

	return -1;
}

gboolean
vips_icc_is_compatible_profile(VipsImage *image,
	const void *data, size_t data_length)
{
	return TRUE;
}

#endif /*HAVE_LCMS2*/

/**
 * vips_icc_import: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @pcs: #VipsPCS,  use XYZ or LAB PCS
 * * @intent: #VipsIntent, transform with this intent
 * * @black_point_compensation: %gboolean, enable black point compensation
 * * @embedded: %gboolean, use profile embedded in input image
 * * @input_profile: %gchararray, get the input profile from here
 *
 * Import an image from device space to D65 LAB with an ICC profile. If @pcs is
 * set to #VIPS_PCS_XYZ, use CIE XYZ PCS instead.
 *
 * The input profile is searched for in three places:
 *
 *	  1. If @embedded is set, libvips will try to use any profile in the input
 *	  image metadata. You can test for the presence of an embedded profile
 *	  with vips_image_get_typeof() with #VIPS_META_ICC_NAME as an argument.
 *	  This will return %GType 0 if there is no profile.
 *
 *	  2. Otherwise, if @input_profile is set, libvips will try to load a
 *	  profile from the named file. This can aslso be the name of one of the
 *	  built-in profiles.
 *
 *	  3. Otherwise, libvips will try to pick a compatible profile from the set
 *	  of built-in profiles.
 *
 * If @black_point_compensation is set, LCMS black point compensation is
 * enabled.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_icc_import(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("icc_import", ap, in, out);
	va_end(ap);

	return result;
}

/**
 * vips_icc_export: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @pcs: #VipsPCS,  use XYZ or LAB PCS
 * * @intent: #VipsIntent, transform with this intent
 * * @black_point_compensation: %gboolean, enable black point compensation
 * * @output_profile: %gchararray, get the output profile from here
 * * @depth: %gint, depth of output image in bits
 *
 * Export an image from D65 LAB to device space with an ICC profile.
 * If @pcs is
 * set to #VIPS_PCS_XYZ, use CIE XYZ PCS instead.
 * If @output_profile is not set, use the embedded profile, if any.
 * If @output_profile is set, export with that and attach it to the output
 * image.
 *
 * If @black_point_compensation is set, LCMS black point compensation is
 * enabled.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_icc_export(VipsImage *in, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("icc_export", ap, in, out);
	va_end(ap);

	return result;
}

/**
 * vips_icc_transform: (method)
 * @in: input image
 * @out: (out): output image
 * @output_profile: get the output profile from here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @pcs: #VipsPCS,  use XYZ or LAB PCS
 * * @intent: #VipsIntent, transform with this intent
 * * @black_point_compensation: %gboolean, enable black point compensation
 * * @embedded: %gboolean, use profile embedded in input image
 * * @input_profile: %gchararray, get the input profile from here
 * * @depth: %gint, depth of output image in bits
 *
 * Transform an image with a pair of ICC profiles. The input image is moved to
 * profile-connection space with the input profile and then to the output
 * space with the output profile.
 *
 * The input profile is searched for in three places:
 *
 *	  1. If @embedded is set, libvips will try to use any profile in the input
 *	  image metadata. You can test for the presence of an embedded profile
 *	  with vips_image_get_typeof() with #VIPS_META_ICC_NAME as an argument.
 *	  This will return %GType 0 if there is no profile.
 *
 *	  2. Otherwise, if @input_profile is set, libvips will try to load a
 *	  profile from the named file. This can aslso be the name of one of the
 *	  built-in profiles.
 *
 *	  3. Otherwise, libvips will try to pick a compatible profile from the set
 *	  of built-in profiles.
 *
 * If @black_point_compensation is set, LCMS black point compensation is
 * enabled.
 *
 * @depth defaults to 8, or 16 if @in is a 16-bit image.
 *
 * The output image has the output profile attached to the #VIPS_META_ICC_NAME
 * field.
 *
 * Use vips_icc_import() and vips_icc_export() to do either the first or
 * second half of this operation in isolation.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_icc_transform(VipsImage *in, VipsImage **out,
	const char *output_profile, ...)
{
	va_list ap;
	int result;

	va_start(ap, output_profile);
	result = vips_call_split("icc_transform", ap,
		in, out, output_profile);
	va_end(ap);

	return result;
}
