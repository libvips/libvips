/* load heif images with libheif
 *
 * 19/1/19
 * 	- from niftiload.c
 * 24/7/19 [zhoux2016]
 * 	- always fetch metadata from the main image (thumbs don't have it)
 * 24/7/19
 * 	- close early on minimise
 * 	- close early on error
 * 1/9/19 [meyermarcel]
 * 	- handle alpha
 * 30/9/19
 * 	- much faster handling of thumbnail=TRUE and missing thumbnail ... we
 * 	  were reselecting the image for each scanline
 * 3/10/19
 * 	- restart after minimise
 * 15/3/20
 * 	- revise for new VipsSource API
 * 10/5/20
 * 	- deprecate autorotate -- it's too difficult to support properly
 * 31/7/20
 * 	- block broken thumbnails, if we can
 * 14/2/21 kleisauke
 * 	- move GObject part to heif2vips.c
 * 22/12/21
 * 	- add >8 bit support
 * 23/2/22 lovell
 * 	- add @unlimited
 * 13/03/23 MathemanFlo
 * 	- add bits per sample metadata
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
#define DEBUG_VERBOSE
#define VIPS_DEBUG
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

/* These are shared with the encoder.
 */
#ifdef HAVE_HEIF

#include "pforeign.h"

const char *vips__heic_suffs[] = {
	".heic",
	".heif",
	NULL
};

const char *vips__avif_suffs[] = {
	".avif",
	NULL
};

const char *vips__heif_suffs[] = {
	".heic",
	".heif",
	".avif",
	NULL
};

#include <libheif/heif.h>

#define VIPS_TYPE_FOREIGN_LOAD_HEIF (vips_foreign_load_heif_get_type())
#define VIPS_FOREIGN_LOAD_HEIF(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_FOREIGN_LOAD_HEIF, VipsForeignLoadHeif))
#define VIPS_FOREIGN_LOAD_HEIF_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		VIPS_TYPE_FOREIGN_LOAD_HEIF, VipsForeignLoadHeifClass))
#define VIPS_IS_FOREIGN_LOAD_HEIF(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), VIPS_TYPE_FOREIGN_LOAD_HEIF))
#define VIPS_IS_FOREIGN_LOAD_HEIF_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), VIPS_TYPE_FOREIGN_LOAD_HEIF))
#define VIPS_FOREIGN_LOAD_HEIF_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
		VIPS_TYPE_FOREIGN_LOAD_HEIF, VipsForeignLoadHeifClass))

typedef struct _VipsForeignLoadHeif {
	VipsForeignLoad parent_object;

	/* Pages to load.
	 */
	int page;
	int n;

	/* Fetch the thumbnail instead of the image. If there is no thumbnail,
	 * just fetch the image.
	 */
	gboolean thumbnail;

	/* Apply any orientation tags in the header.
	 *
	 * This is deprecated and does nothing. Non-autorotated reads from
	 * libheif are surprisingly hard to support well, since orientation can
	 * be represented in several different ways in HEIC files and devices
	 * vary in how they do this.
	 */
	gboolean autorotate;

	/* Remove all denial of service limits.
	 */
	gboolean unlimited;

	/* Context for this image.
	 */
	struct heif_context *ctx;

	/* Number of top-level images in this file.
	 */
	int n_top;

	/* TRUE for RGBA ... otherwise, RGB.
	 */
	gboolean has_alpha;

	/* Size of final output image.
	 */
	int width;
	int height;

	/* Size of each page.
	 */
	int page_width;
	int page_height;

	/* Eg. 8 or 12, typically.
	 */
	int bits_per_pixel;

	/* The page number currently in @handle.
	 */
	int page_no;

	/* TRUE if @handle has selected the thumbnail rather than the main
	 * image.
	 */
	gboolean thumbnail_set;

	/* The page number of the primary image.
	 */
	int primary_page;

	/* Array of top-level image IDs.
	 */
	heif_item_id *id;

	/* Handle for the currently selected image.
	 */
	struct heif_image_handle *handle;

	/* Decoded pixel data for the current image.
	 */
	struct heif_image *img;

	/* Valid until img is released.
	 */
	int stride;
	const uint8_t *data;

	/* Set from subclasses.
	 */
	VipsSource *source;

	/* The reader struct. We use this to attach to our VipsSource. This
	 * has to be alloced rather than in our struct, since it may change
	 * size in libheif API versions.
	 */
	struct heif_reader *reader;

} VipsForeignLoadHeif;

#ifdef HAVE_HEIF_INIT
static void *
vips__heif_init_once(void *client)
{
	struct heif_error error;

	error = heif_init(NULL);
	if (error.code)
		g_warning("heif_init: %s (%d.%d)\n",
			error.message ? error.message : "(null)",
			error.code, error.subcode);

	return NULL;
}
#endif /*HAVE_HEIF_INIT*/

void
vips__heif_init(void)
{
#ifdef HAVE_HEIF_INIT
	static GOnce once = G_ONCE_INIT;

	VIPS_ONCE(&once, vips__heif_init_once, NULL);
#endif /*HAVE_HEIF_INIT*/
}

void
vips__heif_error(struct heif_error *error)
{
	if (error->code)
		vips_error("heif", "%s (%d.%d)",
			error->message ? error->message : "(null)",
			error->code, error->subcode);
}

#ifdef DEBUG
void
vips__heif_image_print(struct heif_image *img)
{
	const static enum heif_channel channel[] = {
		heif_channel_Y,
		heif_channel_Cb,
		heif_channel_Cr,
		heif_channel_R,
		heif_channel_G,
		heif_channel_B,
		heif_channel_Alpha,
		heif_channel_interleaved
	};

	const static char *channel_name[] = {
		"heif_channel_Y",
		"heif_channel_Cb",
		"heif_channel_Cr",
		"heif_channel_R",
		"heif_channel_G",
		"heif_channel_B",
		"heif_channel_Alpha",
		"heif_channel_interleaved"
	};

	int i;

	printf("vips__heif_image_print:\n");
	for (i = 0; i < VIPS_NUMBER(channel); i++) {
		if (!heif_image_has_channel(img, channel[i]))
			continue;

		printf("\t%s:\n", channel_name[i]);
		printf("\t\twidth = %d\n",
			heif_image_get_width(img, channel[i]));
		printf("\t\theight = %d\n",
			heif_image_get_height(img, channel[i]));
		printf("\t\tbits = %d\n",
			heif_image_get_bits_per_pixel(img, channel[i]));
	}
}
#endif /*DEBUG*/

/* Pick a chroma format. Shared with heifsave.
 */
int
vips__heif_chroma(int bits_per_pixel, gboolean has_alpha)
{
	if (bits_per_pixel == 8) {
		if (has_alpha)
			return heif_chroma_interleaved_RGBA;
		else
			return heif_chroma_interleaved_RGB;
	}
	else {
		if (has_alpha)
			return heif_chroma_interleaved_RRGGBBAA_BE;
		else
			return heif_chroma_interleaved_RRGGBB_BE;
	}
}

typedef struct _VipsForeignLoadHeifClass {
	VipsForeignLoadClass parent_class;

} VipsForeignLoadHeifClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignLoadHeif, vips_foreign_load_heif,
	VIPS_TYPE_FOREIGN_LOAD);

static void
vips_foreign_load_heif_dispose(GObject *gobject)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) gobject;

	heif->data = NULL;
	VIPS_FREEF(heif_image_release, heif->img);
	VIPS_FREEF(heif_image_handle_release, heif->handle);
	VIPS_FREEF(heif_context_free, heif->ctx);
	VIPS_FREE(heif->id);
	VIPS_FREE(heif->reader);
	VIPS_UNREF(heif->source);

	G_OBJECT_CLASS(vips_foreign_load_heif_parent_class)->dispose(gobject);
}

static int
vips_foreign_load_heif_build(VipsObject *object)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) object;

#ifdef DEBUG
	printf("vips_foreign_load_heif_build:\n");
#endif /*DEBUG*/

	if (heif->source &&
		vips_source_rewind(heif->source))
		return -1;

	if (!heif->ctx) {
		struct heif_error error;

		heif->ctx = heif_context_alloc();
		/* heifsave is limited to a maximum image size of 16384x16384,
		 * so align the heifload defaults accordingly.
		 */
		heif_context_set_maximum_image_size_limit(heif->ctx,
			heif->unlimited ? USHRT_MAX : 0x4000);
#ifdef HAVE_HEIF_MAX_TOTAL_MEMORY
		if (!heif->unlimited) {
			heif_security_limits *limits =
				heif_context_get_security_limits(heif->ctx);

			limits->max_total_memory = 2L * 1024 * 1024 * 1024;
			limits->max_memory_block_size = 1024 * 1024 * 1024;
			limits->max_items = 16;
		}
#endif /* HAVE_HEIF_MAX_TOTAL_MEMORY */
#ifdef HAVE_HEIF_GET_DISABLED_SECURITY_LIMITS
		if (heif->unlimited)
			heif_context_set_security_limits(heif->ctx,
				heif_get_disabled_security_limits());
#endif /* HAVE_HEIF_GET_DISABLED_SECURITY_LIMITS */
		error = heif_context_read_from_reader(heif->ctx,
			heif->reader, heif, NULL);
		if (error.code) {
			vips__heif_error(&error);
			return -1;
		}
	}

	return VIPS_OBJECT_CLASS(vips_foreign_load_heif_parent_class)
		->build(object);
}

static const char *heif_magic[] = {
	"ftypheic", /* A regular heif image */
	"ftypheix", /* Extended range (>8 bit) image */
	"ftyphevc", /* Image sequence */
	"ftypheim", /* Image sequence */
	"ftypheis", /* Scalable image */
	"ftyphevm", /* Multiview sequence */
	"ftyphevs", /* Scalable sequence */
	"ftypmif1", /* Nokia alpha_ image */
	"ftypmif2", /* mif1 plus rref and iscl boxes */
	"ftypmif3", /* Low-overhead mini box */
	"ftypmsf1", /* Nokia animation image */
	"ftypavif"	/* AV1 image format */
};

/* The API has:
 *
 *	enum heif_filetype_result result = heif_check_filetype(buf, 12);
 *
 * but it's very conservative and seems to be missing some of the Nokia heif
 * types.
 */
static int
vips_foreign_load_heif_is_a(const char *buf, int len)
{
	if (len >= 12) {
		unsigned char *p = (unsigned char *) buf;
		guint32 chunk_len =
			VIPS_LSHIFT_INT(p[0], 24) |
			VIPS_LSHIFT_INT(p[1], 16) |
			VIPS_LSHIFT_INT(p[2], 8) |
			VIPS_LSHIFT_INT(p[3], 0);

		int i;

		/* chunk_len can be pretty big for eg. animated AVIF.
		 */
		if (chunk_len > 2048 ||
			chunk_len % 4 != 0)
			return 0;

		for (i = 0; i < VIPS_NUMBER(heif_magic); i++)
			if (strncmp(buf + 4, heif_magic[i], 8) == 0)
				return 1;
	}

	return 0;
}

static VipsForeignFlags
vips_foreign_load_heif_get_flags(VipsForeignLoad *load)
{
	/* FIXME .. could support random access for grid images.
	 */
	return VIPS_FOREIGN_SEQUENTIAL;
}

/* We've selected the page. Try to select the associated thumbnail instead,
 * if we can.
 */
static int
vips_foreign_load_heif_set_thumbnail(VipsForeignLoadHeif *heif)
{
	heif_item_id thumb_ids[1];
	int n_thumbs;
	struct heif_image_handle *thumb_handle;
	struct heif_image *thumb_img;
	struct heif_error error;
	double main_aspect;
	double thumb_aspect;

#ifdef DEBUG
	printf("vips_foreign_load_heif_set_thumbnail:\n");
#endif /*DEBUG*/

	n_thumbs = heif_image_handle_get_list_of_thumbnail_IDs(
		heif->handle, thumb_ids, 1);
	if (n_thumbs == 0)
		return 0;

	error = heif_image_handle_get_thumbnail(heif->handle,
		thumb_ids[0], &thumb_handle);
	if (error.code) {
		vips__heif_error(&error);
		return -1;
	}

	/* Just checking the width and height of the handle isn't
	 * enough -- we have to experimentally decode it and test the
	 * decoded dimensions.
	 */
	error = heif_decode_image(thumb_handle, &thumb_img,
		heif_colorspace_RGB,
		heif_chroma_interleaved_RGB,
		NULL);
	if (error.code) {
		VIPS_FREEF(heif_image_handle_release, thumb_handle);
		vips__heif_error(&error);
		return -1;
	}

	thumb_aspect = (double)
		heif_image_get_width(thumb_img, heif_channel_interleaved) /
		heif_image_get_height(thumb_img, heif_channel_interleaved);

	VIPS_FREEF(heif_image_release, thumb_img);

	main_aspect = (double)
		heif_image_handle_get_width(heif->handle) /
		heif_image_handle_get_height(heif->handle);

	/* The bug we are working around has decoded thumbs as 512x512
	 * with the main image as 6kx4k, so a 0.1 threshold is more
	 * than tight enough to spot the error.
	 */
	if (fabs(main_aspect - thumb_aspect) > 0.1) {
		VIPS_FREEF(heif_image_handle_release, thumb_handle);
		return 0;
	}

	VIPS_FREEF(heif_image_handle_release, heif->handle);
	heif->handle = thumb_handle;

	return 0;
}

/* Extract ISO 21496-1 / Adobe HDR gain map from HEIC auxiliary images.
 *
 * Detects gain map aux images by matching "hdrgainmap" in the aux type URN
 * (covers Samsung's urn:com:samsung:photo:2024:aux:hdrgainmap and Apple's
 * urn:com:apple:photo:2020:aux:hdrgainmap).
 *
 * Parses the Adobe hdrgm: XML namespace (ISO 21496-1) to populate the
 * gainmap-* metadata fields, matching the format produced by uhdrload.c.
 * The uhdr2scRGB operation can then apply the gain map math to recover HDR.
 *
 * Note: Apple's proprietary HDRGainMap: XML namespace (used by iPhone 16 and
 * later) is not currently parsed. The gain map image is still attached as
 * "gainmap" metadata, but the gainmap-* fields are not populated. Apple HDR
 * support would require mapping HDRGainMapHeadroom to ISO 21496-1 parameters.
 *
 * Pre-iOS 17 Apple HDR (JPEG+MPF) is handled separately by uhdrload.c via
 * libultrahdr.
 */

/* Match gain map aux type URNs by checking for the "hdrgainmap" substring.
 * Covers all known vendor URNs without needing an exhaustive list.
 */
static gboolean
vips_foreign_load_heif_is_gainmap_aux(const char *aux_type)
{
	return aux_type &&
		g_str_has_suffix(aux_type, "hdrgainmap");
}

/* XML parser state for ISO 21496-1 / Adobe hdrgm: gain map metadata.
 */
typedef struct _VipsHeifGainmapXMLParser {
	/* Set to TRUE if we see the hdrgm: namespace declaration.
	 */
	gboolean has_hdrgm_ns;

	/* Set to TRUE if we're inside the <rdf:Description> element where
	 * the hdrgm: attributes live.
	 */
	gboolean in_description;

	/* Parsed attribute values, as strings. NULL if not present.
	 * Freed by the parser end_element callback is not necessary since
	 * we copy them out to doubles immediately.
	 */
	char *gain_map_min;
	char *gain_map_max;
	char *gamma;
	char *offset_sdr;
	char *offset_hdr;
	char *hdr_capacity_min;
	char *hdr_capacity_max;
	char *base_rendition_is_hdr;
} VipsHeifGainmapXMLParser;

/* Parse a single attribute value to a 3-element double array.
 * If the value contains spaces, parse as 3 space-separated values;
 * otherwise broadcast the single value to all 3 channels.
 */
static void
parse_float_attribute(const char *value, double out[3])
{
	gchar **parts;
	int n;

	out[0] = out[1] = out[2] = 0.0;

	if (!value)
		return;

	parts = g_strsplit(value, " ", 3);
	n = g_strv_length(parts);

	if (n == 1) {
		double v = g_ascii_strtod(parts[0], NULL);
		out[0] = out[1] = out[2] = v;
	}
	else if (n >= 3) {
		out[0] = g_ascii_strtod(parts[0], NULL);
		out[1] = g_ascii_strtod(parts[1], NULL);
		out[2] = g_ascii_strtod(parts[2], NULL);
	}

	g_strfreev(parts);
}

/* Handle a single attribute name=value pair from the rdf:Description element.
 */
static void
handle_hdrgm_attribute(VipsHeifGainmapXMLParser *parser,
	const gchar *name, const gchar *value)
{
	if (!value)
		return;

	/* We only process attributes in the hdrgm: namespace.
	 */
	if (g_str_has_prefix(name, "hdrgm:")) {
		const char *attr = name + strlen("hdrgm:");

		if (parser->has_hdrgm_ns) {
			if (g_str_equal(attr, "GainMapMin"))
				parser->gain_map_min = g_strdup(value);
			else if (g_str_equal(attr, "GainMapMax"))
				parser->gain_map_max = g_strdup(value);
			else if (g_str_equal(attr, "Gamma"))
				parser->gamma = g_strdup(value);
			else if (g_str_equal(attr, "OffsetSDR"))
				parser->offset_sdr = g_strdup(value);
			else if (g_str_equal(attr, "OffsetHDR"))
				parser->offset_hdr = g_strdup(value);
			else if (g_str_equal(attr, "HDRCapacityMin"))
				parser->hdr_capacity_min = g_strdup(value);
			else if (g_str_equal(attr, "HDRCapacityMax"))
				parser->hdr_capacity_max = g_strdup(value);
			else if (g_str_equal(attr, "BaseRenditionIsHDR"))
				parser->base_rendition_is_hdr = g_strdup(value);
		}
	}
	else if (g_str_equal(name, "xmlns:hdrgm")) {
		/* We could verify the URI is
		 * http://ns.adobe.com/hdr-gain-map/1.0/, but matching the
		 * namespace prefix is sufficient -- only one widely-deployed
		 * schema uses this prefix.
		 */
		parser->has_hdrgm_ns = TRUE;
	}
}

/* SAX parser callbacks.
 */
static void
xml_start_element(GMarkupParseContext *ctx,
	const gchar *element_name, const gchar **attr_names,
	const gchar **attr_values, gpointer user_data, GError **error)
{
	VipsHeifGainmapXMLParser *parser = user_data;

	/* Detect namespace declarations in the rdf:Description element.
	 */
	if (g_str_equal(element_name, "rdf:Description")) {
		parser->in_description = TRUE;

		for (int i = 0; attr_names[i] != NULL; i++)
			handle_hdrgm_attribute(parser, attr_names[i], attr_values[i]);
	}
	else if (parser->in_description) {
		/* Some XML writers put attributes on nested elements. Not
		 * standard ISO 21496-1, but handle it defensively.
		 */
		for (int i = 0; attr_names[i] != NULL; i++)
			handle_hdrgm_attribute(parser, attr_names[i], attr_values[i]);
	}
}

static void
xml_end_element(GMarkupParseContext *ctx,
	const gchar *element_name, gpointer user_data, GError **error)
{
	VipsHeifGainmapXMLParser *parser = user_data;

	if (g_str_equal(element_name, "rdf:Description"))
		parser->in_description = FALSE;
}

static const GMarkupParser xml_parser = {
	.start_element = xml_start_element,
	.end_element = xml_end_element,
	.text = NULL,
	.passthrough = NULL,
	.error = NULL,
};

/* Parse ISO 21496-1 / Adobe hdrgm: gain map XML and populate the gainmap-*
 * metadata fields on @out. Returns 0 on success, -1 on parse error.
 *
 * If the XML doesn't use the hdrgm: namespace (e.g. Apple's HDRGainMap:
 * namespace), returns 0 but doesn't set any fields. This is not an error
 * -- the gain map image is still attached, just the math metadata is
 * missing.
 */
static int
vips_foreign_load_heif_parse_gainmap_xml(const char *xml_data,
	size_t xml_length, VipsImage *out)
{
	VipsHeifGainmapXMLParser parser = { 0 };
	GMarkupParseContext *ctx;
	GError *error = NULL;

	ctx = g_markup_parse_context_new(&xml_parser,
		G_MARKUP_TREAT_CDATA_AS_TEXT, &parser, NULL);
	if (!g_markup_parse_context_parse(ctx, xml_data, xml_length, &error)) {
		g_markup_parse_context_free(ctx);
		if (error) {
			g_info("heifload: gain map XML parse error: %s", error->message);
			g_error_free(error);
		}
		return -1;
	}
	if (!g_markup_parse_context_end_parse(ctx, &error)) {
		g_markup_parse_context_free(ctx);
		if (error) {
			g_info("heifload: gain map XML end parse error: %s", error->message);
			g_error_free(error);
		}
		return -1;
	}
	g_markup_parse_context_free(ctx);

	/* If we didn't see the hdrgm: namespace, this is not an ISO 21496-1
	 * gain map (could be Apple's HDRGainMap: or some other format). The
	 * gain map image was already attached by the caller; we just don't
	 * populate the math metadata.
	 */
	if (!parser.has_hdrgm_ns) {
		g_info("heifload: gain map XML is not ISO 21496-1 (no hdrgm: namespace), "
			"skipping metadata extraction");
	}
	else {
		double arr[3];
		double val;
		gboolean use_base_cg = FALSE;

		g_info("heifload: parsing ISO 21496-1 gain map metadata");

		/* ISO 21496-1 GainMapMin/GainMapMax are log2 boost values (stops).
		 * libultrahdr's min_content_boost/max_content_boost are linear
		 * ratios (1.0 = no boost, 4.9 = 4.9x boost). uhdr2scRGB takes
		 * log2() of these values internally, so we convert with exp2().
		 */
		parse_float_attribute(parser.gain_map_max, arr);
		for (int k = 0; k < 3; k++)
			arr[k] = exp2(arr[k]);
		vips_image_set_array_double(out, "gainmap-max-content-boost", arr, 3);

		parse_float_attribute(parser.gain_map_min, arr);
		for (int k = 0; k < 3; k++)
			arr[k] = exp2(arr[k]);
		vips_image_set_array_double(out, "gainmap-min-content-boost", arr, 3);

		/* Gamma, offsets are passed through unchanged (same scale in
		 * both ISO 21496-1 and libultrahdr).
		 */
		parse_float_attribute(parser.gamma, arr);
		vips_image_set_array_double(out, "gainmap-gamma", arr, 3);

		parse_float_attribute(parser.offset_sdr, arr);
		vips_image_set_array_double(out, "gainmap-offset-sdr", arr, 3);

		parse_float_attribute(parser.offset_hdr, arr);
		vips_image_set_array_double(out, "gainmap-offset-hdr", arr, 3);

		/* HDRCapacityMin/HDRCapacityMax are also log2 (same axis as
		 * GainMapMin/GainMapMax). Convert to linear.
		 */
		val = parser.hdr_capacity_min
			? exp2(g_ascii_strtod(parser.hdr_capacity_min, NULL)) : 1.0;
		vips_image_set_double(out, "gainmap-hdr-capacity-min", val);

		val = parser.hdr_capacity_max
			? exp2(g_ascii_strtod(parser.hdr_capacity_max, NULL)) : 1.0;
		vips_image_set_double(out, "gainmap-hdr-capacity-max", val);

		/* BaseRenditionIsHDR: "False" (the common case) means the SDR
		 * base is the primary image. use_base_cg is a libultrahdr
		 * parameter; for ISO 21496-1 we default to TRUE (use the
		 * base image's color gamut for the gain map).
		 */
		if (parser.base_rendition_is_hdr) {
			/* Invert: "False" -> use_base_cg=TRUE (use base image CG)
			 * "True" -> use_base_cg=FALSE (base is HDR, gain map is SDR)
			 */
			use_base_cg = !g_ascii_strcasecmp(
				parser.base_rendition_is_hdr, "True") == 0;
		}
		vips_image_set_int(out, "gainmap-use-base-cg", use_base_cg ? 1 : 0);
	}

	g_free(parser.gain_map_min);
	g_free(parser.gain_map_max);
	g_free(parser.gamma);
	g_free(parser.offset_sdr);
	g_free(parser.offset_hdr);
	g_free(parser.hdr_capacity_min);
	g_free(parser.hdr_capacity_max);
	g_free(parser.base_rendition_is_hdr);

	return 0;
}

/* Decode an aux image handle to a VipsImage. Returns a new VipsImage
 * (caller must unref) or NULL on error.
 *
 * The aux image is decoded as 8-bit interleaved RGB, matching what
 * uhdr2scRGB expects for its gainmap input.
 */
static VipsImage *
vips_foreign_load_heif_decode_aux(struct heif_image_handle *aux_handle)
{
	struct heif_image *img = NULL;
	struct heif_error error;
	int width, height, stride;
	const uint8_t *data;
	VipsImage *out;
	gboolean use_y_plane = FALSE;

	/* Gain maps can be either monochrome (1-channel, the common case) or
	 * multi-channel (3-channel, where R/G/B have different gain values).
	 *
	 * For monochrome gain maps stored as HEVC 4:2:0, we extract the Y
	 * (luma) plane directly to avoid chroma upsampling artifacts that
	 * cause visible streaks when the gain map is applied.
	 *
	 * For multi-channel gain maps, we decode as RGB to preserve the
	 * per-channel information.
	 *
	 * We detect monochrome vs multi-channel by checking whether the Cb/Cr
	 * planes deviate from neutral (128). A small deviation (±8) indicates
	 * HEVC compression noise on a monochrome gain map. A larger deviation
	 * indicates a true multi-channel gain map.
	 */
	error = heif_decode_image(aux_handle, &img,
		heif_colorspace_YCbCr,
		heif_chroma_420,
		NULL);
	if (!error.code) {
		/* YCbCr decode succeeded. Check Cb/Cr deviation from neutral.
		 */
		int cb_w = heif_image_get_width(img, heif_channel_Cb);
		int cb_h = heif_image_get_height(img, heif_channel_Cb);
		int cb_stride, cr_stride;
		const uint8_t *cb_data = heif_image_get_plane_readonly(img,
			heif_channel_Cb, &cb_stride);
		const uint8_t *cr_data = heif_image_get_plane_readonly(img,
			heif_channel_Cr, &cr_stride);

		if (cb_data && cr_data && cb_w > 0 && cb_h > 0) {
			int cb_min = 255, cb_max = 0;
			int cr_min = 255, cr_max = 0;

			for (int y = 0; y < cb_h; y++) {
				for (int x = 0; x < cb_w; x++) {
					int cb = cb_data[y * cb_stride + x];
					int cr = cr_data[y * cr_stride + x];
					if (cb < cb_min) cb_min = cb;
					if (cb > cb_max) cb_max = cb;
					if (cr < cr_min) cr_min = cr;
					if (cr > cr_max) cr_max = cr;
				}
			}

			/* If Cb/Cr are within ±8 of neutral (128), the gain map
			 * is effectively monochrome. The small deviation is
			 * HEVC compression noise on 4:2:0 chroma.
			 */
			if (abs(cb_min - 128) <= 8 && abs(cb_max - 128) <= 8 &&
				abs(cr_min - 128) <= 8 && abs(cr_max - 128) <= 8) {
				use_y_plane = TRUE;
#ifdef DEBUG
				printf("heifload: gain map is monochrome "
					"(Cb: %d-%d, Cr: %d-%d), using Y plane\n",
					cb_min, cb_max, cr_min, cr_max);
#endif
			}
			else {
#ifdef DEBUG
				printf("heifload: gain map is multi-channel "
					"(Cb: %d-%d, Cr: %d-%d), using RGB\n",
					cb_min, cb_max, cr_min, cr_max);
#endif
			}
		}

		if (use_y_plane) {
			/* Extract the Y (luma) plane. The Y plane may have
			 * stride > width (alignment padding), so copy
			 * row-by-row to create tightly packed data.
			 */
			width = heif_image_get_width(img, heif_channel_Y);
			height = heif_image_get_height(img, heif_channel_Y);

			if (!(data = heif_image_get_plane_readonly(img,
				heif_channel_Y, &stride))) {
				vips_error("heifload", "%s",
					_("unable to get gainmap Y plane data"));
				heif_image_release(img);
				return NULL;
			}

			if (stride == width) {
				out = vips_image_new_from_memory(data,
					(size_t) stride * height,
					width, height, 1, VIPS_FORMAT_UCHAR);
			}
			else {
				size_t packed_size = (size_t) width * height;
				uint8_t *packed = VIPS_ARRAY(NULL,
					packed_size, uint8_t);
				if (!packed) {
					heif_image_release(img);
					return NULL;
				}
				for (int y = 0; y < height; y++)
					memcpy(packed + (size_t) y * width,
						data + (size_t) y * stride,
						width);
				out = vips_image_new_from_memory(packed,
					packed_size,
					width, height, 1, VIPS_FORMAT_UCHAR);
			}

			if (!out) {
				heif_image_release(img);
				return NULL;
			}

			heif_image_release(img);

			vips_image_init_fields(out,
				width, height, 1,
				VIPS_FORMAT_UCHAR,
				VIPS_CODING_NONE,
				VIPS_INTERPRETATION_B_W,
				1.0, 1.0);
		}
		else {
			/* Multi-channel gain map: re-decode as RGB.
			 */
			heif_image_release(img);
			img = NULL;
			error.code = 1; /* fall through to RGB decode below */
		}
	}

	if (!use_y_plane) {
		/* Decode as interleaved RGB (either YCbCr failed, or the
		 * gain map is multi-channel).
		 */
		if (!img) {
			error = heif_decode_image(aux_handle, &img,
				heif_colorspace_RGB,
				heif_chroma_interleaved_RGB,
				NULL);
		}
		if (error.code) {
			vips__heif_error(&error);
			return NULL;
		}

		width = heif_image_get_width(img, heif_channel_interleaved);
		height = heif_image_get_height(img, heif_channel_interleaved);

		if (!(data = heif_image_get_plane_readonly(img,
			heif_channel_interleaved, &stride))) {
			vips_error("heifload", "%s",
				_("unable to get gainmap image data"));
			heif_image_release(img);
			return NULL;
		}

		out = vips_image_new_from_memory(data,
			(size_t) stride * height,
			width, height, 3, VIPS_FORMAT_UCHAR);
		if (!out) {
			heif_image_release(img);
			return NULL;
		}

		heif_image_release(img);

		vips_image_init_fields(out,
			width, height, 3,
			VIPS_FORMAT_UCHAR,
			VIPS_CODING_NONE,
			VIPS_INTERPRETATION_sRGB,
			1.0, 1.0);
	}

	return out;
}

/* Main orchestrator: find gain map aux image(s) on the primary handle,
 * decode the gain map raster, attach it as "gainmap" metadata, then
 * find and parse the ISO 21496-1 XML on the aux handle to populate the
 * gainmap-* fields.
 *
 * Called from vips_foreign_load_heif_set_header after the existing
 * metadata block loop. Failures are logged but don't fail the load --
 * the primary image is still useful without the gain map.
 */
static void
vips_foreign_load_heif_load_gainmap(VipsForeignLoadHeif *heif, VipsImage *out)
{
	int n_aux;
	heif_item_id aux_ids[16];
	int n_ids;
	int i;
	struct heif_error error;

	/* Limit aux image count for safety (matches the 16-item metadata
	 * limit elsewhere in this file).
	 */
	n_aux = heif_image_handle_get_number_of_auxiliary_images(
		heif->handle, 0);
	if (n_aux <= 0)
		return;

	n_ids = heif_image_handle_get_list_of_auxiliary_image_IDs(
		heif->handle, 0, aux_ids, VIPS_NUMBER(aux_ids));

	for (i = 0; i < n_ids; i++) {
		struct heif_image_handle *aux_handle = NULL;
		const char *aux_type = NULL;
		VipsImage *gainmap_img = NULL;

		error = heif_image_handle_get_auxiliary_image_handle(
			heif->handle, aux_ids[i], &aux_handle);
		if (error.code) {
			g_info("heifload: failed to get aux handle %u: %s",
				aux_ids[i], error.message ? error.message : "(null)");
			continue;
		}

		error = heif_image_handle_get_auxiliary_type(aux_handle,
			&aux_type);
		if (error.code) {
			g_info("heifload: failed to get aux type for %u: %s",
				aux_ids[i], error.message ? error.message : "(null)");
			heif_image_handle_release(aux_handle);
			continue;
		}

		if (!vips_foreign_load_heif_is_gainmap_aux(aux_type)) {
			heif_image_handle_release_auxiliary_type(aux_handle,
				&aux_type);
			heif_image_handle_release(aux_handle);
			continue;
		}

		g_info("heifload: found gain map aux image (type=%s)", aux_type);

		/* Decode the gain map raster image.
		 */
		if (!(gainmap_img = vips_foreign_load_heif_decode_aux(aux_handle))) {
			g_info("heifload: failed to decode gain map aux image");
			heif_image_handle_release_auxiliary_type(aux_handle,
				&aux_type);
			heif_image_handle_release(aux_handle);
			continue;
		}

		vips_image_set_image(out, "gainmap", gainmap_img);
		VIPS_UNREF(gainmap_img);

		/* Set the gain map scale factor (primary / gainmap). uhdrload
		 * sets this; we do the same for compatibility.
		 */
		{
			int primary_w = heif_image_handle_get_width(heif->handle);
			int gainmap_w = heif_image_handle_get_width(aux_handle);
			int scale_factor = VIPS_MAX(1, primary_w / gainmap_w);

			vips_image_set_int(out, "gainmap-scale-factor", scale_factor);
		}

		/* Now look for the ISO 21496-1 XML metadata on the aux handle.
		 * The XML is typically attached to the gain map image item via
		 * a 'cdsc' reference, so it only shows up when we enumerate
		 * metadata on the aux handle (not the primary).
		 */
		{
			heif_item_id meta_ids[16];
			int n_meta = heif_image_handle_get_list_of_metadata_block_IDs(
				aux_handle, NULL, meta_ids, VIPS_NUMBER(meta_ids));
			int j;
			gboolean parsed_xml = FALSE;

			for (j = 0; j < n_meta && !parsed_xml; j++) {
				const char *content_type =
					heif_image_handle_get_metadata_content_type(
						aux_handle, meta_ids[j]);
				size_t meta_size =
					heif_image_handle_get_metadata_size(
						aux_handle, meta_ids[j]);

				if (content_type &&
					g_str_equal(content_type, "application/rdf+xml") &&
					meta_size > 0 && meta_size < 1024 * 1024) {
					unsigned char *xml_data =
						VIPS_ARRAY(NULL, meta_size, unsigned char);

					if (xml_data) {
						error = heif_image_handle_get_metadata(
							aux_handle, meta_ids[j], xml_data);
						if (!error.code) {
							vips_foreign_load_heif_parse_gainmap_xml(
								(const char *) xml_data, meta_size, out);
							parsed_xml = TRUE;
						}
						VIPS_FREE(xml_data);
					}
				}
			}

			if (!parsed_xml)
				g_info("heifload: gain map has no ISO 21496-1 XML metadata; "
					"gainmap-* fields not populated");
		}

		heif_image_handle_release_auxiliary_type(aux_handle, &aux_type);
		heif_image_handle_release(aux_handle);

		/* We only process the first gain map aux image. If there are
		 * multiple (unlikely but possible), we ignore the rest.
		 */
		break;
	}
}

/* Select a page. If thumbnail is set, select the thumbnail for that page, if
 * there is one.
 */
static int
vips_foreign_load_heif_set_page(VipsForeignLoadHeif *heif,
	int page_no, gboolean thumbnail)
{
	if (!heif->handle ||
		page_no != heif->page_no ||
		thumbnail != heif->thumbnail_set) {
		struct heif_error error;

#ifdef DEBUG
		printf("vips_foreign_load_heif_set_page: %d, thumbnail = %d\n",
			page_no, thumbnail);
#endif /*DEBUG*/

		VIPS_FREEF(heif_image_handle_release, heif->handle);
		VIPS_FREEF(heif_image_release, heif->img);
		heif->data = NULL;
		heif->thumbnail_set = FALSE;

		error = heif_context_get_image_handle(heif->ctx,
			heif->id[page_no], &heif->handle);
		if (error.code) {
			vips__heif_error(&error);
			return -1;
		}

		if (thumbnail) {
			if (vips_foreign_load_heif_set_thumbnail(heif))
				return -1;

			/* If we were asked to select the thumbnail, say we
			 * did, even if there are no thumbnails and we just
			 * selected the main image.
			 *
			 * If we don't do this, next time around in _generate
			 * we'll try to select the thumbnail again, which will
			 * be horribly slow.
			 */
			heif->thumbnail_set = TRUE;
		}

		heif->page_no = page_no;
	}

	return 0;
}

static int
vips_foreign_load_heif_set_header(VipsForeignLoadHeif *heif, VipsImage *out)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(heif);
	VipsForeignLoad *load = (VipsForeignLoad *) heif;

	int bands;
	int i;
	/* Surely, 16 metadata items will be enough for anyone.
	 */
	heif_item_id id[16];
	int n_metadata;
	struct heif_error error;
	VipsForeignHeifCompression compression;
	VipsInterpretation interpretation;
	VipsBandFormat format;
	const unsigned char *brand_data;

	/* We take the metadata from the non-thumbnail first page. HEIC
	 * thumbnails don't have metadata.
	 */
	if (vips_foreign_load_heif_set_page(heif, heif->page, FALSE))
		return -1;

	/* Verify dimensions
	 */
	if (heif->page_width < 1 ||
		heif->page_height < 1) {
		vips_error("heifload", "%s", _("bad dimensions"));
		return -1;
	}

	heif->has_alpha = heif_image_handle_has_alpha_channel(heif->handle);
#ifdef DEBUG
	printf("heif_image_handle_has_alpha_channel() = %d\n", heif->has_alpha);
#endif /*DEBUG*/
	bands = heif->has_alpha ? 4 : 3;

#ifdef DEBUG
	printf("heif_image_handle_get_luma_bits_per_pixel() = %d\n",
		heif_image_handle_get_luma_bits_per_pixel(heif->handle));
#endif /*DEBUG*/

	/* FIXME .. IPTC as well?
	 */
	n_metadata = heif_image_handle_get_list_of_metadata_block_IDs(
		heif->handle, NULL, id, VIPS_NUMBER(id));
	for (i = 0; i < n_metadata; i++) {
		size_t length =
			heif_image_handle_get_metadata_size(heif->handle, id[i]);
		const char *type =
			heif_image_handle_get_metadata_type(heif->handle, id[i]);
		const char *content_type =
			heif_image_handle_get_metadata_content_type(heif->handle, id[i]);

		unsigned char *data;
		char name[256];

#ifdef DEBUG
		printf("metadata type = %s, length = %zu\n", type, length);
#endif /*DEBUG*/

		if (!length)
			continue;
		if (!heif->unlimited &&
			length > 64 * 1024 * 1024) {
			vips_error(class->nickname, "%s", _("metadata block too large"));
			return -1;
		}
		if (!(data = VIPS_ARRAY(NULL, length, unsigned char)))
			return -1;
		error = heif_image_handle_get_metadata(heif->handle, id[i], data);
		if (error.code) {
			VIPS_FREE(data);
			vips__heif_error(&error);
			return -1;
		}

		/* We need to skip the first four bytes of EXIF, they just
		 * contain the offset.
		 */
		if (length > 4 &&
			g_ascii_strcasecmp(type, "exif") == 0) {
			length -= 4;
			memmove(data, data + 4, length);
		}

		/* Exif data will have the type string "exif".
		 *
		 * For XMP, the content type is "application/rdf+xml".
		 */
		if (g_ascii_strcasecmp(type, "exif") == 0)
			g_snprintf(name, 256, VIPS_META_EXIF_NAME);
		else if (g_ascii_strcasecmp(content_type, "application/rdf+xml") == 0)
			g_snprintf(name, 256, VIPS_META_XMP_NAME);
		else
			g_snprintf(name, 256, "heif-%s-%d", type, i);

		vips_image_set_blob(out, name,
			(VipsCallbackFn) vips_area_free_cb, data, length);

		/* image_set will automatically parse EXIF, if necessary.
		 */
	}

	/* We use libheif's autorotate, so we need to remove any EXIF
	 * orientation tags.
	 *
	 * According to the HEIF standard, EXIF orientation tags are only
	 * informational and images should not be rotated because of them.
	 * Unless we strip these tags, there's a danger downstream processing
	 * could double-rotate.
	 */
	vips_autorot_remove_angle(out);

	/* If both NCLX and ICC are present, ICC is returned.
	 */
	enum heif_color_profile_type profile_type =
		heif_image_handle_get_color_profile_type(heif->handle);

#ifdef DEBUG
	{
		printf("profile type = ");
		switch (profile_type) {
		case heif_color_profile_type_not_present:
			printf("none");
			break;

		case heif_color_profile_type_nclx:
			printf("nclx");
			break;

		case heif_color_profile_type_rICC:
			printf("rICC");
			break;

		case heif_color_profile_type_prof:
			printf("prof");
			break;

		default:
			printf("unknown");
			break;
		}
		printf("\n");
	}
#endif /*DEBUG*/

	/* lcms can load standard (prof) and reduced (rICC) profiles
	 */
	if (profile_type == heif_color_profile_type_prof ||
		profile_type == heif_color_profile_type_rICC) {
		size_t length = heif_image_handle_get_raw_color_profile_size(
			heif->handle);

		unsigned char *data;

		if (!(data = VIPS_ARRAY(NULL, length, unsigned char)))
			return -1;
		error = heif_image_handle_get_raw_color_profile(heif->handle, data);
		if (error.code) {
			VIPS_FREE(data);
			vips__heif_error(&error);
			return -1;
		}

#ifdef DEBUG
		printf("profile data, length = %zd\n", length);
#endif /*DEBUG*/

		vips_image_set_blob(out, VIPS_META_ICC_NAME,
			(VipsCallbackFn) vips_area_free_cb, data, length);
	}
	/* Always try to fetch the NCLX profile, even when ICC is present.
	 * CICP takes priority over ICC for colour interpretation.
	 */
	{
		struct heif_color_profile_nclx *nclx = NULL;

		error = heif_image_handle_get_nclx_color_profile(heif->handle, &nclx);
		if (error.code == 0 && nclx) {
#ifdef DEBUG
			printf("\tnclx: %p\n", nclx);
			printf("\tnclx->color_primaries: %d\n", nclx->color_primaries);
			printf("\tnclx->transfer_characteristics: %d\n", nclx->transfer_characteristics);
			printf("\tnclx->matrix_coefficients: %d\n", nclx->matrix_coefficients);
			printf("\tnclx->full_range_flag: %d\n", nclx->full_range_flag);
#endif

			g_info("heifload: setting CICP from nclx");

			vips_image_set_int(out, "cicp-colour-primaries",
				nclx->color_primaries);
			vips_image_set_int(out, "cicp-transfer-characteristics",
				nclx->transfer_characteristics);
			vips_image_set_int(out, "cicp-matrix-coefficients",
				nclx->matrix_coefficients);
			vips_image_set_int(out, "cicp-full-range-flag",
				nclx->full_range_flag);
		}

		if (nclx)
			heif_nclx_color_profile_free(nclx);
	}

	/* Extract ISO 21496-1 / Adobe HDR gain map from HEIC auxiliary images,
	 * if present. Populates the "gainmap" image metadata and gainmap-*
	 * metadata fields, matching the format produced by uhdrload.c.
	 * Failures are logged but don't fail the load.
	 */
	vips_foreign_load_heif_load_gainmap(heif, out);

	vips_image_set_int(out, "heif-primary", heif->primary_page);
	vips_image_set_int(out, VIPS_META_N_PAGES, heif->n_top);

	/* Only set page-height if we have more than one page, or this could
	 * accidentally turn into an animated image later.
	 */
	if (heif->n > 1)
		vips_image_set_int(out, VIPS_META_PAGE_HEIGHT, heif->page_height);

	/* Determine compression from HEIF "brand". heif_avif and heif_avis
	 * were added in v1.7.
	 */
	compression = VIPS_FOREIGN_HEIF_COMPRESSION_HEVC;
	if ((brand_data = vips_source_sniff(heif->source, 12))) {
		enum heif_brand brand;
		brand = heif_main_brand(brand_data, 12);
		if (brand == heif_avif ||
			brand == heif_avis)
			compression = VIPS_FOREIGN_HEIF_COMPRESSION_AV1;
	}

	vips_image_set_string(out, "heif-compression",
		vips_enum_nick(VIPS_TYPE_FOREIGN_HEIF_COMPRESSION,
			compression));

	vips_image_set_int(out, VIPS_META_BITS_PER_SAMPLE, heif->bits_per_pixel);

	/* Deprecated "heif-bitdepth" use "bits-per-sample" instead.
	 */
	vips_image_set_int(out, "heif-bitdepth", heif->bits_per_pixel);

	if (heif->bits_per_pixel > 8) {
		interpretation = VIPS_INTERPRETATION_RGB16;
		format = VIPS_FORMAT_USHORT;
	}
	else {
		interpretation = VIPS_INTERPRETATION_sRGB;
		format = VIPS_FORMAT_UCHAR;
	}

	/* FIXME .. we always decode to RGB in generate. We should check for
	 * all grey images, perhaps.
	 */
	if (vips_image_pipelinev(out, VIPS_DEMAND_STYLE_THINSTRIP, NULL))
		return -1;
	vips_image_init_fields(out,
		heif->page_width, heif->page_height * heif->n, bands,
		format, VIPS_CODING_NONE, interpretation,
		1.0, 1.0);

	VIPS_SETSTR(load->out->filename,
		vips_connection_filename(VIPS_CONNECTION(heif->source)));

	return 0;
}

static int
vips_foreign_load_heif_header(VipsForeignLoad *load)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(load);
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) load;

	struct heif_error error;
	heif_item_id primary_id;
	int i;

#ifdef DEBUG
	printf("vips_foreign_load_heif_header:\n");
#endif /*DEBUG*/

	heif->n_top = heif_context_get_number_of_top_level_images(heif->ctx);
	heif->id = VIPS_ARRAY(NULL, heif->n_top, heif_item_id);
	heif_context_get_list_of_top_level_image_IDs(heif->ctx,
		heif->id, heif->n_top);

	/* Note page number of primary image.
	 */
	error = heif_context_get_primary_image_ID(heif->ctx, &primary_id);
	if (error.code) {
		vips__heif_error(&error);
		return -1;
	}
	for (i = 0; i < heif->n_top; i++)
		if (heif->id[i] == primary_id)
			heif->primary_page = i;

	/* If @n and @page have not been set, @page defaults to the primary
	 * page.
	 */
	if (!vips_object_argument_isset(VIPS_OBJECT(load), "page") &&
		!vips_object_argument_isset(VIPS_OBJECT(load), "n"))
		heif->page = heif->primary_page; // FIXME: Invalidates operation cache

	if (heif->n == -1)
		heif->n = heif->n_top - heif->page; // FIXME: Invalidates operation cache
	if (heif->page < 0 ||
		heif->n <= 0 ||
		heif->page + heif->n > heif->n_top) {
		vips_error(class->nickname, "%s", _("bad page number"));
		return -1;
	}

#ifdef DEBUG
	for (i = heif->page; i < heif->page + heif->n; i++) {
		heif_item_id thumb_ids[1];
		int n_items;
		int n_thumbs;
		int j;

		if (vips_foreign_load_heif_set_page(heif, i, FALSE))
			return -1;

		n_thumbs = heif_image_handle_get_number_of_thumbnails(heif->handle);
		n_items = heif_image_handle_get_list_of_thumbnail_IDs(heif->handle,
			thumb_ids, 1);

		printf("page = %d\n", i);
		printf("n_thumbs = %d\n", n_thumbs);
		printf("n_items = %d\n", n_items);

		for (j = 0; j < n_items; j++) {
			struct heif_image_handle *thumb_handle;

			error = heif_image_handle_get_thumbnail(heif->handle,
				thumb_ids[j], &thumb_handle);
			if (error.code) {
				vips__heif_error(&error);
				return -1;
			}

			printf("  thumb %d\n", j);
			printf("    width = %d\n",
				heif_image_handle_get_width(thumb_handle));
			printf("    height = %d\n",
				heif_image_handle_get_height(thumb_handle));
			printf("    bits_per_pixel = %d\n",
				heif_image_handle_get_luma_bits_per_pixel(thumb_handle));
		}
	}
#endif /*DEBUG*/

	/* All pages must be the same size for libvips toilet roll images.
	 */
	if (vips_foreign_load_heif_set_page(heif, heif->page, heif->thumbnail))
		return -1;
	heif->page_width = heif_image_handle_get_width(heif->handle);
	heif->page_height = heif_image_handle_get_height(heif->handle);
	heif->bits_per_pixel =
		heif_image_handle_get_luma_bits_per_pixel(heif->handle);
	if (heif->bits_per_pixel < 0) {
		vips_error(class->nickname, "%s", _("undefined bits per pixel"));
		return -1;
	}

	for (i = heif->page + 1; i < heif->page + heif->n; i++) {
		if (vips_foreign_load_heif_set_page(heif, i, heif->thumbnail))
			return -1;
		if (heif_image_handle_get_width(heif->handle) != heif->page_width ||
			heif_image_handle_get_height(heif->handle) != heif->page_height ||
			heif_image_handle_get_luma_bits_per_pixel(heif->handle) !=
				heif->bits_per_pixel) {
			vips_error(class->nickname, "%s",
				_("not all pages are the same size"));
			return -1;
		}
	}

#ifdef DEBUG
	printf("page_width = %d\n", heif->page_width);
	printf("page_height = %d\n", heif->page_height);
	printf("bits_per_pixel = %d\n", heif->bits_per_pixel);

	printf("n_top = %d\n", heif->n_top);
	for (i = 0; i < heif->n_top; i++) {
		printf("  id[%d] = %d\n", i, heif->id[i]);
		if (vips_foreign_load_heif_set_page(heif, i, FALSE))
			return -1;
		printf("    width = %d\n",
			heif_image_handle_get_width(heif->handle));
		printf("    height = %d\n",
			heif_image_handle_get_height(heif->handle));
		printf("    bits_per_pixel = %d\n",
			heif_image_handle_get_luma_bits_per_pixel(heif->handle));
		printf("    has_depth = %d\n",
			heif_image_handle_has_depth_image(heif->handle));
		printf("    has_alpha = %d\n",
			heif_image_handle_has_alpha_channel(heif->handle));
		printf("    n_metadata = %d\n",
			heif_image_handle_get_number_of_metadata_blocks(
				heif->handle, NULL));
		printf("    colour profile type = 0x%xd\n",
			heif_image_handle_get_color_profile_type(heif->handle));
	}
#endif /*DEBUG*/

	if (vips_foreign_load_heif_set_header(heif, load->out))
		return -1;

	vips_source_minimise(heif->source);

	return 0;
}

static int
vips_foreign_load_heif_generate(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) a;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(heif);
	VipsRect *r = &out_region->valid;

	int page = r->top / heif->page_height + heif->page;
	int line = r->top % heif->page_height;

#ifdef DEBUG_VERBOSE
	printf("vips_foreign_load_heif_generate: line %d\n", r->top);
#endif /*DEBUG_VERBOSE*/

	g_assert(r->height == 1);

	if (vips_foreign_load_heif_set_page(heif, page, heif->thumbnail))
		return -1;

	if (!heif->img) {
		enum heif_chroma chroma =
			vips__heif_chroma(heif->bits_per_pixel, heif->has_alpha);

		struct heif_error error;
		struct heif_decoding_options *options;

		options = heif_decoding_options_alloc();
		error = heif_decode_image(heif->handle, &heif->img,
			heif_colorspace_RGB,
			chroma,
			options);
		heif_decoding_options_free(options);
		if (error.code) {
			vips__heif_error(&error);
			return -1;
		}

#ifdef DEBUG
		vips__heif_image_print(heif->img);
#endif /*DEBUG*/
	}

	if (!heif->data) {
		int image_width = heif_image_get_width(heif->img,
			heif_channel_interleaved);
		int image_height = heif_image_get_height(heif->img,
			heif_channel_interleaved);

		/* We can sometimes get inconsistency between the dimensions
		 * reported on the handle, and the final image we fetch. Error
		 * out to prevent a segv.
		 */
		if (image_width != heif->page_width ||
			image_height != heif->page_height) {
			vips_error(class->nickname,
				"%s", _("bad image dimensions on decode"));
			return -1;
		}

		if (!(heif->data = heif_image_get_plane_readonly(heif->img,
				  heif_channel_interleaved, &heif->stride))) {
			vips_error(class->nickname,
				"%s", _("unable to get image data"));
			return -1;
		}
	}

	memcpy(VIPS_REGION_ADDR(out_region, 0, r->top),
		heif->data + (size_t) heif->stride * line,
		VIPS_IMAGE_SIZEOF_LINE(out_region->im));

	/* We may need to swap bytes and shift to fill 16 bits.
	 */
	if (heif->bits_per_pixel > 8) {
		int shift = 16 - heif->bits_per_pixel;
		int ne = VIPS_REGION_N_ELEMENTS(out_region);

		int i;
		VipsPel *p;

		p = VIPS_REGION_ADDR(out_region, 0, r->top);
		for (i = 0; i < ne; i++) {
			/* We've asked for big endian, we must write native.
			 */
			guint16 v = ((p[0] << 8) | p[1]) << shift;

			*((guint16 *) p) = v;
			p += 2;
		}
	}

	return 0;
}

static void
vips_foreign_load_heif_minimise(VipsObject *object, VipsForeignLoadHeif *heif)
{
	vips_source_minimise(heif->source);
}

static int
vips_foreign_load_heif_load(VipsForeignLoad *load)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) load;

	VipsImage **t = (VipsImage **)
		vips_object_local_array(VIPS_OBJECT(load), 3);

#ifdef DEBUG
	printf("vips_foreign_load_heif_load: loading image\n");
#endif /*DEBUG*/

	t[0] = vips_image_new();
	if (vips_foreign_load_heif_set_header(heif, t[0]))
		return -1;

	/* Close input immediately at end of read.
	 */
	g_signal_connect(t[0], "minimise",
		G_CALLBACK(vips_foreign_load_heif_minimise), heif);

	if (vips_image_generate(t[0],
			NULL, vips_foreign_load_heif_generate, NULL, heif, NULL) ||
		vips_sequential(t[0], &t[1], NULL) ||
		vips_image_write(t[1], load->real))
		return -1;

	if (vips_source_decode(heif->source))
		return -1;

	return 0;
}

static void
vips_foreign_load_heif_class_init(VipsForeignLoadHeifClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	vips__heif_init();

	gobject_class->dispose = vips_foreign_load_heif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifload_base";
	object_class->description = _("load a HEIF image");
	object_class->build = vips_foreign_load_heif_build;

	/* Our is_a() is a cheap ISOBMFF brand check, so high priority.
	 */
	foreign_class->priority = 150;

	load_class->get_flags = vips_foreign_load_heif_get_flags;
	load_class->header = vips_foreign_load_heif_header;
	load_class->load = vips_foreign_load_heif_load;

	VIPS_ARG_INT(class, "page", 2,
		_("Page"),
		_("First page to load"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadHeif, page),
		0, 100000, 0);

	VIPS_ARG_INT(class, "n", 3,
		_("n"),
		_("Number of pages to load, -1 for all"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadHeif, n),
		-1, 100000, 1);

	VIPS_ARG_BOOL(class, "thumbnail", 4,
		_("Thumbnail"),
		_("Fetch thumbnail image"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadHeif, thumbnail),
		FALSE);

	VIPS_ARG_BOOL(class, "autorotate", 21,
		_("Autorotate"),
		_("Rotate image using exif orientation"),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsForeignLoadHeif, autorotate),
		FALSE);

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	VIPS_ARG_BOOL(class, "unlimited", 22,
		_("Unlimited"),
		_("Remove all denial of service limits"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadHeif, unlimited),
		FALSE);
#endif
}

static gint64
vips_foreign_load_heif_get_position(void *userdata)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) userdata;

	return vips_source_seek(heif->source, 0L, SEEK_CUR);
}

/* libheif read() does not work like unix read().
 *
 * This method is cannot return EOF. Instead, the separate wait_for_file_size()
 * is called beforehand to make sure that there's enough data there.
 */
static int
vips_foreign_load_heif_read(void *data, size_t size, void *userdata)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) userdata;

	while (size > 0) {
		gint64 bytes_read;

		bytes_read = vips_source_read(heif->source, data, size);
		if (bytes_read <= 0)
			return -1;

		size -= bytes_read;
		data = (char *) data + bytes_read;
	}

	return 0;
}

static int
vips_foreign_load_heif_seek(gint64 position, void *userdata)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) userdata;

	/* Return 0 on success.
	 */
	return vips_source_seek(heif->source, position, SEEK_SET) == -1;
}

/* libheif calls this to mean "I intend to read() to this position, please
 * check it is OK".
 */
static enum heif_reader_grow_status
vips_foreign_load_heif_wait_for_file_size(gint64 target_size, void *userdata)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) userdata;

	gint64 old_position;
	gint64 result;
	enum heif_reader_grow_status status;

	/* We seek the VipsSource to the position and check for errors.
	 */
	old_position = vips_source_seek(heif->source, 0L, SEEK_CUR);
	result = vips_source_seek(heif->source, target_size, SEEK_SET);
	vips_source_seek(heif->source, old_position, SEEK_SET);

	if (result < 0 || old_position < 0)
		/* Unable to seek to this point, so it's beyond EOF.
		 */
		status = heif_reader_grow_status_size_beyond_eof;
	else
		/* Successfully read to the requested point, but the requested
		 * point is not necessarily EOF.
		 */
		status = heif_reader_grow_status_size_reached;

	return status;
}

static void
vips_foreign_load_heif_init(VipsForeignLoadHeif *heif)
{
	heif->n = 1;
	heif->unlimited = vips_unlimited_get();

	heif->reader = VIPS_ARRAY(NULL, 1, struct heif_reader);

	/* The first version to support heif_reader.
	 */
	heif->reader->reader_api_version = 1;
	heif->reader->get_position = vips_foreign_load_heif_get_position;
	heif->reader->read = vips_foreign_load_heif_read;
	heif->reader->seek = vips_foreign_load_heif_seek;
	heif->reader->wait_for_file_size =
		vips_foreign_load_heif_wait_for_file_size;
}

typedef struct _VipsForeignLoadHeifFile {
	VipsForeignLoadHeif parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadHeifFile;

typedef VipsForeignLoadHeifClass VipsForeignLoadHeifFileClass;

G_DEFINE_TYPE(VipsForeignLoadHeifFile, vips_foreign_load_heif_file,
	vips_foreign_load_heif_get_type());

static int
vips_foreign_load_heif_file_build(VipsObject *object)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) object;
	VipsForeignLoadHeifFile *file = (VipsForeignLoadHeifFile *) object;

	if (file->filename &&
		!(heif->source = vips_source_new_from_file(file->filename)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_load_heif_file_parent_class)
		->build(object);
}

static int
vips_foreign_load_heif_file_is_a(const char *filename)
{
	char buf[12];

	if (vips__get_bytes(filename, (unsigned char *) buf, 12) != 12)
		return 0;

	return vips_foreign_load_heif_is_a(buf, 12);
}

static void
vips_foreign_load_heif_file_class_init(VipsForeignLoadHeifFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifload";
	object_class->build = vips_foreign_load_heif_file_build;

	foreign_class->suffs = vips__heif_suffs;

	load_class->is_a = vips_foreign_load_heif_file_is_a;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadHeifFile, filename),
		NULL);
}

static void
vips_foreign_load_heif_file_init(VipsForeignLoadHeifFile *file)
{
}

typedef struct _VipsForeignLoadHeifBuffer {
	VipsForeignLoadHeif parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadHeifBuffer;

typedef VipsForeignLoadHeifClass VipsForeignLoadHeifBufferClass;

G_DEFINE_TYPE(VipsForeignLoadHeifBuffer, vips_foreign_load_heif_buffer,
	vips_foreign_load_heif_get_type());

static int
vips_foreign_load_heif_buffer_build(VipsObject *object)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) object;
	VipsForeignLoadHeifBuffer *buffer =
		(VipsForeignLoadHeifBuffer *) object;

	if (buffer->buf &&
		!(heif->source = vips_source_new_from_memory(
			VIPS_AREA(buffer->buf)->data,
			VIPS_AREA(buffer->buf)->length)))
		return -1;

	return VIPS_OBJECT_CLASS(vips_foreign_load_heif_buffer_parent_class)
		->build(object);
}

static gboolean
vips_foreign_load_heif_buffer_is_a(const void *buf, size_t len)
{
	return vips_foreign_load_heif_is_a(buf, len);
}

static void
vips_foreign_load_heif_buffer_class_init(
	VipsForeignLoadHeifBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifload_buffer";
	object_class->build = vips_foreign_load_heif_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_heif_buffer_is_a;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadHeifBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_load_heif_buffer_init(VipsForeignLoadHeifBuffer *buffer)
{
}

typedef struct _VipsForeignLoadHeifSource {
	VipsForeignLoadHeif parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadHeifSource;

typedef VipsForeignLoadHeifClass VipsForeignLoadHeifSourceClass;

G_DEFINE_TYPE(VipsForeignLoadHeifSource, vips_foreign_load_heif_source,
	vips_foreign_load_heif_get_type());

static int
vips_foreign_load_heif_source_build(VipsObject *object)
{
	VipsForeignLoadHeif *heif = (VipsForeignLoadHeif *) object;
	VipsForeignLoadHeifSource *source =
		(VipsForeignLoadHeifSource *) object;

	if (source->source) {
		heif->source = source->source;
		g_object_ref(heif->source);
	}

	return VIPS_OBJECT_CLASS(vips_foreign_load_heif_source_parent_class)
		->build(object);
}

static gboolean
vips_foreign_load_heif_source_is_a_source(VipsSource *source)
{
	const char *p;

	return (p = (const char *) vips_source_sniff(source, 12)) &&
		vips_foreign_load_heif_is_a(p, 12);
}

static void
vips_foreign_load_heif_source_class_init(
	VipsForeignLoadHeifSourceClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "heifload_source";
	object_class->build = vips_foreign_load_heif_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_heif_source_is_a_source;

	VIPS_ARG_OBJECT(class, "source", 1,
		_("Source"),
		_("Source to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadHeifSource, source),
		VIPS_TYPE_SOURCE);
}

static void
vips_foreign_load_heif_source_init(VipsForeignLoadHeifSource *source)
{
}

#endif /*HAVE_HEIF*/

/* The C API wrappers are defined in foreign.c.
 */
