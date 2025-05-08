/* load with libMagick
 *
 * 7/1/03 JC
 *	- from im_tiff2vips
 * 3/2/03 JC
 *	- some InitializeMagick() fail with NULL arg
 * 2/11/04
 *	- im_magick2vips_header() also checks sensible width/height
 * 28/10/05
 * 	- copy attributes to meta
 * 	- write many-frame images as a big column if all frames have identical
 * 	  width/height/bands/depth
 * 31/3/06
 * 	- test for magick attr support
 * 8/5/06
 * 	- set RGB16/GREY16 if appropriate
 * 10/8/07
 * 	- support 32/64 bit imagemagick too
 * 21/2/08
 * 	- use MaxRGB if QuantumRange is missing (thanks Bob)
 * 	- look for MAGICKCORE_HDRI_SUPPORT (thanks Marcel)
 * 	- use image->attributes if GetNextImageAttribute() is missing
 * 3/3/09
 * 	- allow funky bit depths, like 14 (thanks Mikkel)
 * 17/3/09
 * 	- reset dcm:display-range to help DICOM read
 * 20/4/09
 * 	- argh libMagick uses 255 == transparent ... we must invert all
 * 	  alpha channels
 * 12/5/09
 *	- fix signed/unsigned warnings
 * 23/7/09
 * 	- SetImageOption() is optional (to help GM)
 * 4/2/10
 * 	- gtkdoc
 * 30/4/10
 * 	- better number of bands detection with GetImageType()
 * 	- use new API stuff, argh
 * 17/12/11
 * 	- turn into a set of read fns ready to be called from a class
 * 17/1/12
 * 	- remove header-only loads
 * 11/6/13
 * 	- add @all_frames option, off by default
 * 4/12/14 Lovell
 * 	- add @density option
 * 16/2/15 mcuelenaere
 * 	- add blob read
 * 26/2/15
 * 	- close the read down early for a header read ... this saves an
 * 	  fd during file read, handy for large numbers of input images
 * 14/2/16
 * 	- add @page option, 0 by default
 * 18/4/16
 * 	- fix @page with graphicsmagick
 * 25/11/16
 * 	- add @n, deprecate @all_frames (just sets n = -1)
 * 23/2/17
 * 	- try using GetImageChannelDepth() instead of ->depth
 * 8/9/17
 * 	- don't cache magickload
 * 25/5/18
 * 	- don't use Ping, it's too unreliable
 * 24/7/18
 * 	- sniff extra filetypes
 * 4/1/19 kleisauke
 * 	- we did not chain exceptions correctly, causing a memory leak
 * 	- added wrapper funcs for exception handling
 * 4/2/19
 * 	- add profile (xmp, ipct, etc.) read
 * 21/4/21 kleisauke
 * 	- include GObject part from magickload.c
 * 12/11/21
 * 	- set "orientation"
 * 26/8/22
 * 	- set "magick-format"
 * 13/3/23 MathemanFlo
 * 	- add bits per sample metadata
 * 08/11/24 kleisauke
 * 	- merge with magick2vips.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#ifdef ENABLE_MAGICKLOAD

#ifdef HAVE_MAGICK6

#include <magick/api.h>

#include "pforeign.h"
#include "magick.h"

/* pre-float Magick used to call this MaxRGB.
 */
#if !defined(QuantumRange)
#define QuantumRange MaxRGB
#endif

/* And this used to be UseHDRI.
 */
#if MAGICKCORE_HDRI_SUPPORT
#define UseHDRI 1
#endif

typedef struct _VipsForeignLoadMagick {
	VipsForeignLoad parent_object;

	/* Deprecated. Just sets n = -1.
	 */
	gboolean all_frames;

	char *density; /* Load at this resolution */
	int page;	   /* Load this page (frame) */
	int n;		   /* Load this many pages */

	Image *image;
	ImageInfo *image_info;
	ExceptionInfo *exception;

	/* Number of pages in image.
	 */
	int n_pages;

	int n_frames;	/* Number of frames we will read */
	Image **frames; /* An Image* for each frame */
	int frame_height;

	/* Mutex to serialise calls to libMagick during threaded read.
	 */
	GMutex lock;

} VipsForeignLoadMagick;

typedef VipsForeignLoadClass VipsForeignLoadMagickClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignLoadMagick, vips_foreign_load_magick,
	VIPS_TYPE_FOREIGN_LOAD);

static VipsForeignFlags
vips_foreign_load_magick_get_flags_filename(const char *filename)
{
	return VIPS_FOREIGN_PARTIAL;
}

static VipsForeignFlags
vips_foreign_load_magick_get_flags(VipsForeignLoad *load)
{
	return VIPS_FOREIGN_PARTIAL;
}

static void
vips_foreign_load_magick_finalize(GObject *gobject)
{
	VipsForeignLoadMagick *magick = (VipsForeignLoadMagick *) gobject;

#ifdef DEBUG
	printf("vips_foreign_load_magick_finalize: %p\n", gobject);
#endif /*DEBUG*/

	VIPS_FREEF(DestroyImageList, magick->image);
	VIPS_FREEF(DestroyImageInfo, magick->image_info);
	VIPS_FREE(magick->frames);
	VIPS_FREEF(magick_destroy_exception, magick->exception);
	g_mutex_clear(&magick->lock);

	G_OBJECT_CLASS(vips_foreign_load_magick_parent_class)->finalize(gobject);
}

static int
vips_foreign_load_magick_build(VipsObject *object)
{
	VipsForeignLoadMagick *magick = (VipsForeignLoadMagick *) object;

#ifdef DEBUG
	printf("vips_foreign_load_magick_build: %p\n", object);
#endif /*DEBUG*/

	magick_genesis();

	magick->image_info = CloneImageInfo(NULL);
	magick->exception = magick_acquire_exception();

	if (!magick->image_info)
		return -1;

	if (magick->all_frames)
		magick->n = -1;

	/* IM doesn't use the -1 means end-of-file convention, change it to a
	 * very large number.
	 */
	if (magick->n == -1)
		magick->n = 10000000;

	/* Canvas resolution for rendering vector formats like SVG.
	 */
	VIPS_SETSTR(magick->image_info->density, magick->density);

	/* When reading DICOM images, we want to ignore any
	 * window_center/_width setting, since it may put pixels outside the
	 * 0-65535 range and lose data.
	 *
	 * These window settings are attached as vips metadata, so our caller
	 * can interpret them if it wants.
	 */
	magick_set_image_option(magick->image_info, "dcm:display-range", "reset");

	if (magick->page > 0)
		magick_set_number_scenes(magick->image_info, magick->page, magick->n);

	if (VIPS_OBJECT_CLASS(vips_foreign_load_magick_parent_class)->build(object))
		return -1;

	return 0;
}

static void
vips_foreign_load_magick_class_init(VipsForeignLoadMagickClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS(class);
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->finalize = vips_foreign_load_magick_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload_base";
	object_class->description = _("load with ImageMagick");
	object_class->build = vips_foreign_load_magick_build;

	/* Don't cache magickload: it can gobble up memory and disc.
	 */
	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	/* *magick is fuzzed, but it's such a huge thing it's safer to
	 * disable it.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	/* We need to be well to the back of the queue since vips's
	 * dedicated loaders are usually preferable.
	 */
	foreign_class->priority = -100;

	load_class->get_flags_filename =
		vips_foreign_load_magick_get_flags_filename;
	load_class->get_flags = vips_foreign_load_magick_get_flags;

	VIPS_ARG_STRING(class, "density", 21,
		_("Density"),
		_("Canvas resolution for rendering vector formats like SVG"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadMagick, density),
		NULL);

	VIPS_ARG_INT(class, "page", 22,
		_("Page"),
		_("First page to load"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadMagick, page),
		0, 100000, 0);

	VIPS_ARG_INT(class, "n", 23,
		_("n"),
		_("Number of pages to load, -1 for all"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadMagick, n),
		-1, 100000, 1);

	VIPS_ARG_BOOL(class, "all_frames", 20,
		_("All frames"),
		_("Read all frames from an image"),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsForeignLoadMagick, all_frames),
		FALSE);
}

static void
vips_foreign_load_magick_init(VipsForeignLoadMagick *magick)
{
	magick->n = 1;
	g_mutex_init(&magick->lock);
}

static int
magick_get_bands(Image *image)
{
	int bands;
	ImageType type = GetImageType(image, &image->exception);

	switch (type) {
	case BilevelType:
	case GrayscaleType:
		bands = 1;
		break;

	case GrayscaleMatteType:
		/* ImageMagick also has PaletteBilevelMatteType, but GraphicsMagick
		 * does not. Skip for portability.
		 */
		bands = 2;
		break;

	case PaletteType:
	case TrueColorType:
		bands = 3;
		break;

	case PaletteMatteType:
	case TrueColorMatteType:
	case ColorSeparationType:
		bands = 4;
		break;

	case ColorSeparationMatteType:
		bands = 5;
		break;

	default:
		vips_error("magick2vips", _("unsupported image type %d"),
			(int) type);
		return -1;
	}

	return bands;
}

static int
vips_foreign_load_magick_parse(VipsForeignLoadMagick *magick,
	Image *image, VipsImage *out)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(magick);

	int depth;
	Image *p;

#ifdef DEBUG
	printf("GetImageChannelDepth(AllChannels) = %zd\n",
		GetImageChannelDepth(image, AllChannels, &image->exception));
	printf("GetImageDepth() = %zd\n",
		GetImageDepth(image, &image->exception));
	printf("image->depth = %zd\n", image->depth);
	printf("GetImageType() = %d\n",
		GetImageType(image, &image->exception));
	printf("IsGrayImage() = %d\n",
		IsGrayImage(image, &image->exception));
	printf("IsMonochromeImage() = %d\n",
		IsMonochromeImage(image, &image->exception));
	printf("IsOpaqueImage() = %d\n",
		IsOpaqueImage(image, &image->exception));
	printf("image->columns = %zd\n", image->columns);
	printf("image->rows = %zd\n", image->rows);
#endif /*DEBUG*/

	/* Ysize updated below once we have worked out how many frames to load.
	 */
	out->Coding = VIPS_CODING_NONE;
	out->Xsize = image->columns;
	out->Ysize = image->rows;
	magick->frame_height = image->rows;
	out->Bands = magick_get_bands(image);
	if (out->Xsize <= 0 ||
		out->Ysize <= 0 ||
		out->Bands <= 0 ||
		out->Xsize >= VIPS_MAX_COORD ||
		out->Ysize >= VIPS_MAX_COORD ||
		out->Bands >= VIPS_MAX_COORD) {
		vips_error(class->nickname,
			_("bad image dimensions %d x %d pixels, %d bands"),
			out->Xsize, out->Ysize, out->Bands);
		return -1;
	}

	/* Depth can be 'fractional'. You'd think we should use
	 * GetImageDepth() but that seems unreliable. 16-bit mono DICOM images
	 * are reported as depth 1, for example.
	 *
	 * Try GetImageChannelDepth(), maybe that works.
	 */
	depth = GetImageChannelDepth(image, AllChannels, &image->exception);

	out->BandFmt = -1;
	if (depth >= 1 && depth <= 8)
		out->BandFmt = VIPS_FORMAT_UCHAR;
	if (depth >= 9 && depth <= 16)
		out->BandFmt = VIPS_FORMAT_USHORT;
#ifdef UseHDRI
	if (depth == 32)
		out->BandFmt = VIPS_FORMAT_FLOAT;
	if (depth == 64)
		out->BandFmt = VIPS_FORMAT_DOUBLE;
#else  /*!UseHDRI*/
	if (depth == 32)
		out->BandFmt = VIPS_FORMAT_UINT;
#endif /*UseHDRI*/

	if (out->BandFmt == -1) {
		vips_error(class->nickname,
			_("unsupported bit depth %d"), depth);
		return -1;
	}

	switch (image->units) {
	case PixelsPerInchResolution:
		out->Xres = image->x_resolution / 25.4;
		out->Yres = image->y_resolution / 25.4;
		vips_image_set_string(out, VIPS_META_RESOLUTION_UNIT, "in");
		break;

	case PixelsPerCentimeterResolution:
		out->Xres = image->x_resolution / 10.0;
		out->Yres = image->y_resolution / 10.0;
		vips_image_set_string(out, VIPS_META_RESOLUTION_UNIT, "cm");
		break;

	default:
		/* Things like GIF have no resolution info.
		 */
		out->Xres = 1.0;
		out->Yres = 1.0;
		break;
	}

	// this can be wrong for some GM versions and must be sanity checked (see
	// below)
	switch (image->colorspace) {
	case GRAYColorspace:
		if (out->BandFmt == VIPS_FORMAT_USHORT)
			out->Type = VIPS_INTERPRETATION_GREY16;
		else
			out->Type = VIPS_INTERPRETATION_B_W;
		break;

	case sRGBColorspace:
	case RGBColorspace:
		if (out->BandFmt == VIPS_FORMAT_USHORT)
			out->Type = VIPS_INTERPRETATION_RGB16;
		else
			out->Type = VIPS_INTERPRETATION_sRGB;
		break;

	case CMYKColorspace:
		out->Type = VIPS_INTERPRETATION_CMYK;
		break;

	default:
		out->Type = VIPS_INTERPRETATION_ERROR;
		break;
	}

	// revise the interpretation if it seems crazy
	out->Type = vips_image_guess_interpretation(out);

	if (vips_image_pipelinev(out, VIPS_DEMAND_STYLE_SMALLTILE, NULL))
		return -1;

#ifdef HAVE_RESETIMAGEPROPERTYITERATOR
	{
		char *key;

		/* This is the most recent imagemagick API, test for this first.
		 */
		ResetImagePropertyIterator(image);
		while ((key = GetNextImageProperty(image))) {
			char name_text[256];
			VipsBuf name = VIPS_BUF_STATIC(name_text);

			vips_buf_appendf(&name, "magick-%s", key);
			vips_image_set_string(out,
				vips_buf_all(&name), GetImageProperty(image, key));
		}
	}
#elif defined(HAVE_RESETIMAGEATTRIBUTEITERATOR)
	{
		const ImageAttribute *attr;

		/* magick6.1-ish and later, deprecated in 6.5ish.
		 */
		ResetImageAttributeIterator(image);
		while ((attr = GetNextImageAttribute(image))) {
			char name_text[256];
			VipsBuf name = VIPS_BUF_STATIC(name_text);

			vips_buf_appendf(&name, "magick-%s", attr->key);
			vips_image_set_string(out, vips_buf_all(&name), attr->value);
		}
	}
#else
	{
		const ImageAttribute *attr;

		/* GraphicsMagick is missing the iterator: we have to loop ourselves.
		 * ->attributes is marked as private in the header, but there's no
		 * getter so we have to access it directly.
		 */
		for (attr = image->attributes; attr; attr = attr->next) {
			char name_text[256];
			VipsBuf name = VIPS_BUF_STATIC(name_text);

			vips_buf_appendf(&name, "magick-%s", attr->key);
			vips_image_set_string(out, vips_buf_all(&name), attr->value);
		}
	}
#endif

	/* Set vips metadata from ImageMagick profiles.
	 */
	if (magick_set_vips_profile(out, image))
		return -1;

	/* Something like "BMP".
	 */
	if (strlen(magick->image->magick) > 0)
		vips_image_set_string(out, "magick-format",
			magick->image->magick);

	magick->n_pages = GetImageListLength(image);
#ifdef DEBUG
	printf("image has %d pages\n", magick->n_pages);
#endif /*DEBUG*/

	/* Do we have a set of equal-sized frames? Append them.

		FIXME ... there must be an attribute somewhere from dicom read
		which says this is a volumetric image

	 */
	magick->n_frames = 0;

	for (p = image; p; (p = GetNextImageInList(p))) {
		int p_depth =
			GetImageChannelDepth(p, AllChannels, &p->exception);

		if (p->columns != (unsigned int) out->Xsize ||
			p->rows != (unsigned int) out->Ysize ||
			magick_get_bands(p) != out->Bands ||
			p_depth != depth) {
#ifdef DEBUG
			printf("frame %d differs\n", read->n_frames);
			printf("%zdx%zd, %d bands\n",
				p->columns, p->rows, get_bands(p));
			printf("first frame is %dx%d, %d bands\n",
				im->Xsize, im->Ysize, im->Bands);
#endif /*DEBUG*/

			break;
		}

		magick->n_frames += 1;
	}
	if (p)
		/* Nope ... just do the first image in the list.
		 */
		magick->n_frames = 1;

#ifdef DEBUG
	printf("will read %d frames\n", magick->n_frames);
#endif /*DEBUG*/

	if (magick->n != -1)
		magick->n_frames = VIPS_MIN(magick->n_frames, magick->n);

	/* So we can finally set the height.
	 */
	if (magick->n_frames > 1) {
		vips_image_set_int(out, VIPS_META_PAGE_HEIGHT, out->Ysize);
		out->Ysize *= magick->n_frames;
	}

	vips_image_set_int(out, VIPS_META_N_PAGES, magick->n_pages);

	vips_image_set_int(out, VIPS_META_ORIENTATION,
		VIPS_CLIP(1, image->orientation, 8));

	vips_image_set_int(out, VIPS_META_BITS_PER_SAMPLE, depth);

	return 0;
}

/* Divide by this to get 0 - MAX from a Quantum. Eg. consider QuantumRange ==
 * 65535, MAX == 255 (a Q16 ImageMagic representing an 8-bit image). Make sure
 * this can't be zero (if QuantumRange < MAX) .. can happen if we have a Q8
 * ImageMagick trying to represent a 16-bit image.
 */
#define SCALE(MAX) \
	(QuantumRange < (MAX) \
			? 1 \
			: ((QuantumRange + 1) / ((MAX) + 1)))

#define GRAY_LOOP(TYPE, MAX) \
	{ \
		TYPE *q = (TYPE *) q8; \
\
		for (x = 0; x < n; x++) \
			q[x] = pixels[x].green / SCALE(MAX); \
	}

#define GRAYA_LOOP(TYPE, MAX) \
	{ \
		TYPE *q = (TYPE *) q8; \
\
		for (x = 0; x < n; x++) { \
			q[0] = pixels[x].green / SCALE(MAX); \
			q[1] = MAX - pixels[x].opacity / SCALE(MAX); \
\
			q += 2; \
		} \
	}

#define RGB_LOOP(TYPE, MAX) \
	{ \
		TYPE *q = (TYPE *) q8; \
\
		for (x = 0; x < n; x++) { \
			q[0] = pixels[x].red / SCALE(MAX); \
			q[1] = pixels[x].green / SCALE(MAX); \
			q[2] = pixels[x].blue / SCALE(MAX); \
\
			q += 3; \
		} \
	}

#define RGBA_LOOP(TYPE, MAX) \
	{ \
		TYPE *q = (TYPE *) q8; \
\
		for (x = 0; x < n; x++) { \
			q[0] = pixels[x].red / SCALE(MAX); \
			q[1] = pixels[x].green / SCALE(MAX); \
			q[2] = pixels[x].blue / SCALE(MAX); \
			q[3] = MAX - pixels[x].opacity / SCALE(MAX); \
\
			q += 4; \
		} \
	}

static void
unpack_pixels(VipsImage *im, VipsPel *q8, PixelPacket *pixels, int n)
{
	int x;

	switch (im->Bands) {
	case 1:
		/* Gray.
		 */
		switch (im->BandFmt) {
		case VIPS_FORMAT_UCHAR:
			GRAY_LOOP(unsigned char, 255);
			break;
		case VIPS_FORMAT_USHORT:
			GRAY_LOOP(unsigned short, 65535);
			break;
		case VIPS_FORMAT_UINT:
			GRAY_LOOP(unsigned int, 4294967295UL);
			break;
		case VIPS_FORMAT_DOUBLE:
			GRAY_LOOP(double, QuantumRange);
			break;

		default:
			g_assert_not_reached();
		}
		break;

	case 2:
		/* Gray plus alpha.
		 */
		switch (im->BandFmt) {
		case VIPS_FORMAT_UCHAR:
			GRAYA_LOOP(unsigned char, 255);
			break;
		case VIPS_FORMAT_USHORT:
			GRAYA_LOOP(unsigned short, 65535);
			break;
		case VIPS_FORMAT_UINT:
			GRAYA_LOOP(unsigned int, 4294967295UL);
			break;
		case VIPS_FORMAT_DOUBLE:
			GRAYA_LOOP(double, QuantumRange);
			break;

		default:
			g_assert_not_reached();
		}
		break;

	case 3:
		/* RGB.
		 */
		switch (im->BandFmt) {
		case VIPS_FORMAT_UCHAR:
			RGB_LOOP(unsigned char, 255);
			break;
		case VIPS_FORMAT_USHORT:
			RGB_LOOP(unsigned short, 65535);
			break;
		case VIPS_FORMAT_UINT:
			RGB_LOOP(unsigned int, 4294967295UL);
			break;
		case VIPS_FORMAT_DOUBLE:
			RGB_LOOP(double, QuantumRange);
			break;

		default:
			g_assert_not_reached();
		}
		break;

	case 4:
		/* RGBA or CMYK.
		 */
		switch (im->BandFmt) {
		case VIPS_FORMAT_UCHAR:
			RGBA_LOOP(unsigned char, 255);
			break;
		case VIPS_FORMAT_USHORT:
			RGBA_LOOP(unsigned short, 65535);
			break;
		case VIPS_FORMAT_UINT:
			RGBA_LOOP(unsigned int, 4294967295UL);
			break;
		case VIPS_FORMAT_DOUBLE:
			RGBA_LOOP(double, QuantumRange);
			break;

		default:
			g_assert_not_reached();
		}
		break;

	default:
		g_assert_not_reached();
	}
}

static PixelPacket *
get_pixels(Image *image, int left, int top, int width, int height)
{
	PixelPacket *pixels;

#ifdef HAVE_GETVIRTUALPIXELS
	if (!(pixels = (PixelPacket *) GetVirtualPixels(image,
			  left, top, width, height, &image->exception)))
#else
	if (!(pixels = GetImagePixels(image, left, top, width, height)))
#endif
		return NULL;

		/* Can't happen if red/green/blue are doubles.
		 */
#ifndef UseHDRI
	/* Unpack palette.
	 */
	if (image->storage_class == PseudoClass) {
#ifdef HAVE_GETVIRTUALPIXELS
		IndexPacket *indexes = (IndexPacket *)
			GetVirtualIndexQueue(image);
#else
		/* Was GetIndexes(), but that's now deprecated.
		 */
		IndexPacket *indexes = AccessMutableIndexes(image);
#endif

		int i;

		for (i = 0; i < width * height; i++) {
			IndexPacket x = indexes[i];

			if (x < image->colors) {
				pixels[i].red = image->colormap[x].red;
				pixels[i].green = image->colormap[x].green;
				pixels[i].blue = image->colormap[x].blue;
			}
		}
	}
#endif /*UseHDRI*/

	return pixels;
}

static int
vips_foreign_load_magick_fill_region(VipsRegion *out_region,
	void *seq, void *a, void *b, gboolean *stop)
{
	VipsForeignLoadMagick *magick = (VipsForeignLoadMagick *) a;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(magick);
	VipsRect *r = &out_region->valid;
	VipsImage *im = out_region->im;

	int y;

	for (y = 0; y < r->height; y++) {
		int top = r->top + y;
		int frame = top / magick->frame_height;
		int line = top % magick->frame_height;

		PixelPacket *pixels;

		vips__worker_lock(&magick->lock);

		pixels = get_pixels(magick->frames[frame], r->left, line, r->width, 1);

		g_mutex_unlock(&magick->lock);

		if (!pixels) {
			vips_foreign_load_invalidate(im);
			vips_error(class->nickname, "%s", _("unable to read pixels"));
			return -1;
		}

		unpack_pixels(im, VIPS_REGION_ADDR(out_region, r->left, top),
			pixels, r->width);
	}

	return 0;
}

static int
vips_foreign_load_magick_load(VipsForeignLoadMagick *magick)
{
	VipsForeignLoad *load = (VipsForeignLoad *) magick;

	Image *p;

#ifdef DEBUG
	printf("vips_foreign_load_magick_load: %p\n", magick);
#endif /*DEBUG*/

	if (vips_foreign_load_magick_parse(magick, magick->image, load->out))
		return -1;

	/* Record frame pointers.
	 */
	g_assert(!magick->frames);
	if (!(magick->frames = VIPS_ARRAY(NULL, magick->n_frames, Image *)))
		return -1;
	p = magick->image;
	for (int i = 0; i < magick->n_frames; i++) {
		magick->frames[i] = p;
		p = GetNextImageInList(p);
	}

	if (vips_image_generate(load->out,
			NULL, vips_foreign_load_magick_fill_region, NULL,
			magick, NULL))
		return -1;

	return 0;
}

typedef struct _VipsForeignLoadMagickFile {
	VipsForeignLoadMagick parent_object;

	char *filename;

} VipsForeignLoadMagickFile;

typedef VipsForeignLoadMagickClass VipsForeignLoadMagickFileClass;

G_DEFINE_TYPE(VipsForeignLoadMagickFile, vips_foreign_load_magick_file,
	vips_foreign_load_magick_get_type());

static gboolean
ismagick(const char *filename)
{
	/* Fetch up to the first 100 bytes. Hopefully that'll be enough.
	 */
	unsigned char buf[100];
	int len;

	return (len = vips__get_bytes(filename, buf, 100)) > 10 &&
		magick_ismagick(buf, len);
}

/* Unfortunately, libMagick does not support header-only reads very well. See
 *
 * http://www.imagemagick.org/discourse-server/viewtopic.php?f=1&t=20017
 *
 * Test especially with BMP, GIF, TGA. So we are forced to read the entire
 * image in the @header() method.
 */
static int
vips_foreign_load_magick_file_header(VipsForeignLoad *load)
{
	VipsForeignLoadMagick *magick = (VipsForeignLoadMagick *) load;
	VipsForeignLoadMagickFile *file = (VipsForeignLoadMagickFile *) load;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(magick);

#ifdef DEBUG
	printf("vips_foreign_load_magick_file_header: %p\n", load);
#endif /*DEBUG*/

	g_strlcpy(magick->image_info->filename, file->filename,
		MaxTextExtent);

	magick_sniff_file(magick->image_info, file->filename);

	magick->image = ReadImage(magick->image_info, magick->exception);
	if (!magick->image) {
		magick_vips_error(class->nickname, magick->exception);
		vips_error(class->nickname,
			_("unable to read file \"%s\""), file->filename);
		return -1;
	}

	if (vips_foreign_load_magick_load(magick))
		return -1;

	VIPS_SETSTR(load->out->filename, file->filename);

	return 0;
}

static void
vips_foreign_load_magick_file_class_init(
	VipsForeignLoadMagickFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload";
	object_class->description = _("load file with ImageMagick");

	load_class->is_a = ismagick;
	load_class->header = vips_foreign_load_magick_file_header;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadMagickFile, filename),
		NULL);
}

static void
vips_foreign_load_magick_file_init(VipsForeignLoadMagickFile *magick_file)
{
}

typedef struct _VipsForeignLoadMagickBuffer {
	VipsForeignLoadMagick parent_object;

	VipsArea *buf;

} VipsForeignLoadMagickBuffer;

typedef VipsForeignLoadMagickClass VipsForeignLoadMagickBufferClass;

G_DEFINE_TYPE(VipsForeignLoadMagickBuffer, vips_foreign_load_magick_buffer,
	vips_foreign_load_magick_get_type());

static gboolean
vips_foreign_load_magick_buffer_is_a_buffer(const void *buf, size_t len)
{
	return len > 10 && magick_ismagick((const unsigned char *) buf, len);
}

/* Unfortunately, libMagick does not support header-only reads very well. See
 *
 * http://www.imagemagick.org/discourse-server/viewtopic.php?f=1&t=20017
 *
 * Test especially with BMP, GIF, TGA. So we are forced to read the entire
 * image in the @header() method.
 */
static int
vips_foreign_load_magick_buffer_header(VipsForeignLoad *load)
{
	VipsForeignLoadMagick *magick = (VipsForeignLoadMagick *) load;
	VipsForeignLoadMagickBuffer *magick_buffer =
		(VipsForeignLoadMagickBuffer *) load;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(magick);

#ifdef DEBUG
	printf("vips_foreign_load_magick_buffer_header: %p\n", load);
#endif /*DEBUG*/

	/* It would be great if we could PingImage and just read the header,
	 * but sadly many IM coders do not support ping. The critical one for
	 * us is DICOM. TGA also has issues.
	 */
	magick_sniff_bytes(magick->image_info,
		magick_buffer->buf->data, magick_buffer->buf->length);
	magick->image = BlobToImage(magick->image_info,
		magick_buffer->buf->data, magick_buffer->buf->length,
		magick->exception);
	if (!magick->image) {
		magick_vips_error(class->nickname, magick->exception);
		vips_error(class->nickname, _("unable to read buffer"));
		return -1;
	}

	if (vips_foreign_load_magick_load(magick))
		return -1;

	return 0;
}

static void
vips_foreign_load_magick_buffer_class_init(
	VipsForeignLoadMagickBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload_buffer";
	object_class->description = _("load buffer with ImageMagick");

	load_class->is_a_buffer = vips_foreign_load_magick_buffer_is_a_buffer;
	load_class->header = vips_foreign_load_magick_buffer_header;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to load from"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignLoadMagickBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_load_magick_buffer_init(VipsForeignLoadMagickBuffer *buffer)
{
}

#endif /*HAVE_MAGICK6*/

#endif /*ENABLE_MAGICKLOAD*/
