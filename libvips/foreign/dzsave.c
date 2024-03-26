/* save to deep zoom format
 *
 * 21/3/12
 *	- from the tiff pyramid writer
 * 5/7/12 (thanks Alexander Koshman)
 *	- make tiles down to 1x1 pixels
 *	- oop make right-hand edge tiles
 *	- improve overlap handling
 * 7/7/12
 *	- threaded write
 * 6/8/12 (thanks to Benjamin Gilbert for pointing out the errors)
 *	- shrink down to a 1x1 pixel tile, even for very long and thin images
 *	- round image size up on shrink
 *	- write a .dzi file with the pyramid params
 *	- default tile size and overlap now matches the openslide writer
 * 7/8/12 (thanks to Benjamin Gilbert again for more testing)
 *	- reorganise the directory structure
 *	- rename to basename and tile_size
 *	- deprecate tile_width/_height and dirname
 * 1/10/12
 *	- did not write low pyramid levels for images with an odd number of
 *	  scan lines (thanks Martin)
 * 2/10/12
 *	- remove filename options from format string in .dzi (thanks Martin)
 * 3/10/12
 *	- add zoomify and google maps output
 * 10/10/12
 *	- add @background option
 * 1/11/12
 *	- add @depth option
 * 21/1/13
 *	- add @centre option
 * 26/2/13
 *	- fix another corner case, thanks Martin
 * 29/5/13
 *	- add --angle option
 * 19/6/13
 *	- faster --centre logic, thanks Kacey
 * 18/4/14
 *	- use libgsf for output so we can write to .zip etc. as well as the
 *	  filesystem
 * 8/5/14
 *	- set Type on strips so we can convert for save correctly, thanks
 *	  philipgiuliani
 * 25/6/14
 *	- stop on zip write >4gb, thanks bgilbert
 *	- save metadata, see https://github.com/libvips/libvips/issues/137
 * 18/8/14
 *	- use g_ date funcs, helps Windows
 * 14/2/15
 *	- use vips_region_shrink()
 * 22/2/15
 *	- use a better temp dir name for fs dz output
 * 8/8/15
 *	- allow zip > 4gb if we have a recent libgsf
 * 9/9/15
 *	- better overlap handling, thanks robclouth
 * 24/11/15
 *	- don't write almost blank tiles in google mode
 * 25/11/15
 *	- always strip tile metadata
 * 16/12/15
 *	- fix overlap handling again, thanks erdmann
 * 8/6/16 Felix Bünemann
 *	- add @compression option
 * 5/9/16
 *	- more overlap changes to help gmaps mode
 * 8/9/16 Felix Bünemann
 *	- move vips-properties out of subdir for gm and zoomify layouts
 * 15/10/16
 *	- add dzsave_buffer
 * 11/11/16 Felix Bünemann
 *	- better >4gb detection for zip output on older libgsfs
 * 18/8/17
 *	- shut down the output earlier to flush zip output
 * 24/11/17
 *	- output overlap-only tiles on edges for better deepzoom spec
 *	  compliance
 * 6/1/18
 *	- add scan-properties.xml for szi output
 *	- write all associated images
 * 19/12/18
 *	- add @skip_blanks
 * 21/10/19
 *	- add @no_strip
 * 9/11/19
 *	- add IIIF layout
 * 24/4/20 [IllyaMoskvin]
 *	- better IIIF tile naming
 * 15/10/21  martimpassos
 *	- add IIIF3 layout
 * 21/12/21  whalehub
 *	- remove trailing comma from IIIFv3 folder names
 * 29/3/22
 *	- always write a properties file
 *	- add .szi as a registered suffix
 * 9/5/22
 *	- add dzsave_target
 * 8/9/23
 *	- add direct mode
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

   This is difficult to test, there are so many options.

   It's failed in the past in these cases. These have levels with strips which
   exactly align with image edges, or which have orphan scanlines which need
   adding for the shrink.

	1.	$ header test.v
		test.v: 14016x16448 uchar, 3 bands, srgb, openin VipsImage (0x11e7060)
		$ time vips dzsave test.v x --overlap 0

		Not all levels written.

	2.	$ header ~/Desktop/leicaimage.scn
		/home/john/Desktop/leicaimage.scn: 4225x7905 uchar, 4 bands, rgb

		Not all levels written.

	3.	$ header ~/leicatest1.scn
		/home/john/leicatest1.scn: 11585x8449 uchar, 4 bands, rgb

		Not all levels written.

	various combinations of odd and even tile-size and overlap need testing too.

	Overlap handling

	For deepzoom, tile-size == 254 and overlap == 1 means that edge tiles are
	255 x 255 (though less at the bottom right) and non-edge tiles are 256 x
	256. Tiles are positioned across the image in tile-size steps. This means
	(confusingly) that two adjoining tiles will have two pixels in common.

	This has caused bugs in the past.

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
#include <errno.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_LIBARCHIVE

typedef struct _VipsForeignSaveDz VipsForeignSaveDz;
typedef struct _Level Level;

/* A level in the pyramid.
 */
struct _Level {
	VipsForeignSaveDz *dz;

	/* The size of this image in pixels. @image can be a bit bigger since it
	 * gets padded up to an even size.
	 */
	int width;
	int height;

	/* Number of tiles across and down in width/height. Zoomify needs this
	 * to calculate the directory to put each tile in.
	 */
	int tiles_across;
	int tiles_down;

	/* The rect we save. It can be a lot smaller than @image, and
	 * not at (0, 0), if we're skipping blank tiles.
	 */
	VipsRect save_area;

	/* The image for this level. Might be bigger than width/height since it's
	 * always rounded up to even.
	 */
	VipsImage *image;

	/* The top of this strip of tiles.
	 */
	int y;

	/* The next line we write to in this strip.
	 */
	int write_y;

	VipsRegion *strip; /* The current strip of pixels */
	VipsRegion *copy;  /* Pixels we copy to the next strip */

	int sub; /* Subsample factor for this level */
	int n;	 /* Level number ... 0 for smallest */

	Level *below; /* Tiles go to here */
	Level *above; /* Tiles come from here */
};

struct _VipsForeignSaveDz {
	VipsForeignSave parent_object;

	/* The target we are writing to. This is set by our subclasses.
	 */
	VipsTarget *target;

	/* Alternatively, the filename, for filesystem output.
	 */
	char *filename;

	char *suffix;
	int overlap;
	int tile_size;
	VipsForeignDzLayout layout;
	VipsForeignDzDepth depth;
	gboolean centre;
	gboolean properties;
	VipsAngle angle;
	VipsForeignDzContainer container;
	int compression;
	VipsRegionShrink region_shrink;
	int skip_blanks;
	gboolean no_strip;
	char *id;
	int Q;

	/* In direct save mode, we write regions of pixels to the output and
	 * avoid creating a pipeline for each tile. This must be disabled if
	 * --suffix has been used.
	 */
	gboolean direct;

	/* Tile and overlap geometry. The members above are the parameters we
	 * accept, this next set are the derived values which are actually
	 * used in pyramid generation.
	 *
	 * Tiles have a base tile_size. Imagine a square placed at the top left.
	 * This is the size of that square.
	 *
	 * Tiles have a margin. The square from tile_size is expanded outward
	 * up/down/left/right by this amount. Parts going off the image are
	 * clipped.
	 *
	 * Each time we write a new tile, we step the position by tile_step
	 * pixels.
	 *
	 * We need all three of tile_size, tile_margin and tile_step since
	 * deepzoom and google maps have different meanings for overlap and we
	 * want to be able to support both models.
	 *
	 * For deepzoom:
	 *
	 *	tile_margin = overlap
	 *	tile_step = tile_size
	 *
	 * For google maps:
	 *
	 *	tile_margin = 0
	 *	tile_step = tile_size - overlap
	 */
	int tile_margin;
	int tile_step;

	Level *level; /* x2 shrink pyr level */

	/* Count zoomify tiles we write.
	 */
	int tile_count;

	/* Where we write ... can be the filesystem, or a zip.
	 */
	VipsArchive *archive;

	/* The name to save as, eg. deepzoom tiles go into ${imagename}_files.
	 * No suffix, no path at the start.
	 */
	char *imagename;

	/* The directory we write the output to.
	 */
	char *dirname;

	/* The name of the directory containing the levels ... eg. perhaps
	 * $(imagename)_files, etc.
	 */
	char *root_name;

	/* @suffix, but without any options. So @suffix == ".jpg[Q=90]"
	 * becomes ".jpg".
	 */
	char *file_suffix;

	/* save->background turned into a pixel that matches the image we are
	 * saving .. used to test for blank tiles.
	 */
	VipsPel *ink;
};

typedef VipsForeignSaveClass VipsForeignSaveDzClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignSaveDz, vips_foreign_save_dz,
	VIPS_TYPE_FOREIGN_SAVE);

/* ZIP and SZI are both written as zip files.
 */
static gboolean
iszip(VipsForeignDzContainer container)
{
	switch (container) {
	case VIPS_FOREIGN_DZ_CONTAINER_ZIP:
	case VIPS_FOREIGN_DZ_CONTAINER_SZI:
		return TRUE;

	default:
		return FALSE;
	}
}

static int
write_image(VipsForeignSaveDz *dz,
	VipsImage *image, const char *filename, const char *format)
{
	VipsForeignSave *save = VIPS_FOREIGN_SAVE(dz);
	VipsImage *t;

	/* We need to block progress signalling on individual image write, so
	 * we need a copy of the tile in case it's shared (eg. associated
	 * images).
	 */
	if (vips_copy(image, &t, NULL))
		return -1;

	vips_image_set_int(t, "hide-progress", 1);

	void *buf;
	size_t len;
	if (vips_image_write_to_buffer(t, format, &buf, &len,
			"keep", save->keep,
			NULL)) {
		VIPS_UNREF(t);
		return -1;
	}
	VIPS_UNREF(t);

	if (vips__archive_mkfile(dz->archive, filename, buf, len)) {
		g_free(buf);
		return -1;
	}
	g_free(buf);

	return 0;
}

/* Free a pyramid.
 */
static void
level_free(Level *level)
{
	VIPS_FREEF(g_object_unref, level->strip);
	VIPS_FREEF(g_object_unref, level->copy);
	VIPS_FREEF(g_object_unref, level->image);

	VIPS_FREEF(level_free, level->below);
}

static void
vips_foreign_save_dz_dispose(GObject *gobject)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) gobject;

	VIPS_FREEF(vips__archive_free, dz->archive);
	VIPS_UNREF(dz->target);

	VIPS_FREEF(level_free, dz->level);

	VIPS_FREE(dz->imagename);
	VIPS_FREE(dz->dirname);
	VIPS_FREE(dz->root_name);
	VIPS_FREE(dz->file_suffix);

	G_OBJECT_CLASS(vips_foreign_save_dz_parent_class)->dispose(gobject);
}

/* Build a pyramid.
 *
 * width/height is the size of this level, real_* the subsection of the level
 * which is real pixels (as opposed to background). left/top of save_area
 * can be >0 if we are centring.
 */
static Level *
pyramid_build(VipsForeignSaveDz *dz,
	Level *above, int width, int height, VipsRect *save_area)
{
	VipsForeignSave *save = VIPS_FOREIGN_SAVE(dz);

	Level *level;
	VipsRect strip;
	int limit;

	if (!(level = VIPS_NEW(dz, Level)))
		return NULL;

	level->dz = dz;
	level->width = width;
	level->height = height;

	/* We need to output all possible tiles, even if they give no new
	 * pixels.
	 */
	level->tiles_across = VIPS_ROUND_UP(width, dz->tile_step) / dz->tile_step;
	level->tiles_down = VIPS_ROUND_UP(height, dz->tile_step) / dz->tile_step;
	level->save_area = *save_area;
	level->image = NULL;
	level->strip = NULL;
	level->copy = NULL;

	if (!above)
		/* Top of pyramid.
		 */
		level->sub = 1;
	else
		level->sub = above->sub * 2;

	level->below = NULL;
	level->above = above;

	/* We round the image size up to an even number to make x2 shrink
	 * easy.
	 */
	level->image = vips_image_new();
	if (vips_image_pipelinev(level->image,
			VIPS_DEMAND_STYLE_ANY, save->ready, NULL)) {
		level_free(level);
		return NULL;
	}
	level->image->Xsize = width + (width & 1);
	level->image->Ysize = height + (height & 1);

	level->strip = vips_region_new(level->image);
	level->copy = vips_region_new(level->image);

	/* The regions will get used in the bg thread callback, so make sure
	 * we don't own them.
	 */
	vips__region_no_ownership(level->strip);
	vips__region_no_ownership(level->copy);

	/* Build a line of tiles here.
	 *
	 * Expand the strip if necessary to make sure we have an even
	 * number of lines.
	 *
	 * This is just the height of the first row of tiles, so only add 1*
	 * tile_margin.
	 */
	level->y = 0;
	level->write_y = 0;
	strip.left = 0;
	strip.top = 0;
	strip.width = level->image->Xsize;
	strip.height = dz->tile_size + dz->tile_margin;
	if ((strip.height & 1) == 1)
		strip.height += 1;
	if (vips_region_buffer(level->strip, &strip)) {
		level_free(level);
		return NULL;
	}

	switch (dz->depth) {
	case VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL:
		limit = 1;
		break;

	case VIPS_FOREIGN_DZ_DEPTH_ONETILE:
		limit = dz->tile_size;
		break;

	case VIPS_FOREIGN_DZ_DEPTH_ONE:
		limit = VIPS_MAX(width, height);
		break;

	default:
		g_assert_not_reached();

		/* Stop compiler warnings.
		 */
		limit = 1;
	}

	if (width > limit ||
		height > limit) {
		/* Round up, so eg. a 5 pixel wide image becomes 3 a level
		 * down.
		 */
		VipsRect half;

		half.left = (save_area->left + 1) / 2;
		half.top = (save_area->top + 1) / 2;
		half.width = (save_area->width + 1) / 2;
		half.height = (save_area->height + 1) / 2;
		if (!(level->below = pyramid_build(dz, level,
				  (width + 1) / 2, (height + 1) / 2, &half))) {
			level_free(level);
			return NULL;
		}
		level->n = level->below->n + 1;
	}
	else
		level->n = 0;

#ifdef DEBUG
	printf("pyramid_build:\n");
	printf("\tn = %d\n", level->n);
	printf("\twidth = %d, height = %d\n", width, height);
	printf("\tXsize = %d, Ysize = %d\n",
		level->image->Xsize, level->image->Ysize);
	printf("\ttiles_across = %d, tiles_down = %d\n",
		level->tiles_across, level->tiles_down);
	printf("\tsave_area.left = %d, save_area.top = %d\n",
		save_area->left, save_area->top);
	printf("\tsave_area.width = %d, save_area.height = %d\n",
		save_area->width, save_area->height);
#endif /*DEBUG*/

	return level;
}

static int
write_dzi(VipsForeignSaveDz *dz)
{
	VipsDbuf dbuf;
	char filename[VIPS_PATH_MAX];
	char format[VIPS_PATH_MAX];
	char *p;
	void *buf;
	size_t len;

	vips_snprintf(filename, VIPS_PATH_MAX, "%s.dzi", dz->imagename);

	vips_dbuf_init(&dbuf);

	vips_snprintf(format, VIPS_PATH_MAX, "%s", dz->suffix + 1);
	if ((p = (char *) vips__find_rightmost_brackets(format)))
		*p = '\0';

	vips_dbuf_writef(&dbuf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	vips_dbuf_writef(&dbuf, "<Image xmlns=\""
							"http://schemas.microsoft.com/deepzoom/2008"
							"\"\n");
	vips_dbuf_writef(&dbuf, "  Format=\"%s\"\n", format);
	vips_dbuf_writef(&dbuf, "  Overlap=\"%d\"\n", dz->overlap);
	vips_dbuf_writef(&dbuf, "  TileSize=\"%d\"\n", dz->tile_size);
	vips_dbuf_writef(&dbuf, "  >\n");
	vips_dbuf_writef(&dbuf, "  <Size \n");
	vips_dbuf_writef(&dbuf, "    Height=\"%d\"\n", dz->level->height);
	vips_dbuf_writef(&dbuf, "    Width=\"%d\"\n", dz->level->width);
	vips_dbuf_writef(&dbuf, "  />\n");
	vips_dbuf_writef(&dbuf, "</Image>\n");

	if ((buf = vips_dbuf_steal(&dbuf, &len))) {
		if (vips__archive_mkfile(dz->archive, filename, buf, len)) {
			g_free(buf);
			return -1;
		}

		g_free(buf);
	}

	return 0;
}

static int
write_properties(VipsForeignSaveDz *dz)
{
	VipsDbuf dbuf;
	char *filename;
	void *buf;
	size_t len;

	filename = g_build_filename(dz->root_name, "ImageProperties.xml", NULL);

	vips_dbuf_init(&dbuf);

	vips_dbuf_writef(&dbuf, "<IMAGE_PROPERTIES "
							"WIDTH=\"%d\" HEIGHT=\"%d\" NUMTILES=\"%d\" "
							"NUMIMAGES=\"1\" VERSION=\"1.8\" "
							"TILESIZE=\"%d\" />\n",
		dz->level->width,
		dz->level->height,
		dz->tile_count,
		dz->tile_size);

	if ((buf = vips_dbuf_steal(&dbuf, &len))) {
		if (vips__archive_mkfile(dz->archive, filename, buf, len)) {
			g_free(buf);
			g_free(filename);
			return -1;
		}

		g_free(buf);
	}

	g_free(filename);

	return 0;
}

static int
write_blank(VipsForeignSaveDz *dz)
{
	VipsForeignSave *save = (VipsForeignSave *) dz;

	VipsImage *x, *t;
	int n;
	VipsArea *ones;
	double *d;
	double *bg;
	int i;
	char *filename;

	/* Number of bands we will end up making. We need to set this in
	 * vips_black() to make sure we set Type correctly, otherwise we can
	 * try saving a B_W image as PNG, with disastrous results.
	 */
	bg = (double *) vips_area_get_data(VIPS_AREA(save->background),
		NULL, &n, NULL, NULL);

	if (vips_black(&x, dz->tile_size, dz->tile_size, "bands", n, NULL))
		return -1;

	ones = vips_area_new_array(G_TYPE_DOUBLE, sizeof(double), n);
	d = (double *) vips_area_get_data(ones, NULL, NULL, NULL, NULL);
	for (i = 0; i < n; i++)
		d[i] = 1.0;

	if (vips_linear(x, &t, d, bg, n, NULL)) {
		vips_area_unref(ones);
		g_object_unref(x);
		return -1;
	}
	vips_area_unref(ones);
	g_object_unref(x);
	x = t;

	filename = g_build_filename(dz->root_name, "blank.png", NULL);

	if (write_image(dz, x, filename, ".png")) {
		g_free(filename);
		g_object_unref(x);

		return -1;
	}

	g_free(filename);
	g_object_unref(x);

	return 0;
}

/* Write IIIF/IIF3 JSON metadata.
 */
static int
write_json(VipsForeignSaveDz *dz)
{
	/* dz->file_suffix has a leading "." character.
	 */
	const char *suffix = dz->file_suffix[0] == '.'
		? dz->file_suffix + 1
		: dz->file_suffix;

	VipsDbuf dbuf;
	char *filename;
	void *buf;
	size_t len;
	int i;

	filename = g_build_filename(dz->root_name, "info.json", NULL);

	vips_dbuf_init(&dbuf);

	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_IIIF3)
		vips_dbuf_writef(&dbuf,
			"{\n"
			"  \"@context\": "
			"\"http://iiif.io/api/image/3/context.json\",\n"
			"  \"id\": \"%s/%s\",\n"
			"  \"type\": \"ImageService3\",\n"
			"  \"profile\": \"level0\",\n"
			"  \"protocol\": \"http://iiif.io/api/image\",\n",
			dz->id ? dz->id : "https://example.com/iiif",
			dz->imagename);
	else
		vips_dbuf_writef(&dbuf,
			"{\n"
			"  \"@context\": "
			"\"http://iiif.io/api/image/2/context.json\",\n"
			"  \"@id\": \"%s/%s\",\n"
			"  \"profile\": [\n"
			"    \"http://iiif.io/api/image/2/level0.json\",\n"
			"    {\n"
			"      \"formats\": [\n"
			"        \"%s\"\n"
			"      ],\n"
			"      \"qualities\": [\n"
			"        \"default\"\n"
			"      ]\n"
			"    }\n"
			"  ],\n"
			"  \"protocol\": \"http://iiif.io/api/image\",\n",
			dz->id ? dz->id : "https://example.com/iiif",
			dz->imagename,
			suffix);

	/* "sizes" is needed for the full/ set of untiled images, which we
	 * don't yet support. Leave this commented out for now.

	vips_dbuf_writef(&dbuf,
		"  \"sizes\": [\n");

	for (i = 0; i < dz->level->n + 5; i++) {
		vips_dbuf_writef(&dbuf,
			"    {\n"
			"      \"width\": %d,\n"
			"      \"height\": \"full\"\n"
			"    }",
				1 << (i + 4));
		if (i != dz->level->n - 4)
			vips_dbuf_writef(&dbuf, ",");
		vips_dbuf_writef(&dbuf, "\n");
	}

	vips_dbuf_writef(&dbuf,
		"  ],\n");

	 */

	/* The set of pyramid levels we have written.
	 */
	vips_dbuf_writef(&dbuf,
		"  \"tiles\": [\n"
		"    {\n"
		"      \"scaleFactors\": [\n");

	for (i = 0; i < dz->level->n; i++) {
		vips_dbuf_writef(&dbuf,
			"        %d",
			1 << i);
		if (i != dz->level->n - 1)
			vips_dbuf_writef(&dbuf, ",");
		vips_dbuf_writef(&dbuf, "\n");
	}

	vips_dbuf_writef(&dbuf,
		"      ],\n"
		"      \"width\": %d\n"
		"    }\n"
		"  ],\n",
		dz->tile_size);

	vips_dbuf_writef(&dbuf,
		"  \"width\": %d,\n"
		"  \"height\": %d\n",
		dz->level->width,
		dz->level->height);

	vips_dbuf_writef(&dbuf,
		"}\n");

	if ((buf = vips_dbuf_steal(&dbuf, &len))) {
		if (vips__archive_mkfile(dz->archive, filename, buf, len)) {
			g_free(filename);
			g_free(buf);
			return -1;
		}

		g_free(buf);
	}

	g_free(filename);

	return 0;
}

static int
write_vips_meta(VipsForeignSaveDz *dz)
{
	VipsForeignSave *save = (VipsForeignSave *) dz;

	char *filename;
	char *dump;

	/* For deepzoom the props must go inside the ${name}_files subdir, for
	 * gm and zoomify it can sit in the main folder.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_DZ)
		filename = g_build_filename(dz->root_name, "vips-properties.xml", NULL);
	else
		filename = g_strdup("vips-properties.xml");

	if (filename == NULL)
		return -1;

	if (!(dump = vips__xml_properties(save->ready))) {
		g_free(filename);
		return -1;
	}

	if (vips__archive_mkfile(dz->archive, filename, dump, strlen(dump))) {
		g_free(filename);
		g_free(dump);
		return -1;
	}

	g_free(filename);
	g_free(dump);

	return 0;
}

static void
build_scan_property(VipsDbuf *dbuf, VipsImage *image,
	const char *vips_name, const char *szi_name)
{
	char *str;
	GValue value = G_VALUE_INIT;
	GValue save_value = G_VALUE_INIT;
	GType type;

	if (!vips_image_get_typeof(image, vips_name))
		return;

	if (vips_image_get(image, vips_name, &value))
		return;
	type = G_VALUE_TYPE(&value);

	if (!g_value_type_transformable(type, VIPS_TYPE_SAVE_STRING)) {
		g_value_unset(&value);
		return;
	}

	g_value_init(&save_value, VIPS_TYPE_SAVE_STRING);
	if (!g_value_transform(&value, &save_value)) {
		g_value_unset(&value);
		return;
	}
	g_value_unset(&value);

	if (!(str = g_utf8_make_valid(
			  vips_value_get_save_string(&save_value), -1))) {
		g_value_unset(&save_value);
		return;
	}

	vips_dbuf_writef(dbuf, "    <property>\n");
	vips_dbuf_writef(dbuf, "      <name>");
	vips_dbuf_write_amp(dbuf, szi_name);
	vips_dbuf_writef(dbuf, "</name>\n");
	vips_dbuf_writef(dbuf, "      <value type=\"%s\">",
		g_type_name(type));
	vips_dbuf_write_amp(dbuf, str);
	vips_dbuf_writef(dbuf, "</value>\n");
	vips_dbuf_writef(dbuf, "    </property>\n");

	g_free(str);

	g_value_unset(&save_value);
}

static char *scan_property_names[][2] = {
	{ "openslide.vendor", "Vendor" },
	{ "openslide.objective-power", "ObjectiveMagnification" },
	{ "openslide.mpp-x", "MicronsPerPixelX" },
	{ "openslide.mpp-y", "MicronsPerPixelY" },
	{ "width", "ImageWidth" },
	{ "height", "ImageHeight" }
};

/* Make the xml we write to scan-properties.xml in szi write.
 * Free with g_free().
 */
static char *
build_scan_properties(VipsImage *image, size_t *len)
{
	VipsDbuf dbuf;
	char *date;
	int i;

	date = vips__get_iso8601();

	vips_dbuf_init(&dbuf);
	vips_dbuf_writef(&dbuf, "<?xml version=\"1.0\"?>\n");
	vips_dbuf_writef(&dbuf,
		"<image xmlns=\"http://www.pathozoom.com/szi\""
		" date=\"%s\" version=\"1.0\">\n",
		date);
	vips_dbuf_writef(&dbuf, "  <properties>\n");

	g_free(date);

	for (i = 0; i < VIPS_NUMBER(scan_property_names); i++)
		build_scan_property(&dbuf, image,
			scan_property_names[i][0],
			scan_property_names[i][1]);

	vips_dbuf_writef(&dbuf, "  </properties>\n");
	vips_dbuf_writef(&dbuf, "</image>\n");

	return (char *) vips_dbuf_steal(&dbuf, len);
}

static int
write_scan_properties(VipsForeignSaveDz *dz)
{
	VipsForeignSave *save = (VipsForeignSave *) dz;

	char *dump;
	size_t len;

	if (!(dump = build_scan_properties(save->ready, &len)))
		return -1;

	if (vips__archive_mkfile(dz->archive, "scan-properties.xml", dump, len)) {
		g_free(dump);
		return -1;
	}

	g_free(dump);

	return 0;
}

static void *
write_associated_images(VipsImage *image,
	const char *field, GValue *value, void *a)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) a;

	if (vips_isprefix("openslide.associated.", field)) {
		VipsImage *associated;
		const char *p;
		const char *q;
		char *out;
		char buf[VIPS_PATH_MAX];

		p = field + strlen("openslide.associated.");

		/* Make sure there are no '/' in the filename.
		 */
		if ((q = strrchr(p, '/')))
			p = q + 1;

		if (vips_image_get_image(image, field, &associated))
			return image;

		if (vips__archive_mkdir(dz->archive, "associated_images"))
			return image;

		vips_snprintf(buf, VIPS_PATH_MAX, "%s.jpg", p);

		out = g_build_filename("associated_images", buf, NULL);

		if (write_image(dz, associated, out, ".jpg")) {
			g_free(out);
			g_object_unref(associated);

			return image;
		}

		g_free(out);
		g_object_unref(associated);
	}

	return NULL;
}

static int
write_associated(VipsForeignSaveDz *dz)
{
	VipsForeignSave *save = (VipsForeignSave *) dz;

	if (vips_image_map(save->ready, write_associated_images, dz))
		return -1;

	return 0;
}

/* Our state during a threaded write of a strip using the image API.
 */
typedef struct _Strip {
	Level *level;

	VipsImage *image;

	/* Allocate the next tile on this boundary.
	 */
	int x;
} ImageStrip;

static void
image_strip_free(ImageStrip *strip)
{
	g_object_unref(strip->image);
}

static void
image_strip_init(ImageStrip *strip, Level *level)
{
	VipsForeignSaveDz *dz = level->dz;

	VipsRect line, image;

	strip->level = level;
	strip->image = NULL;
	strip->x = 0;

	/* The image we wrap around our pixel buffer must be the full width,
	 * including any rounding up, since we must have contiguous pixels.
	 * We can trim the height down though.
	 *
	 * When we loop across the strip writing tiles we have to look out for
	 * the smaller width.
	 */
	image.left = 0;
	image.top = 0;
	image.width = level->image->Xsize;
	image.height = level->height;

	line.left = 0;
	line.top = level->y;
	line.width = image.width;
	line.height = dz->tile_size;
	vips_rect_marginadjust(&line, dz->tile_margin);

	vips_rect_intersectrect(&image, &line, &line);

	if (!(strip->image = vips_image_new_from_memory(
			  VIPS_REGION_ADDR(level->strip, 0, line.top),
			  VIPS_IMAGE_SIZEOF_LINE(level->image) * line.height,
			  line.width, line.height,
			  level->image->Bands, level->image->BandFmt))) {
		image_strip_free(strip);
		return;
	}

	/* The strip needs to inherit the level's metadata.
	 */
	if (vips__image_meta_copy(strip->image, level->image)) {
		image_strip_free(strip);
		return;
	}

	/* Type needs to be set so we know how to convert for save correctly.
	 */
	strip->image->Type = level->image->Type;
}

static int
image_strip_allocate(VipsThreadState *state, void *a, gboolean *stop)
{
	ImageStrip *strip = (ImageStrip *) a;
	Level *level = strip->level;
	VipsForeignSaveDz *dz = level->dz;

	VipsRect image;

#ifdef DEBUG_VERBOSE
	printf("image_strip_allocate\n");
#endif /*DEBUG_VERBOSE*/

	/* We can't test for allocated area empty, since it might just have
	 * bits of the left-hand overlap in and no new pixels. Safest to count
	 * tiles across.
	 */
	if (strip->x / dz->tile_step >= level->tiles_across) {
		*stop = TRUE;
#ifdef DEBUG_VERBOSE
		printf("image_strip_allocate: done\n");
#endif /*DEBUG_VERBOSE*/

		return 0;
	}

	image.left = 0;
	image.top = 0;
	image.width = level->width;
	image.height = level->height;

	/* Position this tile.
	 */
	state->pos.left = strip->x;
	state->pos.top = level->y;
	state->pos.width = dz->tile_size;
	state->pos.height = dz->tile_size;
	vips_rect_marginadjust(&state->pos, dz->tile_margin);

	vips_rect_intersectrect(&image, &state->pos, &state->pos);
	state->x = strip->x;
	state->y = level->y;

	strip->x += dz->tile_step;

	return 0;
}

/* Make a name for a tile in the current layout.
 */
static char *
tile_name(Level *level, int x, int y)
{
	VipsForeignSaveDz *dz = level->dz;
	VipsForeignSave *save = (VipsForeignSave *) dz;

	char *out;
	char *dirname;
	char name[VIPS_PATH_MAX];
	char subdir[VIPS_PATH_MAX];
	Level *p;
	int n;

	switch (dz->layout) {
	case VIPS_FOREIGN_DZ_LAYOUT_DZ:
		vips_snprintf(subdir, VIPS_PATH_MAX, "%d", level->n);
		vips_snprintf(name, VIPS_PATH_MAX, "%d_%d%s", x, y, dz->file_suffix);

		break;

	case VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY:
		/* We need to work out the tile number so we can calculate the
		 * directory to put this tile in.
		 *
		 * Tiles are numbered from 0 for the most-zoomed-out tile.
		 */
		n = 0;

		/* Count all tiles in levels below this one.
		 */
		for (p = level->below; p; p = p->below)
			n += p->tiles_across * p->tiles_down;

		/* And count tiles so far in this level.
		 */
		n += y * level->tiles_across + x;

		vips_snprintf(subdir, VIPS_PATH_MAX, "TileGroup%d", n / 256);
		vips_snprintf(name, VIPS_PATH_MAX,
			"%d-%d-%d%s", level->n, x, y, dz->file_suffix);

		/* Used at the end in ImageProperties.xml
		 */
		dz->tile_count += 1;

		break;

	case VIPS_FOREIGN_DZ_LAYOUT_GOOGLE:
		vips_snprintf(subdir, VIPS_PATH_MAX,
			"%d" G_DIR_SEPARATOR_S "%d", level->n, y);
		vips_snprintf(name, VIPS_PATH_MAX,
			"%d%s", x, dz->file_suffix);

		break;

	case VIPS_FOREIGN_DZ_LAYOUT_IIIF:
	case VIPS_FOREIGN_DZ_LAYOUT_IIIF3: {
		/* Tiles are addressed in full resolution coordinates, so
		 * scale up by level->sub and dz->tile_size
		 *
		 * We always clip against the full-sized image, not the scaled
		 * up level.
		 *
		 * This will break for overlap != 0, but hopefully no one will
		 * ever use that.
		 */
		int left = x * dz->tile_size * level->sub;
		int top = y * dz->tile_size * level->sub;
		int width = VIPS_MIN(dz->tile_size * level->sub,
			save->ready->Xsize - left);
		int height = VIPS_MIN(dz->tile_size * level->sub,
			save->ready->Ysize - top);

		/* Rotation is always 0.
		 */
		int rotation = 0;

		if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_IIIF3) {
			int xsize = VIPS_MIN(dz->tile_size,
				level->width - x * dz->tile_size);
			int ysize = VIPS_MIN(dz->tile_size,
				level->height - y * dz->tile_size);

			vips_snprintf(subdir, VIPS_PATH_MAX,
				"%d,%d,%d,%d" G_DIR_SEPARATOR_S "%d,%d" G_DIR_SEPARATOR_S "%d",
				left, top, width, height,
				xsize, ysize,
				rotation);
		}
		else {
			/* IIIF2 "size" is just real tile width, I think.
			 */
			int size = VIPS_MIN(dz->tile_size,
				level->width - x * dz->tile_size);

			vips_snprintf(subdir, VIPS_PATH_MAX,
				"%d,%d,%d,%d" G_DIR_SEPARATOR_S "%d," G_DIR_SEPARATOR_S "%d",
				left, top, width, height,
				size,
				rotation);
		}

		vips_snprintf(name, VIPS_PATH_MAX, "default%s", dz->file_suffix);
	}

	break;

	default:
		g_assert_not_reached();
	}

	dirname = g_build_filename(dz->root_name, subdir, NULL);

	if (vips__archive_mkdir(dz->archive, dirname)) {
		g_free(dirname);
		return NULL;
	}

	out = g_build_filename(dirname, name, NULL);
	g_free(dirname);

#ifdef DEBUG_VERBOSE
	printf("tile_name: writing to %s\n", out);
#endif /*DEBUG_VERBOSE*/

	return out;
}

/* Test for region nearly equal to background colour. In google maps mode, we
 * skip blank background tiles.
 *
 * Don't use exactly equality since compression artefacts or noise can upset
 * this.
 */
static gboolean
region_tile_equal(VipsRegion *region, VipsRect *rect,
	int threshold, VipsPel *restrict ink)
{
	int bytes = VIPS_REGION_SIZEOF_PEL(region);

	int x, y, b;

	for (y = 0; y < rect->height; y++) {
		VipsPel *restrict p = VIPS_REGION_ADDR(region,
			rect->left, rect->top + y);

		for (x = 0; x < rect->width; x++) {
			for (b = 0; b < bytes; b++)
				if (VIPS_ABS(p[b] - ink[b]) > threshold)
					return FALSE;

			p += bytes;
		}
	}

	return TRUE;
}

static gboolean
image_tile_equal(VipsImage *image, int threshold, VipsPel *restrict ink)
{
	VipsRect rect;
	VipsRegion *region;

	region = vips_region_new(image);

	/* We know @image is part of a memory buffer, so this will be quick.
	 */
	rect.left = 0;
	rect.top = 0;
	rect.width = image->Xsize;
	rect.height = image->Ysize;
	if (vips_region_prepare(region, &rect)) {
		g_object_unref(region);
		return FALSE;
	}

	if (!region_tile_equal(region, &rect, threshold, ink)) {
		g_object_unref(region);
		return FALSE;
	}

	g_object_unref(region);

	return TRUE;
}

static int
image_strip_work(VipsThreadState *state, void *a)
{
	ImageStrip *strip = (ImageStrip *) a;
	Level *level = strip->level;
	VipsForeignSaveDz *dz = level->dz;
	VipsForeignSave *save = (VipsForeignSave *) dz;
	int tile_x = state->x / dz->tile_step;
	int tile_y = state->y / dz->tile_step;

	VipsRect tile;
	VipsImage *x;
	char *out;

#ifdef DEBUG_VERBOSE
	printf("image_strip_work\n");
#endif /*DEBUG_VERBOSE*/

	/* killed is checked by sink_disc, but that's only once per strip, and
	 * they can be huge. Check per output tile as well.
	 */
	if (vips_image_iskilled(save->in))
		return -1;

	/* We may be outside the real pixels.
	 */
	tile.left = state->x;
	tile.top = state->y;
	tile.width = dz->tile_size;
	tile.height = dz->tile_size;
	if (!vips_rect_overlapsrect(&tile, &level->save_area)) {
#ifdef DEBUG_VERBOSE
		printf("image_strip_work: skipping tile %d x %d\n", tile_x, tile_y);
#endif /*DEBUG_VERBOSE*/
		return 0;
	}

	g_assert(vips_object_sanity(VIPS_OBJECT(strip->image)));

	/* Extract relative to the strip top-left corner.
	 */
	if (vips_extract_area(strip->image, &x,
			state->pos.left, 0,
			state->pos.width, state->pos.height, NULL))
		return -1;

	if (dz->skip_blanks >= 0 &&
		image_tile_equal(x, dz->skip_blanks, dz->ink)) {
		g_object_unref(x);

#ifdef DEBUG_VERBOSE
		printf("image_strip_work: skipping blank tile %d x %d\n",
			tile_x, tile_y);
#endif /*DEBUG_VERBOSE*/

		return 0;
	}

	if (!(out = tile_name(level, tile_x, tile_y))) {
		g_object_unref(x);

		return -1;
	}

	/* Don't do a threaded write -- this pipeline is too small to have useful
	 * concurrency, and we are already writing tiles in parallel.
	 */
	vips_image_set_int(x, VIPS_META_CONCURRENCY, 1);

	if (write_image(dz, x, out, dz->suffix)) {
		g_free(out);
		g_object_unref(x);

		return -1;
	}

	g_free(out);
	g_object_unref(x);

#ifdef DEBUG_VERBOSE
	printf("image_strip_work: success\n");
#endif /*DEBUG_VERBOSE*/

	return 0;
}

/* Our state during a direct write of a strip.
 */
typedef struct _DirectStrip {
	Level *level;

	/* Allocate the next tile on this boundary.
	 */
	int x;
} DirectStrip;

static int
direct_strip_allocate(VipsThreadState *state, void *a, gboolean *stop)
{
	DirectStrip *strip = (DirectStrip *) a;
	Level *level = strip->level;
	VipsForeignSaveDz *dz = level->dz;

	VipsRect image;

#ifdef DEBUG_VERBOSE
	printf("direct_strip_allocate\n");
#endif /*DEBUG_VERBOSE*/

	/* We can't test for allocated area empty, since it might just have
	 * bits of the left-hand overlap in and no new pixels. Safest to count
	 * tiles across.
	 */
	if (strip->x / dz->tile_step >= level->tiles_across) {
		*stop = TRUE;
#ifdef DEBUG_VERBOSE
		printf("direct_strip_allocate: done\n");
#endif /*DEBUG_VERBOSE*/

		return 0;
	}

	/* Position this tile.
	 */
	image.left = 0;
	image.top = 0;
	image.width = level->width;
	image.height = level->height;
	state->pos.left = strip->x;
	state->pos.top = level->y;
	state->pos.width = dz->tile_size;
	state->pos.height = dz->tile_size;
	vips_rect_marginadjust(&state->pos, dz->tile_margin);
	vips_rect_intersectrect(&image, &state->pos, &state->pos);

	state->x = strip->x;
	state->y = level->y;
	strip->x += dz->tile_step;

	return 0;
}

static int
direct_image_write(VipsForeignSaveDz *dz,
	VipsRegion *region, VipsRect *rect,
	const char *filename)
{
	VipsForeignSave *save = VIPS_FOREIGN_SAVE(dz);
	VipsTarget *target;

	if (!(target = vips_target_new_to_memory()))
		return -1;

	if (vips__jpeg_region_write_target(region, rect, target,
			dz->Q, NULL,
			FALSE, FALSE,
			save->keep, FALSE,
			FALSE, FALSE,
			0, 0, 0)) {
		g_object_unref(target);
		return -1;
	}

	VipsBlob *blob;
	const void *buf;
	size_t len;
	g_object_get(target, "blob", &blob, NULL);
	buf = vips_blob_get(blob, &len);
	if (vips__archive_mkfile(dz->archive, filename, (void *) buf, len)) {
		vips_area_unref(VIPS_AREA(blob));
		g_object_unref(target);
		return -1;
	}

	vips_area_unref(VIPS_AREA(blob));
	g_object_unref(target);

	return 0;
}

static int
direct_strip_work(VipsThreadState *state, void *a)
{
	DirectStrip *strip = (DirectStrip *) a;
	Level *level = strip->level;
	VipsForeignSaveDz *dz = level->dz;
	VipsForeignSave *save = (VipsForeignSave *) dz;
	int tile_x = state->x / dz->tile_step;
	int tile_y = state->y / dz->tile_step;

	VipsRect tile;

	/* killed is checked by sink_disc, but that's only once per strip, and
	 * they can be huge. Check per output tile as well.
	 */
	if (vips_image_iskilled(save->in))
		return -1;

	/* We may be outside the real pixels.
	 */
	tile.left = state->x;
	tile.top = state->y;
	tile.width = dz->tile_size;
	tile.height = dz->tile_size;
	if (!vips_rect_overlapsrect(&tile, &level->save_area)) {
#ifdef DEBUG_VERBOSE
		printf("direct_strip_work: level %d, skipping tile %d x %d\n",
			level->n, tile_x, tile_y);
#endif /*DEBUG_VERBOSE*/

		return 0;
	}

	if (dz->skip_blanks >= 0 &&
		region_tile_equal(level->strip, &state->pos,
			dz->skip_blanks, dz->ink)) {
#ifdef DEBUG_VERBOSE
		printf("direct_strip_work: level %d, skipping blank tile %d x %d\n",
			level->n, tile_x, tile_y);
#endif /*DEBUG_VERBOSE*/

		return 0;
	}

	char *name;
	if (!(name = tile_name(level, tile_x, tile_y)))
		return -1;

	if (direct_image_write(dz, level->strip, &state->pos, name)) {
		g_free(name);
		return -1;
	}

	g_free(name);

	return 0;
}

/* Write a line of tiles with a threadpool.
 */
static int
strip_save(Level *level)
{
#ifdef DEBUG_VERBOSE
	printf("strip_save: n = %d, y = %d\n", level->n, level->y);
#endif /*DEBUG_VERBOSE*/

	if (level->dz->direct) {
		DirectStrip strip = { level, 0 };

		/* We don't want threadpoolrun to minimise on completion -- we need to
		 * keep the cache on the pipeline before us.
		 */
		vips_image_set_int(level->image, "vips-no-minimise", 1);

		if (vips_threadpool_run(level->image,
				vips_thread_state_new,
				direct_strip_allocate,
				direct_strip_work,
				NULL,
				&strip))
			return -1;
	}
	else {
		ImageStrip strip;

		image_strip_init(&strip, level);

		vips_image_set_int(strip.image, "vips-no-minimise", 1);

		if (vips_threadpool_run(strip.image,
				vips_thread_state_new,
				image_strip_allocate,
				image_strip_work,
				NULL,
				&strip)) {
			image_strip_free(&strip);
			return -1;
		}

		image_strip_free(&strip);
	}

#ifdef DEBUG_VERBOSE
	printf("strip_save: success\n");
#endif /*DEBUG_VERBOSE*/

	return 0;
}

/* A strip has filled, but the rightmost column and the bottom-most row may
 * not have been if we've rounded the size up.
 *
 * Fill them, if necessary, by copying the previous row/column.
 */
static void
level_generate_extras(Level *level)
{
	VipsRegion *strip = level->strip;

	/* We only work for full-width strips.
	 */
	g_assert(strip->valid.width == level->image->Xsize);

	if (level->width < level->image->Xsize) {
		int ps = VIPS_IMAGE_SIZEOF_PEL(strip->im);

		int b, y;

		/* Need to add a right-most column.
		 */
		for (y = 0; y < strip->valid.height; y++) {
			VipsPel *p = VIPS_REGION_ADDR(strip,
				level->width - 1, strip->valid.top + y);
			VipsPel *q = p + ps;

			for (b = 0; b < ps; b++)
				q[b] = p[b];
		}
	}

	if (level->height < level->image->Ysize) {
		VipsRect last;

		/* The last two lines of the image.
		 */
		last.left = 0;
		last.top = level->image->Ysize - 2;
		last.width = level->image->Xsize;
		last.height = 2;

		/* Do we have them both? Fill the last with the next-to-last.
		 */
		vips_rect_intersectrect(&last, &strip->valid, &last);
		if (last.height == 2) {
			last.height = 1;
			vips_region_copy(strip, strip, &last, 0, last.top + 1);
		}
	}
}

static int strip_arrived(Level *level);

/* Shrink what pixels we can from this strip into the level below. If the
 * strip below fills, recurse.
 */
static int
strip_shrink(Level *level)
{
	Level *below = level->below;
	VipsRegion *from = level->strip;
	VipsRegion *to = below->strip;
	VipsForeignSaveDz *dz = level->dz;
	VipsRegionShrink region_shrink = dz->region_shrink;

	VipsRect target;
	VipsRect source;

#ifdef DEBUG_VERBOSE
	printf("strip_shrink: %d lines in level %d to level %d\n",
		from->valid.height, level->n, below->n);
#endif /*DEBUG_VERBOSE*/

	/* We may have an extra column of pixels on the right or
	 * bottom that need filling: generate them.
	 */
	level_generate_extras(level);

	/* Our pixels might cross a strip boundary in the level below, so we
	 * have to write repeatedly until we run out of pixels.
	 */
	for (;;) {
		/* The pixels the level below needs.
		 */
		target.left = 0;
		target.top = below->write_y;
		target.width = below->image->Xsize;
		target.height = to->valid.height;
		vips_rect_intersectrect(&target, &to->valid, &target);

		/* Those pixels need this area of this level.
		 */
		source.left = target.left * 2;
		source.top = target.top * 2;
		source.width = target.width * 2;
		source.height = target.height * 2;

		/* Of which we have these available.
		 */
		vips_rect_intersectrect(&source, &from->valid, &source);

		/* So these are the pixels in the level below we can provide.
		 */
		target.left = source.left / 2;
		target.top = source.top / 2;
		target.width = source.width / 2;
		target.height = source.height / 2;

		/* None? All done.
		 */
		if (vips_rect_isempty(&target))
			break;

		(void) vips_region_shrink_method(from, to, &target, region_shrink);

		below->write_y += target.height;

		/* If we've filled the strip below, let it know.
		 * We can either fill the region, if it's somewhere half-way
		 * down the image, or, if it's at the bottom, get to the last
		 * real line of pixels.
		 */
		if (below->write_y == VIPS_RECT_BOTTOM(&to->valid) ||
			below->write_y == below->height) {
			if (strip_arrived(below))
				return -1;
		}
	}

	return 0;
}

/* A new strip has arrived! The strip has enough pixels in to write a line of
 * tiles.
 *
 * - write a line of tiles
 * - shrink what we can to the level below
 * - move our strip down by the tile step
 * - copy the overlap with the previous strip
 */
static int
strip_arrived(Level *level)
{
	VipsForeignSaveDz *dz = level->dz;

	VipsRect new_strip;
	VipsRect overlap;
	VipsRect image_area;

#ifdef DEBUG_VERBOSE
	printf("strip_arrived: level %d, strip at %d, height %d\n",
		level->n, level->y, level->strip->valid.height);
#endif /*DEBUG_VERBOSE*/

	if (strip_save(level))
		return -1;

	if (level->below &&
		strip_shrink(level))
		return -1;

	/* Position our strip down the image.
	 *
	 * Expand the strip if necessary to make sure we have an even
	 * number of lines.
	 */
	level->y += dz->tile_step;
	new_strip.left = 0;
	new_strip.top = level->y - dz->tile_margin;
	new_strip.width = level->image->Xsize;
	new_strip.height = dz->tile_size + 2 * dz->tile_margin;

	image_area.left = 0;
	image_area.top = 0;
	image_area.width = level->image->Xsize;
	image_area.height = level->image->Ysize;
	vips_rect_intersectrect(&new_strip, &image_area, &new_strip);

	if ((new_strip.height & 1) == 1)
		new_strip.height += 1;

	/* We may exactly hit the bottom of the real image (ie. before borders
	 * have been possibly expanded by 1 pixel). In this case, we'll not
	 * be able to do the expansion in level_generate_extras(), since the
	 * region won't be large enough, and we'll not get another chance
	 * since this is the bottom.
	 *
	 * Add another scanline if this has happened.
	 */
	if (VIPS_RECT_BOTTOM(&new_strip) == level->height)
		new_strip.height = level->image->Ysize - new_strip.top;

	/* What pixels that we will need do we already have? Save them in
	 * overlap.
	 */
	vips_rect_intersectrect(&new_strip, &level->strip->valid, &overlap);
	if (!vips_rect_isempty(&overlap)) {
		if (vips_region_buffer(level->copy, &overlap))
			return -1;
		vips_region_copy(level->strip, level->copy,
			&overlap, overlap.left, overlap.top);
	}

	if (!vips_rect_isempty(&new_strip)) {
		if (vips_region_buffer(level->strip, &new_strip))
			return -1;

		/* And copy back again.
		 */
		if (!vips_rect_isempty(&overlap))
			vips_region_copy(level->copy, level->strip,
				&overlap, overlap.left, overlap.top);
	}

	return 0;
}

/* The image has been completely written. Flush any strips which might have
 * overlaps in.
 */
static int
strip_flush(Level *level)
{
	if (level->y < level->height)
		if (strip_save(level))
			return -1;

	if (level->below)
		if (strip_flush(level->below))
			return -1;

	return 0;
}

/* Another strip of image pixels from vips_sink_disc(). Write into the top
 * pyramid level.
 */
static int
pyramid_strip(VipsRegion *region, VipsRect *area, void *a)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) a;
	Level *level = dz->level;

#ifdef DEBUG_VERBOSE
	printf("pyramid_strip: strip at %d, height %d\n",
		area->top, area->height);
#endif /*DEBUG_VERBOSE*/

	for (;;) {
		VipsRect *to = &level->strip->valid;
		VipsRect target;

		/* The bit of strip that needs filling.
		 */
		target.left = 0;
		target.top = level->write_y;
		target.width = level->image->Xsize;
		target.height = to->height;
		vips_rect_intersectrect(&target, to, &target);

		/* Clip against what we have available.
		 */
		vips_rect_intersectrect(&target, area, &target);

		/* Have we written all the pixels we were given? We are done.
		 */
		if (vips_rect_isempty(&target))
			break;

		/* And copy those pixels in.
		 *
		 * FIXME: If the strip fits inside the region we've just
		 * received, we could skip the copy. Will this happen very
		 * often? Unclear.
		 */
		vips_region_copy(region, level->strip,
			&target, target.left, target.top);

		level->write_y += target.height;

		/* We can either fill the strip, if it's somewhere half-way
		 * down the image, or, if it's at the bottom, get to the last
		 * real line of pixels.
		 */
		if (level->write_y == VIPS_RECT_BOTTOM(to) ||
			level->write_y == level->height) {
			if (strip_arrived(level))
				return -1;
		}
	}

	/* If we've reached the bottom of the image, we won't get called again.
	 *
	 * However, there may be some unwritten pixels in the pyramid still!
	 * Suppose a level is exactly a multiple of tile_step in height.
	 * When we finished that last strip, we will have copied the last few
	 * lines of overlap over into the top of the next row. Deepzoom says we
	 * must flush these half-written strips to the output.
	 */
	if (level->write_y == level->height) {
#ifdef DEBUG
		printf("pyramid_strip: flushing ..\n");
#endif /*DEBUG*/

		if (strip_flush(level))
			return -1;
	}

	return 0;
}

#define UC VIPS_FORMAT_UCHAR

/* We force all types to uchar for save.
 */
static VipsBandFormat bandfmt_dzsave[10] = {
	/* Band format:  UC  C   US  S   UI  I   F   X   D   DX */
	/* Promotion: */ UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static int
vips_foreign_save_dz_build(VipsObject *object)
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) object;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(dz);

	VipsRect save_area;
	char *p;

	// direct mode won't work if the suffix has been set
	if (!vips_object_argument_isset(object, "suffix"))
		dz->direct = TRUE;

	/* We default to stripping all metadata as most people
	 * don't want metadata on every tile. Setting "keep"
	 * or the deprecated "no_strip" turns this off.
	 */
	if (!vips_object_argument_isset(object, "keep") &&
		!vips_object_argument_isset(object, "no_strip"))
		save->keep = VIPS_FOREIGN_KEEP_NONE;

	/* Google, zoomify and iiif default to zero overlap, ".jpg".
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY ||
		dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE ||
		dz->layout == VIPS_FOREIGN_DZ_LAYOUT_IIIF ||
		dz->layout == VIPS_FOREIGN_DZ_LAYOUT_IIIF3) {
		if (!vips_object_argument_isset(object, "overlap"))
			dz->overlap = 0;
		if (!vips_object_argument_isset(object, "suffix"))
			VIPS_SETSTR(dz->suffix, ".jpg");
	}

	/* Google and zoomify default to 256 pixel tiles.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY ||
		dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE) {
		if (!vips_object_argument_isset(object, "tile_size"))
			dz->tile_size = 256;
	}

	/* Some iiif writers default to 256, some to 512. We pick 512.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_IIIF ||
		dz->layout == VIPS_FOREIGN_DZ_LAYOUT_IIIF3) {
		if (!vips_object_argument_isset(object, "tile_size"))
			dz->tile_size = 512;
	}

	/* skip_blanks defaults to 5 in google mode.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE &&
		!vips_object_argument_isset(object, "skip_blanks"))
		dz->skip_blanks = 5;

	/* Our tile layout.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_DZ) {
		dz->tile_margin = dz->overlap;
		dz->tile_step = dz->tile_size;
	}
	else {
		dz->tile_margin = 0;
		dz->tile_step = dz->tile_size - dz->overlap;
	}

	if (dz->tile_step <= 0) {
		vips_error("dzsave", "%s", _("overlap too large"));
		return -1;
	}

	/* Default to white background. vips_foreign_save_init() defaults to
	 * black.
	 */
	if (!vips_object_argument_isset(object, "background")) {
		VipsArrayDouble *background;

		/* Using g_object_set() to set an input param in build will
		 * change the hash and confuse caching, but we don't cache
		 * savers, so it's fine.
		 */
		background = vips_array_double_newv(1, 255.0);
		g_object_set(object, "background", background, NULL);
		vips_area_unref(VIPS_AREA(background));
	}

	/* DeepZoom stops at 1x1 pixels, others when the image fits within a
	 * tile.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_DZ) {
		if (!vips_object_argument_isset(object, "depth"))
			dz->depth = VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL;
	}
	else if (!vips_object_argument_isset(object, "depth"))
		dz->depth = VIPS_FOREIGN_DZ_DEPTH_ONETILE;

	/* We don't support onepixel pyramids in gmaps mode. It doesn't make a lot
	 * of sense anyway, since gmaps tiles are never clipped, so you can't have
	 * a 1x1 pixel tile.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE &&
		dz->depth == VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL)
		dz->depth = VIPS_FOREIGN_DZ_DEPTH_ONETILE;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_dz_parent_class)->build(object))
		return -1;

	/* Optional rotate.
	 */
	{
		VipsImage *z;

		if (vips_rot(save->ready, &z, dz->angle, NULL))
			return -1;

		VIPS_UNREF(save->ready);
		save->ready = z;
	}

	/* If we're saving to direct JPEG, we need to convert to 8-bit RGB |
	 * mono | cmyk.
	 */
	if (dz->direct) {
		VipsImage *z;
		gboolean coding[VIPS_CODING_LAST];

		for (int i = 0; i < VIPS_CODING_LAST; i++)
			coding[i] = FALSE;
		coding[VIPS_CODING_NONE] = TRUE;

		if (vips__foreign_convert_saveable(save->ready, &z,
			VIPS_SAVEABLE_RGB_CMYK, bandfmt_dzsave, coding,
			save->background))
			return -1;

		VIPS_UNREF(save->ready);
		save->ready = z;
	}

	/* We use ink to check for blank tiles.
	 */
	if (dz->skip_blanks >= 0) {
		if (!(dz->ink = vips__vector_to_ink(
				  class->nickname, save->ready,
				  VIPS_AREA(save->background)->data, NULL,
				  VIPS_AREA(save->background)->n)))
			return -1;
	}

	/* The real (not background) pixels we have. save->ready can be a lot
	 * bigger. left/top are moved if we centre.
	 */
	save_area.left = 0;
	save_area.top = 0;
	save_area.width = save->ready->Xsize;
	save_area.height = save->ready->Ysize;

	/* In google mode, we expand the image so we have complete tiles in every
	 * level. We shrink to fit in one tile, then expand those dimensions out
	 * again.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE) {
		VipsImage *z;
		Level *level;
		Level *p;
		int width;
		int height;

		if (!(level = pyramid_build(dz, NULL,
				  save->ready->Xsize, save->ready->Ysize, &save_area)))
			return -1;

		// find the deepest (smallest) level
		for (p = level; p->below; p = p->below)
			;

		// round image size up so we have complete tiles in the base level
		width = VIPS_ROUND_UP(p->width, dz->tile_step) + dz->overlap;
		height = VIPS_ROUND_UP(p->height, dz->tile_step) + dz->overlap;

		// and scale up by 2^depth ... we'll have complete tiles in every
		// level
		width *= 1 << level->n;
		height *= 1 << level->n;

		level_free(level);

#ifdef DEBUG
		printf("vips_foreign_save_dz_build: "
			   "google mode outputs a %d x %d pixel image\n",
			width, height);
#endif /*DEBUG*/

		if (dz->centre) {
#ifdef DEBUG
			printf("vips_foreign_save_dz_build: centring\n");
#endif /*DEBUG*/

			save_area.left = (width - save->ready->Xsize) / 2;
			save_area.top = (height - save->ready->Ysize) / 2;
		}

		if (vips_embed(save->ready, &z,
				save_area.left, save_area.top, width, height,
				"background", save->background,
				NULL))
			return -1;

		VIPS_UNREF(save->ready);
		save->ready = z;
	}

#ifdef DEBUG
	printf("vips_foreign_save_dz_build: tile_size == %d\n", dz->tile_size);
	printf("vips_foreign_save_dz_build: overlap == %d\n", dz->overlap);
	printf("vips_foreign_save_dz_build: tile_margin == %d\n", dz->tile_margin);
	printf("vips_foreign_save_dz_build: tile_step == %d\n", dz->tile_step);
#endif /*DEBUG*/

	/* Init imagename and dirname from the associated filesystem names, if
	 * we can.
	 */
	{
		const char *filename = dz->filename
			? dz->filename
			: vips_connection_filename(VIPS_CONNECTION(dz->target));

		if (!vips_object_argument_isset(object, "imagename") &&
			!vips_object_argument_isset(object, "basename")) {
			if (filename) {
				dz->imagename = g_path_get_basename(filename);

				/* Remove any [options] we may have picked up from the
				 * filename.
				 */
				if ((p = (char *) vips__find_rightmost_brackets(dz->imagename)))
					*p = '\0';
			}
			else
				dz->imagename = g_strdup("untitled");
		}

		if (!vips_object_argument_isset(object, "dirname")) {
			if (filename)
				dz->dirname = g_path_get_dirname(filename);
			else
				dz->dirname = g_strdup(".");
		}
	}

	/* If we're writing thing.zip or thing.szi, default to zip
	 * container.
	 */
	if ((p = strrchr(dz->imagename, '.'))) {
		if (!vips_object_argument_isset(object, "container")) {
			if (g_ascii_strcasecmp(p + 1, "zip") == 0)
				dz->container = VIPS_FOREIGN_DZ_CONTAINER_ZIP;
			if (g_ascii_strcasecmp(p + 1, "szi") == 0)
				dz->container = VIPS_FOREIGN_DZ_CONTAINER_SZI;
		}

		/* Remove any legal suffix. We don't remove all suffixes
		 * since we might be writing to a dirname with a dot in.
		 */
		if (g_ascii_strcasecmp(p + 1, "zip") == 0 ||
			g_ascii_strcasecmp(p + 1, "szi") == 0 ||
			g_ascii_strcasecmp(p + 1, "dz") == 0)
			*p = '\0';
	}

	/* Build the skeleton of the image pyramid.
	 */
	if (!(dz->level = pyramid_build(dz, NULL,
			  save->ready->Xsize, save->ready->Ysize, &save_area)))
		return -1;

	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_DZ)
		dz->root_name = g_strdup_printf("%s_files", dz->imagename);
	else
		dz->root_name = g_strdup(dz->imagename);

	/* Drop any [options] from @suffix.
	 */
	dz->file_suffix = g_strdup(dz->suffix);
	if ((p = (char *) vips__find_rightmost_brackets(dz->file_suffix)))
		*p = '\0';

	/* Make the zip archive we write the tiles into.
	 */
	if (iszip(dz->container)) {
		/* We can have dzsave("x.zip", container="fs"), ie. zip output
		 * from write to file. Make a target if we need one.
		 */
		if (!dz->target) {
			if (!(dz->target = vips_target_new_to_file(dz->filename)))
				return -1;
		}

		// SZI needs an enclosing folder named after the image, according to
		// the spec
		char *path = dz->container == VIPS_FOREIGN_DZ_CONTAINER_SZI
			? dz->imagename
			: "";

		if (!(dz->archive = vips__archive_new_to_target(dz->target,
				  path, dz->compression)))
			return -1;
	}
	else {
		if (!(dz->archive = vips__archive_new_to_dir(dz->dirname)))
			return -1;
	}

	if (vips_sink_disc(save->ready, pyramid_strip, dz))
		return -1;

	switch (dz->layout) {
	case VIPS_FOREIGN_DZ_LAYOUT_DZ:
		if (write_dzi(dz))
			return -1;
		break;

	case VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY:
		if (write_properties(dz))
			return -1;
		break;

	case VIPS_FOREIGN_DZ_LAYOUT_GOOGLE:
		if (write_blank(dz))
			return -1;
		break;

	case VIPS_FOREIGN_DZ_LAYOUT_IIIF:
	case VIPS_FOREIGN_DZ_LAYOUT_IIIF3:
		if (write_json(dz))
			return -1;
		break;

	default:
		g_assert_not_reached();
	}

	if (write_vips_meta(dz))
		return -1;

	if (dz->container == VIPS_FOREIGN_DZ_CONTAINER_SZI &&
		write_scan_properties(dz))
		return -1;

	if (dz->container == VIPS_FOREIGN_DZ_CONTAINER_SZI &&
		write_associated(dz))
		return -1;

	/* Shut down the output to flush everything.
	 */
	VIPS_FREEF(vips__archive_free, dz->archive);

	return 0;
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static VipsBandFormat bandfmt_dz[10] = {
	/* Band format:  UC  C  US  S  UI  I  F  X  D  DX */
	/* Promotion: */ UC, C, US, S, UI, I, F, F, D, D
};

static const char *dz_suffs[] = { ".dz", ".szi", NULL };

static void
vips_foreign_save_dz_class_init(VipsForeignSaveDzClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_dz_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "dzsave_base";
	object_class->description = _("save image to deep zoom format");
	object_class->build = vips_foreign_save_dz_build;

	foreign_class->suffs = dz_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_dz;
	save_class->coding[VIPS_CODING_LABQ] = TRUE;

	VIPS_ARG_STRING(class, "imagename", 2,
		_("Image name"),
		_("Image name"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, imagename),
		NULL);

	VIPS_ARG_ENUM(class, "layout", 8,
		_("Layout"),
		_("Directory layout"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, layout),
		VIPS_TYPE_FOREIGN_DZ_LAYOUT, VIPS_FOREIGN_DZ_LAYOUT_DZ);

	VIPS_ARG_STRING(class, "suffix", 9,
		_("Suffix"),
		_("Filename suffix for tiles"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, suffix),
		".jpeg");

	VIPS_ARG_INT(class, "overlap", 10,
		_("Overlap"),
		_("Tile overlap in pixels"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, overlap),
		0, 8192, 1);

	VIPS_ARG_INT(class, "tile_size", 11,
		_("Tile size"),
		_("Tile size in pixels"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, tile_size),
		1, 8192, 254);

	VIPS_ARG_ENUM(class, "depth", 13,
		_("Depth"),
		_("Pyramid depth"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, depth),
		VIPS_TYPE_FOREIGN_DZ_DEPTH, VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL);

	VIPS_ARG_BOOL(class, "centre", 13,
		_("Center"),
		_("Center image in tile"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, centre),
		FALSE);

	VIPS_ARG_ENUM(class, "angle", 14,
		_("Angle"),
		_("Rotate image during save"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, angle),
		VIPS_TYPE_ANGLE, VIPS_ANGLE_D0);

	VIPS_ARG_ENUM(class, "container", 15,
		_("Container"),
		_("Pyramid container type"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, container),
		VIPS_TYPE_FOREIGN_DZ_CONTAINER, VIPS_FOREIGN_DZ_CONTAINER_FS);

	VIPS_ARG_INT(class, "compression", 17,
		_("Compression"),
		_("ZIP deflate compression level"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, compression),
		-1, 9, 0);

	VIPS_ARG_ENUM(class, "region_shrink", 18,
		_("Region shrink"),
		_("Method to shrink regions"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, region_shrink),
		VIPS_TYPE_REGION_SHRINK, VIPS_REGION_SHRINK_MEAN);

	VIPS_ARG_INT(class, "skip_blanks", 19,
		_("Skip blanks"),
		_("Skip tiles which are nearly equal to the background"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, skip_blanks),
		-1, 65535, -1);

	VIPS_ARG_STRING(class, "id", 20,
		_("id"),
		_("Resource ID"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, id),
		"https://example.com/iiif");

	VIPS_ARG_INT(class, "Q", 21,
		_("Q"),
		_("Q factor"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, Q),
		1, 100, 75);

	/* How annoying. We stupidly had these in earlier versions.
	 */

	VIPS_ARG_BOOL(class, "no_strip", 22,
		_("No strip"),
		_("Don't strip tile metadata"),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsForeignSaveDz, no_strip),
		FALSE);

	VIPS_ARG_STRING(class, "basename", 23,
		_("Base name"),
		_("Base name to save to"),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsForeignSaveDz, imagename),
		NULL);

	VIPS_ARG_STRING(class, "dirname", 1,
		_("Directory name"),
		_("Directory name to save to"),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsForeignSaveDz, dirname),
		NULL);

	VIPS_ARG_INT(class, "tile_width", 12,
		_("Tile width"),
		_("Tile width in pixels"),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsForeignSaveDz, tile_size),
		1, 8192, 254);

	VIPS_ARG_INT(class, "tile_height", 12,
		_("Tile height"),
		_("Tile height in pixels"),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsForeignSaveDz, tile_size),
		1, 8192, 254);

	VIPS_ARG_BOOL(class, "properties", 16,
		_("Properties"),
		_("Write a properties file to the output directory"),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsForeignSaveDz, properties),
		FALSE);
}

static void
vips_foreign_save_dz_init(VipsForeignSaveDz *dz)
{
	VIPS_SETSTR(dz->suffix, ".jpeg");
	dz->layout = VIPS_FOREIGN_DZ_LAYOUT_DZ;
	dz->overlap = 1;
	dz->tile_size = 254;
	dz->tile_count = 0;
	dz->depth = VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL;
	dz->angle = VIPS_ANGLE_D0;
	dz->container = VIPS_FOREIGN_DZ_CONTAINER_FS;
	dz->compression = 0;
	dz->region_shrink = VIPS_REGION_SHRINK_MEAN;
	dz->skip_blanks = -1;
	dz->Q = 75;
}

typedef struct _VipsForeignSaveDzTarget {
	VipsForeignSaveDz parent_object;

	VipsTarget *target;

} VipsForeignSaveDzTarget;

typedef VipsForeignSaveDzClass VipsForeignSaveDzTargetClass;

G_DEFINE_TYPE(VipsForeignSaveDzTarget, vips_foreign_save_dz_target,
	vips_foreign_save_dz_get_type());

static int
vips_foreign_save_dz_target_build(VipsObject *object)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) object;
	VipsForeignSaveDzTarget *target = (VipsForeignSaveDzTarget *) object;

	dz->target = target->target;
	g_object_ref(dz->target);

	if (VIPS_OBJECT_CLASS(vips_foreign_save_dz_target_parent_class)
			->build(object))
		return -1;

	return 0;
}

static void
vips_foreign_save_dz_target_class_init(VipsForeignSaveDzTargetClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "dzsave_target";
	object_class->description = _("save image to deepzoom target");
	object_class->build = vips_foreign_save_dz_target_build;

	VIPS_ARG_OBJECT(class, "target", 1,
		_("Target"),
		_("Target to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDzTarget, target),
		VIPS_TYPE_TARGET);
}

static void
vips_foreign_save_dz_target_init(VipsForeignSaveDzTarget *target)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) target;

	/* zip default for target output.
	 */
	dz->container = VIPS_FOREIGN_DZ_CONTAINER_ZIP;
}

typedef struct _VipsForeignSaveDzFile {
	VipsForeignSaveDz parent_object;

	/* Filename for save.
	 */
	char *filename;

} VipsForeignSaveDzFile;

typedef VipsForeignSaveDzClass VipsForeignSaveDzFileClass;

G_DEFINE_TYPE(VipsForeignSaveDzFile, vips_foreign_save_dz_file,
	vips_foreign_save_dz_get_type());

static int
vips_foreign_save_dz_file_build(VipsObject *object)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) object;
	VipsForeignSaveDzFile *file = (VipsForeignSaveDzFile *) object;

	dz->filename = file->filename;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_dz_file_parent_class)
			->build(object))
		return -1;

	return 0;
}

static void
vips_foreign_save_dz_file_class_init(VipsForeignSaveDzFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "dzsave";
	object_class->description = _("save image to deepzoom file");
	object_class->build = vips_foreign_save_dz_file_build;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDzFile, filename),
		NULL);
}

static void
vips_foreign_save_dz_file_init(VipsForeignSaveDzFile *file)
{
}

typedef struct _VipsForeignSaveDzBuffer {
	VipsForeignSaveDz parent_object;

	VipsArea *buf;
} VipsForeignSaveDzBuffer;

typedef VipsForeignSaveDzClass VipsForeignSaveDzBufferClass;

G_DEFINE_TYPE(VipsForeignSaveDzBuffer, vips_foreign_save_dz_buffer,
	vips_foreign_save_dz_get_type());

static int
vips_foreign_save_dz_buffer_build(VipsObject *object)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) object;
	VipsForeignSaveDzBuffer *buffer = (VipsForeignSaveDzBuffer *) object;

	VipsBlob *blob;

	if (!(dz->target = vips_target_new_to_memory()))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_dz_buffer_parent_class)
			->build(object))
		return -1;

	g_object_get(dz->target, "blob", &blob, NULL);
	g_object_set(buffer, "buffer", blob, NULL);
	vips_area_unref(VIPS_AREA(blob));

	return 0;
}

static void
vips_foreign_save_dz_buffer_class_init(VipsForeignSaveDzBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "dzsave_buffer";
	object_class->description = _("save image to dz buffer");
	object_class->build = vips_foreign_save_dz_buffer_build;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to save to"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDzBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_save_dz_buffer_init(VipsForeignSaveDzBuffer *buffer)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) buffer;

	/* zip default for memory output.
	 */
	dz->container = VIPS_FOREIGN_DZ_CONTAINER_ZIP;
}

#endif /*HAVE_LIBARCHIVE*/

/**
 * vips_dzsave: (method)
 * @in: image to save
 * @name: name to save to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @basename: %gchar base part of name
 * * @layout: #VipsForeignDzLayout directory layout convention
 * * @suffix: %gchar suffix for tiles
 * * @overlap: %gint set tile overlap
 * * @tile_size: %gint set tile size
 * * @background: #VipsArrayDouble background colour
 * * @depth: #VipsForeignDzDepth how deep to make the pyramid
 * * @centre: %gboolean centre the tiles
 * * @angle: #VipsAngle rotate the image by this much
 * * @container: #VipsForeignDzContainer set container type
 * * @compression: %gint zip deflate compression level
 * * @region_shrink: #VipsRegionShrink how to shrink each 2x2 region
 * * @skip_blanks: %gint skip tiles which are nearly equal to the background
 * * @id: %gchar id for IIIF properties
 * * @Q: %gint, quality factor
 *
 * Save an image as a set of tiles at various resolutions. By default dzsave
 * uses DeepZoom layout -- use @layout to pick other conventions.
 *
 * vips_dzsave() creates a directory called @name to hold the tiles. If @name
 * ends `.zip`, vips_dzsave() will create a zip file called @name to hold the
 * tiles. You can use @container to force zip file output.
 *
 * Use @basename to set the name of the image we are creating. The
 * default value is set from @name.
 *
 * By default, tiles are written as JPEGs. Use @Q set set the JPEG quality
 * factor.
 *
 * You can set @suffix to something like `".png[bitdepth=4]"` to write tiles
 * in another format.
 *
 * In Google layout mode, edge tiles are expanded to @tile_size by @tile_size
 * pixels. Normally they are filled with white, but you can set another colour
 * with @background. Images are usually placed at the top-left of the tile,
 * but you can have them centred by turning on @centre.
 *
 * You can set the size and overlap of tiles with @tile_size and @overlap.
 * They default to the correct settings for the selected @layout. The deepzoom
 * defaults produce 256x256 jpeg files for centre tiles, the most efficient
 * size.
 *
 * Use @depth to control how low the pyramid goes. This defaults to the
 * correct setting for the @layout you select.
 *
 * You can rotate the image during write with the @angle argument. However,
 * this will only work for images which support random access, like openslide,
 * and not for things like JPEG. You'll need to rotate those images
 * yourself with vips_rot(). Note that the `autorotate` option to the loader
 * may do what you need.
 *
 * By default, all tiles are stripped since usually you do not want a copy of
 * all metadata in every tile. Set @keep if you want to keep metadata.
 *
 * If @container is set to `zip`, you can set a compression level from -1
 * (use zlib default), 0 (store, compression disabled) to 9 (max compression).
 * If no value is given, the default is to store files without compression.
 *
 * You can use @region_shrink to control the method for shrinking each 2x2
 * region. This defaults to using the average of the 4 input pixels but you can
 * also use the median in cases where you want to preserve the range of values.
 *
 * If you set @skip_blanks to a value greater than or equal to zero, tiles
 * which are all within that many pixel values to the background are skipped.
 * This can save a lot of space for some image types. This option defaults to
 * 5 in Google layout mode, -1 otherwise.
 *
 * In IIIF layout, you can set the base of the `id` property in `info.json`
 * with @id. The default is `https://example.com/iiif`.
 *
 * Use @layout #VIPS_FOREIGN_DZ_LAYOUT_IIIF3 for IIIF v3 layout.
 *
 * See also: vips_tiffsave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_dzsave(VipsImage *in, const char *name, ...)
{
	va_list ap;
	int result;

	va_start(ap, name);
	result = vips_call_split("dzsave", ap, in, name);
	va_end(ap);

	return result;
}

/**
 * vips_dzsave_buffer: (method)
 * @in: image to save
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @basename: %gchar base part of name
 * * @layout: #VipsForeignDzLayout directory layout convention
 * * @suffix: %gchar suffix for tiles
 * * @overlap: %gint set tile overlap
 * * @tile_size: %gint set tile size
 * * @background: #VipsArrayDouble background colour
 * * @depth: #VipsForeignDzDepth how deep to make the pyramid
 * * @centre: %gboolean centre the tiles
 * * @angle: #VipsAngle rotate the image by this much
 * * @container: #VipsForeignDzContainer set container type
 * * @compression: %gint zip deflate compression level
 * * @region_shrink: #VipsRegionShrink how to shrink each 2x2 region.
 * * @skip_blanks: %gint skip tiles which are nearly equal to the background
 * * @id: %gchar id for IIIF properties
 * * @Q: %gint, quality factor
 *
 * As vips_dzsave(), but save to a memory buffer.
 *
 * Output is always in a zip container. Use @basename to set the name of the
 * directory that the zip will create when unzipped.
 *
 * The address of the buffer is returned in @buf, the length of the buffer in
 * @len. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_dzsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_dzsave_buffer(VipsImage *in, void **buf, size_t *len, ...)
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL;

	va_start(ap, len);
	result = vips_call_split("dzsave_buffer", ap, in, &area);
	va_end(ap);

	if (!result &&
		area) {
		if (buf) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if (len)
			*len = area->length;

		vips_area_unref(area);
	}

	return result;
}

/**
 * vips_dzsave_target: (method)
 * @in: image to save
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @basename: %gchar base part of name
 * * @layout: #VipsForeignDzLayout directory layout convention
 * * @suffix: %gchar suffix for tiles
 * * @overlap: %gint set tile overlap
 * * @tile_size: %gint set tile size
 * * @background: #VipsArrayDouble background colour
 * * @depth: #VipsForeignDzDepth how deep to make the pyramid
 * * @centre: %gboolean centre the tiles
 * * @angle: #VipsAngle rotate the image by this much
 * * @container: #VipsForeignDzContainer set container type
 * * @compression: %gint zip deflate compression level
 * * @region_shrink: #VipsRegionShrink how to shrink each 2x2 region.
 * * @skip_blanks: %gint skip tiles which are nearly equal to the background
 * * @id: %gchar id for IIIF properties
 * * @Q: %gint, quality factor
 *
 * As vips_dzsave(), but save to a target.
 *
 * See also: vips_dzsave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_dzsave_target(VipsImage *in, VipsTarget *target, ...)
{
	va_list ap;
	int result;

	va_start(ap, target);
	result = vips_call_split("dzsave_target", ap, in, target);
	va_end(ap);

	return result;
}
