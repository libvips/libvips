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
 *	- did not write low pyramid layers for images with an odd number of
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
 * 	- add dzsave_target
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

   It's failed in the past in these cases. These have layers with strips which
   exactly align with image edges, or which have orphan scanlines which need
   adding for the shrink.

   1.	$ header test.v
	test.v: 14016x16448 uchar, 3 bands, srgb, openin VipsImage (0x11e7060)
	$ time vips dzsave test.v x --overlap 0

	Not all layers written.

   2.	$ header ~/Desktop/leicaimage.scn
	/home/john/Desktop/leicaimage.scn: 4225x7905 uchar, 4 bands, rgb

	Not all layers written.

	3.	$ header ~/leicatest1.scn
	/home/john/leicatest1.scn: 11585x8449 uchar, 4 bands, rgb

	Not all layers written.

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

#ifdef HAVE_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>

static GMutex *vips_libarchive_mutex = NULL;

static ssize_t
zip_write_target_cb(struct archive *a, void *client_data,
	const void *data, size_t length)
{
	VipsTarget *target = VIPS_TARGET(client_data);

	if (vips_target_write(target, data, length))
		return (-1);

	return (length);
}

static int
zip_close_target_cb(struct archive *a, void *client_data)
{
	VipsTarget *target = VIPS_TARGET(client_data);

	if (vips_target_end(target))
		return (ARCHIVE_FATAL);

	return (ARCHIVE_OK);
}

typedef struct _VipsForeignSaveDz VipsForeignSaveDz;
typedef struct _Layer Layer;

/* A layer in the pyramid.
 */
struct _Layer {
	VipsForeignSaveDz *dz;

	/* The real size of the image. image->Xsize and image->Ysize are
	 * always even to make x2 shrink easy. The real image may be a
	 * smaller, odd size,
	 */
	int width;
	int height;

	/* Number of tiles across and down in this layer. Zoomify needs this
	 * to calculate the directory to put each tile in.
	 */
	int tiles_across;
	int tiles_down;

	/* The rect within width/height that contains real image, as opposed
	 * to background. In centre mode we can have large image borders.
	 */
	VipsRect real_pixels;

	/* The image we build.
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

	int sub; /* Subsample factor for this layer */
	int n;	 /* Layer number ... 0 for smallest */

	Layer *below; /* Tiles go to here */
	Layer *above; /* Tiles come from here */
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

	Layer *layer; /* x2 shrink pyr layer */

	/* Count zoomify tiles we write.
	 */
	int tile_count;

	/* The zipfile we are writing tiles to.
	 */
	struct archive *archive;

	/* The name to save as, eg. deepzoom tiles go into ${basename}_files.
	 * No suffix, no path at the start.
	 */
	char *basename;

	/* The directory we write the output to, or "" (empty) for memory output.
	 */
	char *dirname;

	/* The root directory name ... $basename with perhaps some extra
	 * stuff, eg. $(basename)_files, etc.
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
		return (TRUE);

	default:
		return (FALSE);
	}
}

static inline int
vips_mkdir_zip(VipsForeignSaveDz *dz, const char *dirname)
{
	struct archive_entry *entry;

	vips__worker_lock(vips_libarchive_mutex);

	if (!(entry = archive_entry_new())) {
		g_mutex_unlock(vips_libarchive_mutex);
		return (-1);
	}

	archive_entry_set_pathname(entry, dirname);
	archive_entry_set_mode(entry, S_IFDIR | 0755);

	if (archive_write_header(dz->archive, entry) != ARCHIVE_OK) {
		char *utf8name = g_filename_display_name(dirname);
		vips_error("dzsave",
			_("unable to add directory \"%s\", %s"),
			utf8name, archive_error_string(dz->archive));
		g_free(utf8name);
		archive_entry_free(entry);
		g_mutex_unlock(vips_libarchive_mutex);
		return (-1);
	}

	archive_entry_free(entry);
	g_mutex_unlock(vips_libarchive_mutex);

	return (0);
}

static inline int
vips_mkdir_file(const char *dirname)
{
	if (g_mkdir_with_parents(dirname, 0777) &&
		errno != EEXIST) {
		int save_errno = errno;
		char *utf8name = g_filename_display_name(dirname);
		vips_error("dzsave",
			_("unable to create directory \"%s\", %s"),
			utf8name, g_strerror(save_errno));
		g_free(utf8name);
		return (-1);
	}

	return (0);
}

static int
vips_mkdir(VipsForeignSaveDz *dz, const char *dirname)
{
	if (iszip(dz->container))
		return (vips_mkdir_zip(dz, dirname));
	else
		return (vips_mkdir_file(dirname));
}

static inline int
vips_mkfile_zip(VipsForeignSaveDz *dz, const char *filename,
	void *buf, size_t len)
{
	struct archive_entry *entry;

	vips__worker_lock(vips_libarchive_mutex);

	if (!(entry = archive_entry_new())) {
		g_free(buf);
		g_mutex_unlock(vips_libarchive_mutex);
		return (-1);
	}

	archive_entry_set_pathname(entry, filename);
	archive_entry_set_mode(entry, S_IFREG | 0664);
	archive_entry_set_size(entry, len);

	if (archive_write_header(dz->archive, entry) != ARCHIVE_OK) {
		archive_entry_free(entry);
		g_free(buf);
		g_mutex_unlock(vips_libarchive_mutex);
		return (-1);
	}

	archive_entry_free(entry);

	if (archive_write_data(dz->archive, buf, len) != len) {
		g_free(buf);
		g_mutex_unlock(vips_libarchive_mutex);
		return (-1);
	}

	g_free(buf);
	g_mutex_unlock(vips_libarchive_mutex);

	return (0);
}

static inline int
vips_mkfile_file(const char *filename, void *buf, size_t len)
{
	FILE *f;

	if (!(f = vips__file_open_write(filename, TRUE))) {
		g_free(buf);
		return (-1);
	}

	if (fwrite(buf, sizeof(char), len, f) != len) {
		fclose(f);
		g_free(buf);
		return (-1);
	}

	fclose(f);
	g_free(buf);

	return (0);
}

static int
vips_mkfile(VipsForeignSaveDz *dz, const char *filename,
	void *buf, size_t len)
{
	if (iszip(dz->container))
		return (vips_mkfile_zip(dz, filename, buf, len));
	else
		return (vips_mkfile_file(filename, buf, len));
}

static int
write_image(VipsForeignSaveDz *dz,
	VipsImage *image, const char *filename, const char *format)
{
	VipsImage *t;

	/* We need to block progress signalling on individual image write, so
	 * we need a copy of the tile in case it's shared (eg. associated
	 * images).
	 */
	if (vips_copy(image, &t, NULL))
		return (-1);

	/* We default to stripping all metadata. "no_strip" turns this
	 * off. Most people don't want metadata on every tile.
	 */
	vips_image_set_int(t, "hide-progress", 1);

	if (iszip(dz->container)) {
		void *buf;
		size_t len;

		if (vips_image_write_to_buffer(t, format, &buf, &len,
				"strip", !dz->no_strip,
				NULL)) {
			VIPS_UNREF(t);
			return (-1);
		}
		VIPS_UNREF(t);

		/* vips_mkfile_zip() takes the ownership of buf.
		 */
		if (vips_mkfile_zip(dz, filename, buf, len))
			return (-1);
	}
	else {
		if (vips_image_write_to_file(t, filename,
				"strip", !dz->no_strip,
				NULL)) {
			VIPS_UNREF(t);
			return (-1);
		}
		VIPS_UNREF(t);
	}

	return (0);
}

/* Free a pyramid.
 */
static void
layer_free(Layer *layer)
{
	VIPS_FREEF(g_object_unref, layer->strip);
	VIPS_FREEF(g_object_unref, layer->copy);
	VIPS_FREEF(g_object_unref, layer->image);

	VIPS_FREEF(layer_free, layer->below);
}

static void
vips_foreign_save_dz_dispose(GObject *gobject)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) gobject;

	VIPS_FREEF(archive_write_free, dz->archive);

	VIPS_UNREF(dz->target);

	VIPS_FREEF(layer_free, dz->layer);

	VIPS_FREE(dz->basename);
	VIPS_FREE(dz->dirname);
	VIPS_FREE(dz->root_name);
	VIPS_FREE(dz->file_suffix);

	G_OBJECT_CLASS(vips_foreign_save_dz_parent_class)->dispose(gobject);
}

/* Build a pyramid.
 *
 * width/height is the size of this layer, real_* the subsection of the layer
 * which is real pixels (as opposed to background).
 */
static Layer *
pyramid_build(VipsForeignSaveDz *dz, Layer *above,
	int width, int height, VipsRect *real_pixels)
{
	VipsForeignSave *save = VIPS_FOREIGN_SAVE(dz);
	Layer *layer = VIPS_NEW(dz, Layer);

	VipsRect strip;
	int limit;

	layer->dz = dz;
	layer->width = width;
	layer->height = height;

	/* We need to output all possible tiles, even if they give no new pixels.
	 */
	layer->tiles_across = VIPS_ROUND_UP(width, dz->tile_step) /
		dz->tile_step;
	layer->tiles_down = VIPS_ROUND_UP(height, dz->tile_step) /
		dz->tile_step;

	layer->real_pixels = *real_pixels;

	layer->image = NULL;
	layer->strip = NULL;
	layer->copy = NULL;

	if (!above)
		/* Top of pyramid.
		 */
		layer->sub = 1;
	else
		layer->sub = above->sub * 2;

	layer->below = NULL;
	layer->above = above;

	/* We round the image size up to an even number to make x2 shrink
	 * easy.
	 */
	layer->image = vips_image_new();
	if (vips_image_pipelinev(layer->image,
			VIPS_DEMAND_STYLE_ANY, save->ready, NULL)) {
		layer_free(layer);
		return (NULL);
	}
	layer->image->Xsize = width + (width & 1);
	layer->image->Ysize = height + (height & 1);

	layer->strip = vips_region_new(layer->image);
	layer->copy = vips_region_new(layer->image);

	/* The regions will get used in the bg thread callback, so make sure
	 * we don't own them.
	 */
	vips__region_no_ownership(layer->strip);
	vips__region_no_ownership(layer->copy);

	/* Build a line of tiles here.
	 *
	 * Expand the strip if necessary to make sure we have an even
	 * number of lines.
	 *
	 * This is just the height of the first row of tiles, so only add 1*
	 * tile_margin.
	 */
	layer->y = 0;
	layer->write_y = 0;
	strip.left = 0;
	strip.top = 0;
	strip.width = layer->image->Xsize;
	strip.height = dz->tile_size + dz->tile_margin;
	if ((strip.height & 1) == 1)
		strip.height += 1;
	if (vips_region_buffer(layer->strip, &strip)) {
		layer_free(layer);
		return (NULL);
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
		/* Round up, so eg. a 5 pixel wide image becomes 3 a layer
		 * down.
		 *
		 * For the rect, round left/top down, round bottom/right up,
		 * so we get all possible pixels.
		 */
		VipsRect halfrect;

		halfrect.left = real_pixels->left / 2;
		halfrect.top = real_pixels->top / 2;
		halfrect.width = (VIPS_RECT_RIGHT(real_pixels) + 1) / 2 -
			halfrect.left;
		halfrect.height = (VIPS_RECT_BOTTOM(real_pixels) + 1) / 2 -
			halfrect.top;

		if (!(layer->below = pyramid_build(dz, layer,
				  (width + 1) / 2, (height + 1) / 2,
				  &halfrect))) {
			layer_free(layer);
			return (NULL);
		}
		layer->n = layer->below->n + 1;
	}
	else
		layer->n = 0;

#ifdef DEBUG
	printf("pyramid_build:\n");
	printf("\tn = %d\n", layer->n);
	printf("\twidth = %d, height = %d\n", width, height);
	printf("\tXsize = %d, Ysize = %d\n",
		layer->image->Xsize, layer->image->Ysize);
	printf("\ttiles_across = %d, tiles_down = %d\n",
		layer->tiles_across, layer->tiles_down);
	printf("\treal_pixels.left = %d, real_pixels.top = %d\n",
		real_pixels->left, real_pixels->top);
	printf("\treal_pixels.width = %d, real_pixels.height = %d\n",
		real_pixels->width, real_pixels->height);
#endif /*DEBUG*/

	return (layer);
}

static int
write_dzi(VipsForeignSaveDz *dz)
{
	VipsDbuf dbuf;
	char suffix[VIPS_PATH_MAX];
	char *filename;
	char *p;
	void *buf;
	size_t len;

	vips_snprintf(suffix, VIPS_PATH_MAX, "%s.dzi", dz->basename);

	if (!(filename = g_build_filename(dz->dirname, suffix, NULL)))
		return (-1);

	vips_dbuf_init(&dbuf);

	vips_snprintf(suffix, VIPS_PATH_MAX, "%s", dz->suffix + 1);
	if ((p = (char *) vips__find_rightmost_brackets(suffix)))
		*p = '\0';

	vips_dbuf_writef(&dbuf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	vips_dbuf_writef(&dbuf, "<Image "
							"xmlns=\"http://schemas.microsoft.com/deepzoom/2008\"\n");
	vips_dbuf_writef(&dbuf, "  Format=\"%s\"\n", suffix);
	vips_dbuf_writef(&dbuf, "  Overlap=\"%d\"\n", dz->overlap);
	vips_dbuf_writef(&dbuf, "  TileSize=\"%d\"\n", dz->tile_size);
	vips_dbuf_writef(&dbuf, "  >\n");
	vips_dbuf_writef(&dbuf, "  <Size \n");
	vips_dbuf_writef(&dbuf, "    Height=\"%d\"\n", dz->layer->height);
	vips_dbuf_writef(&dbuf, "    Width=\"%d\"\n", dz->layer->width);
	vips_dbuf_writef(&dbuf, "  />\n");
	vips_dbuf_writef(&dbuf, "</Image>\n");

	if (!(buf = vips_dbuf_steal(&dbuf, &len)) ||
		vips_mkfile(dz, filename, buf, len)) {
		g_free(filename);
		return (-1);
	}

	g_free(filename);

	return (0);
}

static int
write_properties(VipsForeignSaveDz *dz)
{
	VipsDbuf dbuf;
	char *filename;
	void *buf;
	size_t len;

	if (!(filename = g_build_filename(dz->dirname, dz->root_name,
			  "ImageProperties.xml", NULL)))
		return (-1);

	vips_dbuf_init(&dbuf);

	vips_dbuf_writef(&dbuf, "<IMAGE_PROPERTIES "
							"WIDTH=\"%d\" HEIGHT=\"%d\" NUMTILES=\"%d\" "
							"NUMIMAGES=\"1\" VERSION=\"1.8\" TILESIZE=\"%d\" />\n",
		dz->layer->width,
		dz->layer->height,
		dz->tile_count,
		dz->tile_size);

	if (!(buf = vips_dbuf_steal(&dbuf, &len)) ||
		vips_mkfile(dz, filename, buf, len)) {
		g_free(filename);
		return (-1);
	}

	g_free(filename);

	return (0);
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
	 * try saving a B_W image as PNG, with disasterous results.
	 */
	bg = (double *) vips_area_get_data(VIPS_AREA(save->background),
		NULL, &n, NULL, NULL);

	if (vips_black(&x, dz->tile_size, dz->tile_size, "bands", n, NULL))
		return (-1);

	ones = vips_area_new_array(G_TYPE_DOUBLE, sizeof(double), n);
	d = (double *) vips_area_get_data(ones, NULL, NULL, NULL, NULL);
	for (i = 0; i < n; i++)
		d[i] = 1.0;

	if (vips_linear(x, &t, d, bg, n, NULL)) {
		vips_area_unref(ones);
		g_object_unref(x);
		return (-1);
	}
	vips_area_unref(ones);
	g_object_unref(x);
	x = t;

	if (!(filename = g_build_filename(dz->dirname, dz->root_name,
			  "blank.png", NULL))) {
		g_object_unref(x);

		return (-1);
	}

	if (write_image(dz, x, filename, ".png")) {
		g_free(filename);
		g_object_unref(x);

		return (-1);
	}

	g_free(filename);
	g_object_unref(x);

	return (0);
}

/* Write IIIF/IIF3 JSON metadata.
 */
static int
write_json(VipsForeignSaveDz *dz)
{
	/* Can be NULL for memory output.
	 */
	const char *name = dz->basename ? dz->basename : "untitled";

	/* dz->file_suffix has a leading "." character.
	 */
	const char *suffix = dz->file_suffix[0] == '.' ? dz->file_suffix + 1 : dz->file_suffix;

	VipsDbuf dbuf;
	char *filename;
	void *buf;
	size_t len;
	int i;

	if (!(filename = g_build_filename(dz->dirname, dz->root_name,
			  "info.json", NULL)))
		return (-1);

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
			name);
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
			name,
			suffix);

	/* "sizes" is needed for the full/ set of untiled images, which we
	 * don't yet support. Leave this commented out for now.

	vips_dbuf_writef( &dbuf,
		"  \"sizes\": [\n" );

	for( i = 0; i < dz->layer->n + 5; i++ ) {
		vips_dbuf_writef( &dbuf,
			"    {\n"
			"      \"width\": %d,\n"
			"      \"height\": \"full\"\n"
			"    }",
				1 << (i + 4) );
		if( i != dz->layer->n - 4 )
			vips_dbuf_writef( &dbuf, "," );
		vips_dbuf_writef( &dbuf, "\n" );
	}

	vips_dbuf_writef( &dbuf,
		"  ],\n" );

	 */

	/* The set of pyramid layers we have written.
	 */
	vips_dbuf_writef(&dbuf,
		"  \"tiles\": [\n"
		"    {\n"
		"      \"scaleFactors\": [\n");

	for (i = 0; i < dz->layer->n; i++) {
		vips_dbuf_writef(&dbuf,
			"        %d",
			1 << i);
		if (i != dz->layer->n - 1)
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
		dz->layer->width,
		dz->layer->height);

	vips_dbuf_writef(&dbuf,
		"}\n");

	if (!(buf = vips_dbuf_steal(&dbuf, &len)) ||
		vips_mkfile(dz, filename, buf, len)) {
		g_free(filename);
		return (-1);
	}

	g_free(filename);

	return (0);
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
		filename = g_build_filename(dz->dirname, dz->root_name,
			"vips-properties.xml", NULL);
	else
		filename = g_build_filename(dz->dirname,
			"vips-properties.xml", NULL);

	if (filename == NULL)
		return (-1);

	if (!(dump = vips__xml_properties(save->ready))) {
		g_free(filename);
		return (-1);
	}

	/* vips_mkfile() takes the ownership of dump.
	 */
	if (vips_mkfile(dz, filename, dump, strlen(dump))) {
		g_free(filename);
		return (-1);
	}

	g_free(filename);

	return (0);
}

static void
build_scan_property(VipsDbuf *dbuf, VipsImage *image,
	const char *vips_name, const char *szi_name)
{
	const char *str;
	GValue value = { 0 };
	GValue save_value = { 0 };
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

	if (!(str = vips_value_get_save_string(&save_value))) {
		g_value_unset(&save_value);
		return;
	}

	if (!g_utf8_validate(str, -1, NULL)) {
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
	vips_dbuf_writef(&dbuf, "<image xmlns=\"http://www.pathozoom.com/szi\""
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

	return ((char *) vips_dbuf_steal(&dbuf, len));
}

static int
write_scan_properties(VipsForeignSaveDz *dz)
{
	VipsForeignSave *save = (VipsForeignSave *) dz;

	char *filename;
	char *dump;
	size_t len;

	if (!(filename = g_build_filename(dz->dirname,
			  "scan-properties.xml", NULL)))
		return (-1);

	if (!(dump = build_scan_properties(save->ready, &len))) {
		g_free(filename);
		return (-1);
	}

	/* vips_mkfile() takes the ownership of dump.
	 */
	if (vips_mkfile(dz, filename, dump, len)) {
		g_free(filename);
		return (-1);
	}

	g_free(filename);

	return (0);
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
		char *dirname;
		char *out;
		char buf[VIPS_PATH_MAX];

		p = field + strlen("openslide.associated.");

		/* Make sure there are no '/' in the filename.
		 */
		if ((q = strrchr(p, '/')))
			p = q + 1;

		if (vips_image_get_image(image, field, &associated))
			return (image);

		if (!(dirname = g_build_filename(dz->dirname,
				  "associated_images", NULL)))
			return (image);

		if (vips_mkdir(dz, dirname)) {
			g_free(dirname);
			return (image);
		}

		vips_snprintf(buf, VIPS_PATH_MAX, "%s.jpg", p);

		if (!(out = g_build_filename(dirname, buf, NULL))) {
			g_free(dirname);
			g_object_unref(associated);

			return (image);
		}
		g_free(dirname);

		if (write_image(dz, associated, out, ".jpg")) {
			g_free(out);
			g_object_unref(associated);

			return (image);
		}

		g_free(out);
		g_object_unref(associated);
	}

	return (NULL);
}

static int
write_associated(VipsForeignSaveDz *dz)
{
	VipsForeignSave *save = (VipsForeignSave *) dz;

	if (vips_image_map(save->ready, write_associated_images, dz))
		return (-1);

	return (0);
}

/* Our state during a threaded write of a strip.
 */
typedef struct _Strip {
	Layer *layer;

	VipsImage *image;

	/* Allocate the next tile on this boundary.
	 */
	int x;
} Strip;

static void
strip_free(Strip *strip)
{
	g_object_unref(strip->image);
}

static void
strip_init(Strip *strip, Layer *layer)
{
	VipsForeignSaveDz *dz = layer->dz;

	VipsRect line, image;

	strip->layer = layer;
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
	image.width = layer->image->Xsize;
	image.height = layer->height;

	line.left = 0;
	line.top = layer->y;
	line.width = image.width;
	line.height = dz->tile_size;
	vips_rect_marginadjust(&line, dz->tile_margin);

	vips_rect_intersectrect(&image, &line, &line);

	if (!(strip->image = vips_image_new_from_memory(
			  VIPS_REGION_ADDR(layer->strip, 0, line.top),
			  VIPS_IMAGE_SIZEOF_LINE(layer->image) * line.height,
			  line.width, line.height,
			  layer->image->Bands, layer->image->BandFmt))) {
		strip_free(strip);
		return;
	}

	/* The strip needs to inherit the layer's metadata.
	 */
	if (vips__image_meta_copy(strip->image, layer->image)) {
		strip_free(strip);
		return;
	}

	/* Type needs to be set so we know how to convert for save correctly.
	 */
	strip->image->Type = layer->image->Type;
}

static int
strip_allocate(VipsThreadState *state, void *a, gboolean *stop)
{
	Strip *strip = (Strip *) a;
	Layer *layer = strip->layer;
	VipsForeignSaveDz *dz = layer->dz;

	VipsRect image;

#ifdef DEBUG_VERBOSE
	printf("strip_allocate\n");
#endif /*DEBUG_VERBOSE*/

	/* We can't test for allocated area empty, since it might just have
	 * bits of the left-hand overlap in and no new pixels. Safest to count
	 * tiles across.
	 */
	if (strip->x / dz->tile_step >= layer->tiles_across) {
		*stop = TRUE;
#ifdef DEBUG_VERBOSE
		printf("strip_allocate: done\n");
#endif /*DEBUG_VERBOSE*/

		return (0);
	}

	image.left = 0;
	image.top = 0;
	image.width = layer->width;
	image.height = layer->height;

	/* Position this tile.
	 */
	state->pos.left = strip->x;
	state->pos.top = layer->y;
	state->pos.width = dz->tile_size;
	state->pos.height = dz->tile_size;
	vips_rect_marginadjust(&state->pos, dz->tile_margin);

	vips_rect_intersectrect(&image, &state->pos, &state->pos);
	state->x = strip->x;
	state->y = layer->y;

	strip->x += dz->tile_step;

	return (0);
}

/* Make an output object for a tile in the current layout.
 */
static char *
tile_name(Layer *layer, int x, int y)
{
	VipsForeignSaveDz *dz = layer->dz;
	VipsForeignSave *save = (VipsForeignSave *) dz;

	char *out;
	char *dirname;
	char name[VIPS_PATH_MAX];
	char subdir[VIPS_PATH_MAX];
	char *suffix;
	Layer *p;
	int n;

	suffix = iszip(dz->container)
		? dz->file_suffix
		: dz->suffix;

	switch (dz->layout) {
	case VIPS_FOREIGN_DZ_LAYOUT_DZ:
		vips_snprintf(subdir, VIPS_PATH_MAX, "%d", layer->n);
		vips_snprintf(name, VIPS_PATH_MAX,
			"%d_%d%s", x, y, suffix);

		break;

	case VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY:
		/* We need to work out the tile number so we can calculate the
		 * directory to put this tile in.
		 *
		 * Tiles are numbered from 0 for the most-zoomed-out tile.
		 */
		n = 0;

		/* Count all tiles in layers below this one.
		 */
		for (p = layer->below; p; p = p->below)
			n += p->tiles_across * p->tiles_down;

		/* And count tiles so far in this layer.
		 */
		n += y * layer->tiles_across + x;

		vips_snprintf(subdir, VIPS_PATH_MAX, "TileGroup%d", n / 256);
		vips_snprintf(name, VIPS_PATH_MAX,
			"%d-%d-%d%s", layer->n, x, y, suffix);

		/* Used at the end in ImageProperties.xml
		 */
		dz->tile_count += 1;

		break;

	case VIPS_FOREIGN_DZ_LAYOUT_GOOGLE:
		vips_snprintf(subdir, VIPS_PATH_MAX,
			"%d" G_DIR_SEPARATOR_S "%d", layer->n, y);
		vips_snprintf(name, VIPS_PATH_MAX,
			"%d%s", x, suffix);

		break;

	case VIPS_FOREIGN_DZ_LAYOUT_IIIF:
	case VIPS_FOREIGN_DZ_LAYOUT_IIIF3: {
		/* Tiles are addressed in full resolution coordinates, so
		 * scale up by layer->sub and dz->tile_size
		 *
		 * We always clip against the full-sized image, not the scaled
		 * up layer.
		 *
		 * This will break for overlap != 0, but hopefully no one will
		 * ever use that.
		 */
		int left = x * dz->tile_size * layer->sub;
		int top = y * dz->tile_size * layer->sub;
		int width = VIPS_MIN(dz->tile_size * layer->sub,
			save->ready->Xsize - left);
		int height = VIPS_MIN(dz->tile_size * layer->sub,
			save->ready->Ysize - top);

		/* Rotation is always 0.
		 */
		int rotation = 0;

		if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_IIIF3) {
			int xsize = VIPS_MIN(dz->tile_size,
				layer->width - x * dz->tile_size);
			int ysize = VIPS_MIN(dz->tile_size,
				layer->height - y * dz->tile_size);

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
				layer->width - x * dz->tile_size);

			vips_snprintf(subdir, VIPS_PATH_MAX,
				"%d,%d,%d,%d" G_DIR_SEPARATOR_S "%d," G_DIR_SEPARATOR_S "%d",
				left, top, width, height,
				size,
				rotation);
		}

		vips_snprintf(name, VIPS_PATH_MAX, "default%s", suffix);
	}

	break;

	default:
		g_assert_not_reached();
	}

	if (!(dirname = g_build_filename(dz->dirname, dz->root_name,
			  subdir, NULL)))
		return (NULL);

	if (vips_mkdir(dz, dirname)) {
		g_free(dirname);
		return (NULL);
	}

	out = g_build_filename(dirname, name, NULL);
	g_free(dirname);

#ifdef DEBUG_VERBOSE
	printf("tile_name: writing to %s\n", out);
#endif /*DEBUG_VERBOSE*/

	return (out);
}

/* Test for tile nearly equal to background colour. In google maps mode, we
 * skip blank background tiles.
 *
 * Don't use exactly equality since compression artefacts or noise can upset
 * this.
 */
static gboolean
tile_equal(VipsImage *image, int threshold, VipsPel *restrict ink)
{
	const int bytes = VIPS_IMAGE_SIZEOF_PEL(image);

	VipsRect rect;
	VipsRegion *region;
	int x, y, b;

	region = vips_region_new(image);

	/* We know @image is part of a memory buffer, so this will be quick.
	 */
	rect.left = 0;
	rect.top = 0;
	rect.width = image->Xsize;
	rect.height = image->Ysize;
	if (vips_region_prepare(region, &rect)) {
		g_object_unref(region);
		return (FALSE);
	}

	for (y = 0; y < image->Ysize; y++) {
		VipsPel *restrict p = VIPS_REGION_ADDR(region, 0, y);

		for (x = 0; x < image->Xsize; x++) {
			for (b = 0; b < bytes; b++)
				if (VIPS_ABS(p[b] - ink[b]) > threshold) {
					g_object_unref(region);
					return (FALSE);
				}

			p += bytes;
		}
	}

	g_object_unref(region);

	return (TRUE);
}

static int
strip_work(VipsThreadState *state, void *a)
{
	Strip *strip = (Strip *) a;
	Layer *layer = strip->layer;
	VipsForeignSaveDz *dz = layer->dz;
	VipsForeignSave *save = (VipsForeignSave *) dz;

	VipsImage *x;
	VipsImage *t;
	char *out;

#ifdef DEBUG_VERBOSE
	printf("strip_work\n");
#endif /*DEBUG_VERBOSE*/

	/* killed is checked by sink_disc, but that's only once per strip, and
	 * they can be huge. Check per output tile as well.
	 */
	if (vips_image_iskilled(save->in))
		return (-1);

	/* If we are centering we may be outside the real pixels. Skip in
	 * this case, and the viewer will display blank.png for us.
	 */
	if (dz->centre) {
		VipsRect tile;

		tile.left = state->x;
		tile.top = state->y;
		tile.width = dz->tile_size;
		tile.height = dz->tile_size;
		if (!vips_rect_overlapsrect(&tile, &layer->real_pixels)) {
#ifdef DEBUG_VERBOSE
			printf("strip_work: skipping tile %d x %d\n",
				state->x / dz->tile_size,
				state->y / dz->tile_size);
#endif /*DEBUG_VERBOSE*/

			return (0);
		}
	}

	g_assert(vips_object_sanity(VIPS_OBJECT(strip->image)));

	/* Extract relative to the strip top-left corner.
	 */
	if (vips_extract_area(strip->image, &x,
			state->pos.left, 0,
			state->pos.width, state->pos.height, NULL))
		return (-1);

	if (dz->skip_blanks >= 0 &&
		tile_equal(x, dz->skip_blanks, dz->ink)) {
		g_object_unref(x);

#ifdef DEBUG_VERBOSE
		printf("strip_work: skipping blank tile %d x %d\n",
			state->x / dz->tile_size,
			state->y / dz->tile_size);
#endif /*DEBUG_VERBOSE*/

		return (0);
	}

	/* Google tiles need to be padded up to tilesize.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE) {
		if (vips_embed(x, &t, 0, 0, dz->tile_size, dz->tile_size,
				"background", save->background,
				NULL)) {
			g_object_unref(x);
			return (-1);
		}
		g_object_unref(x);

		x = t;
	}

	out = tile_name(layer,
		state->x / dz->tile_step, state->y / dz->tile_step);

	/* g_build_filename() can return NULL when it exceeds the path limits.
	 */
	if (out == NULL) {
		g_object_unref(x);

		return (-1);
	}

	vips_image_set_int(x, VIPS_META_CONCURRENCY, 1);

	if (write_image(dz, x, out, dz->suffix)) {
		g_free(out);
		g_object_unref(x);

		return (-1);
	}

	g_free(out);
	g_object_unref(x);

#ifdef DEBUG_VERBOSE
	printf("strip_work: success\n");
#endif /*DEBUG_VERBOSE*/

	return (0);
}

/* Write a line of tiles with a threadpool.
 */
static int
strip_save(Layer *layer)
{
	Strip strip;

#ifdef DEBUG
	printf("strip_save: n = %d, y = %d\n", layer->n, layer->y);
#endif /*DEBUG*/

	strip_init(&strip, layer);
	if (vips_threadpool_run(strip.image,
			vips_thread_state_new, strip_allocate, strip_work, NULL,
			&strip)) {
		strip_free(&strip);
		return (-1);
	}
	strip_free(&strip);

#ifdef DEBUG
	printf("strip_save: success\n");
#endif /*DEBUG*/

	return (0);
}

/* A strip has filled, but the rightmost column and the bottom-most row may
 * not have been if we've rounded the size up.
 *
 * Fill them, if necessary, by copying the previous row/column.
 */
static void
layer_generate_extras(Layer *layer)
{
	VipsRegion *strip = layer->strip;

	/* We only work for full-width strips.
	 */
	g_assert(strip->valid.width == layer->image->Xsize);

	if (layer->width < layer->image->Xsize) {
		int ps = VIPS_IMAGE_SIZEOF_PEL(strip->im);

		int b, y;

		/* Need to add a right-most column.
		 */
		for (y = 0; y < strip->valid.height; y++) {
			VipsPel *p = VIPS_REGION_ADDR(strip,
				layer->width - 1, strip->valid.top + y);
			VipsPel *q = p + ps;

			for (b = 0; b < ps; b++)
				q[b] = p[b];
		}
	}

	if (layer->height < layer->image->Ysize) {
		VipsRect last;

		/* The last two lines of the image.
		 */
		last.left = 0;
		last.top = layer->image->Ysize - 2;
		last.width = layer->image->Xsize;
		last.height = 2;

		/* Do we have them both? Fill the last with the next-to-last.
		 */
		vips_rect_intersectrect(&last, &strip->valid, &last);
		if (last.height == 2) {
			last.height = 1;

			vips_region_copy(strip, strip, &last,
				0, last.top + 1);
		}
	}
}

static int strip_arrived(Layer *layer);

/* Shrink what pixels we can from this strip into the layer below. If the
 * strip below fills, recurse.
 */
static int
strip_shrink(Layer *layer)
{
	Layer *below = layer->below;
	VipsRegion *from = layer->strip;
	VipsRegion *to = below->strip;
	VipsForeignSaveDz *dz = layer->dz;
	VipsRegionShrink region_shrink = dz->region_shrink;

	VipsRect target;
	VipsRect source;

#ifdef DEBUG
	printf("strip_shrink: %d lines in layer %d to layer %d\n",
		from->valid.height, layer->n, below->n);
#endif /*DEBUG*/

	/* We may have an extra column of pixels on the right or
	 * bottom that need filling: generate them.
	 */
	layer_generate_extras(layer);

	/* Our pixels might cross a strip boundary in the layer below, so we
	 * have to write repeatedly until we run out of pixels.
	 */
	for (;;) {
		/* The pixels the layer below needs.
		 */
		target.left = 0;
		target.top = below->write_y;
		target.width = below->image->Xsize;
		target.height = to->valid.height;
		vips_rect_intersectrect(&target, &to->valid, &target);

		/* Those pixels need this area of this layer.
		 */
		source.left = target.left * 2;
		source.top = target.top * 2;
		source.width = target.width * 2;
		source.height = target.height * 2;

		/* Of which we have these available.
		 */
		vips_rect_intersectrect(&source, &from->valid, &source);

		/* So these are the pixels in the layer below we can provide.
		 */
		target.left = source.left / 2;
		target.top = source.top / 2;
		target.width = source.width / 2;
		target.height = source.height / 2;

		/* None? All done.
		 */
		if (vips_rect_isempty(&target))
			break;

		(void) vips_region_shrink_method(from, to,
			&target, region_shrink);

		below->write_y += target.height;

		/* If we've filled the strip below, let it know.
		 * We can either fill the region, if it's somewhere half-way
		 * down the image, or, if it's at the bottom, get to the last
		 * real line of pixels.
		 */
		if (below->write_y == VIPS_RECT_BOTTOM(&to->valid) ||
			below->write_y == below->height) {
			if (strip_arrived(below))
				return (-1);
		}
	}

	return (0);
}

/* A new strip has arrived! The strip has enough pixels in to write a line of
 * tiles.
 *
 * - write a line of tiles
 * - shrink what we can to the layer below
 * - move our strip down by the tile step
 * - copy the overlap with the previous strip
 */
static int
strip_arrived(Layer *layer)
{
	VipsForeignSaveDz *dz = layer->dz;

	VipsRect new_strip;
	VipsRect overlap;
	VipsRect image_area;

#ifdef DEBUG
	printf("strip_arrived: layer %d, strip at %d, height %d\n",
		layer->n, layer->y, layer->strip->valid.height);
#endif /*DEBUG*/

	if (strip_save(layer))
		return (-1);

	if (layer->below &&
		strip_shrink(layer))
		return (-1);

	/* Position our strip down the image.
	 *
	 * Expand the strip if necessary to make sure we have an even
	 * number of lines.
	 */
	layer->y += dz->tile_step;
	new_strip.left = 0;
	new_strip.top = layer->y - dz->tile_margin;
	new_strip.width = layer->image->Xsize;
	new_strip.height = dz->tile_size + 2 * dz->tile_margin;

	image_area.left = 0;
	image_area.top = 0;
	image_area.width = layer->image->Xsize;
	image_area.height = layer->image->Ysize;
	vips_rect_intersectrect(&new_strip, &image_area, &new_strip);

	if ((new_strip.height & 1) == 1)
		new_strip.height += 1;

	/* We may exactly hit the bottom of the real image (ie. before borders
	 * have been possibly expanded by 1 pixel). In this case, we'll not
	 * be able to do the expansion in layer_generate_extras(), since the
	 * region won't be large enough, and we'll not get another chance
	 * since this is the bottom.
	 *
	 * Add another scanline if this has happened.
	 */
	if (VIPS_RECT_BOTTOM(&new_strip) == layer->height)
		new_strip.height = layer->image->Ysize - new_strip.top;

	/* What pixels that we will need do we already have? Save them in
	 * overlap.
	 */
	vips_rect_intersectrect(&new_strip, &layer->strip->valid, &overlap);
	if (!vips_rect_isempty(&overlap)) {
		if (vips_region_buffer(layer->copy, &overlap))
			return (-1);
		vips_region_copy(layer->strip, layer->copy,
			&overlap, overlap.left, overlap.top);
	}

	if (!vips_rect_isempty(&new_strip)) {
		if (vips_region_buffer(layer->strip, &new_strip))
			return (-1);

		/* And copy back again.
		 */
		if (!vips_rect_isempty(&overlap))
			vips_region_copy(layer->copy, layer->strip,
				&overlap, overlap.left, overlap.top);
	}

	return (0);
}

/* The image has been completely written. Flush any strips which might have
 * overlaps in.
 */
static int
strip_flush(Layer *layer)
{
	if (layer->y < layer->height)
		if (strip_save(layer))
			return (-1);

	if (layer->below)
		if (strip_flush(layer->below))
			return (-1);

	return (0);
}

/* Another strip of image pixels from vips_sink_disc(). Write into the top
 * pyramid layer.
 */
static int
pyramid_strip(VipsRegion *region, VipsRect *area, void *a)
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) a;
	Layer *layer = dz->layer;

#ifdef DEBUG
	printf("pyramid_strip: strip at %d, height %d\n",
		area->top, area->height);
#endif /*DEBUG*/

	for (;;) {
		VipsRect *to = &layer->strip->valid;
		VipsRect target;

		/* The bit of strip that needs filling.
		 */
		target.left = 0;
		target.top = layer->write_y;
		target.width = layer->image->Xsize;
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
		vips_region_copy(region, layer->strip,
			&target, target.left, target.top);

		layer->write_y += target.height;

		/* We can either fill the strip, if it's somewhere half-way
		 * down the image, or, if it's at the bottom, get to the last
		 * real line of pixels.
		 */
		if (layer->write_y == VIPS_RECT_BOTTOM(to) ||
			layer->write_y == layer->height) {
			if (strip_arrived(layer))
				return (-1);
		}
	}

	/* If we've reached the bottom of the image, we won't get called again.
	 *
	 * However, there may be some unwritten pixels in the pyramid still!
	 * Suppose a layer is exactly a multiple of tile_step in height.
	 * When we finished that last strip, we will have copied the last few
	 * lines of overlap over into the top of the next row. Deepzoom says we
	 * must flush these half-written strips to the output.
	 */
	if (layer->write_y == layer->height) {
#ifdef DEBUG
		printf("pyramid_strip: flushing ..\n");
#endif /*DEBUG*/

		if (strip_flush(layer))
			return (-1);
	}

	return (0);
}

static int
vips_foreign_save_dz_build(VipsObject *object)
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) object;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(dz);

	VipsRect real_pixels;
	char *p;

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
		return (-1);
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

	if (VIPS_OBJECT_CLASS(vips_foreign_save_dz_parent_class)->build(object))
		return (-1);

	/* Optional rotate.
	 */
	{
		VipsImage *z;

		if (vips_rot(save->ready, &z, dz->angle, NULL))
			return (-1);

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
			return (-1);
	}

	/* The real pixels we have from our input. This is about to get
	 * expanded with background.
	 */
	real_pixels.left = 0;
	real_pixels.top = 0;
	real_pixels.width = save->ready->Xsize;
	real_pixels.height = save->ready->Ysize;

	/* For centred images, imagine shrinking so that the image fits in a
	 * single tile, centering in that tile, then expanding back again.
	 */
	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE &&
		dz->centre) {
		VipsImage *z;
		Layer *layer;
		int n_layers;
		int size;

		if (!(layer = pyramid_build(dz, NULL,
				  save->ready->Xsize, save->ready->Ysize,
				  &real_pixels)))
			return (-1);
		n_layers = layer->n;
		/* This would cause interesting problems.
		 */
		g_assert(n_layers < 30);
		layer_free(layer);
		size = dz->tile_size * (1 << n_layers);

		real_pixels.left = (size - save->ready->Xsize) / 2;
		real_pixels.top = (size - save->ready->Ysize) / 2;

		if (vips_embed(save->ready, &z,
				real_pixels.left, real_pixels.top,
				size, size,
				"background", save->background,
				NULL))
			return (-1);

		VIPS_UNREF(save->ready);
		save->ready = z;

#ifdef DEBUG
		printf("centre: centring within a %d x %d image\n",
			size, size);
#endif /*DEBUG*/
	}

#ifdef DEBUG
	printf("vips_foreign_save_dz_build: tile_size == %d\n",
		dz->tile_size);
	printf("vips_foreign_save_dz_build: overlap == %d\n",
		dz->overlap);
	printf("vips_foreign_save_dz_build: tile_margin == %d\n",
		dz->tile_margin);
	printf("vips_foreign_save_dz_build: tile_step == %d\n",
		dz->tile_step);
#endif /*DEBUG*/

	/* Init basename and dirname from the associated filesystem names, if
	 * we can.
	 */
	{
		const char *filename = dz->filename ? dz->filename : vips_connection_filename(VIPS_CONNECTION(dz->target));

		if (!vips_object_argument_isset(object, "basename")) {
			if (filename)
				dz->basename = g_path_get_basename(filename);
			else
				dz->basename = g_strdup("untitled");
		}

		if (!vips_object_argument_isset(object, "dirname")) {
			if (filename)
				dz->dirname = g_path_get_dirname(filename);
			else
				dz->dirname = g_strdup(".");
		}
	}

	/* Remove any [options] from basename.
	 */
	if ((p = (char *) vips__find_rightmost_brackets(dz->basename)))
		*p = '\0';

	/* If we're writing thing.zip or thing.szi, default to zip
	 * container.
	 */
	if ((p = strrchr(dz->basename, '.'))) {
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
	if (!(dz->layer = pyramid_build(dz, NULL,
			  save->ready->Xsize, save->ready->Ysize, &real_pixels)))
		return (-1);

	if (dz->layout == VIPS_FOREIGN_DZ_LAYOUT_DZ)
		dz->root_name = g_strdup_printf("%s_files", dz->basename);
	else
		dz->root_name = g_strdup(dz->basename);

	/* Drop any [options] from @suffix.
	 */
	dz->file_suffix = g_strdup(dz->suffix);
	if ((p = (char *) vips__find_rightmost_brackets(dz->file_suffix)))
		*p = '\0';

	/* Make the zip archive we write the tiles into.
	 */
	if (iszip(dz->container)) {
		/* Ignore the root directory name for zip output, it should only
		 * be set for filesystem output.
		 */
		VIPS_SETSTR(dz->dirname, "");

		/* We can have dzsave("x.zip", container="fs"), ie. zip output
		 * from write to file. Make a target if we need one.
		 */
		if (!dz->target) {
			if (!(dz->target =
						vips_target_new_to_file(dz->filename)))
				return (-1);
		}

		/* Allocate and initialize a new archive.
		 */
		if (!(dz->archive = archive_write_new()))
			return (-1);

		/* Set format to zip.
		 */
		if (archive_write_set_format(dz->archive,
				ARCHIVE_FORMAT_ZIP) != ARCHIVE_OK) {
			archive_write_free(dz->archive);
			return (-1);
		}

		/* Remap compression=-1 to compression=6.
		 */
		if (dz->compression == -1)
			dz->compression = 6; /* Z_DEFAULT_COMPRESSION */

			/* Deflate compression requires libarchive >= v3.2.0.
			 * https://github.com/libarchive/libarchive/pull/84
			 */
#if ARCHIVE_VERSION_NUMBER >= 3002000
		/* Set deflate compression level.
		 */
		char compression_string[2] = { '0' + dz->compression, 0 };
		if (archive_write_set_format_option(dz->archive, "zip",
				"compression-level", compression_string) != ARCHIVE_OK) {
			archive_write_free(dz->archive);
			return (-1);
		}
#else
		if (dz->compression > 0)
			g_warning(
				"%s: libarchive >= v3.2.0 required for Deflate compression",
				class->nickname);
#endif

		/* Do not pad last block.
		 */
		if (archive_write_set_bytes_in_last_block(dz->archive, 1)) {
			archive_write_free(dz->archive);
			return (-1);
		}

		/* Register target callback functions.
		 */
		if (archive_write_open(dz->archive, dz->target, NULL,
				zip_write_target_cb, zip_close_target_cb) != ARCHIVE_OK) {
			archive_write_free(dz->archive);
			return (-1);
		}
	}

	if (vips_sink_disc(save->ready, pyramid_strip, dz))
		return (-1);

	switch (dz->layout) {
	case VIPS_FOREIGN_DZ_LAYOUT_DZ:
		if (write_dzi(dz))
			return (-1);
		break;

	case VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY:
		if (write_properties(dz))
			return (-1);
		break;

	case VIPS_FOREIGN_DZ_LAYOUT_GOOGLE:
		if (write_blank(dz))
			return (-1);
		break;

	case VIPS_FOREIGN_DZ_LAYOUT_IIIF:
	case VIPS_FOREIGN_DZ_LAYOUT_IIIF3:
		if (write_json(dz))
			return (-1);
		break;

	default:
		g_assert_not_reached();
	}

	if (write_vips_meta(dz))
		return (-1);

	if (dz->container == VIPS_FOREIGN_DZ_CONTAINER_SZI &&
		write_scan_properties(dz))
		return (-1);

	if (dz->container == VIPS_FOREIGN_DZ_CONTAINER_SZI &&
		write_associated(dz))
		return (-1);

	/* Shut down the output to flush everything.
	 */
	if (iszip(dz->container) &&
		archive_write_close(dz->archive))
		return (-1);

	return (0);
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

static void *
vips_foreign_save_dz_once_init(void *client)
{
	vips_libarchive_mutex = vips_g_mutex_new();

	return (NULL);
}

static void
vips_foreign_save_dz_class_init(VipsForeignSaveDzClass *class)
{
	static GOnce once = G_ONCE_INIT;

	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	VIPS_ONCE(&once, vips_foreign_save_dz_once_init, NULL);

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

	VIPS_ARG_STRING(class, "basename", 2,
		_("Base name"),
		_("Base name to save to"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, basename),
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

	VIPS_ARG_BOOL(class, "no_strip", 20,
		_("No strip"),
		_("Don't strip tile metadata"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, no_strip),
		FALSE);

	VIPS_ARG_STRING(class, "id", 21,
		_("id"),
		_("Resource ID"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveDz, id),
		"https://example.com/iiif");

	/* How annoying. We stupidly had these in earlier versions.
	 */

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

	if (VIPS_OBJECT_CLASS(vips_foreign_save_dz_target_parent_class)->build(object))
		return (-1);

	return (0);
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

	if (VIPS_OBJECT_CLASS(vips_foreign_save_dz_file_parent_class)->build(object))
		return (-1);

	return (0);
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
		return (-1);

	if (VIPS_OBJECT_CLASS(vips_foreign_save_dz_buffer_parent_class)->build(object))
		return (-1);

	g_object_get(dz->target, "blob", &blob, NULL);
	g_object_set(buffer, "buffer", blob, NULL);
	vips_area_unref(VIPS_AREA(blob));

	return (0);
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
 * * @no_strip: %gboolean don't strip tiles
 * * @id: %gchar id for IIIF properties
 *
 * Save an image as a set of tiles at various resolutions. By default dzsave
 * uses DeepZoom layout -- use @layout to pick other conventions.
 *
 * vips_dzsave() creates a directory called @name to hold the tiles. If @name
 * ends `.zip`, vips_dzsave() will create a zip file called @name to hold the
 * tiles. You can use @container to force zip file output.
 *
 * Use @basename to set the name of the directory tree we are creating. The
 * default value is set from @name.
 *
 * You can set @suffix to something like `".jpg[Q=85]"` to control the tile
 * write options.
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
 * all metadata in every tile. Set @no_strip if you want to keep metadata.
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

	return (result);
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
 * * @no_strip: %gboolean don't strip tiles
 * * @id: %gchar id for IIIF properties
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

	return (result);
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
 * * @no_strip: %gboolean don't strip tiles
 * * @id: %gchar id for IIIF properties
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

	return (result);
}
