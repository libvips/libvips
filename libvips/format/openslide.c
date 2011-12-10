/* Read a virtual microscope slide using OpenSlide.
 *
 * Benjamin Gilbert
 *
 * Copyright (c) 2011 Carnegie Mellon University
 *
 * 26/11/11
 *	- initial version
 * 27/11/11
 *	- fix black background in transparent areas
 *	- no need to set *stop on fill_region() error return
 *	- add OpenSlide properties to image metadata
 *	- consolidate setup into one function
 *	- support reading arbitrary layers
 *	- use VIPS_ARRAY()
 *	- add helper to copy a line of pixels
 *	- support reading associated images
 * 7/12/11
 *	- redirect OpenSlide error logging to vips_error()
 * 8/12/11
 *	- add more exposition to documentation
 * 9/12/11
 * 	- unpack to a tile cache
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_OPENSLIDE

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include <openslide.h>

typedef struct {
	openslide_t *osr;
	uint32_t background;
	const char *associated;

	/* Only valid if associated == NULL.
	 */
	int32_t layer;
	double downsample;
} ReadSlide;

static void
readslide_destroy_cb( VipsImage *image, ReadSlide *rslide )
{
	VIPS_FREEF( openslide_close, rslide->osr );
}

static int
check_associated_image( openslide_t *osr, const char *name )
{
	const char * const *associated;

	for( associated = openslide_get_associated_image_names( osr );
		*associated != NULL; associated++ )
		if( strcmp( *associated, name ) == 0 )
			return( 0 );

	vips_error( "im_openslide2vips", 
		"%s", _( "invalid associated image name" ) );

	return( -1 );
}

static ReadSlide *
readslide_new( const char *filename, VipsImage *out )
{
	ReadSlide *rslide;
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	const char *background;
	char *endp;
	int64_t w, h;
	const char * const *properties;
	char *associated;

	rslide = VIPS_NEW( out, ReadSlide );
	memset( rslide, 0, sizeof( *rslide ) );
	g_signal_connect( out, "close", G_CALLBACK( readslide_destroy_cb ),
		rslide );

	vips_filename_split( filename, name, mode );
	rslide->osr = openslide_open( name );
	if( rslide->osr == NULL ) {
		vips_error( "im_openslide2vips", 
			"%s", _( "failure opening slide" ) );
		return( NULL );
	}

	background = openslide_get_property_value( rslide->osr,
		OPENSLIDE_PROPERTY_NAME_BACKGROUND_COLOR );
	if( background != NULL )
		rslide->background = strtoul( background, NULL, 16 );
	else
		rslide->background = 0xffffff;

	/* Parse optional mode.
	 */
	rslide->layer = strtol( mode, &endp, 10 );
	if( *mode != 0 && *endp == 0 ) {
		/* Mode specifies slide layer.
		 */
		if( rslide->layer < 0 || rslide->layer >=
			openslide_get_layer_count( rslide->osr ) ) {
			vips_error( "im_openslide2vips",
				"%s", _( "invalid slide layer" ) );
			return( NULL );
		}
	} 
	else if( *mode != 0 ) {
		/* Mode specifies associated image.
		 */
		if ( check_associated_image( rslide->osr, mode ) )
			return( NULL );
		rslide->associated = vips_strdup( VIPS_OBJECT( out ), mode );
	}

	if( rslide->associated ) {
		openslide_get_associated_image_dimensions( rslide->osr,
			rslide->associated, &w, &h );
		vips_image_set_string( out, "slide-associated-image",
			rslide->associated );
	} 
	else {
		openslide_get_layer_dimensions( rslide->osr, rslide->layer,
			&w, &h );
		rslide->downsample = openslide_get_layer_downsample(
			rslide->osr, rslide->layer );
		vips_image_set_int( out, "slide-layer", rslide->layer );
	}
	if( w < 0 || h < 0 || rslide->downsample < 0 ) {
		vips_error( "im_openslide2vips", _( "getting dimensions: %s" ),
			openslide_get_error( rslide->osr ) );
		return( NULL );
	}
	if( w > INT_MAX || h > INT_MAX ) {
		vips_error( "im_openslide2vips",
			"%s", _( "image dimensions overflow int" ) );
		return( NULL );
	}

	vips_image_init_fields( out, (int) w, (int) h, 4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_RGB, 1.0, 1.0 );

	for( properties = openslide_get_property_names( rslide->osr );
		*properties != NULL; properties++ )
		vips_image_set_string( out, *properties,
			openslide_get_property_value( rslide->osr,
			*properties ) );

	associated = g_strjoinv( ", ", (char **)
		openslide_get_associated_image_names( rslide->osr ) );
	vips_image_set_string( out, "slide-associated-images", associated );
	g_free( associated );

	return( rslide );
}

/* The maximum size of the tiles we read from OpenSlide. It can fail with
 * very large tile shapes (eg. 78000 x 1). Also, limiting the tile size means
 * we can have a per-thread buffer for unpacking.
 */
#define TILE_WIDTH (256)
#define TILE_HEIGHT (256)

/* Allocate a per-thread tile buffer. 
 */
static void *
seq_start( VipsImage *out, void *a, void *b )
{
	return( (void *) VIPS_ARRAY( NULL, 
			TILE_WIDTH * TILE_HEIGHT, uint32_t ) );
}

static void
copy_line( ReadSlide *rslide, uint32_t *in, int count, PEL *out )
{
	int i;

	for( i = 0; i < count; i++ ) {
		uint32_t x = in[i];
		uint8_t a = x >> 24;

		/* Convert from ARGB to RGBA and undo premultiplication.
		 */
		if( a != 0 ) {
			out[0] = 255 * ((x >> 16) & 255) / a;
			out[1] = 255 * ((x >> 8) & 255) / a;
			out[2] = 255 * (x & 255) / a;
		} 
		else {
			/* Use background color.
			 */
			out[0] = (rslide->background >> 16) & 255;
			out[1] = (rslide->background >> 8) & 255;
			out[2] = rslide->background & 255;
		}
		out[3] = a;

		out += 4;
	}
}

static int
fill_region( VipsRegion *out, void *seq, void *_rslide, void *unused,
	gboolean *stop )
{
	ReadSlide *rslide = _rslide;
	uint32_t *buf = (uint32_t *) seq;
	VipsRect *r = &out->valid;

	const char *error;
	int x, y, z;

	VIPS_DEBUG_MSG( "fill_region: %dx%d @ %dx%d\n",
		r->width, r->height, r->left, r->top );

	/* Loop over the region to be filled calling openslide_read_region().
	 */
	for( y = 0; y < r->height; y += TILE_HEIGHT ) 
		for( x = 0; x < r->width; x += TILE_WIDTH ) {
			int w = VIPS_MIN( TILE_WIDTH, r->width - x );
			int h = VIPS_MIN( TILE_HEIGHT, r->height - y );

			openslide_read_region( rslide->osr, 
				/* or read directly to the output with this:
				VIPS_REGION_ADDR( out, 
					r->left + x, 
					r->top + y ),
				 */
				buf,
				(r->left + x) * rslide->downsample, 
				(r->top + y) * rslide->downsample, 
				rslide->layer,
				w, h ); 

			for( z = 0; z < h; z++ )
				copy_line( rslide, 
					buf + z * w,
					w,
					VIPS_REGION_ADDR( out, 
						r->left + x, 
						r->top + y + z ) ); 
		}

	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "im_openslide2vips", _( "reading region: %s" ),
			error );
		return( -1 );
	}

	return( 0 );
}

static int
seq_stop( void *seq, void *a, void *b )
{
	vips_free( seq );

	return( 0 );
}

static int
fill_associated( VipsImage *out, ReadSlide *rslide )
{
	uint32_t *buf;
	PEL *line;
	int64_t w, h;
	int y;
	const char *error;

	openslide_get_associated_image_dimensions( rslide->osr,
		rslide->associated, &w, &h );
	if( w == -1 || h == -1 ) {
		vips_error( "im_openslide2vips", _( "getting dimensions: %s" ),
			openslide_get_error( rslide->osr ) );
		return( -1 );
	}

	buf = VIPS_ARRAY( out, w * h, uint32_t );
	line = VIPS_ARRAY( out, VIPS_IMAGE_SIZEOF_LINE( out ), PEL );
	openslide_read_associated_image( rslide->osr, rslide->associated,
		buf );
	for( y = 0; y < h; y++ ) {
		copy_line( rslide, buf + y * w, w, line );
		if( vips_image_write_line( out, y, line ) ) 
			return( -1 );
	}

	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "im_openslide2vips",
			_( "reading associated image: %s" ), error );
		return( -1 );
	}

	return( 0 );
}

static int
openslide2vips_header( const char *filename, VipsImage *out )
{
	ReadSlide *rslide;

	if( !(rslide = readslide_new( filename, out )) )
		return( -1 );

	return( 0 );
}

/**
 * im_openslide2vips:
 * @filename: file to load
 * @out: image to write to
 *
 * Read a virtual slide supported by the OpenSlide library into a VIPS image.
 * OpenSlide supports images in Aperio, Hamamatsu VMS, Hamamatsu VMU, MIRAX,
 * and Trestle formats.  It also supports generic tiled TIFF images, but
 * im_openslide2vips() does not.
 *
 * To facilitate zooming, virtual slide formats include multiple scaled-down
 * versions of the high-resolution image.  These are typically called
 * "levels", though OpenSlide and im_openslide2vips() call them "layers".
 * By default, im_openslide2vips() reads the highest-resolution layer
 * (layer 0).  To read a different layer, specify the layer number as part
 * of the filename (for example, "CMU-1.mrxs:3").
 *
 * In addition to the slide image itself, virtual slide formats sometimes
 * include additional images, such as a scan of the slide's barcode.
 * OpenSlide calls these "associated images".  To read an associated image,
 * specify the image's name as part of the filename (for example,
 * "CMU-1.mrxs:label").  A slide's associated images are listed in the
 * "slide-associated-images" metadata item.
 *
 * See also: #VipsFormat
 *
 * Returns: 0 on success, -1 on error.
 */
static int
im_openslide2vips( const char *filename, VipsImage *out )
{
	ReadSlide *rslide;
	VipsImage *raw;

	VIPS_DEBUG_MSG( "im_openslide2vips: %s\n", filename );

	/* Tile cache: keep enough for two complete rows of tiles.
	 * This lets us do (smallish) area ops, like im_conv(), while
	 * still only hitting each tile once.
	 */
	if( !(raw = im_open_local( out, "cache", "p" )) )
		return( -1 );

	if( !(rslide = readslide_new( filename, raw )) )
		return( -1 );

	if( rslide->associated ) {
		VIPS_DEBUG_MSG( "fill_associated:\n" );

		if( vips_image_wio_output( raw ) )
			return( -1 );

		if( fill_associated( raw, rslide ) )
			return( -1 );
	} 
	else {
		if( vips_image_pio_output( raw ) )
			return( -1 );
		vips_demand_hint( raw, VIPS_DEMAND_STYLE_SMALLTILE, NULL );

		if( vips_image_generate( raw, 
			seq_start, fill_region, seq_stop, rslide, NULL ) )
			return( -1 );
	}

	/* Copy to out, adding a cache. Enough tiles for two complete 
	 * rows.
	 */
	if( im_tile_cache( raw, out, 
		TILE_WIDTH, TILE_HEIGHT,
		2 * (1 + raw->Xsize / TILE_WIDTH) ) ) 
		return( -1 );

	return( 0 );
}

static int
isslide( const char *filename )
{
	openslide_t *osr;
	const char *vendor;
	int ok;

	ok = 1;
	osr = openslide_open( filename );
	if( osr != NULL ) {
		/* If this is a generic tiled TIFF image, decline to support
		 * it, since im_tiff2vips can do better.
		 */
		vendor = openslide_get_property_value( osr,
			OPENSLIDE_PROPERTY_NAME_VENDOR );
		if( vendor == NULL ||
			strcmp( vendor, "generic-tiff" ) == 0 )
			ok = 0;
		openslide_close( osr );
	} 
	else 
		ok = 0;

	VIPS_DEBUG_MSG( "isslide: %s - %d\n", filename, ok );

	return( ok );
}

static VipsFormatFlags
slide_flags( const char *filename )
{
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *endp;

	vips_filename_split( filename, name, mode );
	strtol( mode, &endp, 10 );
	if( *mode == 0 || *endp == 0 ) 
		/* Slide layer or no mode specified.
		 */
		return( VIPS_FORMAT_PARTIAL );
	else 
		/* Associated image specified.
		 */
		return( 0 );
}

static void
error_handler( const char *domain, GLogLevelFlags level, const char *message,
	void *data )
{
	vips_error( "im_openslide2vips", "%s", message );
}

/* openslide format adds no new members.
 */
typedef VipsFormat VipsFormatOpenslide;
typedef VipsFormatClass VipsFormatOpenslideClass;

static const char *slide_suffs[] = {
	".svs",			/* Aperio */
	".vms", ".vmu",		/* Hamamatsu */
	".mrxs",		/* MIRAX */
	".tif",			/* Trestle */
	NULL
};

static void
vips_format_openslide_class_init( VipsFormatOpenslideClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "openslide";
	object_class->description = _( "OpenSlide-supported" );

	format_class->is_a = isslide;
	format_class->header = openslide2vips_header;
	format_class->load = im_openslide2vips;
	format_class->get_flags = slide_flags;
	format_class->suffs = slide_suffs;

	/* Some TIFF files are virtual slides with odd vendor extensions
	 * (or outright format violations!).  Ensure we look at them before
	 * im_tiff2vips does.  OpenSlide tries very hard to reject files it
	 * doesn't understand, so this should be safe.
	 */
	format_class->priority = 100;

	g_log_set_handler( "Openslide",
		G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING,
		error_handler, NULL );
}

static void
vips_format_openslide_init( VipsFormatOpenslide *object )
{
}

G_DEFINE_TYPE( VipsFormatOpenslide, vips_format_openslide, VIPS_TYPE_FORMAT );

#endif /*HAVE_OPENSLIDE*/
