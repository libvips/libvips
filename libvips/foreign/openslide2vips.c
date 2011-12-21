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
 * 11/12/11
 * 	- move argb->rgba into conversion
 * 	- turn into a set of read fns ready to be called from a class
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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include <openslide.h>

#include "openslide2vips.h"

/* We run our own tile cache. The OpenSlide one can't always keep enough for a
 * complete lines of pixels.
 */
#define TILE_WIDTH (256)
#define TILE_HEIGHT (256)

typedef struct {
	openslide_t *osr;
	char *associated;

	/* Only valid if associated == NULL.
	 */
	int32_t layer;
	double downsample;
} ReadSlide;

int
vips__openslide_isslide( const char *filename )
{
	openslide_t *osr;
	const char *vendor;
	int ok;

	ok = 0;
	if( (osr = openslide_open( filename )) ) {
		/* Generic tiled tiff images can be opened by openslide as
		 * well. Only offer to load this file if it's not a generic
		 * tiff since we want vips_tiffload() to handle these.
		 */
		vendor = openslide_get_property_value( osr,
			OPENSLIDE_PROPERTY_NAME_VENDOR );
		if( vendor &&
			strcmp( vendor, "generic-tiff" ) != 0 )
			ok = 1;
		openslide_close( osr );
	} 

	VIPS_DEBUG_MSG( "vips__openslide_isslide: %s - %d\n", filename, ok );

	return( ok );
}

static void
readslide_destroy_cb( VipsImage *image, ReadSlide *rslide )
{
	VIPS_FREEF( openslide_close, rslide->osr );
	VIPS_FREE( rslide->associated );
}

static int
check_associated_image( openslide_t *osr, const char *name )
{
	const char * const *associated;

	for( associated = openslide_get_associated_image_names( osr );
		*associated != NULL; associated++ )
		if( strcmp( *associated, name ) == 0 )
			return( 0 );

	vips_error( "openslide2vips", 
		"%s", _( "invalid associated image name" ) );

	return( -1 );
}

static ReadSlide *
readslide_new( const char *filename, VipsImage *out, 
	int layer, const char *associated )
{
	ReadSlide *rslide;
	int64_t w, h;
	const char *background;
	const char * const *properties;

	rslide = VIPS_NEW( out, ReadSlide );
	memset( rslide, 0, sizeof( *rslide ) );
	g_signal_connect( out, "close", G_CALLBACK( readslide_destroy_cb ),
		rslide );

	rslide->layer = layer;
	rslide->associated = g_strdup( associated );

	rslide->osr = openslide_open( filename );
	if( rslide->osr == NULL ) {
		vips_error( "openslide2vips", 
			"%s", _( "failure opening slide" ) );
		return( NULL );
	}

	if( layer < 0 || 
		layer >= openslide_get_layer_count( rslide->osr ) ) {
		vips_error( "openslide2vips",
			"%s", _( "invalid slide layer" ) );
		return( NULL );
	}

	if( associated &&
		check_associated_image( rslide->osr, associated ) )
		return( NULL );

	if( associated ) {
		openslide_get_associated_image_dimensions( rslide->osr,
			associated, &w, &h );
		vips_image_set_string( out, "slide-associated-image",
			associated );
		vips_demand_hint( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );
	} 
	else {
		openslide_get_layer_dimensions( rslide->osr, 
			layer, &w, &h );
		rslide->downsample = openslide_get_layer_downsample(
			rslide->osr, layer );
		vips_image_set_int( out, "slide-layer", layer );
		vips_demand_hint( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );
	}

	/* This tag is used by argb2rgba() to paint fully-transparent pixels.
	 */
	background = openslide_get_property_value( rslide->osr,
		OPENSLIDE_PROPERTY_NAME_BACKGROUND_COLOR );
	if( background != NULL )
		vips_image_set_int( out, 
			VIPS_META_BACKGROUND_RGB, 
			strtoul( background, NULL, 16 ) );
	else
		vips_image_set_int( out, VIPS_META_BACKGROUND_RGB, 0xffffff );

	if( w < 0 || h < 0 || rslide->downsample < 0 ) {
		vips_error( "openslide2vips", _( "getting dimensions: %s" ),
			openslide_get_error( rslide->osr ) );
		return( NULL );
	}
	if( w > INT_MAX || 
		h > INT_MAX ) {
		vips_error( "openslide2vips",
			"%s", _( "image dimensions overflow int" ) );
		return( NULL );
	}

	vips_image_init_fields( out, w, h, 4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_RGB, 1.0, 1.0 );

	for( properties = openslide_get_property_names( rslide->osr );
		*properties != NULL; properties++ )
		vips_image_set_string( out, *properties,
			openslide_get_property_value( rslide->osr,
			*properties ) );

	associated = g_strjoinv( ", ", (char **)
		openslide_get_associated_image_names( rslide->osr ) );
	vips_image_set_string( out, "slide-associated-images", associated );

	return( rslide );
}

int
vips__openslide_read_header( const char *filename, VipsImage *out, 
	int layer, char *associated )
{
	ReadSlide *rslide;

	if( !(rslide = readslide_new( filename, out, layer, associated )) )
		return( -1 );

	return( 0 );
}

static int
vips__openslide_generate( VipsRegion *out, 
	void *seq, void *_rslide, void *unused, gboolean *stop )
{
	ReadSlide *rslide = _rslide;
	VipsRect *r = &out->valid;

	const char *error;
	int x, y;

	VIPS_DEBUG_MSG( "vips__openslide_generate: %dx%d @ %dx%d\n",
		r->width, r->height, r->left, r->top );

	/* Fill in tile-sized chunks. Some versions of OpenSlide can fail for
	 * very large requests.
	 */
	for( y = 0; y < r->height; y += TILE_HEIGHT ) 
		for( x = 0; x < r->width; x += TILE_WIDTH ) {
			int w = VIPS_MIN( TILE_WIDTH, r->width - x );
			int h = VIPS_MIN( TILE_HEIGHT, r->height - y );

			openslide_read_region( rslide->osr, 
				(uint32_t *) VIPS_REGION_ADDR( out, 
					r->left + x, r->top + y ),
				(r->left + x) * rslide->downsample, 
				(r->top + y) * rslide->downsample, 
				rslide->layer,
				w, h ); 
		}

	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "openslide2vips", 
			_( "reading region: %s" ), error );

		return( -1 );
	}

	return( 0 );
}

int
vips__openslide_read( const char *filename, VipsImage *out, int layer )
{
	ReadSlide *rslide;
	VipsImage *raw;
	VipsImage *t;

	VIPS_DEBUG_MSG( "vips__openslide_read: %s %d\n", 
		filename, layer );

	/* Tile cache: keep enough for two complete rows of tiles. OpenSlide
	 * has its own tile cache, but it's not large enough for a complete
	 * scan line.
	 */
	raw = vips_image_new();
	vips_object_local( out, raw );

	if( !(rslide = readslide_new( filename, raw, layer, NULL )) )
		return( -1 );

	if( vips_image_generate( raw, 
		NULL, vips__openslide_generate, NULL, rslide, NULL ) )
		return( -1 );

	/* Copy to out, adding a cache. Enough tiles for a complete row, plus
	 * 50%.
	 */
	if( vips_tilecache( raw, &t, 
		"tile_width", TILE_WIDTH, 
		"tile_height", TILE_WIDTH,
		"max_tiles", (int) (1.5 * (1 + raw->Xsize / TILE_WIDTH)),
		NULL ) ) 
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
vips__openslide_read_associated( const char *filename, VipsImage *out, 
	const char *associated )
{
	ReadSlide *rslide;
	VipsImage *raw;
	const char *error;

	VIPS_DEBUG_MSG( "vips__openslide_read_associated: %s %s\n", 
		filename, associated );

	/* Memory buffer. Get associated directly to this, then copy to out.
	 */
	raw = vips_image_new_buffer();
	vips_object_local( out, raw );

	if( !(rslide = readslide_new( filename, raw, 0, associated )) ||
		vips_image_write_prepare( raw ) )
		return( -1 );
	openslide_read_associated_image( rslide->osr, rslide->associated, 
		(uint32_t *) VIPS_IMAGE_ADDR( raw, 0, 0 ) );
	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "openslide2vips",
			_( "reading associated image: %s" ), error );
		return( -1 );
	}

	if( vips_image_write( raw, out ) ) 
		return( -1 );

	return( 0 );
}

