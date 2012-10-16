/* Read a virtual microscope slide using OpenSlide.
 *
 * Benjamin Gilbert
 *
 * Copyright (c) 2011-2012 Carnegie Mellon University
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
 * 28/2/12
 * 	- convert "layer" to "level" where externally visible
 * 9/4/12
 * 	- move argb2rgba back in here, we don't have a use for coded pixels
 * 	- small cleanups
 * 11/4/12
 * 	- fail if both level and associated image are specified
 * 20/9/12
 *	- update openslide_open error handling for 3.3.0 semantics
 *	- switch from deprecated _layer_ functions
 * 11/10/12
 * 	- look for tile-width and tile-height properties
 * 	- use threaded tile cache
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

#include "openslide2vips.h"

typedef struct {
	openslide_t *osr;

	char *associated;

	/* Only valid if associated == NULL.
	 */
	int32_t level;
	double downsample;
	uint32_t bg;

	/* Try to get these from openslide properties.
	 */
	int tile_width;
	int tile_height;
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

		/* vendor will be NULL if osr is in error state.
		 */
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
	int level, const char *associated )
{
	ReadSlide *rslide;
	int64_t w, h;
	const char *error;
	const char *background;
	const char * const *properties;

	if( level && associated ) {
		vips_error( "openslide2vips",
			"%s", _( "specify only one of level or associated "
			"image" ) );
		return( NULL );
	}

	rslide = VIPS_NEW( out, ReadSlide );
	memset( rslide, 0, sizeof( *rslide ) );
	g_signal_connect( out, "close", G_CALLBACK( readslide_destroy_cb ),
		rslide );

	rslide->level = level;
	rslide->associated = g_strdup( associated );

	/* Non-crazy defaults, override below if we can.
	 */
	rslide->tile_width = 256;
	rslide->tile_height = 256;

	rslide->osr = openslide_open( filename );
	if( rslide->osr == NULL ) {
		vips_error( "openslide2vips", 
			"%s", _( "unsupported slide format" ) );
		return( NULL );
	}

	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "openslide2vips",
			_( "opening slide: %s" ), error );
		return( NULL );
	}

	if( level < 0 || 
		level >= openslide_get_level_count( rslide->osr ) ) {
		vips_error( "openslide2vips",
			"%s", _( "invalid slide level" ) );
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
		char buf[256];
		const char *value;

		openslide_get_level_dimensions( rslide->osr,
			level, &w, &h );
		rslide->downsample = openslide_get_level_downsample(
			rslide->osr, level );
		vips_image_set_int( out, "slide-level", level );
		vips_demand_hint( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );

		/* Try to get tile width/height. An undocumented, experimental
		 * feature.
		 */
		vips_snprintf( buf, 256, 
			"openslide.level[%d].tile-width", level );
		if( (value = openslide_get_property_value( rslide->osr, buf )) )
			rslide->tile_width = atoi( value );
		vips_snprintf( buf, 256, 
			"openslide.level[%d].tile-height", level );
		if( (value = openslide_get_property_value( rslide->osr, buf )) )
			rslide->tile_height = atoi( value );
		if( value )
			VIPS_DEBUG_MSG( "readslide_new: found tile-size\n" );
	}

	rslide->bg = 0xffffff;
	if( (background = openslide_get_property_value( rslide->osr,
		OPENSLIDE_PROPERTY_NAME_BACKGROUND_COLOR )) )
		rslide->bg = strtoul( background, NULL, 16 );

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
	int level, char *associated )
{
	ReadSlide *rslide;

	if( !(rslide = readslide_new( filename, out, level, associated )) )
		return( -1 );

	return( 0 );
}

static int
vips__openslide_generate( VipsRegion *out, 
	void *_seq, void *_rslide, void *unused, gboolean *stop )
{
	ReadSlide *rslide = _rslide;
	uint32_t bg = rslide->bg;
	VipsRect *r = &out->valid;
	int n = r->width * r->height;
	uint32_t *buf = (uint32_t *) VIPS_REGION_ADDR( out, r->left, r->top );

	const char *error;
	int i;

	VIPS_DEBUG_MSG( "vips__openslide_generate: %dx%d @ %dx%d\n",
		r->width, r->height, r->left, r->top );

	/* We're inside a cache, so requests should always be
	 * tile_width by tile_height pixels and on a tile boundary.
	 */
	g_assert( (r->left % rslide->tile_width) == 0 );
	g_assert( (r->top % rslide->tile_height) == 0 );
	g_assert( r->width <= rslide->tile_width );
	g_assert( r->height <= rslide->tile_height );

	/* The memory on the region should be contiguous for our ARGB->RGBA
	 * loop below.
	 */
	g_assert( VIPS_REGION_LSKIP( out ) == r->width * 4 );

	openslide_read_region( rslide->osr, 
		buf,
		r->left * rslide->downsample, 
		r->top * rslide->downsample, 
		rslide->level,
		r->width, r->height ); 

	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "openslide2vips", 
			_( "reading region: %s" ), error );

		return( -1 );
	}

	/* Convert from ARGB to RGBA and undo premultiplication. Since we are
	 * inside a cache, we know buf must be continuous.
	 */
	for( i = 0; i < n; i++ ) {
		uint32_t *p = buf + i;
		uint32_t x = *p;
		uint8_t a = x >> 24;
		VipsPel *out = (VipsPel *) p;

		if( a != 0 ) {
			out[0] = 255 * ((x >> 16) & 255) / a;
			out[1] = 255 * ((x >> 8) & 255) / a;
			out[2] = 255 * (x & 255) / a;
			out[3] = a;
		} 
		else {
			/* Use background color.
			 */
			out[0] = (bg >> 16) & 255;
			out[1] = (bg >> 8) & 255;
			out[2] = bg & 255;
			out[3] = 0;
		}
	}

	return( 0 );
}

int
vips__openslide_read( const char *filename, VipsImage *out, int level )
{
	ReadSlide *rslide;
	VipsImage *raw;
	VipsImage *t;

	VIPS_DEBUG_MSG( "vips__openslide_read: %s %d\n", 
		filename, level );

	raw = vips_image_new();
	vips_object_local( out, raw );

	if( !(rslide = readslide_new( filename, raw, level, NULL )) )
		return( -1 );

	if( vips_image_generate( raw, 
		NULL, vips__openslide_generate, NULL, rslide, NULL ) )
		return( -1 );

	/* Copy to out, adding a cache. Enough tiles for a complete row, plus
	 * 50%.
	 */
	if( vips_tilecache( raw, &t, 
		"tile_width", rslide->tile_width, 
		"tile_height", rslide->tile_height,
		"max_tiles", 
			(int) (1.5 * (1 + raw->Xsize / rslide->tile_width)),
		"threaded", TRUE,
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

#endif /*HAVE_OPENSLIDE*/
