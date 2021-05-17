/* Read a virtual microscope slide using OpenSlide.
 *
 * Benjamin Gilbert
 *
 * Copyright (c) 2011-2015 Carnegie Mellon University
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
 * 6/8/13
 * 	- always output solid (not transparent) pixels
 * 25/1/14
 * 	- use openslide_detect_vendor() on >= 3.4.0
 * 30/7/14
 * 	- add autocrop toggle
 * 9/8/14
 * 	- do argb -> rgba for associated as well 
 * 27/1/15
 * 	- unpremultiplication speedups for fully opaque/transparent pixels
 * 18/1/17
 * 	- reorganise to support invalidate on read error
 * 27/1/18
 * 	- option to attach associated images as metadata
 * 22/6/20 adamu
 * 	- set libvips xres/yres from openslide mpp-x/mpp-y
 * 13/2/21 kleisauke
 * 	- include GObject part from openslideload.c
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

#include "pforeign.h"

#include <openslide.h>

typedef struct {
	/* Params.
	 */
	char *filename;
	VipsImage *out;
	int32_t level;
	gboolean autocrop;
	char *associated;
	gboolean attach_associated;

	openslide_t *osr;

	/* Crop to image bounds if @autocrop is set. 
	 */
	VipsRect bounds;

	/* Only valid if associated == NULL.
	 */
	double downsample;
	uint32_t bg;

	/* Try to get these from openslide properties.
	 */
	int tile_width;
	int tile_height;
} ReadSlide;

static int
vips__openslide_isslide( const char *filename )
{
#ifdef HAVE_OPENSLIDE_3_4
	const char *vendor;
	int ok;

	vendor = openslide_detect_vendor( filename );

	/* Generic tiled tiff images can be opened by openslide as well.
	 * Only offer to load this file if it's not a generic tiff since
	 * we want vips_tiffload() to handle these.
	 */
	ok = ( vendor &&
		strcmp( vendor, "generic-tiff" ) != 0 );

	VIPS_DEBUG_MSG( "vips__openslide_isslide: %s - %d\n", filename, ok );

	return( ok );
#else
	openslide_t *osr;
	int ok;

	ok = 0;
	osr = openslide_open( filename );

	if( osr ) {
		const char *vendor;

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
#endif
}

static void
readslide_destroy_cb( VipsImage *image, ReadSlide *rslide )
{
	VIPS_FREEF( openslide_close, rslide->osr );
	VIPS_FREE( rslide->associated );
	VIPS_FREE( rslide->filename );
	VIPS_FREE( rslide );
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

static gboolean
get_bounds( openslide_t *osr, VipsRect *rect )
{
	static const char *openslide_names[] = {
		"openslide.bounds-x", 
		"openslide.bounds-y", 
		"openslide.bounds-width", 
		"openslide.bounds-height"
	};
	static int vips_offsets[] = {
		G_STRUCT_OFFSET( VipsRect, left ),
		G_STRUCT_OFFSET( VipsRect, top ),
		G_STRUCT_OFFSET( VipsRect, width ),
		G_STRUCT_OFFSET( VipsRect, height )
	};

	const char *value;
	int i;

	for( i = 0; i < 4; i++ ) { 
		if( !(value = openslide_get_property_value( osr, 
			openslide_names[i] )) ) 
			return( FALSE );
		G_STRUCT_MEMBER( int, rect, vips_offsets[i] ) = 
			atoi( value );
	}

	return( TRUE );
}

static ReadSlide *
readslide_new( const char *filename, VipsImage *out, 
	int level, gboolean autocrop, 
	const char *associated, gboolean attach_associated )
{
	ReadSlide *rslide;

	if( level && 
		associated ) {
		vips_error( "openslide2vips",
			"%s", _( "specify only one of level and "
			"associated image" ) );
		return( NULL );
	}

	if( attach_associated && 
		associated ) {
		vips_error( "openslide2vips",
			"%s", _( "specify only one of attach_assicated and "
			"associated image" ) );
		return( NULL );
	}

	rslide = VIPS_NEW( NULL, ReadSlide );
	memset( rslide, 0, sizeof( *rslide ) );
	g_signal_connect( out, "close", G_CALLBACK( readslide_destroy_cb ),
		rslide );

	rslide->filename = g_strdup( filename );
	rslide->out = out;
	rslide->level = level;
	rslide->autocrop = autocrop;
	rslide->associated = g_strdup( associated );
	rslide->attach_associated = attach_associated;

	/* Non-crazy defaults, override in _parse() if we can.
	 */
	rslide->tile_width = 256;
	rslide->tile_height = 256;

	return( rslide );
}

/* Convert from ARGB to RGBA and undo premultiplication. 
 *
 * We throw away transparency. Formats like Mirax use transparent + bg
 * colour for areas with no useful pixels. But if we output
 * transparent pixels and then convert to RGB for jpeg write later, we
 * would have to pass the bg colour down the pipe somehow. The
 * structure of dzsave makes this tricky.
 *
 * We could output plain RGB instead, but that would break
 * compatibility with older vipses.
 */
static void
argb2rgba( uint32_t * restrict buf, int n, uint32_t bg )
{
	const uint32_t pbg = GUINT32_TO_BE( (bg << 8) | 255 );

	int i;

	for( i = 0; i < n; i++ ) {
		uint32_t * restrict p = buf + i;
		uint32_t x = *p;
		uint8_t a = x >> 24;
		VipsPel * restrict out = (VipsPel *) p;

		if( a == 255 ) 
			*p = GUINT32_TO_BE( (x << 8) | 255 );
		else if( a == 0 ) 
			/* Use background color.
			 */
			*p = pbg;
		else {
			/* Undo premultiplication.
			 */
			out[0] = 255 * ((x >> 16) & 255) / a;
			out[1] = 255 * ((x >> 8) & 255) / a;
			out[2] = 255 * (x & 255) / a;
			out[3] = 255;
		}
	}
}

static int
readslide_attach_associated( ReadSlide *rslide, VipsImage *image )
{
	const char * const *associated_name;

	for( associated_name = 
		openslide_get_associated_image_names( rslide->osr );
		*associated_name != NULL; associated_name++ ) {
		int64_t w, h;
		VipsImage *associated;
		uint32_t *p;
		const char *error;
		char buf[256];

		associated = vips_image_new_memory();
		openslide_get_associated_image_dimensions( rslide->osr,
			*associated_name, &w, &h );
		vips_image_init_fields( associated, w, h, 4, VIPS_FORMAT_UCHAR,
			VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );
		vips_image_pipelinev( associated, 
			VIPS_DEMAND_STYLE_THINSTRIP, NULL );

		if( vips_image_write_prepare( associated ) ) {
			g_object_unref( associated );
			return( -1 );
		}
		p = (uint32_t *) VIPS_IMAGE_ADDR( associated, 0, 0 );
		openslide_read_associated_image( rslide->osr, 
			*associated_name, p );
		error = openslide_get_error( rslide->osr );
		if( error ) {
			vips_error( "openslide2vips",
				_( "reading associated image: %s" ), error );
			g_object_unref( associated );
			return( -1 );
		}
		argb2rgba( p, w * h, rslide->bg );

		vips_snprintf( buf, 256, 
			"openslide.associated.%s", *associated_name );
		vips_image_set_image( image, buf, associated );
		g_object_unref( associated );
	}

	return( 0 );
}

/* Read out a resolution field, converting to pixels per mm.
 */
static double
readslice_parse_res( ReadSlide *rslide, const char *name )
{
	const char *value = openslide_get_property_value( rslide->osr, name );
	double mpp = g_ascii_strtod( value, NULL );

	return( mpp == 0 ? 1.0 : 1000.0 / mpp );
}

static int
readslide_parse( ReadSlide *rslide, VipsImage *image )
{
	int64_t w, h;
	const char *error;
	const char *background;
	const char * const *properties;
	char *associated_names;
	double xres;
	double yres;

	rslide->osr = openslide_open( rslide->filename );
	if( rslide->osr == NULL ) {
		vips_error( "openslide2vips", 
			"%s", _( "unsupported slide format" ) );
		return( -1 );
	}

	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "openslide2vips",
			_( "opening slide: %s" ), error );
		return( -1 );
	}

	if( rslide->level < 0 || 
		rslide->level >= openslide_get_level_count( rslide->osr ) ) {
		vips_error( "openslide2vips",
			"%s", _( "invalid slide level" ) );
		return( -1 );
	}

	if( rslide->associated &&
		check_associated_image( rslide->osr, rslide->associated ) )
		return( -1 );

	if( rslide->associated ) {
		openslide_get_associated_image_dimensions( rslide->osr,
			rslide->associated, &w, &h );
		vips_image_set_string( image, "slide-associated-image",
			rslide->associated );
		vips_image_pipelinev( image, VIPS_DEMAND_STYLE_THINSTRIP, NULL );
	} 
	else {
		char buf[256];
		const char *value;

		openslide_get_level_dimensions( rslide->osr,
			rslide->level, &w, &h );
		rslide->downsample = openslide_get_level_downsample(
			rslide->osr, rslide->level );
		vips_image_set_int( image, "slide-level", rslide->level );
		vips_image_pipelinev( image, VIPS_DEMAND_STYLE_SMALLTILE, NULL );

		/* Try to get tile width/height. An undocumented, experimental
		 * feature.
		 */
		vips_snprintf( buf, 256, 
			"openslide.level[%d].tile-width", rslide->level );
		if( (value = openslide_get_property_value( rslide->osr, buf )) )
			rslide->tile_width = atoi( value );
		vips_snprintf( buf, 256, 
			"openslide.level[%d].tile-height", rslide->level );
		if( (value = openslide_get_property_value( rslide->osr, buf )) )
			rslide->tile_height = atoi( value );
		if( value )
			VIPS_DEBUG_MSG( "readslide_new: found tile-size\n" );

		/* Some images have a bounds in the header. Crop to 
		 * that if autocrop is set. 
		 */
		if( rslide->autocrop ) 
			if( !get_bounds( rslide->osr, &rslide->bounds ) )
				rslide->autocrop = FALSE; 
		if( rslide->autocrop ) {
			VipsRect whole;

			rslide->bounds.left /= rslide->downsample;
			rslide->bounds.top /= rslide->downsample;
			rslide->bounds.width /= rslide->downsample;
			rslide->bounds.height /= rslide->downsample;

			/* Clip against image size.
			 */
			whole.left = 0;
			whole.top = 0;
			whole.width = w;
			whole.height = h;
			vips_rect_intersectrect( &rslide->bounds, &whole, 
				&rslide->bounds );

			/* If we've clipped to nothing, ignore bounds.
			 */
			if( vips_rect_isempty( &rslide->bounds ) )
				rslide->autocrop = FALSE;
		}
		if( rslide->autocrop ) {
			w = rslide->bounds.width;
			h = rslide->bounds.height;
		}

		/* Attach all associated images.
		 */
		if( rslide->attach_associated &&
			readslide_attach_associated( rslide, image ) )
			return( -1 ); 
	}

	rslide->bg = 0xffffff;
	if( (background = openslide_get_property_value( rslide->osr,
		OPENSLIDE_PROPERTY_NAME_BACKGROUND_COLOR )) )
		rslide->bg = strtoul( background, NULL, 16 );

	if( w <= 0 || 
		h <= 0 || 
		rslide->downsample < 0 ) {
		vips_error( "openslide2vips", _( "getting dimensions: %s" ),
			openslide_get_error( rslide->osr ) );
		return( -1 );
	}
	if( w > INT_MAX || 
		h > INT_MAX ) {
		vips_error( "openslide2vips",
			"%s", _( "image dimensions overflow int" ) );
		return( -1 );
	}

	if( !rslide->autocrop ) {
		rslide->bounds.left = 0;
		rslide->bounds.top = 0;
		rslide->bounds.width = w;
		rslide->bounds.height = h;
	}

	/* Try to get resolution from openslide properties.
	 */
	xres = 1.0;
	yres = 1.0;

	for( properties = openslide_get_property_names( rslide->osr );
		*properties != NULL; properties++ ) {
		const char *name = *properties;
		const char *value = 
			openslide_get_property_value( rslide->osr, name );

		/* Can be NULL for some openslides with some images.
		 */
		if( value ) { 
			vips_image_set_string( image, name, value ); 

			if( strcmp( *properties, "openslide.mpp-x" ) == 0 ) 
				xres = readslice_parse_res( rslide, name );
			if( strcmp( *properties, "openslide.mpp-y" ) == 0 ) 
				yres = readslice_parse_res( rslide, name );
		}
	}

	associated_names = g_strjoinv( ", ", (char **)
		openslide_get_associated_image_names( rslide->osr ) );
	vips_image_set_string( image, 
		"slide-associated-images", associated_names );
	VIPS_FREE( associated_names );

	vips_image_init_fields( image, w, h, 4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, xres, yres );

	return( 0 );
}

static int
vips__openslide_read_header( const char *filename, VipsImage *out, 
	int level, gboolean autocrop, 
	char *associated, gboolean attach_associated )
{
	ReadSlide *rslide;

	if( !(rslide = readslide_new( filename, 
		out, level, autocrop, associated, attach_associated )) ||
		readslide_parse( rslide, out ) )
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
		(r->left + rslide->bounds.left) * rslide->downsample, 
		(r->top + rslide->bounds.top) * rslide->downsample, 
		rslide->level,
		r->width, r->height ); 

	/* openslide errors are terminal. To support
	 * @fail we'd have to close the openslide_t and reopen, perhaps 
	 * somehow marking this tile as unreadable.
	 *
	 * See
	 * https://github.com/libvips/libvips/commit/bb0a6643f94e69294e36d2b253f9bdd60c8c40ed#commitcomment-19838911
	 */
	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "openslide2vips", 
			_( "reading region: %s" ), error );
		return( -1 );
	}

	/* Since we are inside a cache, we know buf must be continuous.
	 */
	argb2rgba( buf, n, bg );

	return( 0 );
}

static int
vips__openslide_read( const char *filename, VipsImage *out, 
	int level, gboolean autocrop, gboolean attach_associated )
{
	ReadSlide *rslide;
	VipsImage *raw;
	VipsImage *t;

	VIPS_DEBUG_MSG( "vips__openslide_read: %s %d\n", 
		filename, level );

	if( !(rslide = readslide_new( filename, out, level, autocrop, 
		NULL, attach_associated )) )
		return( -1 );

	raw = vips_image_new();
	vips_object_local( out, raw );

	if( readslide_parse( rslide, raw ) ||
		vips_image_generate( raw, 
			NULL, vips__openslide_generate, NULL, rslide, NULL ) )
		return( -1 );

	/* Copy to out, adding a cache. Enough tiles for two complete rows, 
	 * plus 50%. We need at least two rows, or we'll constantly reload
	 * tiles if they cross a tile boundary.
	 */
	if( vips_tilecache( raw, &t, 
		"tile_width", rslide->tile_width, 
		"tile_height", rslide->tile_height,
		"max_tiles", 
			(int) (2.5 * (1 + raw->Xsize / rslide->tile_width)),
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

static int
vips__openslide_read_associated( const char *filename, VipsImage *out, 
	const char *associated )
{
	ReadSlide *rslide;
	VipsImage *raw;
	uint32_t *buf;
	const char *error;

	VIPS_DEBUG_MSG( "vips__openslide_read_associated: %s %s\n", 
		filename, associated );

	if( !(rslide = readslide_new( filename, out, 0, FALSE, 
		associated, FALSE )) )
		return( -1 );

	/* Memory buffer. Get associated directly to this, then copy to out.
	 */
	raw = vips_image_new_memory();
	vips_object_local( out, raw );

	if( readslide_parse( rslide, raw ) ||
		vips_image_write_prepare( raw ) )
		return( -1 );

	buf = (uint32_t *) VIPS_IMAGE_ADDR( raw, 0, 0 );
	openslide_read_associated_image( rslide->osr, rslide->associated, buf );
	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "openslide2vips",
			_( "reading associated image: %s" ), error );
		return( -1 );
	}
	argb2rgba( buf, raw->Xsize * raw->Ysize, rslide->bg );

	if( vips_image_write( raw, out ) ) 
		return( -1 );

	return( 0 );
}

typedef struct _VipsForeignLoadOpenslide {
	VipsForeignLoad parent_object;

	/* Source to load from (set by subclasses).
	 */
	VipsSource *source;

	/* Filename from source.
	 */
	const char *filename;

	/* Load this level.
	 */
	int level;

	/* Crop to image bounds.
	 */
	gboolean autocrop;

	/* Load just this associated image. 
	 */
	char *associated;

	/* Attach all associated images as metadata items.
	 */
	gboolean attach_associated;

} VipsForeignLoadOpenslide;

typedef VipsForeignLoadClass VipsForeignLoadOpenslideClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadOpenslide, vips_foreign_load_openslide, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_openslide_dispose( GObject *gobject )
{
	VipsForeignLoadOpenslide *openslide = 
		(VipsForeignLoadOpenslide *) gobject;

	VIPS_UNREF( openslide->source );

	G_OBJECT_CLASS( vips_foreign_load_openslide_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_openslide_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignLoadOpenslide *openslide = 
		(VipsForeignLoadOpenslide *) object;

	/* We can only open source which have an associated filename, since
	 * the openslide library works in terms of filenames.
	 */
	if( openslide->source ) {
		openslide->filename = 
			vips_connection_filename( VIPS_CONNECTION( 
				openslide->source ) );
		if( !openslide->filename ) {
			vips_error( class->nickname, "%s", 
				_( "no filename available" ) );
			return( -1 );
		}
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_openslide_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_openslide_get_flags_source( VipsSource *source )
{
	/* We can't tell from just the source, we need to know what part of
	 * the file the user wants. But it'll usually be partial.
	 */
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_openslide_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadOpenslide *openslide = (VipsForeignLoadOpenslide *) load;
	VipsForeignFlags flags;

	flags = 0;
	if( !openslide->associated )
		flags |= VIPS_FOREIGN_PARTIAL;

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_openslide_get_flags_filename( const char *filename )
{
	VipsSource *source;
	VipsForeignFlags flags;

	if( !(source = vips_source_new_from_file( filename )) )
		return( 0 );
	flags = vips_foreign_load_openslide_get_flags_source( source );
	VIPS_UNREF( source );

	return( flags );
}

static int
vips_foreign_load_openslide_header( VipsForeignLoad *load )
{
	VipsForeignLoadOpenslide *openslide = (VipsForeignLoadOpenslide *) load;

	if( vips__openslide_read_header( openslide->filename, load->out, 
		openslide->level, openslide->autocrop, 
		openslide->associated, openslide->attach_associated ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, openslide->filename );

	return( 0 );
}

static int
vips_foreign_load_openslide_load( VipsForeignLoad *load )
{
	VipsForeignLoadOpenslide *openslide = (VipsForeignLoadOpenslide *) load;

	if( !openslide->associated ) {
		if( vips__openslide_read( openslide->filename, load->real, 
			openslide->level, openslide->autocrop, 
			openslide->attach_associated ) )
			return( -1 );
	}
	else {
		if( vips__openslide_read_associated( openslide->filename, 
			load->real, openslide->associated ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_foreign_load_openslide_class_init( VipsForeignLoadOpenslideClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_openslide_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "openslideload_base";
	object_class->description = _( "load OpenSlide base class" );
	object_class->build = vips_foreign_load_openslide_build;

	/* We need to be ahead of the tiff sniffer since many OpenSlide
	 * formats are tiff derivatives. If we see a tiff which would be
	 * better handled by the vips tiff loader we are careful to say no.
	 *
	 * We need to be ahead of JPEG, since MRXS images are also
	 * JPEGs.
	 */
	foreign_class->priority = 100;

	load_class->get_flags_filename = 
		vips_foreign_load_openslide_get_flags_filename;
	load_class->get_flags = vips_foreign_load_openslide_get_flags;
	load_class->header = vips_foreign_load_openslide_header;
	load_class->load = vips_foreign_load_openslide_load;

	VIPS_ARG_INT( class, "level", 20,
		_( "Level" ),
		_( "Load this level from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadOpenslide, level ),
		0, 100000, 0 );

	VIPS_ARG_BOOL( class, "autocrop", 21,
		_( "Autocrop" ),
		_( "Crop to image bounds" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadOpenslide, autocrop ),
		FALSE ); 

	VIPS_ARG_STRING( class, "associated", 22, 
		_( "Associated" ),
		_( "Load this associated image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadOpenslide, associated ),
		NULL );

	VIPS_ARG_BOOL( class, "attach-associated", 13,
		_( "Attach associated" ),
		_( "Attach all associated images" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadOpenslide, attach_associated ),
		FALSE ); 

}

static void
vips_foreign_load_openslide_init( VipsForeignLoadOpenslide *openslide )
{
}

typedef struct _VipsForeignLoadOpenslideFile {
	VipsForeignLoadOpenslide parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadOpenslideFile;

typedef VipsForeignLoadOpenslideClass VipsForeignLoadOpenslideFileClass;

G_DEFINE_TYPE( VipsForeignLoadOpenslideFile, vips_foreign_load_openslide_file, 
	vips_foreign_load_openslide_get_type() );

static int
vips_foreign_load_openslide_file_build( VipsObject *object )
{
	VipsForeignLoadOpenslide *openslide = 
		(VipsForeignLoadOpenslide *) object;
	VipsForeignLoadOpenslideFile *file = 
		(VipsForeignLoadOpenslideFile *) object;

	if( file->filename &&
		!(openslide->source = 
			vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_openslide_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static const char *vips_foreign_openslide_suffs[] = {
	".svs", 	/* Aperio */
	".vms", ".vmu", ".ndpi",  /* Hamamatsu */
	".scn",		/* Leica */
	".mrxs", 	/* MIRAX */
	".svslide",	/* Sakura */
	".tif", 	/* Trestle */
	".bif", 	/* Ventana */
	NULL
};

static void
vips_foreign_load_openslide_file_class_init( 
	VipsForeignLoadOpenslideFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "openslideload";
	object_class->description = _( "load file with OpenSlide" );
	object_class->build = vips_foreign_load_openslide_file_build;

	foreign_class->suffs = vips_foreign_openslide_suffs;

	load_class->is_a = vips__openslide_isslide;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadOpenslideFile, filename ),
		NULL );

}

static void
vips_foreign_load_openslide_file_init( VipsForeignLoadOpenslideFile *openslide )
{
}

typedef struct _VipsForeignLoadOpenslideSource {
	VipsForeignLoadOpenslide parent_object;

	/* Load from a source.
	 */
	VipsSource *source;

} VipsForeignLoadOpenslideSource;

typedef VipsForeignLoadOpenslideClass VipsForeignLoadOpenslideSourceClass;

G_DEFINE_TYPE( VipsForeignLoadOpenslideSource, 
	vips_foreign_load_openslide_source, 
	vips_foreign_load_openslide_get_type() );

static int
vips_foreign_load_openslide_source_build( VipsObject *object )
{
	VipsForeignLoadOpenslide *openslide = 
		(VipsForeignLoadOpenslide *) object;
	VipsForeignLoadOpenslideSource *source = 
		(VipsForeignLoadOpenslideSource *) object;

	if( source->source ) {
		openslide->source = source->source;
		g_object_ref( openslide->source );
	}

	if( VIPS_OBJECT_CLASS( 
		vips_foreign_load_openslide_source_parent_class )->
			build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_openslide_source_is_a_source( VipsSource *source )
{
	const char *filename;

	return( (filename = 
		vips_connection_filename( VIPS_CONNECTION( source ) )) &&
		vips__openslide_isslide( filename ) );
}

static void
vips_foreign_load_openslide_source_class_init( 
	VipsForeignLoadOpenslideSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "openslideload_source";
	object_class->description = _( "load source with OpenSlide" );
	object_class->build = vips_foreign_load_openslide_source_build;

	load_class->is_a_source = 
		vips_foreign_load_openslide_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadOpenslideSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_openslide_source_init( 
	VipsForeignLoadOpenslideSource *openslide )
{
}

#endif /*HAVE_OPENSLIDE*/

/* The C API wrappers are defined in foreign.c.
 */
