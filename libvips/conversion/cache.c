/* vips_sink_screen() as an operation. 
 *
 * 13/1/12
 * 	- from tilecache.c
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

    You should have received a cache of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pconversion.h"

typedef struct _VipsCache {
	VipsConversion parent_instance;

	VipsImage *in;
	int tile_width;	
	int tile_height;
	int max_tiles;
} VipsCache;

typedef VipsConversionClass VipsCacheClass;

G_DEFINE_TYPE( VipsCache, vips_cache, VIPS_TYPE_CONVERSION );

static int
vips_cache_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsCache *cache = (VipsCache *) object;

	VIPS_DEBUG_MSG( "vips_cache_build\n" );

	if( VIPS_OBJECT_CLASS( vips_cache_parent_class )->build( object ) )
		return( -1 );

	if( vips_sink_screen( cache->in, conversion->out, NULL,
		cache->tile_width, cache->tile_height, cache->max_tiles,
		0, NULL, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_cache_class_init( VipsCacheClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_cache_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "cache";
	vobject_class->description = _( "cache an image" );
	vobject_class->build = vips_cache_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCache, in ) );

	VIPS_ARG_INT( class, "tile_width", 3, 
		_( "Tile width" ), 
		_( "Tile width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCache, tile_width ),
		1, 1000000, 128 );

	VIPS_ARG_INT( class, "tile_height", 3, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCache, tile_height ),
		1, 1000000, 128 );

	VIPS_ARG_INT( class, "max_tiles", 3, 
		_( "Max tiles" ), 
		_( "Maximum number of tiles to cache" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCache, max_tiles ),
		-1, 1000000, 1000 );

}

static void
vips_cache_init( VipsCache *cache )
{
	/* By default, enough pixels for two 1920 x 1080 displays.
	 */
	cache->tile_width = 128;
	cache->tile_height = 128;
	cache->max_tiles = 250;
}

/**
 * vips_cache:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @tile_width: width of tiles in cache
 * @tile_height: height of tiles in cache
 * @max_tiles: maximum number of tiles to cache
 *
 * This operation behaves rather like vips_copy() between images
 * @in and @out, except that it keeps a cache of computed pixels. 
 * This cache is made of up to @max_tiles tiles (a value of -1 
 * means any number of tiles), and each tile is of size @tile_width
 * by @tile_height pixels. By default it will cache 250 128 x 128 pixel tiles,
 * enough for two 1920 x 1080 images. 
 *
 * This operation is a thin wrapper over vips_sink_screen(), see the
 * documentation for that operation for details. 
 *
 * It uses a set of background threads to calculate pixels and the various
 * active cache operations coordinate so as not to overwhelm your system.
 *
 * See also: vips_tilecache().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_cache( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "cache", ap, in, out );
	va_end( ap );

	return( result );
}
