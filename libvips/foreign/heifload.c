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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/debug.h>
#include <vips/internal.h>

/* These are shared with the encoder.
 */
#if defined(HAVE_HEIF_DECODER) || defined(HAVE_HEIF_ENCODER)

#include "pforeign.h"

#include <libheif/heif.h>

void
vips__heif_error( struct heif_error *error )
{
	if( error->code ) 
		vips_error( "heif", "%s (%d.%d)", error->message, error->code,
			error->subcode );
}

const char *vips__heif_suffs[] = { 
	".heic",
	".heif",
	".avif",
	NULL 
};

#endif /*defined(HAVE_HEIF_DECODER) || defined(HAVE_HEIF_ENCODER)*/

/**
 * vips_heifload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (top-level image number) to read
 * * @n: %gint, load this many pages
 * * @thumbnail: %gboolean, fetch thumbnail instead of image
 *
 * Read a HEIF image file into a VIPS image. 
 *
 * Use @page to select a page to render, numbering from zero. If neither @n
 * nor @page are set, @page defaults to the primary page, otherwise to 0.
 *
 * Use @n to select the number of pages to render. The default is 1. Pages are
 * rendered in a vertical column. Set to -1 to mean "until the end of the 
 * document". Use vips_grid() to reorganise pages.
 *
 * HEIF images have a primary image. The metadata item `heif-primary` gives 
 * the page number of the primary.
 *
 * If @thumbnail is %TRUE, then fetch a stored thumbnail rather than the
 * image.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "heifload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_heifload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (top-level image number) to read
 * * @n: %gint, load this many pages
 * * @thumbnail: %gboolean, fetch thumbnail instead of image
 *
 * Read a HEIF image file into a VIPS image. 
 * Exactly as vips_heifload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_heifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "heifload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_heifload_source:
 * @source: source to load from
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (top-level image number) to read
 * * @n: %gint, load this many pages
 * * @thumbnail: %gboolean, fetch thumbnail instead of image
 *
 * Exactly as vips_heifload(), but read from a source. 
 *
 * See also: vips_heifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "heifload_source", ap, source, out );
	va_end( ap );

	return( result );
}
