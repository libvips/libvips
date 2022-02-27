/* load with libMagick
 *
 * 5/12/11
 * 	- from openslideload.c
 * 17/1/12
 * 	- remove header-only loads
 * 11/6/13
 * 	- add @all_frames option, off by default
 * 14/2/16
 * 	- add @page option, 0 by default
 * 25/11/16
 * 	- add @n, deprecate @all_frames (just sets n = -1)
 * 8/9/17
 * 	- don't cache magickload
 * 21/4/21 kleisauke
 * 	- move GObject part to magick6load.c
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

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

/**
 * vips_magickload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load from this page
 * * @n: %gint, load this many pages
 * * @density: string, canvas resolution for rendering vector formats like SVG
 *
 * Read in an image using libMagick, the ImageMagick library. This library can
 * read more than 80 file formats, including SVG, BMP, EPS, DICOM and many 
 * others.
 * The reader can handle any ImageMagick image, including the float and double
 * formats. It will work with any quantum size, including HDR. Any metadata
 * attached to the libMagick image is copied on to the VIPS image.
 *
 * The reader should also work with most versions of GraphicsMagick. See the
 * "--with-magickpackage" configure option.
 *
 * The file format is usually guessed from the filename suffix, or sniffed
 * from the file contents.
 *
 * Normally it will only load the first image in a many-image sequence (such
 * as a GIF or a PDF). Use @page and @n to set the start page and number of
 * pages to load. Set @n to -1 to load all pages from @page onwards.
 *
 * @density is "WxH" in DPI, e.g. "600x300" or "600" (default is "72x72"). See
 * the [density 
 * docs](http://www.imagemagick.org/script/command-line-options.php#density) 
 * on the imagemagick website.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magickload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "magickload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_magickload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load from this page
 * * @n: %gint, load this many pages
 * * @density: string, canvas resolution for rendering vector formats like SVG
 *
 * Read an image memory block using libMagick into a VIPS image. Exactly as
 * vips_magickload(), but read from a memory source. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_magickload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magickload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "magickload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}
