/* load openslide from a file
 *
 * 5/12/11
 * 	- from openslideload.c
 * 28/2/12
 * 	- convert "layer" to "level" where externally visible
 * 11/4/12
 * 	- convert remaining uses of "layer" to "level"
 * 20/9/12
 * 	- add Leica filename suffix
 *	- drop glib log handler (unneeded with >= 3.3.0)
 * 27/1/18
 * 	- option to attach associated images as metadata
 * 13/2/21 kleisauke
 * 	- move GObject part to openslide2vips.c
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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

/**
 * vips_openslideload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @level: %gint, load this level
 * * @associated: %gchararray, load this associated image
 * * @attach_associated: %gboolean, attach all associated images as metadata
 * * @autocrop: %gboolean, crop to image bounds
 *
 * Read a virtual slide supported by the OpenSlide library into a VIPS image.
 * OpenSlide supports images in Aperio, Hamamatsu, MIRAX, Sakura, Trestle,
 * and Ventana formats.
 *
 * To facilitate zooming, virtual slide formats include multiple scaled-down
 * versions of the high-resolution image.  These are typically called
 * "levels".  By default, vips_openslideload() reads the highest-resolution
 * level (level 0).  Set @level to the level number you want.
 *
 * In addition to the slide image itself, virtual slide formats sometimes
 * include additional images, such as a scan of the slide's barcode.
 * OpenSlide calls these "associated images".  To read an associated image,
 * set @associated to the image's name.
 * A slide's associated images are listed in the
 * "slide-associated-images" metadata item.
 *
 * If you set @attach_associated, then all associated images are attached as
 * metadata items. Use vips_image_get_image() on @out to retrieve them. Images
 * are attached as "openslide-associated-XXXXX", where XXXXX is the name of the
 * associated image.
 *
 * The output of this operator is always RGBA.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_openslideload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "openslideload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_openslideload_source:
 * @source: source to load from
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @level: %gint, load this level
 * * @associated: %gchararray, load this associated image
 * * @attach_associated: %gboolean, attach all associated images as metadata
 * * @autocrop: %gboolean, crop to image bounds
 *
 * Exactly as vips_openslideload(), but read from a source. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_openslideload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "openslideload_source", ap, source, out );
	va_end( ap );

	return( result );
}
