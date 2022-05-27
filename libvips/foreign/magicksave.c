/* save with libMagick
 *
 * 22/12/17 dlemstra 
 * 6/2/19 DarthSim
 * 	- fix GraphicsMagick support
 * 17/2/19
 * 	- support ICC, XMP, EXIF, IPTC metadata
 * 	- write with a single call to vips_sink_disc()
 * 29/6/19
 * 	- support "strip" option
 * 6/7/19 [deftomat]
 * 	- support array of delays 
 * 5/8/19 DarthSim
 * 	- support GIF optimization
 * 21/4/21 kleisauke
 * 	- move GObject part to vips2magick.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

/**
 * vips_magicksave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @quality: %gint, quality factor
 * * @format: %gchararray, format to save as
 * * @optimize_gif_frames: %gboolean, apply GIF frames optimization
 * * @optimize_gif_transparency: %gboolean, apply GIF transparency optimization
 * * @bitdepth: %gint, number of bits per pixel
 *
 * Write an image using libMagick.
 *
 * Use @quality to set the quality factor. Default 0.
 *
 * Use @format to explicitly set the save format, for example, "BMP". Otherwise
 * the format is guessed from the filename suffix.
 *
 * If @optimize_gif_frames is set, GIF frames are cropped to the smallest size
 * while preserving the results of the GIF animation. This takes some time for
 * computation but saves some time on encoding and produces smaller files in
 * some cases.
 *
 * If @optimize_gif_transparency is set, pixels that don't change the image
 * through animation are made transparent. This takes some time for computation
 * but saves some time on encoding and produces smaller files in some cases.
 *
 * @bitdepth specifies the number of bits per pixel. The image will be quantized
 * and dithered if the value is within the valid range (1 to 8).
 *
 * See also: vips_magicksave_buffer(), vips_magickload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magicksave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "magicksave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_magicksave_buffer: (method)
 * @in: image to save 
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @quality: %gint, quality factor
 * * @format: %gchararray, format to save as
 * * @optimize_gif_frames: %gboolean, apply GIF frames optimization
 * * @optimize_gif_transparency: %gboolean, apply GIF transparency optimization
 * * @bitdepth: %gint, number of bits per pixel
 *
 * As vips_magicksave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @obuf, the length of the buffer in
 * @olen. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_magicksave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magicksave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "magicksave_buffer", ap, in, &area );
	va_end( ap );

	if( !result &&
		area ) { 
		if( buf ) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if( len ) 
			*len = area->length;

		vips_area_unref( area );
	}

	return( result );
}
