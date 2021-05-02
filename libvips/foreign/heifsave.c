/* save to heif
 *
 * 5/7/18
 * 	- from niftisave.c
 * 3/7/19 [lovell]
 * 	- add "compression" option
 * 1/9/19 [meyermarcel]
 * 	- save alpha when necessary
 * 15/3/20
 * 	- revise for new VipsTarget API
 * 14/2/21 kleisauke
 * 	- move GObject part to vips2heif.c
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
#include <vips/internal.h>

/**
 * vips_heifsave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enable lossless encoding
 * * @compression: #VipsForeignHeifCompression, write with this compression
 * * @speed: %gint, encoding speed
 * * @subsample_mode: #VipsForeignSubsample, chroma subsampling mode
 *
 * Write a VIPS image to a file in HEIF format. 
 *
 * Use @Q to set the compression factor. Default 50, which seems to be roughly
 * what the iphone uses. Q 30 gives about the same quality as JPEG Q 75.
 *
 * Set @lossless %TRUE to switch to lossless compression.
 *
 * Use @compression to set the encoder e.g. HEVC, AVC, AV1. It defaults to AV1
 * if the target filename ends with ".avif", otherwise HEVC.
 *
 * Use @speed to control the CPU effort spent improving compression.
 * This is currently only applicable to AV1 encoders. Defaults to 5, 0 is
 * slowest, 9 is fastest.
 *
 * Chroma subsampling is normally automatically disabled for Q >= 90. You can
 * force the subsampling mode with @subsample_mode.
 *
 * See also: vips_image_write_to_file(), vips_heifload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "heifsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_heifsave_buffer: (method)
 * @in: image to save 
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enable lossless encoding
 * * @compression: #VipsForeignHeifCompression, write with this compression
 * * @speed: %gint, encoding speed
 * * @subsample_mode: #VipsForeignSubsample, chroma subsampling mode
 *
 * As vips_heifsave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @obuf, the length of the buffer in
 * @olen. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_heifsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "heifsave_buffer", ap, in, &area );
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

/**
 * vips_heifsave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enable lossless encoding
 * * @compression: #VipsForeignHeifCompression, write with this compression
 * * @speed: %gint, encoding speed
 * * @subsample_mode: #VipsForeignSubsample, chroma subsampling mode
 *
 * As vips_heifsave(), but save to a target.
 *
 * See also: vips_heifsave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_heifsave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "heifsave_target", ap, in, target );
	va_end( ap );

	return( result );
}
