/* save as jpeg-xl
 *
 * 18/3/20
 * 	- from heifload.c
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
#include <vips/intl.h>

#include <vips/vips.h>

/**
 * vips_jxlsave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @tier: %gint, decode speed tier
 * * @distance: %gdouble, maximum encoding error
 * * @effort: %gint, encoding effort
 * * @lossless: %gboolean, enables lossless compression
 * * @Q: %gint, quality setting
 *
 * Write a VIPS image to a file in JPEG-XL format. 
 *
 * The JPEG-XL loader and saver are experimental features and may change
 * in future libvips versions.
 *
 * @tier sets the overall decode speed the encoder will target. Minimum is 0 
 * (highest quality), and maximum is 4 (lowest quality). Default is 0.
 *
 * @distance sets the target maximum encoding error. Minimum is 0 
 * (highest quality), and maximum is 15 (lowest quality). Default is 1.0
 * (visually lossless). 
 *
 * As a convenience, you can also use @Q to set @distance. @Q uses
 * approximately the same scale as regular JPEG.
 *
 * Set @lossless to enable lossless compresion.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jxlsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "jxlsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_jxlsave_buffer: (method)
 * @in: image to save 
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @tier: %gint, decode speed tier
 * * @distance: %gdouble, maximum encoding error
 * * @effort: %gint, encoding effort
 * * @lossless: %gboolean, enables lossless compression
 * * @Q: %gint, quality setting
 *
 * As vips_jxlsave(), but save to a memory buffer.
 *
 * See also: vips_jxlsave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jxlsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "jxlsave_buffer", ap, in, &area );
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
 * vips_jxlsave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @tier: %gint, decode speed tier
 * * @distance: %gdouble, maximum encoding error
 * * @effort: %gint, encoding effort
 * * @lossless: %gboolean, enables lossless compression
 * * @Q: %gint, quality setting
 *
 * As vips_jxlsave(), but save to a target.
 *
 * See also: vips_jxlsave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_jxlsave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "jxlsave_target", ap, in, target );
	va_end( ap );

	return( result );
}
