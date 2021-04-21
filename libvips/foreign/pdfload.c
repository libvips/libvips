/* load PDF with libpoppler
 *
 * 7/2/16
 * 	- from openslideload.c
 * 12/5/16
 * 	- add @n ... number of pages to load
 * 23/11/16
 * 	- set page-height, if we can
 * 28/6/17
 * 	- use a much larger strip size, thanks bubba
 * 8/6/18
 * 	- add background param
 * 16/8/18 [kleisauke]
 * 	- shut down the input file as soon as we can 
 * 19/9/19
 * 	- reopen the input if we minimised too early
 * 11/3/20
 * 	- move on top of VipsSource
 * 21/9/20
 * 	- allow dpi and scale to both be set [le0daniel]
 * 21/4/21 kleisauke
 * 	- move GObject part to poppler2vips.c
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
#include <errno.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

/* Also used by the pdfium loader.
 */
gboolean
vips_foreign_load_pdf_is_a_buffer( const void *buf, size_t len )
{
	const guchar *str = (const guchar *) buf;

	if( len >= 4 &&
		str[0] == '%' && 
		str[1] == 'P' &&
		str[2] == 'D' &&
		str[3] == 'F' )
		return( 1 );

	return( 0 );
}

/* Also used by the pdfium loader.
 */
gboolean
vips_foreign_load_pdf_is_a( const char *filename )
{
	unsigned char buf[4];

	if( vips__get_bytes( filename, buf, 4 ) == 4 &&
		vips_foreign_load_pdf_is_a_buffer( buf, 4 ) )
		return( 1 );

	return( 0 );
}

/**
 * vips_pdfload:
 * @filename: file to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page, numbered from zero
 * * @n: %gint, load this many pages
 * * @dpi: %gdouble, render at this DPI
 * * @scale: %gdouble, scale render by this factor
 * * @background: #VipsArrayDouble background colour
 *
 * Render a PDF file into a VIPS image. Rendering uses the libpoppler library
 * and should be fast. 
 *
 * The output image is always RGBA --- CMYK PDFs will be
 * converted. If you need CMYK bitmaps, you should use vips_magickload()
 * instead.
 *
 * Use @page to select a page to render, numbering from zero.
 *
 * Use @n to select the number of pages to render. The default is 1. Pages are
 * rendered in a vertical column, with each individual page aligned to the
 * left. Set to -1 to mean "until the end of the document". Use vips_grid() 
 * to change page layout.
 *
 * Use @dpi to set the rendering resolution. The default is 72. Additionally,
 * you can scale by setting @scale. If you set both, they combine.
 *
 * Use @background to set the background RGBA colour. The default is 255 
 * (solid white), use eg. 0 for a transparent background.
 *
 * The operation fills a number of header fields with metadata, for example
 * "pdf-author". They may be useful. 
 *
 * This function only reads the image header and does not render any pixel
 * data. Rendering occurs when pixels are accessed.
 *
 * See also: vips_image_new_from_file(), vips_magickload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pdfload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "pdfload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_pdfload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page, numbered from zero
 * * @n: %gint, load this many pages
 * * @dpi: %gdouble, render at this DPI
 * * @scale: %gdouble, scale render by this factor
 * * @background: #VipsArrayDouble background colour
 *
 * Read a PDF-formatted memory buffer into a VIPS image. Exactly as
 * vips_pdfload(), but read from memory. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_pdfload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pdfload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "pdfload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_pdfload_source:
 * @source: source to load from
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page, numbered from zero
 * * @n: %gint, load this many pages
 * * @dpi: %gdouble, render at this DPI
 * * @scale: %gdouble, scale render by this factor
 * * @background: #VipsArrayDouble background colour
 *
 * Exactly as vips_pdfload(), but read from a source. 
 *
 * See also: vips_pdfload()
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_pdfload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "pdfload_source", ap, source, out );
	va_end( ap );

	return( result );
}

