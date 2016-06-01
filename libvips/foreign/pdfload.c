/* load PDF with libpoppler
 *
 * 7/2/16
 * 	- from openslideload.c
 * 12/5/16
 * 	- add @n ... number of pages to load
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

#ifdef HAVE_POPPLER

#include <cairo.h>
#include <poppler.h>

typedef struct _VipsForeignLoadPdf {
	VipsForeignLoad parent_object;

	/* Load this page.
	 */
	int page_no;

	/* Load this many pages.
	 */
	int n; 

	/* Render at this DPI.
	 */
	double dpi;

	/* Calculate this from DPI. At 72 DPI, we render 1:1 with cairo.
	 */
	double scale;

	/* Poppler is not thread-safe, so we run inside a single-threaded
	 * cache. On the plus side, this means we only need one @page pointer,
	 * even though we change this during _generate().
	 */
	PopplerDocument *doc;
	PopplerPage *page;
	int current_page;

	/* Doc has this many pages. 
	 */
	int n_pages;

	/* We need to read out the side of each page we will render, and lay
	 * them out in the final image.
	 */
	VipsRect image;
	VipsRect *pages;

} VipsForeignLoadPdf;

typedef VipsForeignLoadClass VipsForeignLoadPdfClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadPdf, vips_foreign_load_pdf, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_pdf_dispose( GObject *gobject )
{
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) gobject;

	VIPS_UNREF( pdf->page );
	VIPS_UNREF( pdf->doc );

	G_OBJECT_CLASS( vips_foreign_load_pdf_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_pdf_build( VipsObject *object )
{
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) object;

	if( !vips_object_argument_isset( object, "scale" ) )
		pdf->scale = pdf->dpi / 72.0;

	if( VIPS_OBJECT_CLASS( vips_foreign_load_pdf_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_pdf_get_flags_filename( const char *filename )
{
	/* We can render any part of the page on demand.
	 */
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_pdf_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static gboolean
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

static gboolean
vips_foreign_load_pdf_is_a( const char *filename )
{
	unsigned char buf[4];

	if( vips__get_bytes( filename, buf, 4 ) &&
		vips_foreign_load_pdf_is_a_buffer( buf, 4 ) )
		return( 1 );

	return( 0 );
}

static int
vips_foreign_load_pdf_get_page( VipsForeignLoadPdf *pdf, int page_no )
{
	if( pdf->current_page != page_no ) { 
		VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( pdf );

		VIPS_UNREF( pdf->page );
		pdf->current_page = -1;

#ifdef DEBUG
		printf( "vips_foreign_load_pdf_get_page: %d\n", page_no );
#endif /*DEBUG*/

		if( !(pdf->page = poppler_document_get_page( pdf->doc, 
			page_no )) ) {
			vips_error( class->nickname, 
				_( "unable to load page %d" ), page_no );
			return( -1 ); 
		}
		pdf->current_page = page_no;
	}

	return( 0 );
}

/* String-based metadata fields we extract.
 */
typedef struct _VipsForeignLoadPdfMetadata {
	char *(*pdf_fetch)( PopplerDocument *doc );
	char *field;
} VipsForeignLoadPdfMetadata;

static VipsForeignLoadPdfMetadata vips_foreign_load_pdf_metadata[] = {
	{ poppler_document_get_title, "pdf-title" },
	{ poppler_document_get_author, "pdf-author" },
	{ poppler_document_get_subject, "pdf-subject" },
	{ poppler_document_get_keywords, "pdf-keywords" },
	{ poppler_document_get_creator, "pdf-creator" },
	{ poppler_document_get_producer, "pdf-producer" },
	{ poppler_document_get_metadata, "pdf-metadata" },
};
static int n_metadata = VIPS_NUMBER( vips_foreign_load_pdf_metadata );

static int
vips_foreign_load_pdf_set_image( VipsForeignLoadPdf *pdf, VipsImage *out )
{
	int i;
	double res;

#ifdef DEBUG
	printf( "vips_foreign_load_pdf_set_image: %p\n", pdf );
#endif /*DEBUG*/

	/* We render to a linecache, so fat strips work well.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_FATSTRIP, NULL );

	/* Extract and attach metadata.
	 */
	vips_image_set_int( out, "pdf-n_pages", pdf->n_pages ); 

	for( i = 0; i < n_metadata; i++ ) {
		VipsForeignLoadPdfMetadata *metadata = 
			&vips_foreign_load_pdf_metadata[i];

		char *str;

		if( (str = metadata->pdf_fetch( pdf->doc )) ) { 
			vips_image_set_string( out, metadata->field, str ); 
			g_free( str );
		}
	}

	/* We need pixels/mm for vips.
	 */
	res = pdf->dpi / 25.4;

	vips_image_init_fields( out, 
		pdf->image.width, pdf->image.height, 
		4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, res, res );

	return( 0 );
}

static int
vips_foreign_load_pdf_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) load;

	int top;
	int i;

#ifdef DEBUG
	printf( "vips_foreign_load_pdf_header: %p\n", pdf );
#endif /*DEBUG*/

	pdf->n_pages = poppler_document_get_n_pages( pdf->doc );

	/* @n == -1 means until the end of the doc.
	 */
	if( pdf->n == -1 )
		pdf->n = pdf->n_pages - pdf->page_no;

	if( pdf->page_no + pdf->n > pdf->n_pages ||
		pdf->page_no < 0 ||
		pdf->n <= 0 ) {
		vips_error( class->nickname, "%s", _( "pages out of range" ) );
		return( -1 ); 
	}

	/* Lay out the pages in our output image.
	 */
	if( !(pdf->pages = VIPS_ARRAY( pdf, pdf->n, VipsRect )) )
		return( -1 ); 

	top = 0;
	pdf->image.left = 0;
	pdf->image.top = 0;
	pdf->image.width = 0;
	pdf->image.height = 0;
	for( i = 0; i < pdf->n; i++ ) {
		double width;
		double height;

		if( vips_foreign_load_pdf_get_page( pdf, pdf->page_no + i ) )
			return( -1 );
		poppler_page_get_size( pdf->page, &width, &height ); 
		pdf->pages[i].left = 0;
		pdf->pages[i].top = top;
		pdf->pages[i].width = width * pdf->scale;
		pdf->pages[i].height = height * pdf->scale;

		if( pdf->pages[i].width > pdf->image.width )
			pdf->image.width = pdf->pages[i].width;
		pdf->image.height += pdf->pages[i].height;

		top += pdf->pages[i].height;
	}

	vips_foreign_load_pdf_set_image( pdf, load->out ); 

	return( 0 );
}

static int
vips_foreign_load_pdf_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) a;
	VipsRect *r = &or->valid;

	int top;
	int i;
	int y;

	/*
	printf( "vips_foreign_load_pdf_generate: "
		"left = %d, top = %d, width = %d, height = %d\n", 
		r->left, r->top, r->width, r->height ); 
	 */

	/* Poppler won't always paint the background. Use 255 (white) for the
	 * bg, PDFs generally assume a paper backgrocund colour.
	 */
	vips_region_paint( or, r, 255 ); 

	/* Search through the pages we are drawing for the first containing
	 * this rect. This could be quicker, perhaps a binary search, but who 
	 * cares.
	 */
	for( i = 0; i < pdf->n; i++ )
		if( VIPS_RECT_BOTTOM( &pdf->pages[i] ) > r->top )
			break;

	top = r->top; 
	while( top < VIPS_RECT_BOTTOM( r ) ) {
		VipsRect rect;
		cairo_surface_t *surface;
		cairo_t *cr;

		vips_rect_intersectrect( r, &pdf->pages[i], &rect );

		surface = cairo_image_surface_create_for_data( 
			VIPS_REGION_ADDR( or, rect.left, rect.top ), 
			CAIRO_FORMAT_ARGB32, 
			rect.width, rect.height, 
			VIPS_REGION_LSKIP( or ) );
		cr = cairo_create( surface );
		cairo_surface_destroy( surface );

		cairo_scale( cr, pdf->scale, pdf->scale );
		cairo_translate( cr, 
			(pdf->pages[i].left - rect.left) / pdf->scale, 
			(pdf->pages[i].top - rect.top) / pdf->scale );

		/* poppler is single-threaded, but we don't need to lock since 
		 * we're running inside a non-threaded tilecache.
		 */
		if( vips_foreign_load_pdf_get_page( pdf, pdf->page_no + i ) )
			return( -1 ); 
		poppler_page_render( pdf->page, cr );

		cairo_destroy( cr );

		top += rect.height;
		i += 1;
	}

	/* Cairo makes pre-multipled BRGA, we must byteswap and unpremultiply.
	 */
	for( y = 0; y < r->height; y++ ) 
		vips__cairo2rgba( 
			(guint32 *) VIPS_REGION_ADDR( or, r->left, r->top + y ), 
			r->width ); 

	return( 0 ); 
}

static int
vips_foreign_load_pdf_load( VipsForeignLoad *load )
{
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( (VipsObject *) load, 2 );

	int tile_width;
	int tile_height;
	int n_lines;

#ifdef DEBUG
	printf( "vips_foreign_load_pdf_load: %p\n", pdf );
#endif /*DEBUG*/

	/* Use this to pick a tile height for our strip cache.
	 */
	vips_get_tile_size( load->real,
		&tile_width, &tile_height, &n_lines );

	/* Read to this image, then cache to out, see below.
	 */
	t[0] = vips_image_new(); 

	vips_foreign_load_pdf_set_image( pdf, t[0] ); 
	if( vips_image_generate( t[0], 
		NULL, vips_foreign_load_pdf_generate, NULL, pdf, NULL ) )
		return( -1 );

	/* Don't use tilecache to keep the number of calls to
	 * pdf_page_render() low. Don't thread the cache, we rely on
	 * locking to keep pdf single-threaded.
	 */
	if( vips_linecache( t[0], &t[1],
		"tile_height", tile_height,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( t[1], load->real ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_pdf_class_init( VipsForeignLoadPdfClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_pdf_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pdfload";
	object_class->description = _( "load PDF with libpoppler" );
	object_class->build = vips_foreign_load_pdf_build;

	load_class->get_flags_filename = 
		vips_foreign_load_pdf_get_flags_filename;
	load_class->get_flags = vips_foreign_load_pdf_get_flags;
	load_class->load = vips_foreign_load_pdf_load;

	VIPS_ARG_INT( class, "page", 10,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, page_no ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 11,
		_( "n" ),
		_( "Load this many pages" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, n ),
		-1, 100000, 1 );

	VIPS_ARG_DOUBLE( class, "dpi", 12,
		_( "DPI" ),
		_( "Render at this DPI" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, dpi ),
		0.001, 100000.0, 72.0 );

	VIPS_ARG_DOUBLE( class, "scale", 13,
		_( "Scale" ),
		_( "Scale output by this factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, scale ),
		0.001, 100000.0, 1.0 );

}

static void
vips_foreign_load_pdf_init( VipsForeignLoadPdf *pdf )
{
	pdf->dpi = 72.0;
	pdf->scale = 1.0;
	pdf->n = 1;
	pdf->current_page = -1;
}

typedef struct _VipsForeignLoadPdfFile {
	VipsForeignLoadPdf parent_object;

	/* Filename for load.
	 */
	char *filename; 

	char *uri;

} VipsForeignLoadPdfFile;

typedef VipsForeignLoadPdfClass VipsForeignLoadPdfFileClass;

G_DEFINE_TYPE( VipsForeignLoadPdfFile, vips_foreign_load_pdf_file, 
	vips_foreign_load_pdf_get_type() );

static void
vips_foreign_load_pdf_file_dispose( GObject *gobject )
{
	VipsForeignLoadPdfFile *file = 
		(VipsForeignLoadPdfFile *) gobject;

	VIPS_FREE( file->uri );

	G_OBJECT_CLASS( vips_foreign_load_pdf_file_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_pdf_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) load;
	VipsForeignLoadPdfFile *file = (VipsForeignLoadPdfFile *) load;

	char *path;
	GError *error = NULL;

	/* We need an absolute path for a URI.
	 */
	path = vips_realpath( file->filename );
	if( !(file->uri = g_filename_to_uri( path, NULL, &error )) ) { 
		g_free( path );
		vips_g_error( &error );
		return( -1 ); 
	}
	g_free( path );

	if( !(pdf->doc = poppler_document_new_from_file( 
		file->uri, NULL, &error )) ) { 
		vips_g_error( &error );
		return( -1 ); 
	}

	VIPS_SETSTR( load->out->filename, file->filename );

	return( vips_foreign_load_pdf_header( load ) );
}

static const char *vips_foreign_pdf_suffs[] = {
	".pdf",
	NULL
};

static void
vips_foreign_load_pdf_file_class_init( 
	VipsForeignLoadPdfFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_pdf_file_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pdfload";

	foreign_class->suffs = vips_foreign_pdf_suffs;

	load_class->is_a = vips_foreign_load_pdf_is_a;
	load_class->header = vips_foreign_load_pdf_file_header;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPdfFile, filename ),
		NULL );

}

static void
vips_foreign_load_pdf_file_init( VipsForeignLoadPdfFile *file )
{
}

typedef struct _VipsForeignLoadPdfBuffer {
	VipsForeignLoadPdf parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadPdfBuffer;

typedef VipsForeignLoadPdfClass VipsForeignLoadPdfBufferClass;

G_DEFINE_TYPE( VipsForeignLoadPdfBuffer, vips_foreign_load_pdf_buffer, 
	vips_foreign_load_pdf_get_type() );

static int
vips_foreign_load_pdf_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) load;
	VipsForeignLoadPdfBuffer *buffer = 
		(VipsForeignLoadPdfBuffer *) load;

	GError *error = NULL;

	if( !(pdf->doc = poppler_document_new_from_data( 
		buffer->buf->data, buffer->buf->length, NULL, &error )) ) { 
		vips_g_error( &error );
		return( -1 ); 
	}

	return( vips_foreign_load_pdf_header( load ) );
}

static void
vips_foreign_load_pdf_buffer_class_init( 
	VipsForeignLoadPdfBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pdfload_buffer";

	load_class->is_a_buffer = vips_foreign_load_pdf_is_a_buffer;
	load_class->header = vips_foreign_load_pdf_buffer_header;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPdfBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_pdf_buffer_init( VipsForeignLoadPdfBuffer *buffer )
{
}

#endif /*HAVE_POPPLER*/

/**
 * vips_pdfload:
 * @filename: file to load
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page, numbered from zero
 * * @n: %gint, load this many pages
 * * @dpi: %gdouble, render at this DPI
 * * @scale: %gdouble, scale render by this factor
 *
 * Render a PDF file into a VIPS image. Rendering uses the libpoppler library
 * and should be fast. 
 *
 * The output image is always RGBA --- CMYK PDFs will be
 * converted. If you need CMYK bitmaps, you should use vips_magickload()
 * instead.
 *
 * Rendering is progressive, that is, the image is rendered in strips equal in 
 * height to the tile height. If your PDF contains large image files and 
 * they span several strips in the output image, they will be decoded multiple 
 * times. To fix this, increase the the tile height, for example:
 *
 * |[
 * vips copy huge.pdf x.png --vips-tile-height=1024
 * ]|
 *
 * Will process images in 1024-pixel high strips, potentially much faster,
 * though of course also using a lot more memory.
 *
 * Use @page to select a page to render, numbering from zero.
 *
 * Use @n to select the number of pages to render. The default is 1. Pages are
 * rendered in a vertical column, with each individual page aligned to the
 * left. Set to -1 to mean "until the end of the document". Use vips_grid() 
 * to change page layout.
 *
 * Use @dpi to set the rendering resolution. The default is 72. Alternatively,
 * you can scale the rendering from the default 1 point == 1 pixel by 
 * setting @scale.
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
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page, numbered from zero
 * * @n: %gint, load this many pages
 * * @dpi: %gdouble, render at this DPI
 * * @scale: %gdouble, scale render by this factor
 *
 * Read a PDF-formatted memory block into a VIPS image. Exactly as
 * vips_pdfload(), but read from a memory buffer. 
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

