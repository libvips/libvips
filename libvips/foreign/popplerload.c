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
 * 	- include GObject part from pdfload.c
 * 28/1/22
 * 	- add password
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
#include <errno.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_POPPLER

#include <cairo.h>
#include <poppler.h>

/* Render PDFs with tiles this size. They need to be pretty big to limit 
 * overcomputation.
 *
 * An A4 page at 300dpi is 3508 pixels, so this should be enough to prevent
 * most rerendering.
 */
#define TILE_SIZE (4000)

#define VIPS_TYPE_FOREIGN_LOAD_PDF (vips_foreign_load_pdf_get_type())
#define VIPS_FOREIGN_LOAD_PDF( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_PDF, VipsForeignLoadPdf ))
#define VIPS_FOREIGN_LOAD_PDF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_FOREIGN_LOAD_PDF, VipsForeignLoadPdfClass))
#define VIPS_IS_FOREIGN_LOAD_PDF( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FOREIGN_LOAD_PDF ))
#define VIPS_IS_FOREIGN_LOAD_PDF_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FOREIGN_LOAD_PDF ))
#define VIPS_FOREIGN_LOAD_PDF_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_FOREIGN_LOAD_PDF, VipsForeignLoadPdfClass ))

typedef struct _VipsForeignLoadPdf {
	VipsForeignLoad parent_object;

	/* The VipsSource we load from, and the GInputStream we wrap around
	 * it. Set from subclasses.
	 */
	VipsSource *source;
	GInputStream *stream;

	/* Load this page.
	 */
	int page_no;

	/* Load this many pages.
	 */
	int n; 

	/* Render at this DPI.
	 */
	double dpi;

	/* Scale by this factor.
	 */
	double scale;

	/* The total scale factor we render with.
	 */
	double total_scale;

	/* Background colour.
	 */
	VipsArrayDouble *background;

	/* Decrypt with this.
	 */
	const char *password;

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

	/* We need to read out the size of each page we will render, and lay
	 * them out in the final image.
	 */
	VipsRect image;
	VipsRect *pages;

	/* The [double] background converted to the image format.
	 */
	VipsPel *ink;

} VipsForeignLoadPdf;

typedef struct _VipsForeignLoadPdfClass {
	VipsForeignLoadClass parent_class;

} VipsForeignLoadPdfClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadPdf, vips_foreign_load_pdf, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_pdf_dispose( GObject *gobject )
{
	VipsForeignLoadPdf *pdf = VIPS_FOREIGN_LOAD_PDF( gobject );

	VIPS_UNREF( pdf->page );
	VIPS_UNREF( pdf->doc );
	VIPS_UNREF( pdf->source ); 
	VIPS_UNREF( pdf->stream ); 

	G_OBJECT_CLASS( vips_foreign_load_pdf_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_pdf_build( VipsObject *object )
{
	VipsForeignLoadPdf *pdf = VIPS_FOREIGN_LOAD_PDF( object );

	GError *error = NULL;

	if( vips_source_rewind( pdf->source ) )
		return( -1 );

	pdf->total_scale = pdf->scale * pdf->dpi / 72.0;

	pdf->stream = vips_g_input_stream_new_from_source( pdf->source );
	if( !(pdf->doc = poppler_document_new_from_stream( pdf->stream, 
		vips_source_length( pdf->source ), pdf->password, 
		NULL, &error )) ) { 
		vips_g_error( &error );
		return( -1 ); 
	}

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

static int
vips_foreign_load_pdf_get_page( VipsForeignLoadPdf *pdf, int page_no )
{
	if( pdf->current_page != page_no ||
		!pdf->page ) { 
		VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( pdf );

		VIPS_UNREF( pdf->page );
		pdf->current_page = -1;

#ifdef DEBUG
		printf( "vips_foreign_load_pdf_get_page: %d\n", page_no );
#endif /*DEBUG*/

		if( !(pdf->page = 
			poppler_document_get_page( pdf->doc, page_no )) ) {
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
        if( vips_image_pipelinev( out, VIPS_DEMAND_STYLE_FATSTRIP, NULL ) )
		return( -1 );

	/* Extract and attach metadata. Set the old name too for compat.
	 */
	vips_image_set_int( out, "pdf-n_pages", pdf->n_pages ); 
	vips_image_set_int( out, VIPS_META_N_PAGES, pdf->n_pages );

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
	VipsForeignLoadPdf *pdf = VIPS_FOREIGN_LOAD_PDF( load );

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
		/* We do round to nearest, in the same way that vips_resize()
		 * does round to nearest. Without this, things like
		 * shrink-on-load will break.
		 */
		pdf->pages[i].width = VIPS_RINT( width * pdf->total_scale );
		pdf->pages[i].height = VIPS_RINT( height * pdf->total_scale );

		if( pdf->pages[i].width > pdf->image.width )
			pdf->image.width = pdf->pages[i].width;
		pdf->image.height += pdf->pages[i].height;

		top += pdf->pages[i].height;
	}

	/* If all pages are the same height, we can tag this as a toilet roll
	 * image.
	 */
	for( i = 1; i < pdf->n; i++ ) 
		if( pdf->pages[i].height != pdf->pages[0].height )
			break;

	/* Only set page-height if we have more than one page, or this could
	 * accidentally turn into an animated image later.
	 */
	if( pdf->n > 1 )
		vips_image_set_int( load->out, 
			VIPS_META_PAGE_HEIGHT, pdf->pages[0].height );

	vips_foreign_load_pdf_set_image( pdf, load->out ); 

	/* Convert the background to the image format. 
	 */
	if( !(pdf->ink = vips__vector_to_ink( class->nickname, 
		load->out, 
		VIPS_AREA( pdf->background )->data, NULL, 
		VIPS_AREA( pdf->background )->n )) )
		return( -1 );

	/* Swap to cairo-style premultiplied bgra.
	 */
	vips__rgba2bgra_premultiplied( (guint32 *) pdf->ink, 1 ); 

	vips_source_minimise( pdf->source );

	return( 0 );
}

static void
vips_foreign_load_pdf_minimise( VipsImage *image, VipsForeignLoadPdf *pdf )
{
	vips_source_minimise( pdf->source );
}

static int
vips_foreign_load_pdf_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsForeignLoadPdf *pdf = VIPS_FOREIGN_LOAD_PDF( a );
	VipsRect *r = &or->valid;

	int top;
	int i;
	int y;

	/*
	printf( "vips_foreign_load_pdf_generate: "
		"left = %d, top = %d, width = %d, height = %d\n", 
		r->left, r->top, r->width, r->height ); 
	 */

	/* Poppler won't always paint the background. 
	 */
	vips_region_paint_pel( or, r, pdf->ink ); 

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

		cairo_scale( cr, pdf->total_scale, pdf->total_scale );
		cairo_translate( cr, 
			(pdf->pages[i].left - rect.left) / pdf->total_scale, 
			(pdf->pages[i].top - rect.top) / pdf->total_scale );

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
		vips__premultiplied_bgra2rgba( 
			(guint32 *) VIPS_REGION_ADDR( or, r->left, r->top + y ),
			r->width ); 

	return( 0 ); 
}

static int
vips_foreign_load_pdf_load( VipsForeignLoad *load )
{
	VipsForeignLoadPdf *pdf = VIPS_FOREIGN_LOAD_PDF( load );
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( (VipsObject *) load, 2 );

#ifdef DEBUG
	printf( "vips_foreign_load_pdf_load: %p\n", pdf );
#endif /*DEBUG*/

	/* Read to this image, then cache to out, see below.
	 */
	t[0] = vips_image_new(); 

	/* Close input immediately at end of read.
	 */
	g_signal_connect( t[0], "minimise",
		G_CALLBACK( vips_foreign_load_pdf_minimise ), pdf );

	vips_foreign_load_pdf_set_image( pdf, t[0] ); 
	if( vips_image_generate( t[0], 
		NULL, vips_foreign_load_pdf_generate, NULL, pdf, NULL ) ||
		vips_tilecache( t[0], &t[1],
			"tile_width", TILE_SIZE,
			"tile_height", TILE_SIZE,
			"max_tiles", 2 * (1 + t[0]->Xsize / TILE_SIZE),
			NULL ) ||
		vips_image_write( t[1], load->real ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_pdf_class_init( VipsForeignLoadPdfClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_pdf_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pdfload_base";
	object_class->description = _( "load PDF with libpoppler" );
	object_class->build = vips_foreign_load_pdf_build;

	/* libpoppler is fuzzed, but not by us.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	load_class->get_flags_filename = 
		vips_foreign_load_pdf_get_flags_filename;
	load_class->get_flags = vips_foreign_load_pdf_get_flags;
	load_class->header = vips_foreign_load_pdf_header;
	load_class->load = vips_foreign_load_pdf_load;

	VIPS_ARG_INT( class, "page", 20,
		_( "Page" ),
		_( "First page to load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, page_no ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 21,
		_( "n" ),
		_( "Number of pages to load, -1 for all" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, n ),
		-1, 100000, 1 );

	VIPS_ARG_DOUBLE( class, "dpi", 22,
		_( "DPI" ),
		_( "DPI to render at" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, dpi ),
		0.001, 100000.0, 72.0 );

	VIPS_ARG_DOUBLE( class, "scale", 23,
		_( "Scale" ),
		_( "Factor to scale by" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, scale ),
		0.001, 100000.0, 1.0 );

	VIPS_ARG_BOXED( class, "background", 24, 
		_( "Background" ), 
		_( "Background colour" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, background ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_STRING( class, "password", 25, 
		_( "Password" ), 
		_( "Password to decrypt with" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, password ),
		NULL );

}

static void
vips_foreign_load_pdf_init( VipsForeignLoadPdf *pdf )
{
	pdf->dpi = 72.0;
	pdf->scale = 1.0;
	pdf->n = 1;
	pdf->current_page = -1;
	pdf->background = vips_array_double_newv( 1, 255.0 );
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
	VipsForeignLoadPdfFile *file = (VipsForeignLoadPdfFile *) load;

	VIPS_SETSTR( load->out->filename, file->filename );

	return( VIPS_FOREIGN_LOAD_CLASS(
		vips_foreign_load_pdf_file_parent_class )->header( load ) );
}

static const char *vips_foreign_pdf_suffs[] = {
	".pdf",
	NULL
};

static int
vips_foreign_load_pdf_file_build( VipsObject *object )
{
	VipsForeignLoadPdf *pdf = VIPS_FOREIGN_LOAD_PDF( object );
	VipsForeignLoadPdfFile *file = (VipsForeignLoadPdfFile *) pdf;

#ifdef DEBUG
	printf( "vips_foreign_load_pdf_file_build: %s\n", file->filename );
#endif /*DEBUG*/

	if( file->filename ) { 
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

		if( !(pdf->source = 
			vips_source_new_from_file( file->filename )) )
			return( -1 );

	}

	return( VIPS_OBJECT_CLASS( vips_foreign_load_pdf_file_parent_class )->
		build( object ) );
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

	if( vips__get_bytes( filename, buf, 4 ) == 4 &&
		vips_foreign_load_pdf_is_a_buffer( buf, 4 ) )
		return( 1 );

	return( 0 );
}

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
	object_class->description = _( "load PDF from file" );
	object_class->build = vips_foreign_load_pdf_file_build;

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
vips_foreign_load_pdf_buffer_build( VipsObject *object )
{
	VipsForeignLoadPdf *pdf = VIPS_FOREIGN_LOAD_PDF( object );
	VipsForeignLoadPdfBuffer *buffer = (VipsForeignLoadPdfBuffer *) pdf;

	if( buffer->buf &&
		!(pdf->source = vips_source_new_from_memory( 
			VIPS_AREA( buffer->buf )->data, 
			VIPS_AREA( buffer->buf )->length )) )
		return( -1 );

	return( VIPS_OBJECT_CLASS( vips_foreign_load_pdf_buffer_parent_class )->
		build( object ) );
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
	object_class->description = _( "load PDF from buffer" );
	object_class->build = vips_foreign_load_pdf_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_pdf_is_a_buffer;

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

typedef struct _VipsForeignLoadPdfSource {
	VipsForeignLoadPdf parent_object;

	VipsSource *source;

} VipsForeignLoadPdfSource;

typedef VipsForeignLoadPdfClass VipsForeignLoadPdfSourceClass;

G_DEFINE_TYPE( VipsForeignLoadPdfSource, vips_foreign_load_pdf_source, 
	vips_foreign_load_pdf_get_type() );

static int
vips_foreign_load_pdf_source_build( VipsObject *object )
{
	VipsForeignLoadPdf *pdf = VIPS_FOREIGN_LOAD_PDF( object );
	VipsForeignLoadPdfSource *source = (VipsForeignLoadPdfSource *) pdf;

	if( source->source ) {
		pdf->source = source->source;
		g_object_ref( pdf->source );
	}

	return( VIPS_OBJECT_CLASS( vips_foreign_load_pdf_source_parent_class )->
		build( object ) );
}

static gboolean
vips_foreign_load_pdf_source_is_a_source( VipsSource *source )
{
	const unsigned char *p;

	return( (p = vips_source_sniff( source, 4 )) &&
		p[0] == '%' && 
		p[1] == 'P' &&
		p[2] == 'D' &&
		p[3] == 'F' );
}

static void
vips_foreign_load_pdf_source_class_init( 
	VipsForeignLoadPdfSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pdfload_source";
	object_class->description = _( "load PDF from source" );
	object_class->build = vips_foreign_load_pdf_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_pdf_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPdfSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_pdf_source_init( VipsForeignLoadPdfSource *source )
{
}

#endif /*defined(HAVE_POPPLER)*/

/* The C API wrappers are defined in foreign.c.
 */
