/* load PDF with PDFium
 *
 * 5/4/18
 * 	- from pdfload.c
 * 8/6/18
 * 	- add background param
 * 16/8/18
 * 	- shut down the input file as soon as we can [kleisauke]
 * 8/8/19
 * 	- add locks, since pdfium is not threadsafe in any way
 * 13/10/20
 * 	- have a lock just for pdfium [DarthSim]
 * 	- update for current pdfium
 * 	- add _source input
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

/* TODO 
 *
 * - what about filename encodings?
 * - need to test on Windows
 */

/* How to build against PDFium:
 *
 * Download the prebuilt binary from: 
 *
 * 	https://github.com/bblanchon/pdfium-binaries
 *
 * Untar to the libvips install prefix, for example:
 *
 * 	cd ~/vips
 * 	tar xf ~/pdfium-linux.tgz
 *
 * Create a pdfium.pc like this (update the version number):
 *

VIPSHOME=/home/john/vips
cat > $VIPSHOME/lib/pkgconfig/pdfium.pc << EOF
     prefix=$VIPSHOME
     exec_prefix=\${prefix}
     libdir=\${exec_prefix}/lib
     includedir=\${prefix}/include
     Name: pdfium
     Description: pdfium
     Version: 4290
     Requires:
     Libs: -L\${libdir} -lpdfium
     Cflags: -I\${includedir}
EOF

 * 
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

#ifdef HAVE_PDFIUM

#include <fpdfview.h>
#include <fpdf_doc.h>

typedef struct _VipsForeignLoadPdf {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsSource *source;

	/* Load this page.
	 */
	int page_no;

	/* Load this many pages.
	 */
	int n; 

	/* Render at this DPI.
	 */
	double dpi;

	/* Calculate this from DPI. At 72 DPI, we render 1:1.
	 */
	double scale;

	/* Background colour.
	 */
	VipsArrayDouble *background;

	FPDF_FILEACCESS file_access;
	FPDF_DOCUMENT doc;
	FPDF_PAGE page;
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

typedef VipsForeignLoadClass VipsForeignLoadPdfClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadPdf, vips_foreign_load_pdf, 
	VIPS_TYPE_FOREIGN_LOAD );

static char *vips_pdfium_errors[] = {
	"no error",
	"unknown error",
	"file not found or could not be opened",
	"file not in PDF format or corrupted",
	"password required or incorrect password",
	"unsupported security scheme",
	"page not found or content error"
};

static GMutex *vips_pdfium_mutex = NULL;

static void
vips_pdfium_error( void )
{
	int err = FPDF_GetLastError();

	if( err >= 0 && 
		err < VIPS_NUMBER( vips_pdfium_errors ) )
		vips_error( "pdfload", "%s", _( vips_pdfium_errors[err] ) );
	else
		vips_error( "pdfload", "%s", _( "unknown error" ) ); 
}

static void
vips_foreign_load_pdf_close( VipsForeignLoadPdf *pdf )
{
	g_mutex_lock( vips_pdfium_mutex );

	VIPS_FREEF( FPDF_ClosePage, pdf->page ); 
	VIPS_FREEF( FPDF_CloseDocument, pdf->doc ); 

	g_mutex_unlock( vips_pdfium_mutex );
}

static void
vips_foreign_load_pdf_dispose( GObject *gobject )
{
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) gobject;

	vips_foreign_load_pdf_close( pdf ); 

	G_OBJECT_CLASS( vips_foreign_load_pdf_parent_class )->
		dispose( gobject );
}

static void *
vips_pdfium_init_cb( void *dummy )
{
	FPDF_LIBRARY_CONFIG config;

	config.version = 2;
	config.m_pUserFontPaths = NULL;
	config.m_pIsolate = NULL;
	config.m_v8EmbedderSlot = 0;

	FPDF_InitLibraryWithConfig( &config );

	return( NULL );
}

/* This is the m_GetBlock function for FPDF_FILEACCESS.
 */
static gboolean
vips_pdfium_GetBlock( void *param, 
	unsigned long position, unsigned char *pBuf, unsigned long size )
{
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) param;

	/* PDFium guarantees these.
	 */
	g_assert( size > 0 );
	g_assert( position >= 0 );
	g_assert( position + size <= pdf->file_access.m_FileLen );

	if( vips_source_seek( pdf->source, position, SEEK_SET ) < 0 )
		return( FALSE );

	while( size > 0 ) {
		size_t n_read;

		if( (n_read = vips_source_read( pdf->source, pBuf, size )) < 0 )
			return( FALSE );
		pBuf += n_read;
		size -= n_read;
	}

	return( TRUE );
}

static int
vips_foreign_load_pdf_build( VipsObject *object )
{
	static GOnce once = G_ONCE_INIT;

	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) object;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( pdf );

	gint64 length;

	VIPS_ONCE( &once, vips_pdfium_init_cb, NULL );

	if( !vips_object_argument_isset( object, "scale" ) )
		pdf->scale = pdf->dpi / 72.0;

	/* pdfium must know the file length, unfortunately.
	 */
	if( pdf->source ) { 
		if( (length = vips_source_length( pdf->source )) <= 0 )
			return( -1 );
		if( length > 1 << 30 ) {
			vips_error( class->nickname, 
				_( "%s: too large for pdfium" ),
				vips_connection_nick( 
					VIPS_CONNECTION( pdf->source ) ) );
			return( -1 );
		}
		pdf->file_access.m_FileLen = length;
		pdf->file_access.m_GetBlock = vips_pdfium_GetBlock;
		pdf->file_access.m_Param = pdf;

		g_mutex_lock( vips_pdfium_mutex );

		if( !(pdf->doc = FPDF_LoadCustomDocument( &pdf->file_access, 
			NULL )) ) {
			g_mutex_unlock( vips_pdfium_mutex );
			vips_pdfium_error();
			vips_error( "pdfload", 
				_( "%s: unable to load" ), 
				vips_connection_nick( 
					VIPS_CONNECTION( pdf->source ) ) );
			return( -1 ); 
		}

		g_mutex_unlock( vips_pdfium_mutex );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_pdf_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_pdf_get_flags_filename( const char *filename )
{
	/* We can't render any part of the page on demand, but we can render
	 * separate pages. Might as well call ourselves partial.
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
	if( pdf->current_page != page_no ) { 
		VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( pdf );

		g_mutex_lock( vips_pdfium_mutex );

		VIPS_FREEF( FPDF_ClosePage, pdf->page ); 
		pdf->current_page = -1;

#ifdef DEBUG
		printf( "vips_foreign_load_pdf_get_page: %d\n", page_no );
#endif /*DEBUG*/

		if( !(pdf->page = FPDF_LoadPage( pdf->doc, page_no )) ) {
			g_mutex_unlock( vips_pdfium_mutex );
			vips_pdfium_error();
			vips_error( class->nickname, 
				_( "unable to load page %d" ), page_no );
			return( -1 ); 
		}
		pdf->current_page = page_no;

		g_mutex_unlock( vips_pdfium_mutex );
	}

	return( 0 );
}

/* String-based metadata fields we extract.
 */
typedef struct _VipsForeignLoadPdfMetadata {
	char *tag;		/* as understood by PDFium */
	char *field;		/* as understood by libvips */
} VipsForeignLoadPdfMetadata;

static VipsForeignLoadPdfMetadata vips_foreign_load_pdf_metadata[] = {
	{ "Title", "pdf-title" },
	{ "Author", "pdf-author" },
	{ "Subject", "pdf-subject" },
	{ "Keywords", "pdf-keywords" },
	{ "Creator", "pdf-creator" },
	{ "Producer", "pdf-producer" },
	/* poppler has "metadata" as well, but pdfium does not support this */
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

	/* Extract and attach metadata. Set the old name too for compat.
	 */
	vips_image_set_int( out, "pdf-n_pages", pdf->n_pages ); 
	vips_image_set_int( out, VIPS_META_N_PAGES, pdf->n_pages ); 

	g_mutex_lock( vips_pdfium_mutex );

	for( i = 0; i < n_metadata; i++ ) {
		VipsForeignLoadPdfMetadata *metadata = 
			&vips_foreign_load_pdf_metadata[i];

		char text[1024];
		int len;

		len = FPDF_GetMetaText( pdf->doc, metadata->tag, text, 1024 );
		if( len > 0 ) { 
			char *str;

			/* Silently ignore coding errors.
			 */
			if( (str = g_utf16_to_utf8( (gunichar2 *) text, len, 
				NULL, NULL, NULL )) ) {
				vips_image_set_string( out, 
					metadata->field, str ); 
				g_free( str );
			}
		}
	}

	g_mutex_unlock( vips_pdfium_mutex );

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

	g_mutex_lock( vips_pdfium_mutex );
	pdf->n_pages = FPDF_GetPageCount( pdf->doc );
	g_mutex_unlock( vips_pdfium_mutex );

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
		if( vips_foreign_load_pdf_get_page( pdf, pdf->page_no + i ) )
			return( -1 );
		pdf->pages[i].left = 0;
		pdf->pages[i].top = top;
		/* We do round to nearest, in the same way that vips_resize()
		 * does round to nearest. Without this, things like
		 * shrink-on-load will break.
		 */
		pdf->pages[i].width = VIPS_RINT( 
			FPDF_GetPageWidth( pdf->page ) * pdf->scale );
		pdf->pages[i].height = VIPS_RINT( 
			FPDF_GetPageHeight( pdf->page ) * pdf->scale );

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
	if( vips_object_argument_isset( VIPS_OBJECT( pdf ), "n" ) )
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

	return( 0 );
}

static void
vips_foreign_load_pdf_minimise( VipsObject *object, VipsForeignLoadPdf *pdf )
{
	vips_source_minimise( pdf->source );
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

	/* PDFium won't always paint the background. 
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
		FPDF_BITMAP bitmap;

		vips_rect_intersectrect( r, &pdf->pages[i], &rect );

		if( vips_foreign_load_pdf_get_page( pdf, pdf->page_no + i ) )
			return( -1 ); 

		/* 4 means RGBA.
		 */
		g_mutex_lock( vips_pdfium_mutex );

		bitmap = FPDFBitmap_CreateEx( rect.width, rect.height, 4, 
			VIPS_REGION_ADDR( or, rect.left, rect.top ), 
			VIPS_REGION_LSKIP( or ) );  

		FPDF_RenderPageBitmap( bitmap, pdf->page, 
			0, 0, rect.width, rect.height,
			0, 0 ); 

		FPDFBitmap_Destroy( bitmap ); 

		g_mutex_unlock( vips_pdfium_mutex );

		top += rect.height;
		i += 1;
	}

	/* PDFium writes BGRA, we must swap.
	 */
	for( y = 0; y < r->height; y++ )
		vips__bgra2rgba( 
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
		NULL, vips_foreign_load_pdf_generate, NULL, pdf, NULL ) )
		return( -1 );

	/* PDFium does not like rendering parts of pages :-( always render
	 * complete ones. 
	 */
	if( vips_linecache( t[0], &t[1],
		"tile_height", pdf->pages[0].height, 
		NULL ) ) 
		return( -1 );
	if( vips_image_write( t[1], load->real ) ) 
		return( -1 );

	return( 0 );
}

static void *
vips_foreign_load_pdf_once_init( void *client )
{
	/* We must make the mutex on class init (not _build) since we
	 * can lock ebven if build is not called.
	 */
	vips_pdfium_mutex = vips_g_mutex_new();

	return( NULL );
}

static void
vips_foreign_load_pdf_class_init( VipsForeignLoadPdfClass *class )
{
	static GOnce once = G_ONCE_INIT;

	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	VIPS_ONCE( &once, vips_foreign_load_pdf_once_init, NULL );

	gobject_class->dispose = vips_foreign_load_pdf_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pdfload_base";
	object_class->description = _( "load PDF with PDFium" );
	object_class->build = vips_foreign_load_pdf_build;

	load_class->get_flags_filename = 
		vips_foreign_load_pdf_get_flags_filename;
	load_class->get_flags = vips_foreign_load_pdf_get_flags;
	load_class->header = vips_foreign_load_pdf_header;
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

	VIPS_ARG_BOXED( class, "background", 14, 
		_( "Background" ), 
		_( "Background value" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadPdf, background ),
		VIPS_TYPE_ARRAY_DOUBLE );

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

} VipsForeignLoadPdfFile;

typedef VipsForeignLoadPdfClass VipsForeignLoadPdfFileClass;

G_DEFINE_TYPE( VipsForeignLoadPdfFile, vips_foreign_load_pdf_file, 
	vips_foreign_load_pdf_get_type() );

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
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) object;
	VipsForeignLoadPdfFile *file = (VipsForeignLoadPdfFile *) pdf;

#ifdef DEBUG
	printf( "vips_foreign_load_pdf_file_build: %s\n", file->filename );
#endif /*DEBUG*/

	if( file->filename &&
		!(pdf->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

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
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) object;
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
	VipsForeignLoadPdf *pdf = (VipsForeignLoadPdf *) object;
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
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pdfload_source";
	object_class->description = _( "load PDF from source" );
	object_class->build = vips_foreign_load_pdf_source_build;

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

#endif /*HAVE_PDFIUM*/
