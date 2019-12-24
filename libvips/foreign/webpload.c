/* load webp images
 *
 * 6/8/13
 * 	- from pngload.c
 * 28/2/16
 * 	- add @shrink
 * 1/11/18
 * 	- add @page, @n
 * 30/4/19
 * 	- deprecate @shrink, use @scale instead
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

#include <string.h>

#include <vips/vips.h>

#include "pforeign.h"

#ifdef HAVE_LIBWEBP

typedef struct _VipsForeignLoadWebp {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsStreami *streami;

	/* Load this page (frame number).
	 */
	int page;

	/* Load this many pages.
	 */
	int n;

	/* Scale by this much during load.
	 */
	double scale; 

	/* Old and deprecated scaling path.
	 */
	int shrink;
} VipsForeignLoadWebp;

typedef VipsForeignLoadClass VipsForeignLoadWebpClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadWebp, vips_foreign_load_webp, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_webp_dispose( GObject *gobject )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) gobject;

	VIPS_UNREF( webp->streami );

	G_OBJECT_CLASS( vips_foreign_load_webp_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_webp_build( VipsObject *object )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) object;

	/* BC for the old API.
	 */
	if( !vips_object_argument_isset( VIPS_OBJECT( webp ), "scale" ) &&
		vips_object_argument_isset( VIPS_OBJECT( webp ), "shrink" ) &&
		webp->shrink != 0 )
		webp->scale = 1.0 / webp->shrink;

	if( VIPS_OBJECT_CLASS( vips_foreign_load_webp_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_webp_get_flags( VipsForeignLoad *load )
{
	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_webp_get_flags_filename( const char *filename )
{
	return( 0 );
}

static int
vips_foreign_load_webp_header( VipsForeignLoad *load )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) load;

	if( vips__webp_read_header_stream( webp->streami, load->out, 
		webp->page, webp->n, webp->scale ) ) 
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_webp_load( VipsForeignLoad *load )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) load;

	if( vips__webp_read_stream( webp->streami, load->real, 
		webp->page, webp->n, webp->scale ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_webp_class_init( VipsForeignLoadWebpClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_webp_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload_base";
	object_class->description = _( "load webp" );
	object_class->build = vips_foreign_load_webp_build;

	/* is_a() is not that quick ... lower the priority.
	 */
	foreign_class->priority = -50;

	load_class->get_flags_filename = 
		vips_foreign_load_webp_get_flags_filename;
	load_class->get_flags = vips_foreign_load_webp_get_flags;
	load_class->header = vips_foreign_load_webp_header;
	load_class->load = vips_foreign_load_webp_load;

	VIPS_ARG_INT( class, "page", 20,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadWebp, page ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 21,
		_( "n" ),
		_( "Load this many pages" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadWebp, n ),
		-1, 100000, 1 );

	VIPS_ARG_DOUBLE( class, "scale", 22, 
		_( "Scale" ), 
		_( "Scale factor on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadWebp, scale ),
		0.0, 1024.0, 1.0 );

	/* Old and deprecated scaling API. A float param lets do
	 * shrink-on-load for thumbnail faster and more accurately.
	 */
	VIPS_ARG_INT( class, "shrink", 23, 
		_( "Shrink" ), 
		_( "Shrink factor on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignLoadWebp, shrink ),
		1, 1024, 1 );

}

static void
vips_foreign_load_webp_init( VipsForeignLoadWebp *webp )
{
	webp->n = 1;
	webp->shrink = 1;
	webp->scale = 1.0;
}

typedef struct _VipsForeignLoadWebpStream {
	VipsForeignLoadWebp parent_object;

	VipsStreami *streami;

} VipsForeignLoadWebpStream;

typedef VipsForeignLoadWebpClass VipsForeignLoadWebpStreamClass;

G_DEFINE_TYPE( VipsForeignLoadWebpStream, vips_foreign_load_webp_stream, 
	vips_foreign_load_webp_get_type() );

static int
vips_foreign_load_webp_stream_build( VipsObject *object )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) object;
	VipsForeignLoadWebpStream *stream = 
		(VipsForeignLoadWebpStream *) object;

	if( stream->streami ) {
		webp->streami = stream->streami;
		g_object_ref( webp->streami );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_webp_stream_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_webp_stream_class_init( 
	VipsForeignLoadWebpStreamClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload_stream";
	object_class->description = _( "load webp from stream" );
	object_class->build = vips_foreign_load_webp_stream_build;

	load_class->is_a_stream = vips__iswebp_stream; 

	VIPS_ARG_OBJECT( class, "streami", 1,
		_( "Streami" ),
		_( "Stream to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadWebpStream, streami ),
		VIPS_TYPE_STREAMI );

}

static void
vips_foreign_load_webp_stream_init( VipsForeignLoadWebpStream *buffer )
{
}

typedef struct _VipsForeignLoadWebpFile {
	VipsForeignLoadWebp parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadWebpFile;

typedef VipsForeignLoadWebpClass VipsForeignLoadWebpFileClass;

G_DEFINE_TYPE( VipsForeignLoadWebpFile, vips_foreign_load_webp_file, 
	vips_foreign_load_webp_get_type() );

static int
vips_foreign_load_webp_file_build( VipsObject *object )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) object;
	VipsForeignLoadWebpFile *file = (VipsForeignLoadWebpFile *) object;

	if( file->filename &&
		!(webp->streami = 
			vips_streami_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_webp_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_webp_file_is_a( const char *filename )
{
	VipsStreami *streami;
	gboolean result;

	if( !(streami = vips_streami_new_from_file( filename )) )
		return( FALSE );
	result = vips__iswebp_stream( streami );
	VIPS_UNREF( streami );

	return( result );
}

const char *vips__webp_suffs[] = { ".webp", NULL };

static void
vips_foreign_load_webp_file_class_init( VipsForeignLoadWebpFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload";
	object_class->description = _( "load webp from file" );
	object_class->build = vips_foreign_load_webp_file_build;

	foreign_class->suffs = vips__webp_suffs;

	load_class->is_a = vips_foreign_load_webp_file_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadWebpFile, filename ),
		NULL );
}

static void
vips_foreign_load_webp_file_init( VipsForeignLoadWebpFile *file )
{
}

typedef struct _VipsForeignLoadWebpBuffer {
	VipsForeignLoadWebp parent_object;

	/* Load from a buffer.
	 */
	VipsBlob *blob;

} VipsForeignLoadWebpBuffer;

typedef VipsForeignLoadWebpClass VipsForeignLoadWebpBufferClass;

G_DEFINE_TYPE( VipsForeignLoadWebpBuffer, vips_foreign_load_webp_buffer, 
	vips_foreign_load_webp_get_type() );

static int
vips_foreign_load_webp_buffer_build( VipsObject *object )
{
	VipsForeignLoadWebp *webp = (VipsForeignLoadWebp *) object;
	VipsForeignLoadWebpBuffer *buffer = 
		(VipsForeignLoadWebpBuffer *) object;

	if( buffer->blob &&
		!(webp->streami = vips_streami_new_from_memory( 
			VIPS_AREA( buffer->blob )->data, 
			VIPS_AREA( buffer->blob )->length )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_webp_buffer_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_webp_buffer_is_a_buffer( const void *buf, size_t len )
{
	VipsStreami *streami;
	gboolean result;

	if( !(streami = vips_streami_new_from_memory( buf, len )) )
		return( FALSE );
	result = vips__iswebp_stream( streami );
	VIPS_UNREF( streami );

	return( result );
}

static void
vips_foreign_load_webp_buffer_class_init( 
	VipsForeignLoadWebpBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload_buffer";
	object_class->description = _( "load webp from buffer" );
	object_class->build = vips_foreign_load_webp_buffer_build;

	load_class->is_a_buffer = vips_foreign_load_webp_buffer_is_a_buffer; 

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadWebpBuffer, blob ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_load_webp_buffer_init( VipsForeignLoadWebpBuffer *buffer )
{
}

#endif /*HAVE_LIBWEBP*/

/**
 * vips_webpload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @n: %gint, load this many pages
 * * @scale: %gdouble, scale by this much on load
 *
 * Read a WebP file into a VIPS image. 
 *
 * Use @page to select a page to render, numbering from zero.
 *
 * Use @n to select the number of pages to render. The default is 1. Pages are
 * rendered in a vertical column, with each individual page aligned to the
 * left. Set to -1 to mean "until the end of the document". Use vips_grid() 
 * to change page layout.
 *
 * Use @scale to specify a scale-on-load factor. For example, 2.0 to double
 * the size on load.
 *
 * The loader supports ICC, EXIF and XMP metadata. 
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "webpload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_webpload_buffer:
 * @buf: (array length=len) (element-type guint8): memory area to load
 * @len: (type gsize): size of memory area
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @n: %gint, load this many pages
 * * @scale: %gdouble, scale by this much on load
 *
 * Read a WebP-formatted memory block into a VIPS image. Exactly as
 * vips_webpload(), but read from a memory buffer. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_webpload()
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "webpload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}

/**
 * vips_webpload_stream:
 * @streami: stream to load from
 * @out: (out): image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @n: %gint, load this many pages
 * * @scale: %gdouble, scale by this much on load
 *
 * Exactly as vips_webpload(), but read from a stream. 
 *
 * See also: vips_webpload()
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpload_stream( VipsStreami *streami, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "webpload_stream", ap, streami, out );
	va_end( ap );

	return( result );
}
