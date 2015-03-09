/* load jpeg from a file
 *
 * 24/11/11
 * 	- wrap a class around the jpeg writer
 * 29/11/11
 * 	- split to make load, load from buffer and load from file
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

#ifdef HAVE_JPEG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#ifdef HAVE_EXIF
#ifdef UNTAGGED_EXIF
#include <exif-data.h>
#include <exif-loader.h>
#include <exif-ifd.h>
#include <exif-utils.h>
#else /*!UNTAGGED_EXIF*/
#include <libexif/exif-data.h>
#include <libexif/exif-loader.h>
#include <libexif/exif-ifd.h>
#include <libexif/exif-utils.h>
#endif /*UNTAGGED_EXIF*/
#endif /*HAVE_EXIF*/

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "vipsjpeg.h"

typedef struct _VipsForeignLoadJpeg {
	VipsForeignLoad parent_object;

	/* Shrink by this much during load.
	 */
	int shrink;

	/* Fail on first warning.
	 */
	gboolean fail;

	/* Autorotate using exif orientation tag.
	 */
	gboolean autorotate;

} VipsForeignLoadJpeg;

typedef VipsForeignLoadClass VipsForeignLoadJpegClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadJpeg, vips_foreign_load_jpeg, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_jpeg_get_flags( VipsForeignLoad *load )
{
	/* The jpeg reader supports sequential read.
	 */
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static int
vips_foreign_load_jpeg_build( VipsObject *object )
{
	VipsForeignLoadJpeg *jpeg = (VipsForeignLoadJpeg *) object;

	if( jpeg->shrink != 1 && 
		jpeg->shrink != 2 && 
		jpeg->shrink != 4 && 
		jpeg->shrink != 8 ) {
		vips_error( "VipsFormatLoadJpeg", 
			_( "bad shrink factor %d" ), jpeg->shrink );
		return( -1 );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_jpeg_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_jpeg_class_init( VipsForeignLoadJpegClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegload_base";
	object_class->description = _( "load jpeg" );
	object_class->build = vips_foreign_load_jpeg_build;

	load_class->get_flags = vips_foreign_load_jpeg_get_flags;

	VIPS_ARG_INT( class, "shrink", 10, 
		_( "Shrink" ), 
		_( "Shrink factor on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadJpeg, shrink ),
		1, 16, 1 );

	VIPS_ARG_BOOL( class, "fail", 11, 
		_( "Fail" ), 
		_( "Fail on first warning" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadJpeg, fail ),
		FALSE );

	VIPS_ARG_BOOL( class, "autorotate", 12, 
		_( "Autorotate" ), 
		_( "Rotate image using exif orientation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadJpeg, autorotate ),
		FALSE );
}

static void
vips_foreign_load_jpeg_init( VipsForeignLoadJpeg *jpeg )
{
	jpeg->shrink = 1;
}

typedef struct _VipsForeignLoadJpegFile {
	VipsForeignLoadJpeg parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadJpegFile;

typedef VipsForeignLoadJpegClass VipsForeignLoadJpegFileClass;

G_DEFINE_TYPE( VipsForeignLoadJpegFile, vips_foreign_load_jpeg_file, 
	vips_foreign_load_jpeg_get_type() );

static VipsForeignFlags
vips_foreign_load_jpeg_file_get_flags_filename( const char *filename )
{
	/* The jpeg reader supports sequential read.
	 */
	return( VIPS_FOREIGN_SEQUENTIAL );
}

static gboolean
vips_foreign_load_jpeg_file_is_a( const char *filename )
{
	return( vips__isjpeg( filename ) );
}

static int
vips_foreign_load_jpeg_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadJpeg *jpeg = (VipsForeignLoadJpeg *) load;
	VipsForeignLoadJpegFile *file = (VipsForeignLoadJpegFile *) load;

	if( vips__jpeg_read_file( file->filename, load->out, 
		TRUE, jpeg->shrink, jpeg->fail, FALSE, jpeg->autorotate ) ) 
		return( -1 );

	VIPS_SETSTR( load->out->filename, file->filename );

	return( 0 );
}

static int
vips_foreign_load_jpeg_file_load( VipsForeignLoad *load )
{
	VipsForeignLoadJpeg *jpeg = (VipsForeignLoadJpeg *) load;
	VipsForeignLoadJpegFile *file = (VipsForeignLoadJpegFile *) load;

	if( vips__jpeg_read_file( file->filename, load->real, 
		FALSE, jpeg->shrink, jpeg->fail,
		load->access == VIPS_ACCESS_SEQUENTIAL, jpeg->autorotate ) )
		return( -1 );

	return( 0 );
}

static const char *jpeg_suffs[] = { ".jpg", ".jpeg", ".jpe", NULL };

static void
vips_foreign_load_jpeg_file_class_init( VipsForeignLoadJpegFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegload";
	object_class->description = _( "load jpeg from file" );

	foreign_class->suffs = jpeg_suffs;

	load_class->get_flags_filename = 
		vips_foreign_load_jpeg_file_get_flags_filename;
	load_class->is_a = vips_foreign_load_jpeg_file_is_a;
	load_class->header = vips_foreign_load_jpeg_file_header;
	load_class->load = vips_foreign_load_jpeg_file_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadJpegFile, filename ),
		NULL );
}

static void
vips_foreign_load_jpeg_file_init( VipsForeignLoadJpegFile *file )
{
}

typedef struct _VipsForeignLoadJpegBuffer {
	VipsForeignLoadJpeg parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadJpegBuffer;

typedef VipsForeignLoadJpegClass VipsForeignLoadJpegBufferClass;

G_DEFINE_TYPE( VipsForeignLoadJpegBuffer, vips_foreign_load_jpeg_buffer, 
	vips_foreign_load_jpeg_get_type() );

static int
vips_foreign_load_jpeg_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadJpeg *jpeg = (VipsForeignLoadJpeg *) load;
	VipsForeignLoadJpegBuffer *buffer = (VipsForeignLoadJpegBuffer *) load;

	if( vips__jpeg_read_buffer( buffer->buf->data, buffer->buf->length, 
		load->out, TRUE, jpeg->shrink, jpeg->fail, FALSE, 
		jpeg->autorotate ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_jpeg_buffer_load( VipsForeignLoad *load )
{
	VipsForeignLoadJpeg *jpeg = (VipsForeignLoadJpeg *) load;
	VipsForeignLoadJpegBuffer *buffer = (VipsForeignLoadJpegBuffer *) load;

	if( vips__jpeg_read_buffer( buffer->buf->data, buffer->buf->length, 
		load->real, FALSE, jpeg->shrink, jpeg->fail,
		load->access == VIPS_ACCESS_SEQUENTIAL, jpeg->autorotate ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_jpeg_buffer_is_a( const void *buf, size_t len )
{
	return( vips__isjpeg_buffer( buf, len ) );
}

static void
vips_foreign_load_jpeg_buffer_class_init( 
	VipsForeignLoadJpegBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegload_buffer";
	object_class->description = _( "load jpeg from buffer" );

	load_class->is_a_buffer = vips_foreign_load_jpeg_buffer_is_a;
	load_class->header = vips_foreign_load_jpeg_buffer_header;
	load_class->load = vips_foreign_load_jpeg_buffer_load;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadJpegBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_load_jpeg_buffer_init( VipsForeignLoadJpegBuffer *buffer )
{
}

typedef struct _VipsForeignLoadJpegStream {
	VipsForeignLoadJpeg parent_object;

	/* Load from a stream. 
	 */
	VipsStreamInput *stream;

} VipsForeignLoadJpegStream;

typedef VipsForeignLoadJpegClass VipsForeignLoadJpegStreamClass;

G_DEFINE_TYPE( VipsForeignLoadJpegStream, vips_foreign_load_jpeg_stream, 
	vips_foreign_load_jpeg_get_type() );

static int
vips_foreign_load_jpeg_stream_load( VipsForeignLoad *load )
{
	VipsForeignLoadJpeg *jpeg = (VipsForeignLoadJpeg *) load;
	VipsForeignLoadJpegStream *stream = (VipsForeignLoadJpegStream *) load;

	if( vips__jpeg_read_stream( stream->stream, load->out, 
		FALSE, jpeg->shrink, jpeg->fail, 
		load->access == VIPS_ACCESS_SEQUENTIAL, jpeg->autorotate ) )
		return( -1 );

	return( 0 );
}

/* There's no _load() method: we do everything in _header). 
 *
 * You can't just read the header from a stream and then read again from 
 * scratch to get the image.
 */

static void
vips_foreign_load_jpeg_stream_class_init( 
	VipsForeignLoadJpegStreamClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = (VipsOperationClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegload_stream";
	object_class->description = _( "load jpeg from stream" );

	/* Musn't cache load from stream, we can have several images coming
	 * from the same source.
	 */
	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->header = vips_foreign_load_jpeg_stream_load;
	load_class->is_a_buffer = vips_foreign_load_jpeg_buffer_is_a;

	VIPS_ARG_STREAM_INPUT( class, "stream", 1, 
		_( "Stream" ),
		_( "Stream to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadJpegStream, stream ) ); 
}

static void
vips_foreign_load_jpeg_stream_init( VipsForeignLoadJpegStream *stream )
{
}

#endif /*HAVE_JPEG*/
