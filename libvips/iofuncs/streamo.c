/* A byte source/sink .. it can be a pipe, file descriptor, memory area, 
 * socket, node.js stream, etc.
 * 
 * J.Cupitt, 19/6/14
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
 * - filename encoding
 * - need printf()-style output? eg. for CSV write ... see dbuf.c
 * - test we can really change all behaviour in the subclass ... add callbacks
 *   as well to make it simpler for language bindings
 */

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

/* Try to make an O_BINARY ... sometimes need the leading '_'.
 */
#ifdef BINARY_OPEN
#ifndef O_BINARY
#ifdef _O_BINARY
#define O_BINARY _O_BINARY
#endif /*_O_BINARY*/
#endif /*!O_BINARY*/
#endif /*BINARY_OPEN*/

/* If we have O_BINARY, add it to a mode flags set.
 */
#ifdef O_BINARY
#define BINARYIZE(M) ((M) | O_BINARY)
#else /*!O_BINARY*/
#define BINARYIZE(M) (M)
#endif /*O_BINARY*/

#define MODE_READ BINARYIZE (O_RDONLY)
#define MODE_READWRITE BINARYIZE (O_RDWR)
#define MODE_WRITE BINARYIZE (O_WRONLY | O_CREAT | O_TRUNC)

G_DEFINE_TYPE( VipsStreamo, vips_streamo, VIPS_TYPE_STREAM );

static void
vips_streamo_finalize( GObject *gobject )
{
	VipsStreamo *streamo = VIPS_STREAMO( gobject );

	VIPS_DEBUG_MSG( "vips_streamo_finalize:\n" );

	VIPS_FREEF( g_byte_array_unref, streamo->memory ); 
	if( streamo->blob ) { 
		vips_area_unref( VIPS_AREA( streamo->blob ) ); 
		streamo->blob = NULL;
	}

	G_OBJECT_CLASS( vips_streamo_parent_class )->finalize( gobject );
}

static int
vips_streamo_build( VipsObject *object )
{
	VipsStream *stream = VIPS_STREAM( object );
	VipsStreamo *streamo = VIPS_STREAMO( object );

	VIPS_DEBUG_MSG( "vips_streamo_build: %p\n", stream );

	if( VIPS_OBJECT_CLASS( vips_streamo_parent_class )->build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "filename" ) &&
		vips_object_argument_isset( object, "descriptor" ) ) { 
		vips_error( vips_stream_nick( stream ), 
			"%s", _( "don't set 'filename' and 'descriptor'" ) ); 
		return( -1 ); 
	}

	if( vips_object_argument_isset( object, "filename" ) ) {
		const char *filename = stream->filename;

		int fd;

		/* 0644 is rw user, r group and other.
		 */
		if( (fd = vips_tracked_open( filename, 
			MODE_WRITE, 0644 )) == -1 ) {
			vips_error_system( errno, vips_stream_nick( stream ), 
				"%s", _( "unable to open for write" ) ); 
			return( -1 ); 
		}

		stream->tracked_descriptor = fd;
		stream->descriptor = fd;
	}
	else if( vips_object_argument_isset( object, "descriptor" ) ) {
		stream->descriptor = dup( stream->descriptor );
		stream->close_descriptor = stream->descriptor;
	}
	else {
		streamo->memory = g_byte_array_new();
	}

	return( 0 );
}

static ssize_t 
vips_streamo_write_real( VipsStreamo *streamo, const void *data, size_t length )
{
	VipsStream *stream = VIPS_STREAM( streamo );

	ssize_t len;

	VIPS_DEBUG_MSG( "vips_streamo_write_real: %zd bytes\n", length );

	if( streamo->memory ) {
		g_byte_array_append( streamo->memory, data, length );
		len = length;
	}
	else 
		len = write( stream->descriptor, data, length );

	return( len );
}

static void
vips_streamo_finish_real( VipsStreamo *streamo ) 
{
	VIPS_DEBUG_MSG( "vips_streamo_finish_real:\n" );

	/* Move the stream buffer into the blob so it can be read out.
	 */
	if( streamo->memory ) {
		unsigned char *data;
		size_t length;

		length = streamo->memory->len;
		data = g_byte_array_free( streamo->memory, FALSE );
		streamo->memory = NULL;
		vips_blob_set( streamo->blob,
			(VipsCallbackFn) g_free, data, length );
	}
}

static void
vips_streamo_class_init( VipsStreamoClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_streamo_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "streamo";
	object_class->description = _( "stream stream" );

	object_class->build = vips_streamo_build;

	class->write = vips_streamo_write_real;
	class->finish = vips_streamo_finish_real;

	/* SET_ALWAYS means that blob is set by C and the obj system is not
	 * involved in creation or destruction. It can be read at any time.
	 */
	VIPS_ARG_BOXED( class, "blob", 3, 
		_( "Blob" ),
		_( "Blob to save to" ),
		VIPS_ARGUMENT_SET_ALWAYS, 
		G_STRUCT_OFFSET( VipsStreamo, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_streamo_init( VipsStreamo *streamo )
{
	streamo->blob = vips_blob_new( NULL, NULL, 0 );
}

/**
 * vips_streamo_new_from_descriptor:
 * @descriptor: write to this file descriptor
 *
 * Create a stream attached to a file descriptor.
 * @descriptor is closed when
 * the #VipsStream is finalized. 
 *
 * See also: vips_streamo_write().
 *
 * Returns: a new #VipsStream
 */
VipsStreamo *
vips_streamo_new_from_descriptor( int descriptor )
{
	VipsStreamo *streamo;

	VIPS_DEBUG_MSG( "vips_streamo_new_from_descriptor: %d\n", 
		descriptor );

	streamo = VIPS_STREAMO( g_object_new( VIPS_TYPE_STREAMO, 
		"descriptor", descriptor,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( streamo ) ) ) {
		VIPS_UNREF( streamo );
		return( NULL );
	}

	return( streamo ); 
}

/**
 * vips_streamo_new_from_filename:
 * @filename: write to this file 
 *
 * Create a stream attached to a file.
 *
 * See also: vips_streamo_write().
 *
 * Returns: a new #VipsStream
 */
VipsStreamo *
vips_streamo_new_from_filename( const char *filename )
{
	VipsStreamo *streamo;

	VIPS_DEBUG_MSG( "vips_streamo_new_from_filename: %s\n", 
		filename );

	streamo = VIPS_STREAMO( g_object_new( VIPS_TYPE_STREAMO, 
		"filename", filename,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( streamo ) ) ) {
		VIPS_UNREF( streamo );
		return( NULL );
	}

	return( streamo ); 
}

/**
 * vips_streamo_new_memory:
 *
 * Create a stream which will stream to a memory area. Read from @blob to get
 * memory stream.
 *
 * See also: vips_streamo_write().
 *
 * Returns: a new #VipsStream
 */
VipsStreamo *
vips_streamo_new_memory( void )
{
	VipsStreamo *streamo;

	VIPS_DEBUG_MSG( "vips_streamo_new_memory:\n" ); 

	streamo = VIPS_STREAMO( g_object_new( VIPS_TYPE_STREAMO, NULL ) );

	if( vips_object_build( VIPS_OBJECT( streamo ) ) ) {
		VIPS_UNREF( streamo );
		return( NULL );
	}

	return( streamo ); 
}

int
vips_streamo_write( VipsStreamo *streamo, const void *data, size_t length )
{
	VipsStreamoClass *class = VIPS_STREAMO_GET_CLASS( streamo );

	VIPS_DEBUG_MSG( "vips_streamo_write: %zd bytes\n", length );

	while( length > 0 ) { 
		ssize_t n;

		n = class->write( streamo, data, length );

		/* n == 0 isn't strictly an error, but we treat it as one to
		 * make sure we don't get stuck in this loop.
		 */
		if( n <= 0 ) {
			vips_error_system( errno, 
				vips_stream_nick( VIPS_STREAM( streamo ) ),
				"%s", _( "write error" ) ); 
			return( -1 ); 
		}

		length -= n;
		data += n;
	}

	return( 0 );
}

void
vips_streamo_finish( VipsStreamo *streamo )
{
	VipsStreamoClass *class = VIPS_STREAMO_GET_CLASS( streamo );

	VIPS_DEBUG_MSG( "vips_streamo_finish:\n" );

	class->finish( streamo );
}
