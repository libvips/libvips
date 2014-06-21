/* A byte source/sink .. it can be a pipe, socket, or perhaps a node.js stream.
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

/*
 */
#define VIPS_DEBUG

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

#include <vips/vips.h>
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

/**
 * SECTION: stream
 * @short_description: a source/sink of bytes, perhaps a network socket
 * @stability: Stable
 * @see_also: <link linkend="libvips-foreign">foreign</link> 
 * @include: vips/vips.h
 *
 * A #VipsStream is a source or sink of bytes for something like jpeg loading. 
 * It can be connected to a network socket, for example, or perhaps a node.js
 * stream.
 */

/**
 * VipsStream:
 *
 * A #VipsStream is a source of bytes for something like jpeg loading. It can
 * be connected to a network socket, for example. 
 */

G_DEFINE_ABSTRACT_TYPE( VipsStream, vips_stream, VIPS_TYPE_OBJECT );

static void
vips_stream_finalize( GObject *gobject )
{
	VipsStream *stream = (VipsStream *) gobject;

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_stream_finalize: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	VIPS_DEBUG_MSG( "\n" );
#endif /*VIPS_DEBUG*/

	if( stream->descriptor >= 0 ) {
		vips_tracked_close( stream->descriptor );
		stream->descriptor = -1;
	}
	VIPS_FREE( stream->filename ); 

	G_OBJECT_CLASS( vips_stream_parent_class )->finalize( gobject );
}

static void
vips_stream_class_init( VipsStreamClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );

	gobject_class->finalize = vips_stream_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	VIPS_ARG_INT( class, "descriptor", 1, 
		_( "Descriptor" ), 
		_( "File descriptor for read or write" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsStream, descriptor ),
		-1, 1000000000, 0 );

	VIPS_ARG_STRING( class, "filename", 2, 
		_( "Filename" ), 
		_( "Name of file to open" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsStream, filename ),
		NULL );

}

static void
vips_stream_init( VipsStream *stream )
{
	stream->descriptor = -1;
}

void
vips_stream_attach( VipsStream *stream )
{
	VIPS_DEBUG_MSG( "vips_stream_attach:\n" ); 

	g_assert( !stream->attached ); 
	stream->attached = TRUE; 
}

G_DEFINE_TYPE( VipsStreamInput, vips_stream_input, VIPS_TYPE_STREAM );

static void
vips_stream_input_finalize( GObject *gobject )
{
	VipsStreamInput *stream = (VipsStreamInput *) gobject;

	VIPS_FREE( stream->buffer ); 

	G_OBJECT_CLASS( vips_stream_parent_class )->finalize( gobject );
}

static int
vips_stream_input_build( VipsObject *object )
{
	VipsStreamInput *stream = VIPS_STREAM_INPUT( object );

	VIPS_DEBUG_MSG( "vips_stream_input_build: %p\n", stream );

	if( VIPS_OBJECT_CLASS( vips_stream_input_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "filename" ) &&
		!vips_object_argument_isset( object, "descriptor" ) ) { 
		const char *filename = VIPS_STREAM( stream )->filename;

		int fd;

		if( (fd = vips_tracked_open( filename, MODE_READ )) == -1 ) {
			vips_error_system( errno, filename, 
				"%s", _( "unable to open for read" ) ); 
			return( -1 ); 
		}

		g_object_set( object, "descriptor", fd, NULL ); 
	}

	g_assert( !stream->buffer );
	g_assert( stream->buffer_size > 0 && 
		stream->buffer_size < 1000000 ); 
	stream->buffer = g_new0( unsigned char, stream->buffer_size );
	stream->next_byte = NULL;
	stream->bytes_available = 0;

	return( 0 );
}

static void
vips_stream_input_class_init( VipsStreamInputClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_stream_input_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->build = vips_stream_input_build;

	VIPS_ARG_INT( class, "buffer_size", 2, 
		_( "Buffer size" ), 
		_( "Size of input buffer" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsStreamInput, buffer_size ),
		1, 10000000, 4096 );
}

static void
vips_stream_input_init( VipsStreamInput *stream )
{
	stream->buffer_size = 4096;
}

/**
 * vips_stream_input_new_from_descriptor:
 * @descriptor: read from this file descriptor
 *
 * Create a stream attached to a file descriptor. @descriptor is closed when
 * the #VipsStream is finalized. 
 *
 * #VipsStream s start out empty, you need to call 
 * vips_stream_input_read() to fill them with bytes.
 *
 * See also: vips_stream_input_read().
 *
 * Returns: a new #VipsStream
 */
VipsStreamInput *
vips_stream_input_new_from_descriptor( int descriptor )
{
	VipsStreamInput *stream;

	VIPS_DEBUG_MSG( "vips_stream_input_new_from_descriptor: %d\n", 
		descriptor );

	stream = VIPS_STREAM_INPUT( 
		g_object_new( VIPS_TYPE_STREAM_INPUT, 
			"descriptor", descriptor,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( stream ) ) ) {
		VIPS_UNREF( stream );
		return( NULL );
	}

	return( stream ); 
}

/**
 * vips_stream_input_new_from_filename:
 * @descriptor: read from this filename 
 *
 * Create a stream attached to a file.
 *
 * #VipsStream s start out empty, you need to call 
 * vips_stream_input_read() to fill them with bytes.
 *
 * See also: vips_stream_input_read().
 *
 * Returns: a new #VipsStream
 */
VipsStreamInput *
vips_stream_input_new_from_filename( const char *filename )
{
	VipsStreamInput *stream;

	VIPS_DEBUG_MSG( "vips_stream_input_new_from_filename: %s\n", 
		filename );

	stream = VIPS_STREAM_INPUT( 
		g_object_new( VIPS_TYPE_STREAM_INPUT, 
			"filename", filename,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( stream ) ) ) {
		VIPS_UNREF( stream );
		return( NULL );
	}

	return( stream ); 
}

static ssize_t
vips_stream_input_read( VipsStreamInput *stream, 
	unsigned char *buffer, size_t buffer_size )
{
	VipsStreamInputClass *class = VIPS_STREAM_INPUT_GET_CLASS( stream );

	ssize_t len;

	if( class->read )
		len = class->read( stream, buffer, buffer_size );
	else 
		len = read( VIPS_STREAM( stream )->descriptor, 
			buffer, buffer_size );

	return( len );
}

/**
 * vips_stream_input_refill:
 * @stream: fill the stream buffer
 *
 * Reads data into the stream buffer. 
 *
 * Returns: 0 on success, -1 on error or EOF. 
 */
int
vips_stream_input_refill( VipsStreamInput *stream )
{
	ssize_t len;

	/* If we're not attached, we can read even when the buffer isn't
	 * empty. Just move the unused bytes down and top up.
	 *
	 * If we're attached, we don't own the next_byte and bytes_available
	 * values (they are run by the load library) so we can't do this.
	 *
	 * We need to be able to refill the unattached buffer so we can do
	 * file format sniffing. 
	 */
	if( !VIPS_STREAM( stream )->attached ) {
		memmove( stream->buffer, stream->next_byte, 
			stream->bytes_available );
		stream->next_byte = stream->buffer;

		len = vips_stream_input_read( stream, 
			stream->next_byte, 
			stream->buffer_size - stream->bytes_available ); 
	}
	else {
		len = vips_stream_input_read( stream, 
			stream->buffer, stream->buffer_size );
		stream->next_byte = stream->buffer;

		/* This is incremented below, after we check the return value.
		 */
		stream->bytes_available = 0;
	}

#ifdef VIPS_DEBUG
	if( len > 0 ) 
		VIPS_DEBUG_MSG( "vips_stream_read: read %zd bytes\n", len );
#endif /*VIPS_DEBUG*/

	if( len <= 0 ) {
		stream->eof = TRUE;

		if( len < 0 ) 
			vips_error_system( errno, "read", 
				"%s", _( "read error" ) ); 

		return( -1 ); 
	}

	stream->bytes_available += len;

	return( 0 );
}

gboolean
vips_stream_input_eof( VipsStreamInput *stream )
{
	if( !stream->eof && 
		stream->bytes_available == 0  &&
		!VIPS_STREAM( stream )->attached ) 
		vips_stream_input_refill( stream ); 

	return( stream->eof ); 
}

void
vips_stream_input_detach( VipsStreamInput *stream,
	unsigned char *next_byte, size_t bytes_available )
{
	VIPS_DEBUG_MSG( "vips_stream_input_detach:\n" ); 

	g_assert( VIPS_STREAM( stream )->attached ); 
	VIPS_STREAM( stream )->attached = FALSE; 

	stream->next_byte = next_byte;
	stream->bytes_available = bytes_available;
}

/**
 * vips_stream_input_sniff: 
 * @bytes: number of bytes to sniff
 *
 * Return a pointer to the start of the next @bytes bytes. This can only be
 * used in detached mode.
 */
unsigned char *
vips_stream_input_sniff( VipsStreamInput *stream, int bytes )
{
	g_assert( !VIPS_STREAM( stream )->attached );

	while( stream->bytes_available < bytes )
		if( vips_stream_input_refill( stream ) )
			return( NULL );

	return( stream->next_byte );
}

G_DEFINE_TYPE( VipsStreamOutput, vips_stream_output, VIPS_TYPE_STREAM );

static int
vips_stream_output_build( VipsObject *object )
{
	VipsStreamOutput *stream = VIPS_STREAM_OUTPUT( object );

	VIPS_DEBUG_MSG( "vips_stream_output_build: %p\n", stream );

	if( VIPS_OBJECT_CLASS( vips_stream_output_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "filename" ) &&
		!vips_object_argument_isset( object, "descriptor" ) ) { 
		const char *filename = VIPS_STREAM( stream )->filename;

		int fd;

		if( (fd = vips_tracked_open( filename, MODE_WRITE )) == -1 ) {
			vips_error_system( errno, filename, 
				"%s", _( "unable to open for write" ) ); 
			return( -1 ); 
		}

		g_object_set( object, "descriptor", fd, NULL ); 
	}

	return( 0 );
}

static void
vips_stream_output_class_init( VipsStreamOutputClass *class )
{
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	vobject_class->build = vips_stream_output_build;
}

static void
vips_stream_output_init( VipsStreamOutput *stream )
{
}

/**
 * vips_stream_output_new_from_descriptor:
 * @descriptor: write to this file descriptor
 *
 * Create a stream attached to a file descriptor.
 * @descriptor is closed when
 * the #VipsStream is finalized. 
 *
 * See also: vips_stream_output_write().
 *
 * Returns: a new #VipsStream
 */
VipsStreamOutput *
vips_stream_output_new_from_descriptor( int descriptor )
{
	VipsStreamOutput *stream;

	VIPS_DEBUG_MSG( "vips_stream_output_new_from_descriptor: %d\n", 
		descriptor );

	stream = VIPS_STREAM_OUTPUT( 
		g_object_new( VIPS_TYPE_STREAM_OUTPUT, 
			"descriptor", descriptor,
			"filename", "descriptor",
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( stream ) ) ) {
		VIPS_UNREF( stream );
		return( NULL );
	}

	return( stream ); 
}

/**
 * vips_stream_output_new_from_filename:
 * @filename: write to this file 
 *
 * Create a stream attached to a file.
 *
 * See also: vips_stream_output_write().
 *
 * Returns: a new #VipsStream
 */
VipsStreamOutput *
vips_stream_output_new_from_filename( const char *filename )
{
	VipsStreamOutput *stream;

	VIPS_DEBUG_MSG( "vips_stream_output_new_from_filename: %s\n", 
		filename );

	stream = VIPS_STREAM_OUTPUT( 
		g_object_new( VIPS_TYPE_STREAM_OUTPUT, 
			"filename", filename,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( stream ) ) ) {
		VIPS_UNREF( stream );
		return( NULL );
	}

	return( stream ); 
}

void
vips_stream_output_detach( VipsStreamOutput *stream )
{
	VIPS_DEBUG_MSG( "vips_stream_output_detach:\n" ); 

	g_assert( VIPS_STREAM( stream )->attached ); 
	VIPS_STREAM( stream )->attached = FALSE; 
}

int
vips_stream_output_write( VipsStreamOutput *stream, 
	const unsigned char *buffer, size_t buffer_size )
{
	VipsStreamOutputClass *class = VIPS_STREAM_OUTPUT_GET_CLASS( stream );

	while( buffer_size > 0 ) { 
		ssize_t len;

		if( class->write )
			len = class->write( stream, buffer, buffer_size );
		else 
			len = write( VIPS_STREAM( stream )->descriptor, 
				buffer, buffer_size );

#ifdef VIPS_DEBUG
		if( len > 0 ) 
			VIPS_DEBUG_MSG( "vips_stream_output_write: "
				"written %zd bytes\n", len );
#endif /*VIPS_DEBUG*/

		/* len == 0 isn't strictly an error, but we treat it as one to
		 * make sure we don't get stuck in this loop.
		 */
		if( len <= 0 ) {
			vips_error_system( errno, 
				VIPS_OBJECT( stream )->nickname, 
				"%s", _( "write error" ) ); 
			return( -1 ); 
		}

		buffer_size -= len;
		buffer += len;
	}

	return( 0 );
}

