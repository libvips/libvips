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
 * - add seekable input sources
 * - need to be able to set seekable and mapable via constructor
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

/**
 * SECTION: stream
 * @short_description: a source/sink of bytes, perhaps a network socket
 * @stability: Stable
 * @see_also: <link linkend="libvips-foreign">foreign</link> 
 * @include: vips/vips.h
 *
 * A #VipsStream is a source or sink of bytes for something like jpeg loading. 
 * It can be connected to a network socket, for example, or perhaps a node.js
 * stream, or to an area of memory. 
 *
 * Subclass to add other input sources. 
 */

/**
 * VipsStream:
 *
 * A #VipsStream is a source of bytes for something like jpeg loading. It can
 * be connected to a network socket, for example. 
 */

G_DEFINE_ABSTRACT_TYPE( VipsStream, vips_stream, VIPS_TYPE_OBJECT );

#define STREAM_NAME( STREAM ) \
	(VIPS_STREAM( STREAM )->filename ? \
		VIPS_STREAM( STREAM )->filename : \
		VIPS_OBJECT( STREAM )->nickname)

static void
vips_stream_close( VipsStream *stream )
{
	if( stream->close_descriptor >= 0 ) {
		close( stream->close_descriptor );
		stream->close_descriptor = -1;
	}

	if( stream->tracked_descriptor >= 0 ) {
		vips_tracked_close( stream->tracked_descriptor );
		stream->tracked_descriptor = -1;
	}

	stream->descriptor = -1;
}

static void
vips_stream_finalize( GObject *gobject )
{
	VipsStream *stream = (VipsStream *) gobject;

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_stream_finalize: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	VIPS_DEBUG_MSG( "\n" );
#endif /*VIPS_DEBUG*/

	vips_stream_close( stream );
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
	stream->tracked_descriptor = -1;
	stream->close_descriptor = -1;
}

const char *
vips_stream_filename( VipsStream *stream )
{
	return( stream->filename );
}

G_DEFINE_TYPE( VipsStreamInput, vips_stream_input, VIPS_TYPE_STREAM );

static void
vips_stream_input_finalize( GObject *gobject )
{
	VipsStreamInput *input = VIPS_STREAM_INPUT( gobject );

	VIPS_FREEF( g_byte_array_unref, input->header_bytes ); 
	VIPS_FREEF( g_byte_array_unref, input->sniff ); 

	G_OBJECT_CLASS( vips_stream_input_parent_class )->finalize( gobject );
}

static int
vips_stream_input_open( VipsStreamInput *input )
{
	VipsStream *stream = VIPS_STREAM( input );

	if( stream->descriptor == -1 &&
		stream->tracked_descriptor == -1 &&
		stream->filename ) {
		int fd;
		off_t new_pos;

		if( (fd = vips_tracked_open( stream->filename, 
			MODE_READ )) == -1 ) {
			vips_error_system( errno, STREAM_NAME( stream ), 
				"%s", _( "unable to open for read" ) ); 
			return( -1 ); 
		}

		stream->tracked_descriptor = fd;
		stream->descriptor = fd;

		VIPS_DEBUG_MSG( "vips_stream_input_open: "
			"restoring read position %zd\n", input->read_position );
		new_pos = lseek( stream->descriptor, 0, SEEK_SET );
		if( new_pos == -1 ) {
			vips_error_system( errno, STREAM_NAME( stream ),
				"%s", _( "unable to lseek()" ) ); 
			return( 0 );
		}
	}

	return( 0 );
}

static int
vips_stream_input_build( VipsObject *object )
{
	VipsStream *stream = VIPS_STREAM( object );
	VipsStreamInput *input = VIPS_STREAM_INPUT( object );

	VIPS_DEBUG_MSG( "vips_stream_input_build: %p\n", input );

	if( VIPS_OBJECT_CLASS( vips_stream_input_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "filename" ) &&
		vips_object_argument_isset( object, "descriptor" ) ) { 
		vips_error( STREAM_NAME( stream ), 
			"%s", _( "don't set 'filename' and 'descriptor'" ) ); 
		return( -1 ); 
	}

	if( vips_object_argument_isset( object, "filename" ) &&
		vips_stream_input_open( input ) )
		return( -1 );

	if( vips_object_argument_isset( object, "descriptor" ) ) {
		stream->descriptor = dup( stream->descriptor );
		stream->close_descriptor = stream->descriptor;
	}

	/* If there's a descriptor for input, test its properties.
	 */
	if( stream->descriptor != -1 ) {
		/* Do +=0 on the current position. This fails for pipes, at
		 * least on linux.
		 */
		if( lseek( stream->descriptor, 0, SEEK_CUR ) != -1 )
			input->seekable = TRUE;

		if( vips__mmap_supported( stream->descriptor ) ) 
			input->mapable = TRUE;
	}

	if( vips_object_argument_isset( object, "blob" ) )
		input->seekable = TRUE;

	/* Need to save the header if the source is not seekable.
	 */
	if( !input->seekable )
		input->header_bytes = g_byte_array_new();

	/* We always want a sniff buffer.
	 */
	input->sniff = g_byte_array_new();

	return( 0 );
}

static ssize_t
vips_stream_input_read_real( VipsStreamInput *input, 
	unsigned char *data, size_t length )
{
	VipsStream *stream = VIPS_STREAM( input );

	VIPS_DEBUG_MSG( "vips_stream_input_read_real:\n" );

	/* Make sure we are open, in case we've been minimised.
	 */
	if( vips_stream_input_open( input ) )
		return( -1 );

	if( input->blob ) {
		VipsArea *area = (VipsArea *) input->blob;
		ssize_t available = VIPS_MIN( length,
			area->length - input->read_position );

		if( available <= 0 )
			return( 0 );

		memcpy( data, area->data + input->read_position, available );

		return( available );
	}
	else if( stream->descriptor != -1 ) {
		return( read( stream->descriptor, data, length ) );
	}
	else {
		g_assert( 0 );
		return( -1 );
	}
}

static const void *
vips_stream_input_map_real( VipsStreamInput *input, size_t *length )
{
	VipsStream *stream = VIPS_STREAM( input );

	gint64 file_length;
	const void *file_baseaddr;

	if( (file_length = vips_file_length( stream->descriptor )) < 0 ) 
		return( NULL );

	if( !(file_baseaddr = vips__mmap( stream->descriptor, 
		FALSE, file_length, 0 )) )
		return( NULL );

	if( length )
		*length = file_length;

	return( file_baseaddr );
}

static int
vips_stream_input_rewind_real( VipsStreamInput *input )
{
	VipsStream *stream = VIPS_STREAM( input );

	VIPS_DEBUG_MSG( "vips_stream_input_rewind_real:\n" );

	if( input->seekable &&
		stream->descriptor != -1 ) {
		off_t new_pos;

		VIPS_DEBUG_MSG( "   rewinding desriptor %d\n", 
			stream->descriptor );

		new_pos = lseek( stream->descriptor, 0, SEEK_SET );
		if( new_pos == -1 ) {
			vips_error_system( errno, STREAM_NAME( stream ),
				"%s", _( "unable to rewind" ) ); 
			return( 0 );
		}
	}

	return( 0 );
}

static void
vips_stream_input_minimise_real( VipsStreamInput *input )
{
	VipsStream *stream = VIPS_STREAM( input );

	if( stream->filename &&
		stream->descriptor != -1 &&
		input->seekable ) 
		vips_stream_close( stream );
}

static void
vips_stream_input_class_init( VipsStreamInputClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_stream_input_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "stream_input";
	object_class->description = _( "input stream" );

	object_class->build = vips_stream_input_build;

	class->read = vips_stream_input_read_real;
	class->map = vips_stream_input_map_real;
	class->rewind = vips_stream_input_rewind_real;
	class->minimise = vips_stream_input_minimise_real;

	VIPS_ARG_BOXED( class, "blob", 3, 
		_( "Blob" ),
		_( "blob to load from" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsStreamInput, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_stream_input_init( VipsStreamInput *input )
{
	input->length = -1;
}

/**
 * vips_stream_input_new_from_descriptor:
 * @descriptor: read from this file descriptor
 *
 * Create an input stream attached to a file descriptor. @descriptor is 
 * closed with close() when the #VipsStream is finalized. 
 *
 * Returns: a new #VipsStream
 */
VipsStreamInput *
vips_stream_input_new_from_descriptor( int descriptor )
{
	VipsStreamInput *input;

	VIPS_DEBUG_MSG( "vips_stream_input_new_from_descriptor: %d\n", 
		descriptor );

	input = VIPS_STREAM_INPUT( 
		g_object_new( VIPS_TYPE_STREAM_INPUT, 
			"descriptor", descriptor,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( input ) ) ) {
		VIPS_UNREF( input );
		return( NULL );
	}

	return( input ); 
}

/**
 * vips_stream_input_new_from_filename:
 * @descriptor: read from this filename 
 *
 * Create an input stream attached to a file.
 *
 * Returns: a new #VipsStream
 */
VipsStreamInput *
vips_stream_input_new_from_filename( const char *filename )
{
	VipsStreamInput *input;

	VIPS_DEBUG_MSG( "vips_stream_input_new_from_filename: %s\n", 
		filename );

	input = VIPS_STREAM_INPUT( 
		g_object_new( VIPS_TYPE_STREAM_INPUT, 
			"filename", filename,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( input ) ) ) {
		VIPS_UNREF( input );
		return( NULL );
	}

	return( input ); 
}

/**
 * vips_stream_input_new_from_blob:
 * @blob: memory area to load
 *
 * Create a stream attached to an area of memory. 
 *
 * Returns: a new #VipsStream
 */
VipsStreamInput *
vips_stream_input_new_from_blob( VipsBlob *blob )
{
	VipsStreamInput *input;

	VIPS_DEBUG_MSG( "vips_stream_input_new_from_blob: %p\n", blob ); 

	input = VIPS_STREAM_INPUT( 
		g_object_new( VIPS_TYPE_STREAM_INPUT, 
			"blob", blob,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( input ) ) ) {
		VIPS_UNREF( input );
		return( NULL );
	}

	return( input ); 
}

/**
 * vips_stream_input_new_from_memory:
 * @data: memory area to load
 * @length: size of memory area
 *
 * Create a stream attached to an area of memory. 
 *
 * You must not free @data while the stream is active. 
 *
 * Returns: a new #VipsStream
 */
VipsStreamInput *
vips_stream_input_new_from_memory( const void *data, size_t length )
{
	VipsStreamInput *input;
	VipsBlob *blob;

	VIPS_DEBUG_MSG( "vips_stream_input_new_from_buffer: "
		"%p, length = %zd\n", data, length ); 

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, data, length );

	input = vips_stream_input_new_from_blob( blob ); 

	vips_area_unref( VIPS_AREA( blob ) );

	return( input ); 
}

/**
 * vips_stream_input_new_from_options:
 * @options: option string
 *
 * Create a stream from an option string.
 *
 * Returns: a new #VipsStream
 */
VipsStreamInput *
vips_stream_input_new_from_options( const char *options )
{
	VipsStreamInput *input;

	VIPS_DEBUG_MSG( "vips_stream_input_new_from_options: %s\n", options ); 

	input = VIPS_STREAM_INPUT( 
		g_object_new( VIPS_TYPE_STREAM_INPUT, NULL ) );

	if( vips_object_set_from_string( VIPS_OBJECT( input ), options ) ||
		vips_object_build( VIPS_OBJECT( input ) ) ) {
		VIPS_UNREF( input );
		return( NULL );
	}

	return( input ); 
}

ssize_t
vips_stream_input_read( VipsStreamInput *input, 
	unsigned char *buffer, size_t length )
{
	VipsStreamInputClass *class = VIPS_STREAM_INPUT_GET_CLASS( input );

	ssize_t bytes_read;

	VIPS_DEBUG_MSG( "vips_stream_input_read:\n" );

	bytes_read = 0;

	/* Are we serving from header_bytes? Get what we can from there.
	 */
	if( input->header_bytes &&
		input->read_position < input->header_bytes->len ) {
		ssize_t available;

		available = VIPS_MIN( length, 
			input->header_bytes->len - input->read_position );
		memcpy( buffer, 
			input->header_bytes->data + input->read_position, 
			available );
		input->read_position += available;
		buffer += available;
		length -= available;
		bytes_read += available;

		VIPS_DEBUG_MSG( "    %zd bytes from cache\n", available );
	}

	/* Any more bytes required? Call the read() method.
	 */
	if( length > 0 ) {
		ssize_t n;

		if( (n = class->read( input, buffer, length )) == -1 ) {
			vips_error_system( errno, STREAM_NAME( input ), 
				"%s", _( "read error" ) ); 
			return( -1 );
		}

		/* If we're not seekable, we need to save header bytes for
		 * reuse.
		 */
		if( input->header_bytes &&
			!input->seekable &&
			!input->decode &&
			n > 0 ) 
			g_byte_array_append( input->header_bytes, 
				buffer, n );

		input->read_position += n;
		bytes_read += n;

		VIPS_DEBUG_MSG( "    %zd bytes from read()\n", n );
	}

	VIPS_DEBUG_MSG( "    %zd bytes total\n", bytes_read );

	return( bytes_read );
}

const void *
vips_stream_input_map( VipsStreamInput *input, size_t *length )
{
	VipsStreamInputClass *class = VIPS_STREAM_INPUT_GET_CLASS( input );

	unsigned char buffer[4096];

	VIPS_DEBUG_MSG( "vips_stream_input_map:\n" );

	/* Memory source ... easy!
	 */
	if( input->blob ) {
		VIPS_DEBUG_MSG( "    memory source\n" );
		return( vips_blob_get( input->blob, length ) );
	}

	/* An input that supports mmap.
	 */
	if( input->mapable ) {
		VIPS_DEBUG_MSG( "    mmaping source\n" );
		if( !input->baseaddr ) {
			input->baseaddr = class->map( input, &input->length );
			if( !input->baseaddr )
				return( NULL );
		}

		if( length )
			*length = input->length;

		return( input->baseaddr );
	}

	/* Have to read() the whole thing. header_bytes will keep a copy of
	 * the file.
	 */
	VIPS_DEBUG_MSG( "    read() of entire source\n" );
	if( vips_stream_input_rewind( input ) )
		return( NULL );
	while( vips_stream_input_read( input, buffer, 4096 ) > 0 )
		;

	if( length )
		*length = input->header_bytes->len;

	return( input->header_bytes->data );
}

int
vips_stream_input_rewind( VipsStreamInput *input )
{
	VipsStreamInputClass *class = VIPS_STREAM_INPUT_GET_CLASS( input );

	VIPS_DEBUG_MSG( "vips_stream_input_rewind:\n" );

	if( input->decode ) {
		vips_error( STREAM_NAME( input ),
			"%s", _( "can't rewind after decode begins" ) );
		return( -1 );
	}

	input->read_position = 0;

	return( class->rewind( input ) );
}

void
vips_stream_input_minimise( VipsStreamInput *input )
{
	VipsStreamInputClass *class = VIPS_STREAM_INPUT_GET_CLASS( input );

	class->minimise( input );
}

void 
vips_stream_input_decode( VipsStreamInput *input )
{
	if( !input->decode ) {
		VIPS_DEBUG_MSG( "vips_stream_input_decode:\n" );

		input->decode = TRUE;
		VIPS_FREEF( g_byte_array_unref, input->header_bytes ); 
		VIPS_FREEF( g_byte_array_unref, input->sniff ); 
	}
}

/**
 * vips_stream_input_sniff: 
 * @input: sniff this stream
 * @length: number of bytes to sniff
 *
 * Return a pointer to the first few bytes of the file.
 */
unsigned char *
vips_stream_input_sniff( VipsStreamInput *input, size_t length )
{
	ssize_t n;
	unsigned char *q;

	VIPS_DEBUG_MSG( "vips_stream_input_sniff: %zd bytes\n", length );

	if( vips_stream_input_rewind( input ) )
		return( NULL );

	g_byte_array_set_size( input->sniff, length );

	for( q = input->sniff->data; length > 0; length -= n, q += n )
		if( (n = vips_stream_input_read( input, q, length )) == -1 ||
			n == 0 )
			return( NULL );

	return( input->sniff->data );
}

G_DEFINE_TYPE( VipsStreamOutput, vips_stream_output, VIPS_TYPE_STREAM );

static void
vips_stream_output_finalize( GObject *gobject )
{
	VipsStreamOutput *output = VIPS_STREAM_OUTPUT( gobject );

	VIPS_DEBUG_MSG( "vips_stream_output_finalize:\n" );

	VIPS_FREEF( g_byte_array_unref, output->memory ); 
	if( output->blob ) { 
		vips_area_unref( VIPS_AREA( output->blob ) ); 
		output->blob = NULL;
	}

	G_OBJECT_CLASS( vips_stream_output_parent_class )->finalize( gobject );
}

static int
vips_stream_output_build( VipsObject *object )
{
	VipsStream *stream = VIPS_STREAM( object );
	VipsStreamOutput *output = VIPS_STREAM_OUTPUT( object );

	VIPS_DEBUG_MSG( "vips_stream_output_build: %p\n", output );

	if( VIPS_OBJECT_CLASS( vips_stream_output_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "filename" ) &&
		vips_object_argument_isset( object, "descriptor" ) ) { 
		vips_error( STREAM_NAME( stream ), 
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
			vips_error_system( errno, STREAM_NAME( stream ), 
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
		output->memory = g_byte_array_new();
	}

	return( 0 );
}

static ssize_t 
vips_stream_output_write_real( VipsStreamOutput *output, 
	const unsigned char *data, size_t length )
{
	VipsStream *stream = VIPS_STREAM( output );

	ssize_t len;

	VIPS_DEBUG_MSG( "vips_stream_output_write_real: %zd bytes\n", length );

	if( output->memory ) {
		g_byte_array_append( output->memory, data, length );
		len = length;
	}
	else 
		len = write( stream->descriptor, data, length );

	return( len );
}

static void
vips_stream_output_finish_real( VipsStreamOutput *output ) 
{
	VIPS_DEBUG_MSG( "vips_stream_output_finish_real:\n" );

	/* Move the output buffer into the blob so it can be read out.
	 */
	if( output->memory ) {
		unsigned char *data;
		size_t length;

		length = output->memory->len;
		data = g_byte_array_free( output->memory, FALSE );
		output->memory = NULL;
		vips_blob_set( output->blob,
			(VipsCallbackFn) g_free, data, length );
	}
}

static void
vips_stream_output_class_init( VipsStreamOutputClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_stream_output_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "stream_output";
	object_class->description = _( "output stream" );

	object_class->build = vips_stream_output_build;

	class->write = vips_stream_output_write_real;
	class->finish = vips_stream_output_finish_real;

	/* SET_ALWAYS means that blob is set by C and the obj system is not
	 * involved in creation or destruction. It can be read at any time.
	 */
	VIPS_ARG_BOXED( class, "blob", 3, 
		_( "Blob" ),
		_( "Blob to save to" ),
		VIPS_ARGUMENT_SET_ALWAYS, 
		G_STRUCT_OFFSET( VipsStreamOutput, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_stream_output_init( VipsStreamOutput *output )
{
	output->blob = vips_blob_new( NULL, NULL, 0 );
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

/**
 * vips_stream_output_new_memory:
 *
 * Create a stream which will output to a memory area. Read from @blob to get
 * memory output.
 *
 * See also: vips_stream_output_write().
 *
 * Returns: a new #VipsStream
 */
VipsStreamOutput *
vips_stream_output_new_memory( void )
{
	VipsStreamOutput *stream;

	VIPS_DEBUG_MSG( "vips_stream_output_new_memory:\n" ); 

	stream = VIPS_STREAM_OUTPUT( 
		g_object_new( VIPS_TYPE_STREAM_OUTPUT, 
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( stream ) ) ) {
		VIPS_UNREF( stream );
		return( NULL );
	}

	return( stream ); 
}

int
vips_stream_output_write( VipsStreamOutput *output, 
	const unsigned char *data, size_t length )
{
	VipsStreamOutputClass *class = VIPS_STREAM_OUTPUT_GET_CLASS( output );

	VIPS_DEBUG_MSG( "vips_stream_output_write: %zd bytes\n", length );

	while( length > 0 ) { 
		ssize_t n;

		n = class->write( output, data, length );

		/* n == 0 isn't strictly an error, but we treat it as one to
		 * make sure we don't get stuck in this loop.
		 */
		if( n <= 0 ) {
			vips_error_system( errno, STREAM_NAME( output ),
				"%s", _( "write error" ) ); 
			return( -1 ); 
		}

		length -= n;
		data += n;
	}

	return( 0 );
}

void
vips_stream_output_finish( VipsStreamOutput *output )
{
	VipsStreamOutputClass *class = VIPS_STREAM_OUTPUT_GET_CLASS( output );

	VIPS_DEBUG_MSG( "vips_stream_output_finish:\n" );

	class->finish( output );
}
