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
 * - catch out of range seeks
 * - some sanity thing to prevent endless streams filling memory?
 * - filename encoding
 * - seek END and _size need thinking about with pipes ... perhaps we should
 *   force-read the whole thing in
 * - _size() needs to be a vfunc too (libtiff needs it)
 * - _miminize() is a vfunc, so _open() must be as well 
 *   + perhaps minimise should not be a vfunc? is it really useful for 
 *     subclasses? 
 *   + perhaps make _open() / _close() into vfuncs and don't expose minimise
 * - only fetch length once
 * - need to be able to set is_pipe via constructor
 * - test we can really change all behaviour in the subclass ... add callbacks
 *   as well to make it simpler for language bindings
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

G_DEFINE_TYPE( VipsStreami, vips_streami, VIPS_TYPE_STREAM );

static int
vips_streami_sanity( VipsStreami *streami )
{
	VipsStream *stream = VIPS_STREAM( streami );

	if( streami->blob ) {
		VipsArea *area = VIPS_AREA( streami->blob );

		/* Not a pipe (can map and seek).
		 */
		g_assert( !streami->is_pipe );

		/* Read position must lie within the buffer.
		 */
		g_assert( streami->read_position >= 0 );
		g_assert( streami->read_position < streami->length );
		g_assert( streami->read_position < area->length );

		/* No need for header tracking.
		 */
		g_assert( !streami->header_bytes );

		/* Only have sniff during header,
		 */
		g_assert( streami->decode || 
			!streami->sniff );

		/* No descriptor or filename.
		 */
		g_assert( stream->descriptor == -1 );
		g_assert( stream->close_descriptor == -1 );
		g_assert( stream->tracked_descriptor == -1 );
		g_assert( !stream->filename );
	}
	else if( streami->is_pipe ) {
		/* In header, read_position must be within header_bytes.
		 */
		g_assert( !streami->decode || 
			(streami->read_position >= 0 && 
			 streami->read_position < streami->header_bytes->len) );

		/* If we're in the header, we must save bytes we read. If not 
		 * in header, should have no saved bytes.
		 */
		g_assert( streami->decode || 
			streami->header_bytes );
		g_assert( !streami->decode || 
			!streami->header_bytes );

		/* After we're done with the header, the sniff buffer should
		 * be gone.
		 */
		g_assert( !streami->decode || 
			!streami->sniff );

		/* No length available.
		 */
		g_assert( streami->length == -1 );
	}
	else {
		/* Something that supports seek and map. No need to save
		 * header bytes.
		 */
		g_assert( !streami->header_bytes );

		/* After we're done with the header, the sniff buffer should
		 * be gone.
		 */
		g_assert( !streami->decode || 
			!streami->sniff );

		/* Have length.
		 */
		g_assert( streami->length != -1 );

		/* Read position must lie within the file.
		 */
		g_assert( streami->read_position >= 0 );
		g_assert( streami->read_position < streami->length );

		/* No need for header tracking.
		 */
		g_assert( !streami->header_bytes );

		/* Only have sniff during header,
		 */
		g_assert( streami->decode || 
			!streami->sniff );

		/* Supports minimise, so if descriptor is -1, we must have a
		 * filename we can reopen.
		 */
		g_assert( stream->descriptor != -1 ||
			(stream->filename && stream->descriptor) );
	}
}

static void
vips_streami_finalize( GObject *gobject )
{
	VipsStreami *streami = VIPS_STREAMI( gobject );

	VIPS_FREEF( g_byte_array_unref, streami->header_bytes ); 
	VIPS_FREEF( g_byte_array_unref, streami->sniff ); 

	G_OBJECT_CLASS( vips_streami_parent_class )->finalize( gobject );
}

static int
vips_streami_open( VipsStreami *streami )
{
	VipsStream *stream = VIPS_STREAM( streami );

	vips_streami_sanity( streami );

	if( stream->descriptor == -1 &&
		stream->tracked_descriptor == -1 &&
		stream->filename ) {
		int fd;

		if( (fd = vips_tracked_open( stream->filename, 
			MODE_READ )) == -1 ) {
			vips_error_system( errno, vips_stream_name( stream ), 
				"%s", _( "unable to open for read" ) ); 
			return( -1 ); 
		}

		stream->tracked_descriptor = fd;
		stream->descriptor = fd;

		if( stream->length == -1 &&
			(stream->length = vips_file_length( fd )) == -1 )
			return( -1 );

		VIPS_DEBUG_MSG( "vips_streami_open: "
			"restoring read position %zd\n", 
			streami->read_position );
		if( vips__seek( stream->descriptor, 
			streami->read_position, SEEK_SET ) == -1 )
			return( -1 );
	}

	return( 0 );
}

static int
vips_streami_build( VipsObject *object )
{
	VipsStream *stream = VIPS_STREAM( object );
	VipsStreami *streami = VIPS_STREAMI( object );

	VIPS_DEBUG_MSG( "vips_streami_build: %p\n", streami );

	if( VIPS_OBJECT_CLASS( vips_streami_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "filename" ) &&
		vips_object_argument_isset( object, "descriptor" ) ) { 
		vips_error( STREAM_NAME( stream ), 
			"%s", _( "don't set 'filename' and 'descriptor'" ) ); 
		return( -1 ); 
	}

	if( vips_object_argument_isset( object, "filename" ) &&
		vips_streami_open( streami ) )
		return( -1 );

	if( vips_object_argument_isset( object, "descriptor" ) ) {
		stream->descriptor = dup( stream->descriptor );
		stream->close_descriptor = stream->descriptor;
	}

	/* If there's a descriptor for streami, test its properties.
	 */
	if( stream->descriptor != -1 ) {
		/* Do +=0 on the current position. This fails for pipes, at
		 * least on linux. 
		 */
		if( vips__seek( stream->descriptor, 0, SEEK_CUR ) != -1 )
			streami->is_pipe = TRUE;
	}

	/* Need to save the header for pipe-style sources.
	 */
	if( streami->is_pipe )
		streami->header_bytes = g_byte_array_new();

	/* We always want a sniff buffer.
	 */
	streami->sniff = g_byte_array_new();

	return( 0 );
}

static ssize_t
vips_streami_read_real( VipsStreami *streami, void *data, size_t length )
{
	VipsStream *stream = VIPS_STREAM( streami );

	VIPS_DEBUG_MSG( "vips_streami_read_real:\n" );

	if( streami->blob ) {
		VipsArea *area = VIPS_AREA( streami->blob );
		ssize_t available = VIPS_MIN( length,
			area->length - streami->read_position );

		if( available <= 0 )
			return( 0 );

		memcpy( data, area->data + streami->read_position, available );

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
vips_streami_map_real( VipsStreami *streami, size_t *length )
{
	VipsStream *stream = VIPS_STREAM( streami );

	const void *file_baseaddr;

	g_assert( streami->length > 0 );

	if( !(file_baseaddr = vips__mmap( stream->descriptor, 
		FALSE, streami->length, 0 )) )
		return( NULL );

	if( length )
		*length = streami->length;

	return( file_baseaddr );
}

static gint64
vips_streami_seek_real( VipsStreami *streami, gint64 offset, int whence )
{
	VipsStream *stream = VIPS_STREAM( streami );

	VIPS_DEBUG_MSG( "vips_streami_seek_real:\n" );

	if( streami->is_pipe ||
		stream->descriptor == -1 ) {
		vips_error( vips_stream_name( stream ), 
			"%s", _( "not seekable" ) ); 
		return( -1 );
	}

	return( vips__seek( stream->descriptor, offset, whence ) );
}

static void
vips_streami_minimise_real( VipsStreami *streami )
{
	VipsStream *stream = VIPS_STREAM( streami );

	VIPS_DEBUG_MSG( "vips_streami_minimise_real:\n" );

	if( stream->filename &&
		stream->descriptor != -1 &&
		!streami->is_pipe ) 
		vips_stream_close( stream );
}

static void
vips_streami_class_init( VipsStreamiClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_streami_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "streami";
	object_class->description = _( "streami stream" );

	object_class->build = vips_streami_build;

	class->read = vips_streami_read_real;
	class->map = vips_streami_map_real;
	class->seek = vips_streami_seek_real;
	class->minimise = vips_streami_minimise_real;

	VIPS_ARG_BOXED( class, "blob", 3, 
		_( "Blob" ),
		_( "blob to load from" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsStreami, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_streami_init( VipsStreami *streami )
{
	streami->length = -1;
}

/**
 * vips_streami_new_from_descriptor:
 * @descriptor: read from this file descriptor
 *
 * Create an streami stream attached to a file descriptor. @descriptor is 
 * closed with close() when the #VipsStream is finalized. 
 *
 * Returns: a new #VipsStream
 */
VipsStreami *
vips_streami_new_from_descriptor( int descriptor )
{
	VipsStreami *streami;

	VIPS_DEBUG_MSG( "vips_streami_new_from_descriptor: %d\n", 
		descriptor );

	streami = VIPS_STREAMI( 
		g_object_new( VIPS_TYPE_STREAMI, 
			"descriptor", descriptor,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( streami ) ) ) {
		VIPS_UNREF( streami );
		return( NULL );
	}

	vips_streami_sanity( streami );

	return( streami ); 
}

/**
 * vips_streami_new_from_filename:
 * @descriptor: read from this filename 
 *
 * Create an streami stream attached to a file.
 *
 * Returns: a new #VipsStream
 */
VipsStreami *
vips_streami_new_from_filename( const char *filename )
{
	VipsStreami *streami;

	VIPS_DEBUG_MSG( "vips_streami_new_from_filename: %s\n", 
		filename );

	streami = VIPS_STREAMI( 
		g_object_new( VIPS_TYPE_STREAMI, 
			"filename", filename,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( streami ) ) ) {
		VIPS_UNREF( streami );
		return( NULL );
	}

	vips_streami_sanity( streami );

	return( streami ); 
}

/**
 * vips_streami_new_from_blob:
 * @blob: memory area to load
 *
 * Create a stream attached to an area of memory. 
 *
 * Returns: a new #VipsStream
 */
VipsStreami *
vips_streami_new_from_blob( VipsBlob *blob )
{
	VipsStreami *streami;

	VIPS_DEBUG_MSG( "vips_streami_new_from_blob: %p\n", blob ); 

	streami = VIPS_STREAMI( 
		g_object_new( VIPS_TYPE_STREAMI, 
			"blob", blob,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( streami ) ) ) {
		VIPS_UNREF( streami );
		return( NULL );
	}

	vips_streami_sanity( streami );

	return( streami ); 
}

/**
 * vips_streami_new_from_memory:
 * @data: memory area to load
 * @length: size of memory area
 *
 * Create a stream attached to an area of memory. 
 *
 * You must not free @data while the stream is active. 
 *
 * Returns: a new #VipsStream
 */
VipsStreami *
vips_streami_new_from_memory( const void *data, size_t length )
{
	VipsStreami *streami;
	VipsBlob *blob;

	VIPS_DEBUG_MSG( "vips_streami_new_from_buffer: "
		"%p, length = %zd\n", data, length ); 

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, data, length );

	streami = vips_streami_new_from_blob( blob ); 

	vips_area_unref( VIPS_AREA( blob ) );

	vips_streami_sanity( streami );

	return( streami ); 
}

/**
 * vips_streami_new_from_options:
 * @options: option string
 *
 * Create a stream from an option string.
 *
 * Returns: a new #VipsStream
 */
VipsStreami *
vips_streami_new_from_options( const char *options )
{
	VipsStreami *streami;

	VIPS_DEBUG_MSG( "vips_streami_new_from_options: %s\n", options ); 

	streami = VIPS_STREAMI( 
		g_object_new( VIPS_TYPE_STREAMI, NULL ) );

	if( vips_object_set_from_string( VIPS_OBJECT( streami ), options ) ||
		vips_object_build( VIPS_OBJECT( streami ) ) ) {
		VIPS_UNREF( streami );
		return( NULL );
	}

	vips_streami_sanity( streami );

	return( streami ); 
}

ssize_t
vips_streami_read( VipsStreami *streami, void *buffer, size_t length )
{
	VipsStreamiClass *class = VIPS_STREAMI_GET_CLASS( streami );

	ssize_t bytes_read;

	VIPS_DEBUG_MSG( "vips_streami_read:\n" );

	vips_streami_sanity( streami );

	bytes_read = 0;

	/* Are we serving from header_bytes? Get what we can from there.
	 */
	if( streami->header_bytes &&
		streami->read_position < streami->header_bytes->len ) {
		ssize_t available;

		available = VIPS_MIN( length, 
			streami->header_bytes->len - streami->read_position );
		memcpy( buffer, 
			streami->header_bytes->data + streami->read_position, 
			available );
		streami->read_position += available;
		buffer += available;
		length -= available;
		bytes_read += available;

		VIPS_DEBUG_MSG( "    %zd bytes from cache\n", available );
	}

	/* Any more bytes required? Call the read() vfunc.
	 */
	if( length > 0 ) {
		ssize_t n;

		if( (n = class->read( streami, buffer, length )) == -1 ) {
			vips_error_system( errno, STREAM_NAME( streami ), 
				"%s", _( "read error" ) ); 
			return( -1 );
		}

		/* We need to save bytes if we're in header mode and we can't
		 * seek or map.
		 */
		if( streami->header_bytes &&
			streami->is_pipe &&
			!streami->decode &&
			n > 0 ) 
			g_byte_array_append( streami->header_bytes, 
				buffer, n );

		streami->read_position += n;
		bytes_read += n;

		VIPS_DEBUG_MSG( "    %zd bytes from read()\n", n );
	}

	VIPS_DEBUG_MSG( "    %zd bytes total\n", bytes_read );

	vips_streami_sanity( streami );

	return( bytes_read );
}

/* Read the entire pipe into memory and turn this into a memory source stream.
 */
static int
vips_streami_read_whole_pipe( VipsStreami *streami )
{
	gint64 old_read_position;
	unsigned char buffer[4096];
	unsigned char *data;

	VIPS_DEBUG_MSG( "vips_streami_read_whole_pipe:\n" );

	vips_streami_sanity( streami );

	old_read_position = streami->read_position;

	if( vips_streami_rewind( streami ) )
		return( -1 );
	/* TODO ... add something to prevent unbounded streams filling memory.
	 */
	while( vips_streami_read( streami, buffer, 4096 ) > 0 )
		;

	streami->read_position = old_read_position;

	/* Move header_bytes into the memory blob and set up as a memory
	 * source.
	 */
	streami->length = streami->header_bytes->len;
	data = g_byte_array_free( streami->header_bytes, FALSE );
	streami->header_bytes = NULL;
	vips_blob_set( streami->blob,
		(VipsCallbackFn) g_free, data, streami->length );
	vips_stream_close( stream );
	streami->is_pipe = FALSE;

	vips_streami_sanity( streami );

	return( 0 );
}

const void *
vips_streami_map( VipsStreami *streami, size_t *length_out )
{
	VipsStreamiClass *class = VIPS_STREAMI_GET_CLASS( streami );

	void *data;
	ssize_t length;

	VIPS_DEBUG_MSG( "vips_streami_map:\n" );

	vips_streami_sanity( streami );

	/* Memory source ... easy!
	 */
	if( streami->blob ) {
		VIPS_DEBUG_MSG( "    memory source\n" );

		data = vips_blob_get( streami->blob, &length );
	}
	else if( streami->is_pipe ) {
		if( vips_streami_read_whole_pipe( streami ) )
			return( NULL );

		data = vips_blob_get( streami->blob, &length );
	}
	else {
		/* A streami that supports mmap.
		 */
		VIPS_DEBUG_MSG( "    mmaping source\n" );
		if( !streami->baseaddr &&
			!(streami->baseaddr = 
				class->map( streami, &streami->length )) )
			return( NULL );

		length = streami->length;
		data = streami->baseaddr;
	}

	if( length_out )
		*length_out = length;

	vips_streami_sanity( streami );

	return( data );
}

gint64
vips_streami_seek( VipsStreami *streami, gint64 offset, int whence )
{
	VipsStreamiClass *class = VIPS_STREAMI_GET_CLASS( streami );

	gint64 new_pos;

	VIPS_DEBUG_MSG( "vips_streami_seek:\n" );

	vips_streami_sanity( streami );

	switch( whence ) {
	case SEEK_SET:
		new_pos = offset;
		break;

	case SEEK_CUR:
		new_pos = streami->read_position + offset;
		break;

	case SEEK_END:
		if( streami->length == -1 &&
			vips_streami_read_whole_pipe( streami ) )
			return( -1 );

		new_pos = streami->length + offset;
		break;

	default:
		vips_error( vips_stream_name( VIPS_STREAM( streami ) ), 
			"%s", _( "bad 'whence'" ) );
                return( -1 );
		break;
	}

	if( streami->is_pipe ) {
		/* We can seek on non-seekable streams during the header phase.
		 */
		if( streami->decode ) { 
			vips_error( STREAM_NAME( streami ),
				"%s", _( "can't rewind after decode begins" ) );
			return( -1 );
		}

		g_assert( streami->header_bytes );

		/* We may not have read up to the new position.
		 */
		while( streami->read_position < new_pos ) {
			unsigned char buffer[4096];
			ssize_t read;

			read = vips_streami_read( streami, buffer, 4096 );
			if( read < 0 )
				return( -1 );
			if( read == 0 ) {
			}
		}
	}
	else {
		if( (new_pos = class->seek( streami, offset, whence )) == -1 )
			return( -1 );
	}

	streami->read_position = new_pos;

	vips_streami_sanity( streami );

	return( new_pos );
}

int
vips_streami_rewind( VipsStreami *streami )
{
	VIPS_DEBUG_MSG( "vips_streami_rewind:\n" );

	vips_streami_sanity( streami );

	if( vips_streami_seek( streami, 0, SEEK_SET ) != 0 )
		return( -1 );

	vips_streami_sanity( streami );

	return( 0 );
}

void
vips_streami_minimise( VipsStreami *streami )
{
	VipsStreamiClass *class = VIPS_STREAMI_GET_CLASS( streami );

	vips_streami_sanity( streami );

	class->minimise( streami );

	vips_streami_sanity( streami );
}

int 
vips_streami_decode( VipsStreami *streami )
{
	VIPS_DEBUG_MSG( "vips_streami_decode:\n" );

	vips_streami_sanity( streami );

	/* We have finished reading the header. We can discard the bytes we
	 * saved.
	 */
	if( !streami->decode ) {
		streami->decode = TRUE;
		VIPS_FREEF( g_byte_array_unref, streami->header_bytes ); 
		VIPS_FREEF( g_byte_array_unref, streami->sniff ); 
	}

	/* Make sure we are open, in case we've been minimised.
	 */
	if( vips_streami_open( streami ) )
		return( -1 );

	vips_streami_sanity( streami );

	return( 0 );
}

/**
 * vips_streami_sniff: 
 * @streami: sniff this stream
 * @length: number of bytes to sniff
 *
 * Return a pointer to the first few bytes of the file.
 */
unsigned char *
vips_streami_sniff( VipsStreami *streami, size_t length )
{
	ssize_t n;
	unsigned char *q;

	VIPS_DEBUG_MSG( "vips_streami_sniff: %zd bytes\n", length );

	vips_streami_sanity( streami );

	if( vips_streami_rewind( streami ) )
		return( NULL );

	g_byte_array_set_size( streami->sniff, length );

	for( q = streami->sniff->data; length > 0; length -= n, q += n )
		if( (n = vips_streami_read( streami, q, length )) == -1 ||
			n == 0 )
			return( NULL );

	vips_streami_sanity( streami );

	return( streami->sniff->data );
}

gint64
vips_streami_size( VipsStreami *streami )
{
	VipsStream *stream = VIPS_STREAM( streami );

	gint64 size;

	vips_streami_sanity( streami );

	if( stream->descriptor >= 0 &&
		(size = vips_file_length( stream->descriptor )) >= 0 ) 
		return( size );
	else if( streami->blob )
		return( VIPS_AREA( streami->blob )->length );
	else if( streami->header_bytes )
		return( streami->header_bytes->len );
	else 
		return( -1 );
}
