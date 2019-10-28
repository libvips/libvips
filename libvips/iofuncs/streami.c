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
 * - something to stop unbounded streams filling memory
 * - gaussblur is missing the vector path again argh
 * - can we map and then close the fd? how about on Windows?
 * - make a subclass that lets you set vfuncs as params, inc. close(),
 *   is_pipe etc.
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

G_DEFINE_TYPE( VipsStreami, vips_streami, VIPS_TYPE_STREAM );

#ifdef VIPS_DEBUG
static void
vips_streami_sanity( VipsStreami *streami )
{
	if( streami->data ) {
		/* Not a pipe (can map and seek).
		 */
		g_assert( !streami->is_pipe );

		/* Read position must lie within the buffer. <= length, since
		 * it can be one beyond. Imagine read_position 0 and a
		 * zero-length buffer.
		 */
		g_assert( streami->read_position >= 0 );
		g_assert( streami->read_position <= streami->length );

		/* No need for header tracking.
		 */
		g_assert( !streami->header_bytes );

		/* After we're done with the header, the sniff buffer should
		 * be gone.
		 */
		g_assert( !streami->decode || 
			!streami->sniff );
	}
	else if( streami->is_pipe ) {
		/* In header, read_position must be within header_bytes.
		 */
		g_assert( streami->decode || 
			(streami->read_position >= 0 && 
			 streami->read_position <= 
			 	streami->header_bytes->len) );

		/* If we're in the header, we must save bytes we read. If not 
		 * in header, should have no saved bytes.
		 */
		g_assert( (streami->decode && !streami->header_bytes) ||
			(!streami->decode && streami->header_bytes ) );

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
		g_assert( streami->read_position <= streami->length );

		/* No need for header tracking.
		 */
		g_assert( !streami->header_bytes );

		/* After we're done with the header, the sniff buffer should
		 * be gone.
		 */
		g_assert( !streami->decode || 
			!streami->sniff );

		/* Supports minimise, so if descriptor is -1, we must have a
		 * filename we can reopen.
		 */
		g_assert( VIPS_STREAM( streami )->descriptor != -1 ||
			(VIPS_STREAM( streami )->filename && 
			 VIPS_STREAM( streami )->descriptor) );
	}
}
#endif /*VIPS_DEBUG*/

#ifdef VIPS_DEBUG
#define SANITY( S ) vips_streami_sanity( S )
#else /*!VIPS_DEBUG*/
#define SANITY( S )
#endif /*VIPS_DEBUG*/

static void
vips_streami_finalize( GObject *gobject )
{
	VipsStreami *streami = VIPS_STREAMI( gobject );

	VIPS_FREEF( g_byte_array_unref, streami->header_bytes ); 
	VIPS_FREEF( g_byte_array_unref, streami->sniff ); 
	if( streami->mmap_baseaddr ) {
		vips__munmap( streami->mmap_baseaddr, streami->mmap_length );
		streami->mmap_baseaddr = NULL;
	}

	G_OBJECT_CLASS( vips_streami_parent_class )->finalize( gobject );
}

static int
vips_streami_build( VipsObject *object )
{
	VipsStream *stream = VIPS_STREAM( object );
	VipsStreami *streami = VIPS_STREAMI( object );
	VipsStreamiClass *class = VIPS_STREAMI_GET_CLASS( streami );

	VIPS_DEBUG_MSG( "vips_streami_build: %p\n", streami );

	if( VIPS_OBJECT_CLASS( vips_streami_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "filename" ) &&
		vips_object_argument_isset( object, "descriptor" ) ) { 
		vips_error( vips_stream_nick( stream ), 
			"%s", _( "don't set 'filename' and 'descriptor'" ) ); 
		return( -1 ); 
	}

	/* unminimise will open the filename.
	 */
	if( vips_object_argument_isset( object, "filename" ) &&
		vips_streami_unminimise( streami ) )
		return( -1 );

	if( vips_object_argument_isset( object, "descriptor" ) ) {
		stream->descriptor = dup( stream->descriptor );
		stream->close_descriptor = stream->descriptor;
	}

	if( vips_object_argument_isset( object, "blob" ) ) {
		size_t length;

		streami->data = vips_blob_get( streami->blob, &length );
		streami->length = VIPS_MIN( length, G_MAXSSIZE );
	}

	/* If there's a descriptor for streami, test its properties.
	 */
	if( stream->descriptor != -1 ) {
		/* Can we seek? If not, this is some kind of pipe.
		 * 
		 * We must call the class method directly: if we go via
		 * vips_streami_seek() we'll trigger seek emulation on pipes.
		 */
		if( class->seek( streami, 0, SEEK_CUR ) == -1 ) {
			VIPS_DEBUG_MSG( "    not seekable\n" );
			streami->is_pipe = TRUE;
		}

		/* Try and get the length, as long as we're seekable.
		 */
		if( !streami->is_pipe &&
			(streami->length = vips_streami_size( streami )) == -1 )
			return( -1 );
	}

	/* If we can seek, we won't need to save header bytes.
	 */
	if( !streami->is_pipe ) 
		VIPS_FREEF( g_byte_array_unref, streami->header_bytes ); 

	return( 0 );
}

static ssize_t
vips_streami_read_real( VipsStreami *streami, void *data, size_t length )
{
	VipsStream *stream = VIPS_STREAM( streami );

	ssize_t bytes_read;

	VIPS_DEBUG_MSG( "vips_streami_read_real:\n" );

	do { 
		bytes_read = read( stream->descriptor, data, length );
	} while( bytes_read < 0 && errno == EINTR );

	return( bytes_read );

}

static gint64
vips_streami_seek_real( VipsStreami *streami, gint64 offset, int whence )
{
	VipsStream *stream = VIPS_STREAM( streami );

	gint64 new_pos;

	VIPS_DEBUG_MSG( "vips_streami_seek_real:\n" );

	/* Like _read_real(), we must not set a vips_error. We need to use the
	 * vips__seek() wrapper so we can seek long files on Windows.
	 */
	vips_error_freeze();
	new_pos = vips__seek( stream->descriptor, offset, whence );
	vips_error_thaw();

	return( new_pos );
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
	class->seek = vips_streami_seek_real;

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
	streami->sniff = g_byte_array_new();
	streami->header_bytes = g_byte_array_new();
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

	streami = VIPS_STREAMI( g_object_new( VIPS_TYPE_STREAMI, 
		"descriptor", descriptor,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( streami ) ) ) {
		VIPS_UNREF( streami );
		return( NULL );
	}

	SANITY( streami );

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

	streami = VIPS_STREAMI( g_object_new( VIPS_TYPE_STREAMI, 
		"filename", filename,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( streami ) ) ) {
		VIPS_UNREF( streami );
		return( NULL );
	}

	SANITY( streami );

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

	streami = VIPS_STREAMI( g_object_new( VIPS_TYPE_STREAMI, 
		"blob", blob,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( streami ) ) ) {
		VIPS_UNREF( streami );
		return( NULL );
	}

	SANITY( streami );

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

	SANITY( streami );

	return( streami ); 
}

/**
 * vips_streami_new_from_options:
 * @options: option string
 *
 * Create a stream from an option string.
 *
 * Returns: a new #VipsStreami
 */
VipsStreami *
vips_streami_new_from_options( const char *options )
{
	VipsStreami *streami;

	VIPS_DEBUG_MSG( "vips_streami_new_from_options: %s\n", options ); 

	streami = VIPS_STREAMI( g_object_new( VIPS_TYPE_STREAMI, NULL ) );

	if( vips_object_set_from_string( VIPS_OBJECT( streami ), options ) ||
		vips_object_build( VIPS_OBJECT( streami ) ) ) {
		VIPS_UNREF( streami );
		return( NULL );
	}

	SANITY( streami );

	return( streami ); 
}

/**
 * vips_streami_minimise:
 * @streami: input stream to operate on
 *
 * Minimise the stream. As many stream resources as can be safely removed are
 * removed. Use vips_streami_unminimise() to restore the stream if you wish to
 * use it again.
 *
 * Loaders should call this in response to the minimise signal on their output
 * image.
 *
 * Returns: 0 on success, or -1 on error.
 */
void
vips_streami_minimise( VipsStreami *streami )
{
	VipsStream *stream = VIPS_STREAM( streami );

	VIPS_DEBUG_MSG( "vips_streami_minimise:\n" );

	SANITY( streami );

	if( stream->filename &&
		stream->descriptor != -1 &&
		stream->tracked_descriptor == stream->descriptor &&
		!streami->is_pipe ) {
		VIPS_DEBUG_MSG( "    tracked_close()\n" );
		vips_tracked_close( stream->tracked_descriptor );
		stream->tracked_descriptor = -1;
		stream->descriptor = -1;
	}

	SANITY( streami );
}

/**
 * vips_streami_unminimise:
 * @streami: input stream to operate on
 *
 * Restore the stream after minimisation. This is called at the start 
 * of every stream method, so loaders should not usually need this.
 *
 * See also: vips_streami_minimise().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_streami_unminimise( VipsStreami *streami )
{
	VipsStream *stream = VIPS_STREAM( streami );

	VIPS_DEBUG_MSG( "vips_streami_unminimise:\n" );

	if( stream->descriptor == -1 &&
		stream->tracked_descriptor == -1 &&
		stream->filename ) {
		int fd;

		if( (fd = vips_tracked_open( stream->filename, 
			MODE_READ )) == -1 ) 
			return( -1 ); 

		stream->tracked_descriptor = fd;
		stream->descriptor = fd;

		VIPS_DEBUG_MSG( "vips_streami_unminimise: "
			"restoring read position %zd\n", 
			streami->read_position );
		if( vips__seek( stream->descriptor, 
			streami->read_position, SEEK_SET ) == -1 )
			return( -1 );
	}

	return( 0 );
}

/**
 * vips_streami_decode:
 * @streami: input stream to operate on
 *
 * Signal the end of header read and the start of the pixel decode phase. 
 * After this, you can no longer seek on this stream.
 *
 * Loaders should call this at the end of header read.
 *
 * See also: vips_streami_unminimise().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_streami_decode( VipsStreami *streami )
{
	VIPS_DEBUG_MSG( "vips_streami_decode:\n" );

	SANITY( streami );

	/* We have finished reading the header. We can discard the header bytes
	 * we saved.
	 */
	if( !streami->decode ) {
		streami->decode = TRUE;
		VIPS_FREEF( g_byte_array_unref, streami->header_bytes ); 
		VIPS_FREEF( g_byte_array_unref, streami->sniff ); 
	}

	vips_streami_minimise( streami );

	SANITY( streami );

	return( 0 );
}

/**
 * vips_streami_read:
 * @streami: input stream to operate on
 * @buffer: store bytes here
 * @length: length of @buffer in bytes
 *
 * Read up to @length bytes from @streami and store the bytes in @buffer.
 * Return the number of bytes actually read. If all bytes have been read from 
 * the file, return 0.
 *
 * Arguments exactly as read(2).
 *
 * Returns: the number of bytes raed, 0 on end of file, -1 on error.
 */
ssize_t
vips_streami_read( VipsStreami *streami, void *buffer, size_t length )
{
	VipsStreamiClass *class = VIPS_STREAMI_GET_CLASS( streami );

	ssize_t bytes_read;

	VIPS_DEBUG_MSG( "vips_streami_read:\n" );

	SANITY( streami );

	if( vips_streami_unminimise( streami ) )
		return( -1 );

	bytes_read = 0;

	if( streami->data ) {
		/* The whole thing is in memory somehow.
		 */
		ssize_t available = VIPS_MIN( length,
			streami->length - streami->read_position );

		VIPS_DEBUG_MSG( "    %zd bytes from memory\n", available );
		memcpy( buffer, 
			streami->data + streami->read_position, available );
		streami->read_position += available;
		bytes_read += available;
	}
	else {
		/* Some kind of filesystem source. 
		 *
		 * Get what we can from header_bytes. We may need to read 
		 * some more after this.
		 */
		if( streami->header_bytes &&
			streami->read_position < streami->header_bytes->len ) {
			ssize_t available = VIPS_MIN( length, 
				streami->header_bytes->len - 
					streami->read_position );

			VIPS_DEBUG_MSG( "    %zd bytes from cache\n", 
				available );
			memcpy( buffer, 
				streami->header_bytes->data + 
					streami->read_position, 
				available );
			streami->read_position += available;
			buffer += available;
			length -= available;
			bytes_read += available;
		}

		/* Any more bytes requested? Call the read() vfunc.
		 */
		if( length > 0 ) {
			ssize_t n;

			n = class->read( streami, buffer, length );
			VIPS_DEBUG_MSG( "    %zd bytes from read()\n", n );
			if( n == -1 ) {
				vips_error_system( errno, 
					vips_stream_nick( 
						VIPS_STREAM( streami ) ), 
					"%s", _( "read error" ) ); 
				return( -1 );
			}

			/* We need to save bytes if we're in header mode and 
			 * we can't seek or map.
			 */
			if( streami->header_bytes &&
				streami->is_pipe &&
				!streami->decode &&
				n > 0 ) 
				g_byte_array_append( streami->header_bytes, 
					buffer, n );

			streami->read_position += n;
			bytes_read += n;
		}
	}

	VIPS_DEBUG_MSG( "    %zd bytes total\n", bytes_read );

	SANITY( streami );

	return( bytes_read );
}

/* Read to a position. -1 means read to end of stream. Does not chenge 
 * read_position.
 */
static int
vips_streami_pipe_read_to_position( VipsStreami *streami, gint64 target )
{
	gint64 old_read_position;
	unsigned char buffer[4096];

	VIPS_DEBUG_MSG( "vips_streami_pipe_read_position: %" G_GINT64_FORMAT 
		"\n", target );

	g_assert( !streami->decode );
	g_assert( streami->header_bytes );

	if( target < 0 ||
		(streami->length != -1 && 
		 target > streami->length) ) {
		vips_error( vips_stream_nick( VIPS_STREAM( streami ) ), 
			_( "bad read to %" G_GINT64_FORMAT ), target );
		return( -1 );
	}

	old_read_position = streami->read_position;

	/* TODO ... add something to prevent unbounded streams filling memory
	 * if target == -1.
	 */
	while( target == -1 ||
		streami->read_position < target ) {
		ssize_t read;

		read = vips_streami_read( streami, buffer, 4096 );
		if( read == -1 )
			return( -1 );
		if( read == 0 )
			break;
	}

	streami->read_position = old_read_position;

	return( 0 );
}

/* Read the entire pipe into memory and turn this into a memory source stream.
 */
static int
vips_streami_pipe_to_memory( VipsStreami *streami )
{
	VIPS_DEBUG_MSG( "vips_streami_pipe_to_memory:\n" );

	g_assert( streami->is_pipe );
	g_assert( !streami->blob );
	g_assert( !streami->decode );
	g_assert( streami->header_bytes );

	if( vips_streami_pipe_read_to_position( streami, -1 ) )
		return( -1 );

	/* Move header_bytes into the memory blob and set up as a memory
	 * source.
	 */
	streami->length = streami->header_bytes->len;
	streami->data = streami->header_bytes->data;
	streami->is_pipe = FALSE;

	/* TODO ... we could close more fds here.
	 */
	vips_streami_minimise( streami );

	return( 0 );
}

static int
vips_streami_descriptor_to_memory( VipsStreami *streami )
{
	VipsStream *stream = VIPS_STREAM( streami );

	VIPS_DEBUG_MSG( "vips_streami_descriptor_to_memory:\n" );

	g_assert( streami->length > 0 );
	g_assert( !streami->blob );

	if( !(streami->mmap_baseaddr = vips__mmap( stream->descriptor, 
		FALSE, streami->length, 0 )) )
		return( -1 );
	streami->data = streami->mmap_baseaddr;
	streami->mmap_length = streami->length;

	return( 0 );
}

/**
 * vips_streami_map:
 * @streami: input stream to operate on
 * @length_out: return the file length here, or NULL
 *
 * Map the stream object entirely into memory, and return a pointer to the
 * start. If @length_out is non-NULL, the file size if written to it.
 *
 * This operation can take a long time.
 *
 * Returns: a pointer to the start of the file contents, or NULL on error.
 */
const void *
vips_streami_map( VipsStreami *streami, size_t *length_out )
{
	VipsStream *stream = VIPS_STREAM( streami );

	VIPS_DEBUG_MSG( "vips_streami_map:\n" );

	SANITY( streami );

	if( vips_streami_unminimise( streami ) )
		return( NULL );

	/* Pipes need to be converted to memory streams.
	 */
	if( streami->is_pipe &&
		vips_streami_pipe_to_memory( streami ) )
		return( NULL );

	/* Seekable descriptor sources can be mmaped and become memory
	 * sources.
	 */
	if( !streami->is_pipe &&
		!streami->mmap_baseaddr &&
		streami->length > 0 &&
		stream->descriptor != -1 &&
		vips_streami_descriptor_to_memory( streami ) )
		return( NULL );

	if( length_out )
		*length_out = streami->length;

	SANITY( streami );

	return( streami->data );
}

/**
 * vips_streami_seek:
 * @streami: input stream to operate on
 * @offset: seek by this offset
 * @whence: seek relative to this point
 *
 * Move the file read position. You can't call this after pixel decode starts.
 * The arguments are exactly as lseek(2).
 *
 * Returns: the new file position, or -1 on error.
 */
gint64
vips_streami_seek( VipsStreami *streami, gint64 offset, int whence )
{
	VipsStreamiClass *class = VIPS_STREAMI_GET_CLASS( streami );

	gint64 new_pos;

	VIPS_DEBUG_MSG( "vips_streami_seek: offset = %" G_GINT64_FORMAT 
		", whence = %d\n", offset, whence );

	SANITY( streami );

	if( vips_streami_unminimise( streami ) )
		return( -1 );

	if( streami->data ) {
		switch( whence ) {
		case SEEK_SET:
			new_pos = offset;
			break;

		case SEEK_CUR:
			new_pos = streami->read_position + offset;
			break;

		case SEEK_END:
			new_pos = streami->length + offset;
			break;

		default:
			vips_error( vips_stream_nick( VIPS_STREAM( streami ) ), 
				"%s", _( "bad 'whence'" ) );
			return( -1 );
			break;
		}
	}
	else if( streami->is_pipe ) {
		switch( whence ) {
		case SEEK_SET:
			new_pos = offset;
			break;

		case SEEK_CUR:
			new_pos = streami->read_position + offset;
			break;

		case SEEK_END:
			/* We have to read the whole stream into memory to get
			 * the length.
			 */
			if( streami->length == -1 &&
				vips_streami_pipe_to_memory( streami ) )
				return( -1 );

			new_pos = streami->length + offset;
			break;

		default:
			vips_error( vips_stream_nick( VIPS_STREAM( streami ) ), 
				"%s", _( "bad 'whence'" ) );
			return( -1 );
			break;
		}

		if( vips_streami_pipe_read_to_position( streami, new_pos ) )
			return( -1 );
	}
	else {
		if( (new_pos = class->seek( streami, offset, whence )) == -1 )
			return( -1 );
	}

	/* Don't allow out of range seeks.
	 */
	if( new_pos < 0 ||
		(streami->length != -1 && 
		 new_pos > streami->length) ) {
		vips_error( vips_stream_nick( VIPS_STREAM( streami ) ), 
			_( "bad seek to %" G_GINT64_FORMAT ), new_pos );
                return( -1 );
	}

	streami->read_position = new_pos;

	SANITY( streami );

	VIPS_DEBUG_MSG( "    new_pos = %" G_GINT64_FORMAT "\n", new_pos );

	return( new_pos );
}

/**
 * vips_streami_rewind:
 * @streami: input stream to operate on
 *
 * Rewind the stream to the start. You can't do this after pixel decode phase
 * starts.
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_streami_rewind( VipsStreami *streami )
{
	VIPS_DEBUG_MSG( "vips_streami_rewind:\n" );

	SANITY( streami );

	if( vips_streami_seek( streami, 0, SEEK_SET ) != 0 )
		return( -1 );

	SANITY( streami );

	return( 0 );
}

/**
 * vips_streami_size:
 * @streami: input stream to operate on
 *
 * Return the size in bytes of the stream object. Unseekable streams, for
 * example pipes, will have to be read entirely into memory before the size 
 * can be found, so this operation can take a long time.
 *
 * Returns: number of bytes in stream, or -1 on error.
 */
gint64
vips_streami_size( VipsStreami *streami )
{
	gint64 size;
	gint64 read_position;

	VIPS_DEBUG_MSG( "vips_streami_size:\n" );

	SANITY( streami );

	read_position = vips_streami_seek( streami, 0, SEEK_CUR );
	size = vips_streami_seek( streami, 0, SEEK_END );
	vips_streami_seek( streami, read_position, SEEK_SET );

	SANITY( streami );

	return( size );
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

	SANITY( streami );

	if( vips_streami_unminimise( streami ) ||
		vips_streami_rewind( streami ) )
		return( NULL );

	g_byte_array_set_size( streami->sniff, length );

	for( q = streami->sniff->data; length > 0; length -= n, q += n )
		if( (n = vips_streami_read( streami, q, length )) == -1 ||
			n == 0 )
			return( NULL );

	SANITY( streami );

	return( streami->sniff->data );
}
