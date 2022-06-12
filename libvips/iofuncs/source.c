/* A byte source/sink .. it can be a pipe, file descriptor, memory area, 
 * socket, node.js stream, etc.
 * 
 * 19/6/14
 *
 * 3/2/20
 * 	- add vips_pipe_read_limit_set()
 * 3/10/20
 * 	- improve behaviour with read and seek on pipes
 * 26/11/20
 * 	- use _setmode() on win to force binary read for previously opened
 * 	  descriptors
 * 8/10/21
 * 	- fix named pipes
 * 10/5/22
 * 	- add vips_source_new_from_target()
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
 * - can we map and then close the fd? how about on Windows?
 */

/*
#define TEST_SANITY
#define VIPS_DEBUG
#define DEBUG_MINIMISE
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

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

#ifdef G_OS_WIN32
#include <io.h>
#endif /*G_OS_WIN32*/

#include <vips/debug.h>
#include <vips/internal.h>

#define MODE_READ CLOEXEC (BINARYIZE (O_RDONLY))

/* -1 on a pipe isn't actually unbounded. Have a limit to prevent
 * huge sources accidentally filling memory.
 *
 * This can be configured with vips_pipe_read_limit_set().
 */
static gint64 vips__pipe_read_limit = 1024 * 1024 * 1024;

/**
 * vips_pipe_read_limit_set:
 * @limit: maximum number of bytes to buffer from a pipe
 *
 * If a source does not support mmap or seek and the source is
 * used with a loader that can only work from memory, then the data will be
 * automatically read into memory to EOF before the loader starts. This can
 * produce high memory use if the descriptor represents a large object.
 *
 * Use vips_pipe_read_limit_set() to limit the size of object that
 * will be read in this way. The default is 1GB. 
 *
 * Set a value of -1 to mean no limit.
 *
 * See also: `--vips-pipe-read-limit` and the environment variable 
 * `VIPS_PIPE_READ_LIMIT`.
 */
void
vips_pipe_read_limit_set( gint64 limit )
{
	vips__pipe_read_limit = limit;
}

G_DEFINE_TYPE( VipsSource, vips_source, VIPS_TYPE_CONNECTION );

/* Does this source support seek. You must unminimise before calling this.
 */
static int
vips_source_test_seek( VipsSource *source )
{
	if( !source->have_tested_seek ) {
		VipsSourceClass *class = VIPS_SOURCE_GET_CLASS( source );

		source->have_tested_seek = TRUE;

		VIPS_DEBUG_MSG( "vips_source_can_seek: testing seek ..\n" );

		/* Can we seek this input?
		 *
		 * We need to call the method directly rather than via
		 * vips_source_seek() etc. or we might trigger seek emulation.
		 */
		if( source->data ||
			class->seek( source, 0, SEEK_CUR ) != -1 ) { 
			gint64 length;

			VIPS_DEBUG_MSG( "    seekable source\n" );

			/* We should be able to get the length of seekable 
			 * objects.
			 */
			if( (length = vips_source_length( source )) == -1 ) 
				return( -1 );

			source->length = length;

			/* If we can seek, we won't need to save header bytes.
			 */
			VIPS_FREEF( g_byte_array_unref, source->header_bytes ); 
		}
		else {
			/* Not seekable. This must be some kind of pipe.
			 */
			VIPS_DEBUG_MSG( "    not seekable\n" );
			source->is_pipe = TRUE;
		}
	}

	return( 0 );
}

/* We can't test for seekability or length during _build, since the read and 
 * seek signal handlers might not have been connected yet. Instead, we test 
 * when we first need to know.
 */
static int
vips_source_test_features( VipsSource *source )
{
	if( vips_source_unminimise( source ) || 
		vips_source_test_seek( source ) )
		return( -1 );

	return( 0 );
}

#ifdef TEST_SANITY
static void
vips_source_sanity( VipsSource *source )
{
	if( source->data ) {
		/* Not a pipe (can map and seek).
		 */
		g_assert( !source->is_pipe );

		/* Read position must lie within the buffer.
		 */
		g_assert( source->read_position >= 0 );
		g_assert( source->read_position <= source->length );

		/* After we're done with the header, the sniff buffer should
		 * be gone.
		 */
		g_assert( !source->decode || 
			!source->sniff );

		/* Have length.
		 */
		g_assert( source->length != -1 );
	}
	else if( source->is_pipe ) {
		if( source->decode ) {
			/* Reading pixel data.
			 */
			g_assert( !source->header_bytes );
			g_assert( !source->sniff );
		}
		else {
			/* Reading header data.
			 */
			g_assert( source->header_bytes );
			g_assert( source->read_position >= 0 );
			g_assert( source->read_position <= 
			 	source->header_bytes->len );
		}

		/* No length available.
		 */
		g_assert( source->length == -1 );
	}
	else {
		/* Something like a seekable file.
		 */

		/* After we're done with the header, the sniff buffer should
		 * be gone.
		 */
		if( source->decode ) {
			g_assert( !source->sniff );
		}

		/* Once we've tested seek, the read position must lie within 
		 * the file.
		 */
		if( source->have_tested_seek ) { 
			g_assert( source->length != -1 );
			g_assert( source->read_position >= 0 );
			g_assert( source->read_position <= source->length );
		}

		/* Supports minimise, so if descriptor is -1, we must have a
		 * filename we can reopen.
		 */
		g_assert( VIPS_CONNECTION( source )->descriptor != -1 ||
			(VIPS_CONNECTION( source )->filename && 
			 VIPS_CONNECTION( source )->descriptor) );
	}
}
#endif /*TEST_SANITY*/

#ifdef TEST_SANITY
#define SANITY( S ) vips_source_sanity( S )
#warning "sanity tests on in source.c"
#else /*!TEST_SANITY*/
#define SANITY( S )
#endif /*TEST_SANITY*/

static void
vips_source_finalize( GObject *gobject )
{
	VipsSource *source = VIPS_SOURCE( gobject );

#ifdef DEBUG_MINIMISE
	printf( "vips_source_finalize: %p\n", source );
#endif /*DEBUG_MINIMISE*/

	VIPS_FREEF( g_byte_array_unref, source->header_bytes ); 
	VIPS_FREEF( g_byte_array_unref, source->sniff ); 
	if( source->mmap_baseaddr ) {
		vips__munmap( source->mmap_baseaddr, source->mmap_length );
		source->mmap_baseaddr = NULL;
	}

	G_OBJECT_CLASS( vips_source_parent_class )->finalize( gobject );
}

static int
vips_source_build( VipsObject *object )
{
	VipsConnection *connection = VIPS_CONNECTION( object );
	VipsSource *source = VIPS_SOURCE( object );

	VIPS_DEBUG_MSG( "vips_source_build: %p\n", source );

	if( VIPS_OBJECT_CLASS( vips_source_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "filename" ) &&
		vips_object_argument_isset( object, "descriptor" ) ) { 
		vips_error( vips_connection_nick( connection ), 
			"%s", _( "don't set 'filename' and 'descriptor'" ) ); 
		return( -1 ); 
	}

	/* unminimise will open the filename.
	 */
	if( vips_object_argument_isset( object, "filename" ) &&
		vips_source_unminimise( source ) )
		return( -1 );

	if( vips_object_argument_isset( object, "descriptor" ) ) {
		connection->descriptor = dup( connection->descriptor );
		connection->close_descriptor = connection->descriptor;

#ifdef G_OS_WIN32
		/* Windows will create eg. stdin and stdout in text mode.
		 * We always read in binary mode.
		 */
		_setmode( connection->descriptor, _O_BINARY );
#endif /*G_OS_WIN32*/
	}

	if( vips_object_argument_isset( object, "blob" ) ) {
		size_t length;

		if( !(source->data = vips_blob_get( source->blob, &length )) )
			return( -1 );

		source->length = VIPS_MIN( length, G_MAXSSIZE );
	}

	return( 0 );
}

static gint64
vips_source_read_real( VipsSource *source, void *data, size_t length )
{
	VipsConnection *connection = VIPS_CONNECTION( source );

	gint64 bytes_read;

	VIPS_DEBUG_MSG( "vips_source_read_real:\n" );

	do { 
		bytes_read = read( connection->descriptor, data, length );
	} while( bytes_read < 0 && errno == EINTR );

	return( bytes_read );
}

static gint64
vips_source_seek_real( VipsSource *source, gint64 offset, int whence )
{
	VipsConnection *connection = VIPS_CONNECTION( source );

	VIPS_DEBUG_MSG( "vips_source_seek_real:\n" );

	/* Like _read_real(), we must not set a vips_error. We need to use the
	 * vips__seek() wrapper so we can seek long files on Windows.
	 */
	if( connection->descriptor != -1 )
		return( vips__seek_no_error( connection->descriptor, 
			offset, whence ) );

	return( -1 );
}

static void
vips_source_class_init( VipsSourceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_source_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "source";
	object_class->description = _( "input source" );

	object_class->build = vips_source_build;

	class->read = vips_source_read_real;
	class->seek = vips_source_seek_real;

	VIPS_ARG_BOXED( class, "blob", 3, 
		_( "Blob" ),
		_( "Blob to load from" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsSource, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_source_init( VipsSource *source )
{
	source->length = -1;
	source->sniff = g_byte_array_new();
	source->header_bytes = g_byte_array_new();
}

/**
 * vips_source_new_from_descriptor:
 * @descriptor: read from this file descriptor
 *
 * Create an source attached to a file descriptor. @descriptor is 
 * closed with close() when source is finalized. 
 *
 * Returns: a new source.
 */
VipsSource *
vips_source_new_from_descriptor( int descriptor )
{
	VipsSource *source;

	VIPS_DEBUG_MSG( "vips_source_new_from_descriptor: %d\n", 
		descriptor );

	source = VIPS_SOURCE( g_object_new( VIPS_TYPE_SOURCE, 
		"descriptor", descriptor,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( source ) ) ) {
		VIPS_UNREF( source );
		return( NULL );
	}

	SANITY( source );

	return( source ); 
}

/**
 * vips_source_new_from_file:
 * @descriptor: read from this filename 
 *
 * Create an source attached to a file.
 *
 * If this descriptor does not support mmap and the source is
 * used with a loader that can only work from memory, then the data will be
 * automatically read into memory to EOF before the loader starts. This can
 * produce high memory use if the descriptor represents a large object.
 *
 * Use vips_pipe_read_limit_set() to limit the size of object that
 * will be read in this way. The default is 1GB.
 *
 * Returns: a new source.
 */
VipsSource *
vips_source_new_from_file( const char *filename )
{
	VipsSource *source;

	VIPS_DEBUG_MSG( "vips_source_new_from_file: %s\n", 
		filename );

	source = VIPS_SOURCE( g_object_new( VIPS_TYPE_SOURCE, 
		"filename", filename,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( source ) ) ) {
		VIPS_UNREF( source );
		return( NULL );
	}

	SANITY( source );

	return( source ); 
}

/**
 * vips_source_new_from_blob:
 * @blob: memory area to load
 *
 * Create a source attached to an area of memory. 
 *
 * Returns: a new source.
 */
VipsSource *
vips_source_new_from_blob( VipsBlob *blob )
{
	VipsSource *source;

	VIPS_DEBUG_MSG( "vips_source_new_from_blob: %p\n", blob ); 

	source = VIPS_SOURCE( g_object_new( VIPS_TYPE_SOURCE, 
		"blob", blob,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( source ) ) ) {
		VIPS_UNREF( source );
		return( NULL );
	}

	SANITY( source );

	return( source ); 
}

/**
 * vips_source_new_from_target:
 * @target: build the source from this target
 *
 * Create a source from a temp target that has been written to.
 *
 * Returns: a new source.
 */
VipsSource *
vips_source_new_from_target( VipsTarget *target )
{
	VipsConnection *connection = VIPS_CONNECTION( target );

	VipsSource *source;

	VIPS_DEBUG_MSG( "vips_source_new_from_target: %p\n", target ); 

	/* Flush output buffer, move memory into the blob, etc.
	 */
	if( vips_target_end( target ) )
		return( NULL );

	if( connection->descriptor > 0 ) {
		source = vips_source_new_from_descriptor( 
			connection->descriptor ); 
	}
	else if( target->memory ) {
		VipsBlob *blob;

		g_object_get( target, "blob", &blob, NULL );
		source = vips_source_new_from_blob( blob ); 
		vips_area_unref( VIPS_AREA( blob ) );
	}
	else {
		vips_error( vips_connection_nick( connection ),
			"%s", _( "unimplemented target" ) );
		return( NULL ); 
	}

	return( source ); 
}

/**
 * vips_source_new_from_memory:
 * @data: memory area to load
 * @length: size of memory area
 *
 * Create a source attached to an area of memory. 
 *
 * You must not free @data while the source is active. 
 *
 * Returns: a new source.
 */
VipsSource *
vips_source_new_from_memory( const void *data, size_t length )
{
	VipsSource *source;
	VipsBlob *blob;

	VIPS_DEBUG_MSG( "vips_source_new_from_buffer: "
		"%p, length = %zd\n", data, length ); 

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, data, length );

	source = vips_source_new_from_blob( blob ); 

	vips_area_unref( VIPS_AREA( blob ) );

	SANITY( source );

	return( source ); 
}

/**
 * vips_source_new_from_options:
 * @options: option string
 *
 * Create a source from an option string.
 *
 * Returns: a new source.
 */
VipsSource *
vips_source_new_from_options( const char *options )
{
	VipsSource *source;

	VIPS_DEBUG_MSG( "vips_source_new_from_options: %s\n", options ); 

	source = VIPS_SOURCE( g_object_new( VIPS_TYPE_SOURCE, NULL ) );

	if( vips_object_set_from_string( VIPS_OBJECT( source ), options ) ||
		vips_object_build( VIPS_OBJECT( source ) ) ) {
		VIPS_UNREF( source );
		return( NULL );
	}

	SANITY( source );

	return( source ); 
}

/**
 * vips_source_minimise:
 * @source: source to operate on
 *
 * Minimise the source. As many resources as can be safely removed are
 * removed. Use vips_source_unminimise() to restore the source if you wish to
 * use it again.
 *
 * Loaders should call this in response to the minimise signal on their output
 * image.
 */
void
vips_source_minimise( VipsSource *source )
{
	VipsConnection *connection = VIPS_CONNECTION( source );

	SANITY( source );

	(void) vips_source_test_features( source );

	if( connection->filename &&
		connection->descriptor != -1 &&
		connection->tracked_descriptor == connection->descriptor &&
		!source->is_pipe ) {
#ifdef DEBUG_MINIMISE
		printf( "vips_source_minimise: %p %s\n", 
			source,
			vips_connection_nick( VIPS_CONNECTION( source ) ) );
#endif /*DEBUG_MINIMISE*/

		vips_tracked_close( connection->tracked_descriptor );
		connection->tracked_descriptor = -1;
		connection->descriptor = -1;
	}

	SANITY( source );
}

/**
 * vips_source_unminimise:
 * @source: source to operate on
 *
 * Restore the source after minimisation. This is called at the start 
 * of every source method, so loaders should not usually need this.
 *
 * See also: vips_source_minimise().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_source_unminimise( VipsSource *source )
{
	VipsConnection *connection = VIPS_CONNECTION( source );

	if( connection->descriptor == -1 &&
		connection->tracked_descriptor == -1 &&
		connection->filename ) {
		int fd;

#ifdef DEBUG_MINIMISE
		printf( "vips_source_unminimise: %p %s\n",
			source,
			vips_connection_nick( VIPS_CONNECTION( source ) ) );
#endif /*DEBUG_MINIMISE*/

		if( (fd = vips_tracked_open( connection->filename, 
			MODE_READ, 0 )) == -1 ) {
			vips_error_system( errno, 
				vips_connection_nick( connection ),
				"%s", _( "unable to open for read" ) );
			return( -1 ); 
		}

		connection->tracked_descriptor = fd;
		connection->descriptor = fd;

		if( vips_source_test_seek( source ) ) 
			return( -1 ); 

		/* It might be a named pipe.
		 */
		if( !source->is_pipe ) {
			VIPS_DEBUG_MSG( "vips_source_unminimise: restoring "
				"read position %" G_GINT64_FORMAT "\n", 
				source->read_position );
			if( vips__seek( connection->descriptor, 
				source->read_position, SEEK_SET ) == -1 )
				return( -1 );
		}
	}

	return( 0 );
}

/**
 * vips_source_decode:
 * @source: source to operate on
 *
 * Signal the end of header read and the start of the pixel decode phase. 
 * After this, you can no longer seek on this source.
 *
 * Loaders should call this at the end of header read.
 *
 * See also: vips_source_unminimise().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_source_decode( VipsSource *source )
{
	VIPS_DEBUG_MSG( "vips_source_decode:\n" );

	SANITY( source );

	if( !source->decode ) {
		source->decode = TRUE;

		VIPS_FREEF( g_byte_array_unref, source->sniff ); 

		/* Now decode is set, header_bytes will be freed once it's 
		 * exhausted, see vips_source_read().
		 */
	}

	vips_source_minimise( source );

	SANITY( source );

	return( 0 );
}

#ifdef VIPS_DEBUG
static void
vips_source_print( VipsSource *source )
{
	printf( "vips_source_print: %p\n", source );
	printf( "  source->read_position = %zd\n", source->read_position );
	printf( "  source->is_pipe = %d\n", source->is_pipe );
	printf( "  source->length = %zd\n", source->length );
	printf( "  source->data = %p\n", source->data );
	printf( "  source->header_bytes = %p\n", source->header_bytes );
	if( source->header_bytes ) 
		printf( "  source->header_bytes->len = %d\n", 
			source->header_bytes->len );
	printf( "  source->sniff = %p\n", source->sniff );
	if( source->sniff )
		printf( "  source->sniff->len = %d\n", source->sniff->len );
}
#endif /*VIPS_DEBUG*/

/**
 * vips_source_read:
 * @source: source to operate on
 * @buffer: store bytes here
 * @length: length of @buffer in bytes
 *
 * Read up to @length bytes from @source and store the bytes in @buffer.
 * Return the number of bytes actually read. If all bytes have been read from 
 * the file, return 0.
 *
 * Arguments exactly as read(2).
 *
 * Returns: the number of bytes read, 0 on end of file, -1 on error.
 */
gint64
vips_source_read( VipsSource *source, void *buffer, size_t length )
{
	VipsSourceClass *class = VIPS_SOURCE_GET_CLASS( source );

	gint64 total_read;

	VIPS_DEBUG_MSG( "vips_source_read:\n" );

	SANITY( source );

	if( vips_source_unminimise( source ) ||
		vips_source_test_features( source ) )
		return( -1 );

	total_read = 0;

	if( source->data ) {
		/* The whole thing is in memory somehow.
		 */
		gint64 available = VIPS_MIN( length,
			source->length - source->read_position );

		VIPS_DEBUG_MSG( "    %zd bytes from memory\n", available );
		memcpy( buffer, 
			source->data + source->read_position, available );
		source->read_position += available;
		total_read += available;
	}
	else {
		/* Some kind of filesystem or custom source. 
		 *
		 * Get what we can from header_bytes. We may need to read 
		 * some more after this.
		 */
		if( source->header_bytes &&
			source->read_position < source->header_bytes->len ) {
			gint64 available = VIPS_MIN( length, 
				source->header_bytes->len - 
					source->read_position );

			VIPS_DEBUG_MSG( "    %zd bytes from cache\n", 
				available );
			memcpy( buffer, 
				source->header_bytes->data + 
					source->read_position, 
				available );
			source->read_position += available;
			buffer += available;
			length -= available;
			total_read += available;
		}

		/* We're in pixel decode mode and we've exhausted the header
		 * cache. We can safely junk it.
		 */
		if( source->decode &&
			source->header_bytes &&
			source->read_position >= source->header_bytes->len )
			VIPS_FREEF( g_byte_array_unref, source->header_bytes ); 

		/* Any more bytes requested? Call the read() vfunc.
		 */
		if( length > 0 ) {
			gint64 bytes_read;

			VIPS_DEBUG_MSG( "    calling class->read()\n" );
			bytes_read = class->read( source, buffer, length );
			VIPS_DEBUG_MSG( "    %zd bytes from read()\n", 
				bytes_read );
			if( bytes_read == -1 ) {
				vips_error_system( errno, 
					vips_connection_nick( 
						VIPS_CONNECTION( source ) ), 
					"%s", _( "read error" ) ); 
				return( -1 );
			}

			/* We need to save bytes if we're in header mode and 
			 * we can't seek or map.
			 */
			if( source->header_bytes &&
				source->is_pipe &&
				!source->decode &&
				bytes_read > 0 ) 
				g_byte_array_append( source->header_bytes, 
					buffer, bytes_read );

			source->read_position += bytes_read;
			total_read += bytes_read;
		}
	}

	VIPS_DEBUG_MSG( "    %zd bytes total\n", total_read );

	SANITY( source );

	return( total_read );
}

/* Read to a position. 
 *
 * target == -1 means read to end of source -- useful for forcing a pipe into
 * memory, for example. This will always set length to the pipe length.
 *
 * If we hit EOF and we're buffering, set length on the pipe and turn it into
 * a memory source.
 *
 * read_position is left somewhere indeterminate.
 */
static int
vips_source_pipe_read_to_position( VipsSource *source, gint64 target )
{
	const char *nick = vips_connection_nick( VIPS_CONNECTION( source ) );

	unsigned char buffer[4096];

	/* This is only useful for pipes (sources where we don't know the
	 * length).
	 */
	g_assert( source->length == -1 );
	g_assert( source->is_pipe );

	while( target == -1 ||
		source->read_position < target ) {
		gint64 bytes_read;

		bytes_read = vips_source_read( source, buffer, 4096 );
		if( bytes_read == -1 )
			return( -1 );

		if( bytes_read == 0 ) {
			/* No more bytes available, we must be at EOF.
			 */
			source->length = source->read_position;

			/* Have we been buffering the whole thing? We can
			 * become a memory source.
			 */
			if( source->header_bytes ) {
				source->data = source->header_bytes->data;
				source->is_pipe = FALSE;

				/* TODO ... we could close more fds here.
				 */
				vips_source_minimise( source );
			}

			break;
		}

		if( target == -1 &&
			vips__pipe_read_limit != -1 &&
			source->read_position > vips__pipe_read_limit ) {
			vips_error( nick, "%s", _( "pipe too long" ) );
			return( -1 );
		}
	}

	return( 0 );
}

/* Convert a seekable source that can't be mapped (eg. a custom input with a
 * seek method) into a memory source. 
 */
static int
vips_source_read_to_memory( VipsSource *source )
{
	GByteArray *byte_array;
	gint64 read_position;
	unsigned char *q;

	VIPS_DEBUG_MSG( "vips_source_read_to_memory:\n" );

	g_assert( !source->is_pipe );
	g_assert( !source->blob );
	g_assert( !source->header_bytes );
	g_assert( source->length >= 0 );

	if( vips_source_rewind( source ) )
		return( -1 );

	/* We know the length, so we can size the buffer correctly and read
	 * directly to it.
	 */
	byte_array = g_byte_array_new();
	g_byte_array_set_size( byte_array, source->length );

	read_position = 0;
	q = byte_array->data;
	while( read_position < source->length ) {
		gint64 bytes_read;

		bytes_read = vips_source_read( source, q, 
			VIPS_MAX( 4096, source->length - read_position ) );
		if( bytes_read == -1 ) {
			VIPS_FREEF( g_byte_array_unref, byte_array ); 
			return( -1 );
		}
		if( bytes_read == 0 )
			break;

		read_position += bytes_read;
		q += bytes_read;
	}

	/* Steal the byte_array pointer and turn into a memory source.
	 *
	 * We save byte_array in the header_bytes field to get it freed when
	 * we are freed.
	 */
	source->data = byte_array->data;
	source->is_pipe = FALSE;
	source->header_bytes = byte_array;

	vips_source_minimise( source );

	return( 0 );
}

static int
vips_source_descriptor_to_memory( VipsSource *source )
{
	VipsConnection *connection = VIPS_CONNECTION( source );

	VIPS_DEBUG_MSG( "vips_source_descriptor_to_memory:\n" );

	g_assert( !source->blob );
	g_assert( !source->mmap_baseaddr );

	if( !(source->mmap_baseaddr = vips__mmap( connection->descriptor, 
		FALSE, source->length, 0 )) )
		return( -1 );

	/* And it's now a memory source.
	 */
	source->data = source->mmap_baseaddr;
	source->mmap_length = source->length;

	return( 0 );
}

/**
 * vips_source_is_mappable:
 * @source: source to operate on
 *
 * Some sources can be efficiently mapped into memory.
 * You can still use vips_source_map() if this function returns %FALSE,
 * but it will be slow.
 *
 * Returns: %TRUE if the source can be efficiently mapped into memory.
 */
gboolean 
vips_source_is_mappable( VipsSource *source )
{
	if( vips_source_unminimise( source ) ||
		vips_source_test_features( source ) )
		return( -1 );

	/* Already a memory object, or there's a filename we can map, or
	 * there's a seekable descriptor.
	 */
	return( source->data ||
		VIPS_CONNECTION( source )->filename ||
		(!source->is_pipe && 
		 VIPS_CONNECTION( source )->descriptor != -1) );
}

/**
 * vips_source_is_file:
 * @source: source to operate on
 *
 * Test if this source is a simple file with support for seek. Named pipes,
 * for example, will fail this test. If TRUE, you can use
 * vips_connection_filename() to find the filename.
 *
 * Use this to add basic source support for older loaders which can only work
 * on files.
 *
 * Returns: %TRUE if the source is a simple file.
 */
gboolean 
vips_source_is_file( VipsSource *source )
{
	if( vips_source_unminimise( source ) ||
		vips_source_test_features( source ) )
		return( -1 );

	/* There's a filename, and it supports seek.
	 */
	return( VIPS_CONNECTION( source )->filename &&
		!source->is_pipe );
}

/**
 * vips_source_map:
 * @source: source to operate on
 * @length_out: return the file length here, or NULL
 *
 * Map the source entirely into memory and return a pointer to the
 * start. If @length_out is non-NULL, the source size is written to it.
 *
 * This operation can take a long time. Use vips_source_is_mappable() to 
 * check if a source can be mapped efficiently.
 *
 * The pointer is valid for as long as @source is alive.
 *
 * Returns: a pointer to the start of the file contents, or NULL on error.
 */
const void *
vips_source_map( VipsSource *source, size_t *length_out )
{
	VIPS_DEBUG_MSG( "vips_source_map:\n" );

	SANITY( source );

	if( vips_source_unminimise( source ) ||
		vips_source_test_features( source ) )
		return( NULL );

	/* Try to map the file into memory, if possible. Some filesystems have
	 * mmap disabled, so we don't give up if this fails.
	 */
	if( !source->data &&
		vips_source_is_mappable( source ) ) 
		(void) vips_source_descriptor_to_memory( source );

	/* If it's not a pipe, we can rewind, get the length, and read the
	 * whole thing.
	 */
	if( !source->data &&
		!source->is_pipe &&
		vips_source_read_to_memory( source ) )
		return( NULL );

	/* We don't know the length and must read and assemble in chunks.
	 */
	if( !source->data &&
		vips_source_pipe_read_to_position( source, -1 ) )
		return( NULL );

	if( length_out )
		*length_out = source->length;

	SANITY( source );

	return( source->data );
}

static int
vips_source_map_cb( void *a, VipsArea *area )
{
	GObject *gobject = G_OBJECT( area->client );

	VIPS_UNREF( gobject );

	return( 0 );
}

/**
 * vips_source_map_blob:
 * @source: source to operate on
 *
 * Just like vips_source_map(), but return a #VipsBlob containing the
 * pointer. @source will stay alive as long as the result is alive.
 *
 * Returns: a new #VipsBlob containing the data, or NULL on error.
 */
VipsBlob *
vips_source_map_blob( VipsSource *source )
{
	const void *buf;
	size_t len;
	VipsBlob *blob;

	if( !(buf = vips_source_map( source, &len )) ||
		!(blob = vips_blob_new( (VipsCallbackFn) vips_source_map_cb, 
			buf, len )) ) 
		return( NULL );

	/* The source must stay alive until the blob is done.
	 */
	g_object_ref( source );
	VIPS_AREA( blob )->client = source;

	return( blob );
}

/**
 * vips_source_seek:
 * @source: source to operate on
 * @offset: seek by this offset
 * @whence: seek relative to this point
 *
 * Move the file read position. You can't call this after pixel decode starts.
 * The arguments are exactly as lseek(2).
 *
 * Returns: the new file position, or -1 on error.
 */
gint64
vips_source_seek( VipsSource *source, gint64 offset, int whence )
{
	const char *nick = vips_connection_nick( VIPS_CONNECTION( source ) );
	VipsSourceClass *class = VIPS_SOURCE_GET_CLASS( source );

	gint64 new_pos;

	VIPS_DEBUG_MSG( "vips_source_seek: offset = %" G_GINT64_FORMAT 
		", whence = %d\n", offset, whence );

	if( vips_source_unminimise( source ) ||
		vips_source_test_features( source ) )
		return( -1 );

	if( source->data ) {
		switch( whence ) {
		case SEEK_SET:
			new_pos = offset;
			break;

		case SEEK_CUR:
			new_pos = source->read_position + offset;
			break;

		case SEEK_END:
			new_pos = source->length + offset;
			break;

		default:
			vips_error( nick, "%s", _( "bad 'whence'" ) );
			return( -1 );
		}
	}
	else if( source->is_pipe ) {
		switch( whence ) {
		case SEEK_SET:
			new_pos = offset;
			break;

		case SEEK_CUR:
			new_pos = source->read_position + offset;
			break;

		case SEEK_END:
			/* We have to read the whole source into memory to get
			 * the length.
			 */
			if( vips_source_pipe_read_to_position( source, -1 ) )
				return( -1 );

			new_pos = source->length + offset;
			break;

		default:
			vips_error( nick, "%s", _( "bad 'whence'" ) );
			return( -1 );
		}
	}
	else {
		if( (new_pos = class->seek( source, offset, whence )) == -1 )
			return( -1 );
	}

	/* For pipes, we have to fake seek by reading to that point. This
	 * might hit EOF and turn the pipe into a memory source.
	 */
	if( source->is_pipe &&
		vips_source_pipe_read_to_position( source, new_pos ) )
		return( -1 );

	/* Don't allow out of range seeks.
	 */
	if( new_pos < 0 ||
		(source->length != -1 && 
		 new_pos > source->length) ) {
		vips_error( nick, 
			_( "bad seek to %" G_GINT64_FORMAT ), new_pos );
                return( -1 );
	}

	source->read_position = new_pos;

	VIPS_DEBUG_MSG( "    new_pos = %" G_GINT64_FORMAT "\n", new_pos );

	return( new_pos );
}

/**
 * vips_source_rewind:
 * @source: source to operate on
 *
 * Rewind the source to the start. 
 *
 * You can't always do this after the pixel decode phase starts -- for
 * example, pipe-like sources can't be rewound.
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_source_rewind( VipsSource *source )
{
	VIPS_DEBUG_MSG( "vips_source_rewind:\n" );

	SANITY( source );

	if( vips_source_test_features( source ) ||
		vips_source_seek( source, 0, SEEK_SET ) != 0 )
		return( -1 );

	/* Back into sniff + header decode state.
	 */
	source->decode = FALSE;
	if( !source->sniff )
		source->sniff = g_byte_array_new();

	SANITY( source );

	return( 0 );
}

/**
 * vips_source_length:
 * @source: source to operate on
 *
 * Return the length in bytes of the source. Unseekable sources, for
 * example pipes, will have to be read entirely into memory before the length 
 * can be found, so this operation can take a long time.
 *
 * Returns: number of bytes in source, or -1 on error.
 */
gint64
vips_source_length( VipsSource *source )
{
	gint64 length;
	gint64 read_position;

	VIPS_DEBUG_MSG( "vips_source_length:\n" );

	if( vips_source_test_features( source ) )
		return( -1 );

	read_position = vips_source_seek( source, 0, SEEK_CUR );
	length = vips_source_seek( source, 0, SEEK_END );
	vips_source_seek( source, read_position, SEEK_SET );

	return( length );
}

/**
 * vips_source_sniff_at_most: 
 * @source: peek this source
 * @data: return a pointer to the bytes read here
 * @length: max number of bytes to read
 *
 * Attempt to sniff at most @length bytes from the start of the source. A 
 * pointer to the bytes is returned in @data. The number of bytes actually 
 * read is returned -- it may be less than @length if the file is shorter than
 * @length. A negative number indicates a read error.
 *
 * Returns: number of bytes read, or -1 on error.
 */
gint64
vips_source_sniff_at_most( VipsSource *source, 
	unsigned char **data, size_t length )
{
	unsigned char *q;
	gint64 read_position;

	VIPS_DEBUG_MSG( "vips_source_sniff_at_most: %zd bytes\n", length );

	SANITY( source );

	if( vips_source_test_features( source ) ||
		vips_source_rewind( source ) )
		return( -1 );

	g_byte_array_set_size( source->sniff, length );

	read_position = 0; 
	q = source->sniff->data;
	while( read_position < length ) {
		gint64 bytes_read;

		bytes_read = vips_source_read( source, q, 
			length - read_position );
		if( bytes_read == -1 )
			return( -1 );
		if( bytes_read == 0 )
			break;

		read_position += bytes_read;
		q += bytes_read;
	}

	SANITY( source );

	*data = source->sniff->data;

	return( read_position );
}

/**
 * vips_source_sniff: 
 * @source: sniff this source
 * @length: number of bytes to sniff
 *
 * Return a pointer to the first few bytes of the file. If the file is too
 * short, return NULL.
 *
 * Returns: a pointer to the bytes at the start of the file, or NULL on error.
 */
unsigned char *
vips_source_sniff( VipsSource *source, size_t length )
{
	unsigned char *data;
	gint64 bytes_read;

	if( vips_source_test_features( source ) )
		return( NULL );

	bytes_read = vips_source_sniff_at_most( source, &data, length );
	if( bytes_read == -1 )
		return( NULL );
	if( bytes_read < length )
		return( NULL );

	return( data );
}
