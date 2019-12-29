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

G_DEFINE_TYPE( VipsDestination, vips_destination, VIPS_TYPE_CONNECTION );

static void
vips_destination_finalize( GObject *gobject )
{
	VipsDestination *destination = VIPS_DESTINATION( gobject );

	VIPS_DEBUG_MSG( "vips_destination_finalize:\n" );

	VIPS_FREEF( g_byte_array_unref, destination->memory_buffer ); 
	if( destination->blob ) { 
		vips_area_unref( VIPS_AREA( destination->blob ) ); 
		destination->blob = NULL;
	}

	G_OBJECT_CLASS( vips_destination_parent_class )->finalize( gobject );
}

static int
vips_destination_build( VipsObject *object )
{
	VipsConnection *stream = VIPS_CONNECTION( object );
	VipsDestination *destination = VIPS_DESTINATION( object );

	VIPS_DEBUG_MSG( "vips_destination_build: %p\n", stream );

	if( VIPS_OBJECT_CLASS( vips_destination_parent_class )->build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "filename" ) &&
		vips_object_argument_isset( object, "descriptor" ) ) { 
		vips_error( vips_connection_nick( stream ), 
			"%s", _( "don't set 'filename' and 'descriptor'" ) ); 
		return( -1 ); 
	}

	if( stream->filename ) { 
		const char *filename = stream->filename;

		int fd;

		/* 0644 is rw user, r group and other.
		 */
		if( (fd = vips_tracked_open( filename, 
			MODE_WRITE, 0644 )) == -1 ) {
			vips_error_system( errno, vips_connection_nick( stream ), 
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
	else if( destination->memory ) {
		destination->memory_buffer = g_byte_array_new();
	}

	return( 0 );
}

static gint64 
vips_destination_write_real( VipsDestination *destination, const void *data, size_t length )
{
	VipsConnection *stream = VIPS_CONNECTION( destination );

	VIPS_DEBUG_MSG( "vips_destination_write_real: %zd bytes\n", length );

	return( write( stream->descriptor, data, length ) );
}

static void
vips_destination_finish_real( VipsDestination *destination ) 
{
	VIPS_DEBUG_MSG( "vips_destination_finish_real:\n" );
}

static void
vips_destination_class_init( VipsDestinationClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_destination_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "destination";
	object_class->description = _( "stream stream" );

	object_class->build = vips_destination_build;

	class->write = vips_destination_write_real;
	class->finish = vips_destination_finish_real;

	VIPS_ARG_BOOL( class, "memory", 3, 
		_( "Memory" ), 
		_( "File descriptor should output to memory" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsDestination, memory ),
		FALSE );

	/* SET_ALWAYS means that blob is set by C and the obj system is not
	 * involved in creation or destruction. It can be read at any time.
	 */
	VIPS_ARG_BOXED( class, "blob", 4, 
		_( "Blob" ),
		_( "Blob to save to" ),
		VIPS_ARGUMENT_SET_ALWAYS, 
		G_STRUCT_OFFSET( VipsDestination, blob ),
		VIPS_TYPE_BLOB );

}

static void
vips_destination_init( VipsDestination *destination )
{
	destination->blob = vips_blob_new( NULL, NULL, 0 );
	destination->write_point = 0;
}

/**
 * vips_destination_new_to_descriptor:
 * @descriptor: write to this file descriptor
 *
 * Create a stream attached to a file descriptor.
 * @descriptor is kept open until the #VipsDestination is finalized.
 *
 * See also: vips_destination_new_to_file().
 *
 * Returns: a new #VipsDestination
 */
VipsDestination *
vips_destination_new_to_descriptor( int descriptor )
{
	VipsDestination *destination;

	VIPS_DEBUG_MSG( "vips_destination_new_to_descriptor: %d\n", 
		descriptor );

	destination = VIPS_DESTINATION( g_object_new( VIPS_TYPE_DESTINATION, 
		"descriptor", descriptor,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( destination ) ) ) {
		VIPS_UNREF( destination );
		return( NULL );
	}

	return( destination ); 
}

/**
 * vips_destination_new_to_file:
 * @filename: write to this file 
 *
 * Create a stream attached to a file.
 *
 * Returns: a new #VipsDestination
 */
VipsDestination *
vips_destination_new_to_file( const char *filename )
{
	VipsDestination *destination;

	VIPS_DEBUG_MSG( "vips_destination_new_to_file: %s\n", 
		filename );

	destination = VIPS_DESTINATION( g_object_new( VIPS_TYPE_DESTINATION, 
		"filename", filename,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( destination ) ) ) {
		VIPS_UNREF( destination );
		return( NULL );
	}

	return( destination ); 
}

/**
 * vips_destination_new_to_memory:
 *
 * Create a stream which will stream to a memory area. Read from @blob to get
 * memory.
 *
 * See also: vips_destination_new_to_file().
 *
 * Returns: a new #VipsConnection
 */
VipsDestination *
vips_destination_new_to_memory( void )
{
	VipsDestination *destination;

	VIPS_DEBUG_MSG( "vips_destination_new_to_memory:\n" ); 

	destination = VIPS_DESTINATION( g_object_new( VIPS_TYPE_DESTINATION,
		"memory", TRUE,
		NULL ) );

	if( vips_object_build( VIPS_OBJECT( destination ) ) ) {
		VIPS_UNREF( destination );
		return( NULL );
	}

	return( destination ); 
}

static int
vips_destination_write_unbuffered( VipsDestination *destination, 
	const void *data, size_t length )
{
	VipsDestinationClass *class = VIPS_DESTINATION_GET_CLASS( destination );

	VIPS_DEBUG_MSG( "vips_destination_write_unbuffered:\n" );

	if( destination->finished )
		return( 0 );

	if( destination->memory_buffer ) 
		g_byte_array_append( destination->memory_buffer, data, length );
	else 
		while( length > 0 ) { 
			gint64 bytes_written;

			bytes_written = class->write( destination, data, length );

			/* n == 0 isn't strictly an error, but we treat it as 
			 * one to make sure we don't get stuck in this loop.
			 */
			if( bytes_written <= 0 ) {
				vips_error_system( errno, 
					vips_connection_nick( 
						VIPS_CONNECTION( destination ) ),
					"%s", _( "write error" ) ); 
				return( -1 ); 
			}

			length -= bytes_written;
			data += bytes_written;
		}

	return( 0 );
}

static int
vips_destination_flush( VipsDestination *destination )
{
	g_assert( destination->write_point >= 0 );
	g_assert( destination->write_point <= VIPS_DESTINATION_BUFFER_SIZE );

	VIPS_DEBUG_MSG( "vips_destination_flush:\n" );

	if( destination->write_point > 0 ) {
		if( vips_destination_write_unbuffered( destination, 
			destination->output_buffer, destination->write_point ) )
			return( -1 );
		destination->write_point = 0;
	}

	return( 0 );
}

/**
 * vips_destination_write:
 * @destination: output stream to operate on
 * @buffer: bytes to write
 * @length: length of @buffer in bytes
 *
 * Write @length bytes from @buffer to the output. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_destination_write( VipsDestination *destination, const void *buffer, size_t length )
{
	VIPS_DEBUG_MSG( "vips_destination_write: %zd bytes\n", length );

	if( length > VIPS_DESTINATION_BUFFER_SIZE - destination->write_point &&
		vips_destination_flush( destination ) )
		return( -1 );

	if( length > VIPS_DESTINATION_BUFFER_SIZE - destination->write_point ) {
		/* Still too large? Do an unbuffered write.
		 */
		if( vips_destination_write_unbuffered( destination, buffer, length ) )
			return( -1 );
	}
	else {
		memcpy( destination->output_buffer + destination->write_point, 
			buffer, length );
		destination->write_point += length;
	}

	return( 0 );
}

/**
 * vips_destination_finish:
 * @destination: output stream to operate on
 * @buffer: bytes to write
 * @length: length of @buffer in bytes
 *
 * Call this at the end of write to make the stream do any cleaning up. You
 * can call it many times. 
 *
 * After a destination has been finished, further writes will do nothing.
 */
void
vips_destination_finish( VipsDestination *destination )
{
	VipsDestinationClass *class = VIPS_DESTINATION_GET_CLASS( destination );

	VIPS_DEBUG_MSG( "vips_destination_finish:\n" );

	if( destination->finished )
		return;

	(void) vips_destination_flush( destination );

	/* Move the stream buffer into the blob so it can be read out.
	 */
	if( destination->memory_buffer ) {
		unsigned char *data;
		size_t length;

		length = destination->memory_buffer->len;
		data = g_byte_array_free( destination->memory_buffer, FALSE );
		destination->memory_buffer = NULL;
		vips_blob_set( destination->blob,
			(VipsCallbackFn) g_free, data, length );
	}
	else
		class->finish( destination );

	destination->finished = TRUE;
}

/**
 * vips_destination_steal: 
 * @destination: output stream to operate on
 * @length: return number of bytes of data
 *
 * Memory streams only (see vips_destination_new_to_memory()). Steal all data
 * written to the stream so far, and finish it.
 *
 * You must free the returned pointer with g_free().
 *
 * The data is NOT automatically null-terminated. vips_destination_putc() a '\0' 
 * before calling this to get a null-terminated string.
 *
 * Returns: (array length=length) (element-type guint8) (transfer full): the 
 * data
 */
unsigned char *
vips_destination_steal( VipsDestination *destination, size_t *length )
{
	unsigned char *data;

	(void) vips_destination_flush( destination );

	if( !destination->memory_buffer ||
		destination->finished ) {
		if( length )
			*length = destination->memory_buffer->len;

		return( NULL );
	}

	if( length )
		*length = destination->memory_buffer->len;
	data = g_byte_array_free( destination->memory_buffer, FALSE );
	destination->memory_buffer = NULL;

	/* We must have a valid byte array or finish will fail.
	 */
	destination->memory_buffer = g_byte_array_new();

	vips_destination_finish( destination );

	return( data );
}

/**
 * vips_destination_steal_text: 
 * @destination: output stream to operate on
 *
 * As vips_destination_steal_text(), but return a null-terminated string.
 *
 * Returns: (transfer full): stream contents as a null-terminated string.
 */
char *
vips_destination_steal_text( VipsDestination *destination )
{
	vips_destination_putc( destination, '\0' );  

	return( (char *) vips_destination_steal( destination, NULL ) ); 
}

/**
 * vips_destination_putc:
 * @destination: output stream to operate on
 * @ch: character to write
 *
 * Write a single character @ch to @destination. See the macro VIPS_DESTINATION_PUTC()
 * for a faster way to do this.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_destination_putc( VipsDestination *destination, int ch )
{
	VIPS_DEBUG_MSG( "vips_destination_putc: %d\n", ch );

	if( destination->write_point >= VIPS_DESTINATION_BUFFER_SIZE && 
		vips_destination_flush( destination ) )
		return( -1 );

	destination->output_buffer[destination->write_point++] = ch;

	return( 0 );
}

/**
 * vips_destination_writes:
 * @destination: output stream to operate on
 * @str: string to write
 *
 * Write a null-terminated string to @destination.
 * 
 * Returns: 0 on success, and -1 on error.
 */
int
vips_destination_writes( VipsDestination *destination, const char *str )
{
	return( vips_destination_write( destination, 
		(unsigned char *) str, strlen( str ) ) );
}

/**
 * vips_destination_writef:
 * @destination: output stream to operate on
 * @fmt: <function>printf()</function>-style format string
 * @...: arguments to format string
 *
 * Format the string and write to @destination. 
 * 
 * Returns: 0 on success, and -1 on error.
 */
int
vips_destination_writef( VipsDestination *destination, const char *fmt, ... )
{
	va_list ap;
	char *line;
	int result;

        va_start( ap, fmt );
	line = g_strdup_vprintf( fmt, ap ); 
        va_end( ap );

	result = vips_destination_writes( destination, line ); 

	g_free( line ); 

	return( result ); 
}

/**
 * vips_destination_write_amp: 
 * @destination: output stream to operate on
 * @str: string to write
 *
 * Write @str to @destination, but escape stuff that xml hates in text. Our
 * argument string is utf-8.
 *
 * XML rules:
 *
 * - We must escape &<> 
 * - Don't escape \n, \t, \r
 * - Do escape the other ASCII codes. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_destination_write_amp( VipsDestination *destination, const char *str )
{
	const char *p;

	for( p = str; *p; p++ ) 
		if( *p < 32 &&
			*p != '\n' &&
			*p != '\t' &&
			*p != '\r' ) {
			/* You'd think we could output "&#x02%x;", but xml
			 * 1.0 parsers barf on that. xml 1.1 allows this, but
			 * there are almost no parsers. 
			 *
			 * U+2400 onwards are unicode glyphs for the ASCII 
			 * control characters, so we can use them -- thanks
			 * electroly.
			 */
			if( vips_destination_writef( destination, 
				"&#x%04x;", 0x2400 + *p ) )
				return( -1 );	
		}
		else if( *p == '<' ) {
			if( vips_destination_writes( destination, "&lt;" ) )
				return( -1 );
		}
		else if( *p == '>' ) {
			if( vips_destination_writes( destination, "&gt;" ) )
				return( -1 );
		}
		else if( *p == '&' ) {
			if( vips_destination_writes( destination, "&amp;" ) )
				return( -1 );
		}
		else  {
			if( VIPS_DESTINATION_PUTC( destination, *p ) )
				return( -1 );
		}

	return( 0 ); 
}

