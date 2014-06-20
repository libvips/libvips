/* A byte source .. it can be a pipe, socket, or perhaps a node.js stream.
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

#include <vips/vips.h>
#include <vips/debug.h>

/**
 * SECTION: stream
 * @short_description: a source of bytes, perhaps a network socket
 * @stability: Stable
 * @see_also: <link linkend="libvips-foreign">foreign</link> 
 * @include: vips/vips.h
 *
 * A #VipsStream is a source of bytes for something like jpeg loading. It can
 * be connected to a network socket, for example. 
 */

/**
 * VipsStream:
 *
 * A #VipsStream is a source of bytes for something like jpeg loading. It can
 * be connected to a network socket, for example. 
 */

G_DEFINE_TYPE( VipsStream, vips_stream, VIPS_TYPE_OBJECT );

static void
vips_stream_finalize( GObject *gobject )
{
	VipsStream *stream = (VipsStream *) gobject;

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_stream_finalize: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	VIPS_DEBUG_MSG( "\n" );
#endif /*VIPS_DEBUG*/

	VIPS_FREE( stream->buffer ); 

	G_OBJECT_CLASS( vips_stream_parent_class )->finalize( gobject );
}

static int
vips_stream_build( VipsObject *object )
{
	VipsStream *stream = VIPS_STREAM( object );

	VIPS_DEBUG_MSG( "vips_stream_build: %p\n", stream );

	if( VIPS_OBJECT_CLASS( vips_stream_parent_class )->build( object ) )
		return( -1 );

	g_assert( !stream->buffer );
	g_assert( stream->buffer_size > 0 && 
		stream->buffer_size < 1000000 ); 
	stream->buffer = g_new0( unsigned char, stream->buffer_size );
	stream->next_byte = NULL;
	stream->bytes_available = 0;

	return( 0 );
}

static void
vips_stream_class_init( VipsStreamClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_stream_finalize;

	vobject_class->build = vips_stream_build;
}

static void
vips_stream_init( VipsStream *stream )
{
	stream->buffer_size = 4096;
}

/**
 * vips_stream_new_from_descriptor:
 * @descriptor: read from this file descriptor
 *
 * Create a stream attached to a file descriptor.
 *
 * #VipsStream s start out empty, you need to call 
 * vips_stream_read() to fill them with bytes.
 *
 * See also: vips_stream_read().
 *
 * Returns: a new #VipsStream
 */
VipsStream *
vips_stream_new_from_descriptor( int descriptor )
{
	VipsStream *stream;

	VIPS_DEBUG_MSG( "vips_stream_new_from_descriptor: %d\n", descriptor );

	stream = VIPS_STREAM( g_object_new( VIPS_TYPE_STREAM, NULL ) );
	stream->descriptor = descriptor;

	if( vips_object_build( VIPS_OBJECT( stream ) ) ) {
		VIPS_UNREF( stream );
		return( NULL );
	}

	return( stream ); 
}

/**
 * vips_stream_read:
 * @stream: fill the stream buffer
 *
 * Reads data into the stream buffer. 
 *
 * See also: vips_stream_read().
 *
 * Returns: 0 on success, -1 on error. 
 */
int
vips_stream_read( VipsStream *stream )
{
	VipsStreamClass *class = VIPS_STREAM_GET_CLASS( stream );

	ssize_t len;

	if( class->read )
		len = class->read( stream, 
			stream->buffer, stream->buffer_size );
	else 
		len = read( stream->descriptor, 
			stream->buffer, stream->buffer_size );

#ifdef VIPS_DEBUG
	if( len > 0 ) 
		VIPS_DEBUG_MSG( "vips_stream_read: read %zd bytes\n", len );
#endif /*VIPS_DEBUG*/

	if( len <= 0 ) {
		stream->eof = TRUE;

		if( stream < 0 ) 
			vips_error_system( errno, "read", 
				"%s", _( "read error" ) ); 

		return( -1 ); 
	}

	stream->next_byte = stream->buffer;
	stream->bytes_available = len;

	return( 0 );
}

gboolean
vips_stream_eof( VipsStream *stream )
{
	if( !stream->eof && 
		stream->bytes_available == 0  &&
		!stream->attached ) 
		vips_stream_read( stream ); 

	return( stream->eof ); 
}

void
vips_stream_attach( VipsStream *stream )
{
	VIPS_DEBUG_MSG( "vips_stream_attach:\n" ); 

	g_assert( !stream->attached ); 
	stream->attached = TRUE; 
}

void
vips_stream_detach( VipsStream *stream,
	unsigned char *next_byte, size_t bytes_available )
{
	VIPS_DEBUG_MSG( "vips_stream_detach:\n" ); 

	g_assert( stream->attached ); 
	stream->attached = FALSE; 

	stream->next_byte = next_byte;
	stream->bytes_available = bytes_available;
}
