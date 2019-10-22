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
 * A #VipsStream is a source or sink of bytes for something like jpeg loading. 
 * It can be connected to a network socket, for example. 
 */

G_DEFINE_ABSTRACT_TYPE( VipsStream, vips_stream, VIPS_TYPE_OBJECT );

static void
vips_stream_close( VipsStream *stream )
{
	VIPS_DEBUG_MSG( "vips_stream_close:\n" );

	if( stream->close_descriptor >= 0 ) {
		VIPS_DEBUG_MSG( "    close()\n" );
		close( stream->close_descriptor );
		stream->close_descriptor = -1;
	}

	if( stream->tracked_descriptor >= 0 ) {
		VIPS_DEBUG_MSG( "    vips_tracked_close()\n" );
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
vips_stream_name( VipsStream *stream )
{
	return( stream->filename ?
		stream->filename :
		VIPS_OBJECT( stream )->nickname );
}
