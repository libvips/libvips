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

/**
 * SECTION: connection
 * @short_description: a source/sink of bytes, perhaps a network socket
 * @stability: Stable
 * @see_also: <link linkend="libvips-foreign">foreign</link> 
 * @include: vips/vips.h
 * @title: VipsConnection
 *
 * A #VipsConnection is a source or sink of bytes for something like jpeg 
 * loading, see for example vips_jpegload_source(). 
 *
 * It can be connected to a network socket, for example, or perhaps 
 * a node.js stream, or to an area of memory. 
 *
 * Subclass to add other input sources. Use #VipsSourceCustom and
 * #VipsTargetCustom to make a source or target with action signals for 
 * ::read, ::write and ::seek.
 */

/**
 * VipsConnection:
 *
 * A #VipsConnection is a source or sink of bytes for something like jpeg 
 * loading. It can be connected to a network socket, for example. 
 */

G_DEFINE_ABSTRACT_TYPE( VipsConnection, vips_connection, VIPS_TYPE_OBJECT );

static void
vips_connection_finalize( GObject *gobject )
{
	VipsConnection *connection = (VipsConnection *) gobject;

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_connection_finalize: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	VIPS_DEBUG_MSG( "\n" );
#endif /*VIPS_DEBUG*/

	if( connection->tracked_descriptor >= 0 ) {
		VIPS_DEBUG_MSG( "    tracked_close()\n" );
		vips_tracked_close( connection->tracked_descriptor );
		connection->tracked_descriptor = -1;
		connection->descriptor = -1;
	}

	if( connection->close_descriptor >= 0 ) {
		VIPS_DEBUG_MSG( "    close()\n" );
		close( connection->close_descriptor );
		connection->close_descriptor = -1;
		connection->descriptor = -1;
	}

	VIPS_FREE( connection->filename ); 

	G_OBJECT_CLASS( vips_connection_parent_class )->finalize( gobject );
}

static void
vips_connection_class_init( VipsConnectionClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );

	gobject_class->finalize = vips_connection_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	VIPS_ARG_INT( class, "descriptor", 1, 
		_( "Descriptor" ), 
		_( "File descriptor for read or write" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConnection, descriptor ),
		-1, 1000000000, 0 );

	VIPS_ARG_STRING( class, "filename", 2,
		_( "Filename" ),
		_( "Name of file to open" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConnection, filename ),
		NULL );

}

static void
vips_connection_init( VipsConnection *connection )
{
	connection->descriptor = -1;
	connection->tracked_descriptor = -1;
	connection->close_descriptor = -1;
}

/** 
 * vips_connection_filename: 
 * @connection: connection to operate on
 *
 * Returns: any filename associated with this connection, or NULL.
 */
const char *
vips_connection_filename( VipsConnection *connection )
{
	return( connection->filename );
}

/** 
 * vips_connection_nick: 
 * @connection: connection to operate on
 *
 * Returns: a string describing this connection which could be displayed to a
 * user.
 */
const char *
vips_connection_nick( VipsConnection *connection )
{
	return( connection->filename ?
		connection->filename :
		VIPS_OBJECT( connection )->nickname );
}
