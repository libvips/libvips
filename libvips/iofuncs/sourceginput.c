/* A Source subclass which wraps a ginputstream.
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

#include "vipsmarshal.h"

G_DEFINE_TYPE( VipsSourceGInputStream, vips_source_g_input_stream, 
	VIPS_TYPE_SOURCE );

/* TODO:
 * 	- some more docs
 */

/* This will only be useful for memory and pipe-style streams. It's not
 * possible to get filename or filenos from GInputStream objects. 
 * Without those two bits of information, important VipsSource features like
 * mmap and openslide load will not work.
 *
 * For sources which are files on local disc, you should use
 * vips_source_new_from_file() instead.
 */

static int
vips_source_g_input_stream_build( VipsObject *object )
{
	VipsSource *source = VIPS_SOURCE( object );
	VipsSourceGInputStream *source_ginput = 
		VIPS_SOURCE_G_INPUT_STREAM( source );
	GError *error = NULL;

	VIPS_DEBUG_MSG( "vips_source_g_input_stream_build: %p\n", source );

	if( VIPS_OBJECT_CLASS( vips_source_g_input_stream_parent_class )->
		build( object ) )
		return( -1 );

	if( G_IS_FILE_INPUT_STREAM( source_ginput->stream ) ) {
		const char *name;

		/* It's unclear if this will ever produce useful output.
		 */
		if( !(source_ginput->info = g_file_input_stream_query_info( 
			G_FILE_INPUT_STREAM( source_ginput->stream ), 
			G_FILE_ATTRIBUTE_STANDARD_NAME,
			NULL, &error )) ) {
			vips_g_error( &error );
			return( -1 );
		}

#ifdef VIPS_DEBUG
{
		char **attributes;
		int i;

		/* Swap G_FILE_ATTRIBUTE_STANDARD_NAME above for "*" to get a
		 * list of all available attributes.
		 */
		attributes = g_file_info_list_attributes( 
			source_ginput->info, NULL );
		printf( "stream attributes:\n" );
		for( i = 0; attributes[i]; i++ ) {
			char *name = attributes[i];
			char *value;

			value = g_file_info_get_attribute_as_string( 
				source_ginput->info, name );
			printf( "\t%s = %s\n", name, value );
			g_free( value );
		}
		g_strfreev( attributes );
}
#endif /*VIPS_DEBUG*/

		if( (name = g_file_info_get_name( source_ginput->info )) ) 
			g_object_set( object,
				"filename", name,
				NULL );
	}	

	if( G_IS_SEEKABLE( source_ginput->stream ) &&
		g_seekable_can_seek( G_SEEKABLE( source_ginput->stream ) ) ) 
		source_ginput->seekable = G_SEEKABLE( source_ginput->stream );

	return( 0 );
}

static gint64
vips_source_g_input_stream_read( VipsSource *source, 
	void *buffer, size_t length )
{
	VipsSourceGInputStream *source_ginput = 
		VIPS_SOURCE_G_INPUT_STREAM( source );
	GError *error = NULL;

	gint64 bytes_read;

	VIPS_DEBUG_MSG( "vips_source_g_input_stream_read: %zd bytes\n", 
		length );

	/* Do we need to loop on this call? The docs are unclear.
	 */
	if( (bytes_read = g_input_stream_read( source_ginput->stream, 
		buffer, length, NULL, &error )) < 0 ) {
		VIPS_DEBUG_MSG( "    %s\n", error->message );
		vips_g_error( &error );
		return( -1 );
	}

	VIPS_DEBUG_MSG( "    (returned %zd bytes)\n", bytes_read );

	return( bytes_read );
}

static GSeekType
lseek_to_seek_type( int whence )
{
	switch( whence ) {
	default:
	case SEEK_CUR:
		return( G_SEEK_CUR );
	case SEEK_SET:
		return( G_SEEK_SET );
	case SEEK_END:
		return( G_SEEK_END );
	}
}

static gint64
vips_source_g_input_stream_seek( VipsSource *source, gint64 offset, int whence )
{
	VipsSourceGInputStream *source_ginput = 
		VIPS_SOURCE_G_INPUT_STREAM( source );
	GSeekType type = lseek_to_seek_type( whence );
	GError *error = NULL;

	gint64 new_position;

	VIPS_DEBUG_MSG( "vips_source_g_input_stream_seek: "
		"offset = %zd, whence = %d\n", offset, whence );

	if( source_ginput->seekable ) {
		if( !g_seekable_seek( source_ginput->seekable, 
			offset, type, NULL, &error ) ) {
			vips_g_error( &error );
			return( -1 );
		}

		new_position = g_seekable_tell( source_ginput->seekable );
	}
	else
		new_position = -1;

	VIPS_DEBUG_MSG( "  (new position = %zd)\n", new_position );

	return( new_position );
}

static void
vips_source_g_input_stream_class_init( VipsSourceGInputStreamClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsSourceClass *source_class = VIPS_SOURCE_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "source_g_input_stream";
	object_class->description = _( "GInputStream source" );

	object_class->build = vips_source_g_input_stream_build;

	source_class->read = vips_source_g_input_stream_read;
	source_class->seek = vips_source_g_input_stream_seek;

	VIPS_ARG_OBJECT( class, "stream", 3, 
		_( "stream" ),
		_( "GInputStream to read from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsSourceGInputStream, stream ),
		G_TYPE_INPUT_STREAM );

}

static void
vips_source_g_input_stream_init( VipsSourceGInputStream *source )
{
}

/**
 * vips_source_g_input_stream_new:
 * @stream: read from this stream
 *
 * Create a #VipsSourceGInputStream which wraps @stream.
 *
 * Returns: the new source.
 */
VipsSourceGInputStream *
vips_source_g_input_stream_new( GInputStream *stream )
{
	VipsSourceGInputStream *source;

	VIPS_DEBUG_MSG( "vips_source_g_input_stream_new:\n" );

	source = VIPS_SOURCE_G_INPUT_STREAM( 
		g_object_new( VIPS_TYPE_SOURCE_G_INPUT_STREAM, 
			"stream", stream,
			NULL ) );

	if( vips_object_build( VIPS_OBJECT( source ) ) ) {
		VIPS_UNREF( source );
		return( NULL );
	}

	return( source ); 
}
