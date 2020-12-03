/* A Source subclass with signals you can easily hook up to other input
 * sources.
 * 
 * J.Cupitt, 21/11/19
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

G_DEFINE_TYPE( VipsSourceCustom, vips_source_custom, VIPS_TYPE_SOURCE );

/* Our signals. 
 */
enum {
	SIG_SEEK,		
	SIG_READ,		
	SIG_LAST
};

static guint vips_source_custom_signals[SIG_LAST] = { 0 };

static gint64
vips_source_custom_read_real( VipsSource *source, 
	void *buffer, size_t length )
{
	gint64 bytes_read;

	VIPS_DEBUG_MSG( "vips_source_custom_read_real:\n" );

	/* Return this value (error) if there's no attached handler.
	 */
	bytes_read = 0;

	g_signal_emit( source, vips_source_custom_signals[SIG_READ], 0,
		buffer, (gint64) length, &bytes_read );

	VIPS_DEBUG_MSG( "  vips_source_custom_read_real, seen %zd bytes\n", 
		bytes_read );

	return( bytes_read );
}

static gint64
vips_source_custom_seek_real( VipsSource *source, 
	gint64 offset, int whence )
{
	GValue args[3] = { { 0 } };
	GValue result = { 0 };
	gint64 new_position;

	VIPS_DEBUG_MSG( "vips_source_custom_seek_real:\n" );

	/* Set the signal args.
	 */
	g_value_init( &args[0], G_TYPE_OBJECT );
	g_value_set_object( &args[0], source );
	g_value_init( &args[1], G_TYPE_INT64 );
	g_value_set_int64( &args[1], offset );
	g_value_init( &args[2], G_TYPE_INT );
	g_value_set_int( &args[2], whence );

	/* Set the default value if no handlers are attached.
	 */
	g_value_init( &result, G_TYPE_INT64 );
	g_value_set_int64( &result, -1 );

	/* We need to use this signal interface since we want a default value 
	 * if no handlers are attached.
	 */
	g_signal_emitv( (const GValue *) &args, 
		vips_source_custom_signals[SIG_SEEK], 0, &result );

	new_position = g_value_get_int64( &result );

	g_value_unset( &args[0] );
	g_value_unset( &args[1] );
	g_value_unset( &args[2] );
	g_value_unset( &result );

	VIPS_DEBUG_MSG( "  vips_source_custom_seek_real, seen new pos %zd\n", 
		new_position );

	return( new_position );
}

static gint64
vips_source_custom_read_signal_real( VipsSourceCustom *source_custom, 
	void *data, gint64 length )
{
	VIPS_DEBUG_MSG( "vips_source_custom_read_signal_real:\n" );

	return( 0 );
}

static gint64
vips_source_custom_seek_signal_real( VipsSourceCustom *source_custom, 
	gint64 offset, int whence )
{
	VIPS_DEBUG_MSG( "vips_source_custom_seek_signal_real:\n" );

	return( -1 );
}

static void
vips_source_custom_class_init( VipsSourceCustomClass *class )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsSourceClass *source_class = VIPS_SOURCE_CLASS( class );

	object_class->nickname = "source_custom";
	object_class->description = _( "Custom source" );

	source_class->read = vips_source_custom_read_real;
	source_class->seek = vips_source_custom_seek_real;

	class->read = vips_source_custom_read_signal_real;
	class->seek = vips_source_custom_seek_signal_real;

	/**
	 * VipsSourceCustom::read:
	 * @source_custom: the source being operated on
	 * @buffer: %gpointer, buffer to fill
	 * @size: %gint64, size of buffer
	 *
	 * This signal is emitted to read bytes from the source into @buffer.
	 *
	 * Returns: the number of bytes read. Return 0 for EOF.
	 */
	vips_source_custom_signals[SIG_READ] = g_signal_new( "read",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_ACTION,
		G_STRUCT_OFFSET( VipsSourceCustomClass, read ), 
		NULL, NULL,
		vips_INT64__POINTER_INT64,
		G_TYPE_INT64, 2,
		G_TYPE_POINTER, G_TYPE_INT64 );

	/**
	 * VipsSourceCustom::seek:
	 * @source_custom: the source being operated on
	 * @offset: %gint64, seek offset
	 * @whence: %gint, seek origin
	 *
	 * This signal is emitted to seek the source. The handler should
	 * change the source position appropriately.
	 *
	 * The handler for an unseekable source should always return -1.
	 *
	 * Returns: the new seek position.
	 */
	vips_source_custom_signals[SIG_SEEK] = g_signal_new( "seek",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_ACTION,
		G_STRUCT_OFFSET( VipsSourceCustomClass, seek ), 
		NULL, NULL,
		vips_INT64__INT64_INT,
		G_TYPE_INT64, 2,
		G_TYPE_INT64, G_TYPE_INT );

}

static void
vips_source_custom_init( VipsSourceCustom *source_custom )
{
}

/**
 * vips_source_custom_new:
 *
 * Create a #VipsSourceCustom. Attach signals to implement read and seek.
 *
 * Returns: a new #VipsSourceCustom
 */
VipsSourceCustom *
vips_source_custom_new( void )
{
	VipsSourceCustom *source_custom;

	VIPS_DEBUG_MSG( "vips_source_custom_new:\n" );

	source_custom = VIPS_SOURCE_CUSTOM(
		g_object_new( VIPS_TYPE_SOURCE_CUSTOM, NULL ) );

	if( vips_object_build( VIPS_OBJECT( source_custom ) ) ) {
		VIPS_UNREF( source_custom );
		return( NULL );
	}

	return( source_custom ); 
}
