/* A GInputStream that links to a VipsSource under the hood. 
 *
 * 10/11/19 kleisauke
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include <gio/gio.h>

static void vips_g_input_stream_seekable_iface_init( GSeekableIface *iface );

G_DEFINE_TYPE_WITH_CODE( VipsGInputStream, vips_g_input_stream, 
	G_TYPE_INPUT_STREAM, G_IMPLEMENT_INTERFACE( G_TYPE_SEEKABLE,
		vips_g_input_stream_seekable_iface_init ) )

enum {
	PROP_0,
	PROP_STREAM
};

static void
vips_g_input_stream_get_property( GObject *object, guint prop_id,
	GValue *value, GParamSpec *pspec )
{
	VipsGInputStream *gstream = VIPS_G_INPUT_STREAM( object );

	switch( prop_id ) {
	case PROP_STREAM:
		g_value_set_object( value, gstream->source );
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID( object, prop_id, pspec );
	}
}

static void
vips_g_input_stream_set_property( GObject *object, guint prop_id,
	const GValue *value, GParamSpec *pspec )
{
	VipsGInputStream *gstream = VIPS_G_INPUT_STREAM( object );

	switch( prop_id ) {
	case PROP_STREAM:
		gstream->source = g_value_dup_object( value );
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID( object, prop_id, pspec );
	}
}

static void
vips_g_input_stream_finalize( GObject *object )
{
	VipsGInputStream *gstream = VIPS_G_INPUT_STREAM( object );

	VIPS_FREEF( g_object_unref, gstream->source );

	G_OBJECT_CLASS( vips_g_input_stream_parent_class )->finalize( object );
}

static goffset
vips_g_input_stream_tell( GSeekable *seekable )
{
	VipsSource *source = VIPS_G_INPUT_STREAM( seekable )->source;

	goffset pos;

	VIPS_DEBUG_MSG( "vips_g_input_stream_tell:\n" );

	pos = vips_source_seek( source, 0, SEEK_CUR );
	if( pos == -1 )
		return( 0 );

	return( pos );
}

static gboolean
vips_g_input_stream_can_seek( GSeekable *seekable )
{
	VipsSource *source = VIPS_G_INPUT_STREAM( seekable )->source;

	VIPS_DEBUG_MSG( "vips_g_input_stream_can_seek: %d\n", 
		!source->is_pipe );

	return( !source->is_pipe );
}

static int
seek_type_to_lseek( GSeekType type )
{
	switch( type ) {
	default:
	case G_SEEK_CUR:
		return( SEEK_CUR );
	case G_SEEK_SET:
		return( SEEK_SET );
	case G_SEEK_END:
		return( SEEK_END );
	}
}

static gboolean
vips_g_input_stream_seek( GSeekable *seekable, goffset offset,
	GSeekType type, GCancellable *cancellable, GError **error )
{
	VipsSource *source = VIPS_G_INPUT_STREAM( seekable )->source;

	VIPS_DEBUG_MSG( "vips_g_input_stream_seek: offset = %" G_GINT64_FORMAT
		", type = %d\n", offset, type );

	if( vips_source_seek( source, offset, 
		seek_type_to_lseek( type ) ) == -1 ) {
		g_set_error( error, G_IO_ERROR,
			G_IO_ERROR_FAILED,
			_( "Error while seeking: %s" ),
			vips_error_buffer() );
		return( FALSE );
	}


	return( TRUE );
}

static gboolean
vips_g_input_stream_can_truncate( GSeekable *seekable )
{
	return( FALSE );
}

static gboolean
vips_g_input_stream_truncate( GSeekable *seekable, goffset offset,
	GCancellable *cancellable, GError **error )
{
	g_set_error_literal( error,
		G_IO_ERROR,
		G_IO_ERROR_NOT_SUPPORTED,
		_( "Cannot truncate VipsGInputStream" ) );

	return( FALSE );
}

static gssize
vips_g_input_stream_read( GInputStream *stream, void *buffer, gsize count,
	GCancellable *cancellable, GError **error )
{
	VipsSource *source;
	gssize res;

	source = VIPS_G_INPUT_STREAM( stream )->source;

	VIPS_DEBUG_MSG( "vips_g_input_stream_read: count: %zd\n", count );

	if( g_cancellable_set_error_if_cancelled( cancellable, error ) )
		return( -1 );

	if( (res = vips_source_read( source, buffer, count )) == -1 )
		g_set_error( error, G_IO_ERROR,
			G_IO_ERROR_FAILED,
			_( "Error while reading: %s" ),
			vips_error_buffer() );

	return( res );
}

static gssize
vips_g_input_stream_skip( GInputStream *stream, gsize count,
	GCancellable *cancellable, GError **error )
{
	VipsSource *source;
	gssize position;

	source = VIPS_G_INPUT_STREAM( stream )->source;

	VIPS_DEBUG_MSG( "vips_g_input_stream_skip: count: %zd\n", count );

	if( g_cancellable_set_error_if_cancelled( cancellable, error ) )
		return( -1 );

	position = vips_source_seek( source, count, SEEK_CUR );
	if( position == -1 ) {
		g_set_error( error, G_IO_ERROR,
			G_IO_ERROR_FAILED,
			_( "Error while seeking: %s" ),
			vips_error_buffer() );
		return( -1 );
	}

	return( position );
}

static gboolean
vips_g_input_stream_close( GInputStream *stream,
	GCancellable *cancellable, GError **error )
{
	VipsGInputStream *gstream = VIPS_G_INPUT_STREAM( stream );

	vips_source_minimise( gstream->source );

	return( TRUE );
}

static void
vips_g_input_stream_seekable_iface_init( GSeekableIface *iface )
{
	iface->tell = vips_g_input_stream_tell;
	iface->can_seek = vips_g_input_stream_can_seek;
	iface->seek = vips_g_input_stream_seek;
	iface->can_truncate = vips_g_input_stream_can_truncate;
	iface->truncate_fn = vips_g_input_stream_truncate;
}

static void
vips_g_input_stream_class_init( VipsGInputStreamClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	GInputStreamClass *istream_class = G_INPUT_STREAM_CLASS( class );

	gobject_class->finalize = vips_g_input_stream_finalize;
	gobject_class->get_property = vips_g_input_stream_get_property;
	gobject_class->set_property = vips_g_input_stream_set_property;

	istream_class->read_fn = vips_g_input_stream_read;
	istream_class->skip = vips_g_input_stream_skip;
	istream_class->close_fn = vips_g_input_stream_close;

	g_object_class_install_property( gobject_class, PROP_STREAM,
		g_param_spec_object( "input",
			_( "Input" ),
			_( "Stream to wrap" ),
			VIPS_TYPE_SOURCE, G_PARAM_CONSTRUCT_ONLY | 
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS ) );

}

static void
vips_g_input_stream_init( VipsGInputStream *gstream )
{
}

/**
 * vips_g_input_stream_new_from_source:
 * @source: vips source to wrap
 *
 * Create a new #GInputStream wrapping a #VipsSource. This is useful for
 * loaders like SVG and PDF which support GInput methods.
 *
 * Returns: a new #GInputStream
 */
GInputStream *
vips_g_input_stream_new_from_source( VipsSource *source )
{
	return( g_object_new( VIPS_TYPE_G_INPUT_STREAM,
		"input", source,
		NULL ) );
}
