/* GInputStream <--> VipsStreami
 * 
 * Kleis Auke, 9/11/19
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
 * - Should we conditionally exclude this class? It's only needed for librsvg.
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

static void vips_streamiw_seekable_iface_init( GSeekableIface *iface );

G_DEFINE_TYPE_WITH_CODE( VipsStreamiw, vips_streamiw, G_TYPE_INPUT_STREAM,
	G_IMPLEMENT_INTERFACE( G_TYPE_SEEKABLE,
		vips_streamiw_seekable_iface_init ) )

enum
{
	PROP_0,
	PROP_STREAM
};

static void
vips_streamiw_get_property( GObject *object, guint prop_id,
	GValue *value, GParamSpec *pspec )
{
	VipsStreamiw *streamiw = VIPS_STREAMIW( object );

	switch (prop_id) {
	case PROP_STREAM:
		g_value_set_object( value, streamiw->streami );
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID( object, prop_id, pspec );
	}
}

static void
vips_streamiw_set_property( GObject *object, guint prop_id,
	const GValue *value, GParamSpec *pspec)
{
	VipsStreamiw *streamiw = VIPS_STREAMIW( object );

	switch (prop_id) {
	case PROP_STREAM:
		streamiw->streami = g_value_dup_object( value );
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID( object, prop_id, pspec );
	}
}

static void
vips_streamiw_finalize( GObject *object )
{
	VipsStreamiw *streamiw = VIPS_STREAMIW( object );

	VIPS_FREEF( g_object_unref, streamiw->streami );

	G_OBJECT_CLASS( vips_streamiw_parent_class )->finalize( object );
}

static goffset
vips_streamiw_tell( GSeekable *seekable )
{
	VipsStreami *streami;
	goffset pos;

	streami = VIPS_STREAMIW( seekable )->streami;

	VIPS_DEBUG_MSG( "vips_streamiw_tell:\n" );

	pos = vips_streami_seek( streami, 0, SEEK_CUR );

	if( pos == -1 )
		return 0;

	return pos;
}

static gboolean
vips_streamiw_can_seek( GSeekable *seekable )
{
	VipsStreami *streami = VIPS_STREAMIW( seekable )->streami;

	VIPS_DEBUG_MSG( "vips_streamiw_can_seek: %d\n", !streami->is_pipe);

	return !streami->is_pipe;
}

static int
seek_type_to_lseek( GSeekType type )
{
	switch (type) {
	default:
	case G_SEEK_CUR:
		return SEEK_CUR;
	case G_SEEK_SET:
		return SEEK_SET;
	case G_SEEK_END:
		return SEEK_END;
	}
}

static gboolean
vips_streamiw_seek( GSeekable *seekable, goffset offset,
	GSeekType type, GCancellable *cancellable, GError **error )
{
	VipsStreami *streami = VIPS_STREAMIW( seekable )->streami;

	VIPS_DEBUG_MSG( "vips_streamiw_seek: offset = %" G_GINT64_FORMAT
		", type = %d\n", offset, type );

	if( vips_streami_seek( streami, offset, 
		seek_type_to_lseek( type ) ) == -1 ) 
	{
		g_set_error( error, G_IO_ERROR,
			G_IO_ERROR_FAILED,
			_("Error while seeking: %s"),
			vips_error_buffer() );
		return( FALSE );
	}


	return( TRUE );
}

static gboolean
vips_streamiw_can_truncate( GSeekable *seekable )
{
	return( FALSE );
}

static gboolean
vips_streamiw_truncate( GSeekable *seekable, goffset offset,
	GCancellable *cancellable, GError **error )
{
	g_set_error_literal( error,
		G_IO_ERROR,
		G_IO_ERROR_NOT_SUPPORTED,
		_("Cannot truncate VipsStreamiw") );

	return( FALSE );
}

static gssize
vips_streamiw_read( GInputStream *stream, void *buffer, gsize count,
	GCancellable *cancellable, GError **error )
{
	VipsStreami *streami;
	gssize res;

	streami = VIPS_STREAMIW( stream )->streami;

	VIPS_DEBUG_MSG( "vips_streamiw_read: count: %zd\n", count );

	if ( g_cancellable_set_error_if_cancelled( cancellable, error ) )
		return( -1 );

	if( (res = vips_streami_read( streami, buffer, count )) == -1 )
		g_set_error( error, G_IO_ERROR,
			G_IO_ERROR_FAILED,
			_("Error while reading: %s"),
			vips_error_buffer() );

	return( res );
}

static gssize
vips_streamiw_skip( GInputStream *stream, gsize count,
	GCancellable *cancellable, GError **error )
{
	VipsStreami *streami;
	goffset start;
	goffset end;

	streami = VIPS_STREAMIW( stream )->streami;

	VIPS_DEBUG_MSG( "vips_streamiw_skip: count: %zd\n", count );

	if( g_cancellable_set_error_if_cancelled( cancellable, error ) )
		return( -1 );

	start = vips_streami_seek( streami, 0, SEEK_CUR );

	if( start == -1 )
	{
		g_set_error( error, G_IO_ERROR,
			G_IO_ERROR_FAILED,
			_("Error while seeking: %s"),
			vips_error_buffer() );
		return -1;
	}

	end = vips_streami_seek( streami, 0, SEEK_END );
	if( end == -1 )
	{
		g_set_error( error, G_IO_ERROR,
			G_IO_ERROR_FAILED,
			_("Error while seeking: %s"),
			vips_error_buffer() );
		return -1;
	}

	if( end - start > count )
	{
		end = vips_streami_seek( streami, count - (end - start),
			SEEK_CUR );
		if( end == -1 )
		{
			g_set_error( error, G_IO_ERROR,
				G_IO_ERROR_FAILED,
				_("Error while seeking: %s"),
				vips_error_buffer() );
			return -1;
		}
	}

	return( end - start );
}

static gboolean
vips_streamiw_close( GInputStream *stream,
	GCancellable *cancellable, GError **error )
{
	VipsStreamiw *streamiw = VIPS_STREAMIW( stream );

	vips_streami_minimise( streamiw->streami );

	return( TRUE );
}

static void
vips_streamiw_seekable_iface_init( GSeekableIface *iface )
{
	iface->tell = vips_streamiw_tell;
	iface->can_seek = vips_streamiw_can_seek;
	iface->seek = vips_streamiw_seek;
	iface->can_truncate = vips_streamiw_can_truncate;
	iface->truncate_fn = vips_streamiw_truncate;
}

static void
vips_streamiw_class_init( VipsStreamiwClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	GInputStreamClass *istream_class = G_INPUT_STREAM_CLASS( class );

	gobject_class->finalize = vips_streamiw_finalize;
	gobject_class->get_property = vips_streamiw_get_property;
	gobject_class->set_property = vips_streamiw_set_property;

	istream_class->read_fn = vips_streamiw_read;
	istream_class->skip = vips_streamiw_skip;
	istream_class->close_fn = vips_streamiw_close;

	g_object_class_install_property( gobject_class, PROP_STREAM,
			g_param_spec_object( "input",
			_("Input"),
			_("Stream to wrap"),
			VIPS_TYPE_STREAMI, G_PARAM_CONSTRUCT_ONLY | 
			G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS) );

}

static void
vips_streamiw_init( VipsStreamiw *streamiw )
{
}

/**
 * g_input_stream_new_from_vips:
 * @streami: stream to wrap
 *
 * Create a new #GInputStream wrapping a #VipsStreami.
 *
 * Returns: a new #GInputStream
 */
GInputStream *
g_input_stream_new_from_vips( VipsStreami *streami )
{
	return( g_object_new( VIPS_TYPE_STREAMIW,
			"input", streami,
			NULL ) );
}
