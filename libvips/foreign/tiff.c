/* Some shared TIFF utilities.
 *
 * 14/10/16
 * 	- from vips2tiff.c
 *
 * 26/8/17
 * 	- add openout_read, to help tiffsave_buffer for pyramids
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

#ifdef HAVE_TIFF

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include <tiffio.h>

#include "tiff.h"

/* Handle TIFF errors here. Shared with vips2tiff.c. These can be called from
 * more than one thread.
 */
static void
vips__thandler_error( const char *module, const char *fmt, va_list ap )
{
	vips_verror( module, fmt, ap );
}

/* It'd be nice to be able to support the @fail option for the tiff loader, but
 * there's no easy way to do this, since libtiff has a global warning handler.
 */
static void
vips__thandler_warning( const char *module, const char *fmt, va_list ap )
{
	g_logv( G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, fmt, ap );
}

/* Called during library init.
 *
 * libtiff error and warning handlers may be called from other threads 
 * running in other libs. Other libs may install error handlers and capture 
 * messages caused by us.
 */
void
vips__tiff_init( void )
{
	TIFFSetErrorHandler( vips__thandler_error );
	TIFFSetWarningHandler( vips__thandler_warning );
}

/* Open TIFF for output.
 */
TIFF *
vips__tiff_openout( const char *path, gboolean bigtiff )
{
	TIFF *tif;
	const char *mode = bigtiff ? "w8" : "w";

#ifdef DEBUG
	printf( "vips__tiff_openout( \"%s\", \"%s\" )\n", path, mode );
#endif /*DEBUG*/

	/* Need the utf-16 version on Windows.
	 */
#ifdef G_OS_WIN32
{
	GError *error = NULL;
	wchar_t *path16;

	if( !(path16 = (wchar_t *)
		g_utf8_to_utf16( path, -1, NULL, NULL, &error )) ) {
		vips_g_error( &error );
		return( NULL );
	}

	tif = TIFFOpenW( path16, mode );

	g_free( path16 );
}
#else /*!G_OS_WIN32*/
	tif = TIFFOpen( path, mode );
#endif /*G_OS_WIN32*/

	if( !tif ) {
		vips_error( "tiff",
			_( "unable to open \"%s\" for output" ), path );
		return( NULL );
	}

	return( tif );
}

/* TIFF input from a vips source.
 */

static tsize_t
openin_source_read( thandle_t st, tdata_t data, tsize_t size )
{
	VipsSource *source = VIPS_SOURCE( st );

	return( vips_source_read( source, data, size ) );
}

static tsize_t
openin_source_write( thandle_t st, tdata_t buffer, tsize_t size )
{
	g_assert_not_reached();

	return( 0 );
}

static toff_t
openin_source_seek( thandle_t st, toff_t position, int whence )
{
	VipsSource *source = VIPS_SOURCE( st );

	/* toff_t is usually uint64, with -1 cast to uint64 to indicate error.
	 */
	return( (toff_t) vips_source_seek( source, position, whence ) );
}

static int
openin_source_close( thandle_t st )
{
	VipsSource *source = VIPS_SOURCE( st );

	VIPS_UNREF( source );

	return( 0 );
}

static toff_t
openin_source_length( thandle_t st )
{
	VipsSource *source = VIPS_SOURCE( st );

	/* libtiff will use this to get file size if tags like StripByteCounts
	 * are missing.
	 *
	 * toff_t is usually uint64, with -1 cast to uint64 to indicate error.
	 */
	return( (toff_t) vips_source_length( source ) );
}

static int
openin_source_map( thandle_t st, tdata_t *start, toff_t *len )
{
	g_assert_not_reached();

	return( 0 );
}

static void
openin_source_unmap( thandle_t st, tdata_t start, toff_t len )
{
	g_assert_not_reached();

	return;
}

TIFF *
vips__tiff_openin_source( VipsSource *source )
{
	TIFF *tiff;

#ifdef DEBUG
	printf( "vips__tiff_openin_source:\n" );
#endif /*DEBUG*/

	if( vips_source_rewind( source ) )
		return( NULL );

	if( !(tiff = TIFFClientOpen( "source input", "rm",
		(thandle_t) source,
		openin_source_read,
		openin_source_write,
		openin_source_seek,
		openin_source_close,
		openin_source_length,
		openin_source_map,
		openin_source_unmap )) ) {
		vips_error( "vips__tiff_openin_source", "%s",
			_( "unable to open source for input" ) );
		return( NULL );
	}

	/* Unreffed on close(), see above.
	 */
	g_object_ref( source );

	return( tiff );
}

/* TIFF output to a memory buffer.
 */

typedef struct _VipsTiffOpenoutBuffer {
	VipsDbuf dbuf;

	/* On close, consolidate and write the output here.
	 */
	void **out_data;
	size_t *out_length;
} VipsTiffOpenoutBuffer;

static tsize_t
openout_buffer_read( thandle_t st, tdata_t data, tsize_t size )
{
	VipsTiffOpenoutBuffer *buffer = (VipsTiffOpenoutBuffer *) st;

#ifdef DEBUG
	printf( "openout_buffer_read: %zd bytes\n", size );
#endif /*DEBUG*/

	return( vips_dbuf_read( &buffer->dbuf, data, size ) );
}

static tsize_t
openout_buffer_write( thandle_t st, tdata_t data, tsize_t size )
{
	VipsTiffOpenoutBuffer *buffer = (VipsTiffOpenoutBuffer *) st;

#ifdef DEBUG
	printf( "openout_buffer_write: %zd bytes\n", size );
#endif /*DEBUG*/

	vips_dbuf_write( &buffer->dbuf, data, size );

	return( size );
}

static int
openout_buffer_close( thandle_t st )
{
	VipsTiffOpenoutBuffer *buffer = (VipsTiffOpenoutBuffer *) st;

	*(buffer->out_data) = vips_dbuf_steal( &buffer->dbuf,
		buffer->out_length);

	return( 0 );
}

static toff_t
openout_buffer_seek( thandle_t st, toff_t position, int whence )
{
	VipsTiffOpenoutBuffer *buffer = (VipsTiffOpenoutBuffer *) st;

#ifdef DEBUG
	printf( "openout_buffer_seek: position %zd, whence %d ",
		position, whence );
	switch( whence ) {
	case SEEK_SET:
		printf( "set" ); 
		break;

	case SEEK_END:
		printf( "end" ); 
		break;

	case SEEK_CUR:
		printf( "cur" ); 
		break;

	default:
		printf( "unknown" ); 
		break;
	}
	printf( "\n" ); 
#endif /*DEBUG*/

	vips_dbuf_seek( &buffer->dbuf, position, whence );

	return( vips_dbuf_tell( &buffer->dbuf ) );
}

static toff_t
openout_buffer_length( thandle_t st )
{
	g_assert_not_reached();

	return( 0 );
}

static int
openout_buffer_map( thandle_t st, tdata_t *start, toff_t *len )
{
	g_assert_not_reached();

	return( 0 );
}

static void
openout_buffer_unmap( thandle_t st, tdata_t start, toff_t len )
{
	g_assert_not_reached();

	return;
}

/* On TIFFClose(), @data and @length are set to point to the output buffer.
 */
TIFF *
vips__tiff_openout_buffer( VipsImage *image,
	gboolean bigtiff, void **out_data, size_t *out_length )
{
	const char *mode = bigtiff ? "w8" : "w";

	VipsTiffOpenoutBuffer *buffer;
	TIFF *tiff;

#ifdef DEBUG
	printf( "vips__tiff_openout_buffer:\n" );
#endif /*DEBUG*/

	g_assert( out_data );
	g_assert( out_length );

	buffer = VIPS_NEW( image, VipsTiffOpenoutBuffer );
	vips_dbuf_init( &buffer->dbuf );
	buffer->out_data = out_data;
	buffer->out_length = out_length;

	if( !(tiff = TIFFClientOpen( "memory output", mode,
		(thandle_t) buffer,
		openout_buffer_read,
		openout_buffer_write,
		openout_buffer_seek,
		openout_buffer_close,
		openout_buffer_length,
		openout_buffer_map,
		openout_buffer_unmap )) ) {
		vips_error( "vips__tiff_openout_buffer", "%s",
			_( "unable to open memory buffer for output" ) );
		return( NULL );
	}

	return( tiff );
}

#endif /*HAVE_TIFF*/

