/* Some shared TIFF utilities. 
 *
 * 14/10/16
 * 	- from vips2tiff.c
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

/* Call this during startup. Other libraries may be using libtiff and we want
 * to capture any messages they send as well.
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
#ifdef OS_WIN32
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
#else /*!OS_WIN32*/
	tif = TIFFOpen( path, mode );
#endif /*OS_WIN32*/

	if( !tif ) {
		vips_error( "tiff", 
			_( "unable to open \"%s\" for output" ), path );
		return( NULL );
	}

	return( tif );
}

/* Open TIFF for input from a file. 
 */
TIFF *
vips__tiff_openin( const char *path )
{
	/* No mmap --- no performance advantage with libtiff, and it burns up
	 * our VM if the tiff file is large.
	 */
	const char *mode = "rm";

	TIFF *tif;

#ifdef DEBUG
	printf( "vips__tiff_openin( \"%s\" )\n", path ); 
#endif /*DEBUG*/

	/* Need the utf-16 version on Windows.
	 */
#ifdef OS_WIN32
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
#else /*!OS_WIN32*/
	tif = TIFFOpen( path, mode );
#endif /*OS_WIN32*/

	if( !tif ) {
		vips_error( "tiff", 
			_( "unable to open \"%s\" for input" ), path );
		return( NULL );
	}

	return( tif );
}

/* TIFF input from a memory buffer. 
 */

typedef struct _VipsTiffOpeninBuffer {
	size_t position;
	const void *data;
	size_t length;
} VipsTiffOpeninBuffer;

static tsize_t 
openin_buffer_read( thandle_t st, tdata_t data, tsize_t size )
{
	VipsTiffOpeninBuffer *buffer = (VipsTiffOpeninBuffer *) st;

	size_t available;
	size_t copied;

	if( buffer->position > buffer->length ) {
		vips_error( "openin_buffer_read", 
			"%s", _( "read beyond end of buffer" ) );
		return( 0 );
	}

	available = buffer->length - buffer->position;
	copied = VIPS_MIN( size, available );
	memcpy( data, 
		(unsigned char *) buffer->data + buffer->position, copied );
	buffer->position += copied;

	return( copied ); 
}

static tsize_t 
openin_buffer_write( thandle_t st, tdata_t buffer, tsize_t size )
{
	g_assert_not_reached(); 

	return( 0 ); 
}

static int 
openin_buffer_close( thandle_t st )
{
	return( 0 );
}

/* After calling this, ->pos is not bound by the size of the buffer, it can 
 * have any positive value.
 */
static toff_t 
openin_buffer_seek( thandle_t st, toff_t position, int whence )
{
	VipsTiffOpeninBuffer *buffer = (VipsTiffOpeninBuffer *) st;

	if( whence == SEEK_SET )
		buffer->position = position;
	else if( whence == SEEK_CUR )
		buffer->position += position;
	else if( whence == SEEK_END )
		buffer->position = buffer->length + position;
	else
		g_assert_not_reached(); 

	return( buffer->position ); 
}

static toff_t 
openin_buffer_size( thandle_t st )
{
	VipsTiffOpeninBuffer *buffer = (VipsTiffOpeninBuffer *) st;

	return( buffer->length ); 
}

static int 
openin_buffer_map( thandle_t st, tdata_t *start, toff_t *len )
{
	g_assert_not_reached(); 

	return( 0 );
}

static void 
openin_buffer_unmap( thandle_t st, tdata_t start, toff_t len )
{
	g_assert_not_reached(); 

	return;
}

TIFF *
vips__tiff_openin_buffer( VipsImage *image, const void *data, size_t length )
{
	VipsTiffOpeninBuffer *buffer;
	TIFF *tiff;

#ifdef DEBUG
	printf( "vips__tiff_openin_buffer:\n" ); 
#endif /*DEBUG*/

	buffer = VIPS_NEW( image, VipsTiffOpeninBuffer );
	buffer->position = 0;
	buffer->data = data;
	buffer->length = length;

	if( !(tiff = TIFFClientOpen( "memory input", "rm",
		(thandle_t) buffer,
		openin_buffer_read, 
		openin_buffer_write, 
		openin_buffer_seek, 
		openin_buffer_close, 
		openin_buffer_size, 
		openin_buffer_map, 
		openin_buffer_unmap )) ) { 
		vips_error( "vips__tiff_openin_buffer", "%s", 
			_( "unable to open memory buffer for input" ) );
		return( NULL );
	}

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
	g_assert_not_reached(); 
	
	return( 0 ); 
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
	printf( "openout_buffer_seek: position %zd, whence %d\n", 
		position, whence ); 
#endif /*DEBUG*/

	vips_dbuf_seek( &buffer->dbuf, position, whence ); 

	return( vips_dbuf_tell( &buffer->dbuf ) ); 
}

static toff_t 
openout_buffer_size( thandle_t st )
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
		openout_buffer_size, 
		openout_buffer_map, 
		openout_buffer_unmap )) ) { 
		vips_error( "vips__tiff_openout_buffer", "%s", 
			_( "unable to open memory buffer for output" ) );
		return( NULL );
	}

	return( tiff ); 
}

#endif /*HAVE_TIFF*/

