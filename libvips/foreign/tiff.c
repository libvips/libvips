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
#include <glib/gi18n-lib.h>

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
openin_source_seek( thandle_t st, toff_t offset, int whence )
{
	VipsSource *source = VIPS_SOURCE( st );

	return( (toff_t) vips_source_seek( source, offset, whence ) );
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

	/* Disable memory mapped input -- it chews up VM and the performance
	 * gain is very small. 
	 *
	 * C enables strip chopping: very large uncompressed strips are 
	 * chopped into c. 8kb chunks. This can reduce peak memory use for 
	 * this type of file.
	 */
	if( !(tiff = TIFFClientOpen( "source input", "rmC",
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

/* TIFF output to a target.
 */

/* libtiff needs this (!!?!?!) for writing multipage images.
 */
static tsize_t
openout_target_read( thandle_t st, tdata_t data, tsize_t size )
{
	VipsTarget *target = (VipsTarget *) st;

	return( vips_target_read( target, data, size ) );
}

static tsize_t
openout_target_write( thandle_t st, tdata_t data, tsize_t size )
{
	VipsTarget *target = (VipsTarget *) st;

	if( vips_target_write( target, data, size ) )
		return( (tsize_t) -1 );

	return( size );
}

static toff_t
openout_target_seek( thandle_t st, toff_t offset, int whence )
{
	VipsTarget *target = (VipsTarget *) st;

	return( vips_target_seek( target, offset, whence ) );
}

static int
openout_target_close( thandle_t st )
{
	VipsTarget *target = (VipsTarget *) st;

	if( vips_target_end( target ) )
		return( -1 );

	return( 0 );
}

static toff_t
openout_target_length( thandle_t st )
{
	g_assert_not_reached();

	return( (toff_t) -1 );
}

static int
openout_target_map( thandle_t st, tdata_t *start, toff_t *len )
{
	g_assert_not_reached();

	return( -1 );
}

static void
openout_target_unmap( thandle_t st, tdata_t start, toff_t len )
{
	g_assert_not_reached();

	return;
}

TIFF *
vips__tiff_openout_target( VipsTarget *target, gboolean bigtiff )
{
	const char *mode = bigtiff ? "w8" : "w";

	TIFF *tiff;

#ifdef DEBUG
	printf( "vips__tiff_openout_buffer:\n" );
#endif /*DEBUG*/

	if( !(tiff = TIFFClientOpen( "target output", mode,
		(thandle_t) target,
		openout_target_read,
		openout_target_write,
		openout_target_seek,
		openout_target_close,
		openout_target_length,
		openout_target_map,
		openout_target_unmap )) ) {
		vips_error( "vips__tiff_openout_target", "%s",
			_( "unable to open target for output" ) );
		return( NULL );
	}

	return( tiff );
}

#endif /*HAVE_TIFF*/
