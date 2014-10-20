// Object part of VImage class

/*

    Copyright (C) 1991-2001 The National Gallery

    This program is free software; you can redistribute it and/or modify
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include <vips/vipscpp.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/*
#define DEBUG
 */

VIPS_NAMESPACE_START

/* Useful to have these as namespaced C++ functions.
 */
void init( const char *argv0 )
{
	if( vips_init( argv0 ) )
		throw VError();
}

void shutdown()
{
	vips_shutdown(); 
}

void thread_shutdown()
{
	vips_thread_shutdown(); 
}

// see vips_image_new_from_file()
VImage::VImage( const char *name, ... ) 
	__attribute__((sentinel)) throw( VError )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	va_list ap;
	int result;

	vips_check_init();

	vips__filename_split8( name, filename, option_string );
	if( !(operation_name = vips_foreign_find_load( filename )) )
		throw VError(); 

	va_start( ap, name );
	result = vips_call_split_option_string( operation_name, 
		option_string, ap, filename, &im );
	va_end( ap );

	if( result )
		throw VError(); 
}

// see vips_image_new_from_buffer()
VImage::VImage( void *buffer, size_t length, const char *option_string, ... )
{
	const char *operation_name;
	VipsBlob *blob;
	va_list ap;
	int result;

	vips_check_init();

	if( !(operation_name = 
		vips_foreign_find_load_buffer( buffer, length )) )
		throw VError();

	/* We don't take a copy of the data or free it. 
	 */
	blob = vips_blob_new( NULL, buffer, length );

	va_start( ap, option_string );
	result = vips_call_split_option_string( operation_name, 
			option_string, ap, blob, &im );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	if( result )
		throw VError();
}

// see vips_image_write_to_file()
void VImage::write( const char *name, ... ) 
	throw( VError )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	va_list ap;
	int result;

	vips__filename_split8( name, filename, option_string );
	if( !(operation_name = vips_foreign_find_save( filename )) )
		throw VError(); 

	va_start( ap, name );
	result = vips_call_split_option_string( operation_name, option_string,
		ap, image, filename );
	va_end( ap );

	if( result )
		throw VError(); 
}

// see vips_image_write_to_buffer()
void *VImage::write( const char *suffix, size_t *size, ... )
	throw( VError )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	va_list ap;
	VipsBlob *blob;
	int result;
	void *buf;

	vips__filename_split8( suffix, filename, option_string );
	if( !(operation_name = vips_foreign_find_save_buffer( filename )) )
		throw VError(); 

	va_start( ap, size );
	result = vips_call_split_option_string( operation_name, option_string,
		ap, in, &blob );
	va_end( ap );

	if( result )
		throw VError(); 

	g_assert( blob );

	buf = VIPS_AREA( blob )->data;
	VIPS_AREA( blob )->free_fn = NULL;
	if( size )
		*size = VIPS_AREA( blob )->length;

	vips_area_unref( VIPS_AREA( blob ) );

	return( buf );
}


/* Insert automatically generated wrappers for vips operators.
 */
#include "vips-operators.cc"

VIPS_NAMESPACE_END
