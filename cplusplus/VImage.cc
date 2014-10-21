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
#include <vips/debug.h>

#include <gobject/gvaluecollector.h>

#include "include/vips/vips8"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/*
#define DEBUG
 */

VIPS_NAMESPACE_START

/* Useful to have these as namespaced C++ functions.
 */
void 
init( const char *argv0 )
	throw( VError )
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

static void
call_get( GParamSpec *pspec, void *arg )
{
	/* We've read out of the VipsObject to the pointer. If it's a
	 * VipsImage, we need to box it.
	 */
	if( G_IS_PARAM_SPEC_OBJECT( pspec ) ) {
		VImage *image = new VImage( *((VipsImage **) arg) ); 

		*((VImage *) arg) = *image; 
	}
}

static void
call_set( GParamSpec *pspec, GValue *value )
{
	if( G_VALUE_HOLDS( value, VIPS_TYPE_IMAGE ) ) {
		/* A VImage has been written to the GValue, extract the VImage
		 * and swap it for the underlying VipsImage* pointer.
		 */
		VImage *image = static_cast<VImage *>( 
			g_value_peek_pointer( value ) );

		g_value_set_object( value, (gpointer) (image->image()) ); 
	}
}

/* Some systems do not have va_copy() ... this might work (it does on MSVC,
 * apparently).
 *
 * FIXME ... this should be in configure.in
 */
#ifndef va_copy
#define va_copy(d,s) ((d) = (s))
#endif

void
call( const char *operation_name, ... )
	throw( VError )
{
	VipsCollect collect;
	VipsOperation *operation;
	int result;
	va_list required;
	va_list optional;

	if( !(operation = vips_operation_new( operation_name )) )
		throw VError(); 

	/* We have to break the va_list into separate required and optional 
	 * components.
	 *
	 * Note the start, grab the required, then copy and reuse.
	 */
	va_start( required, operation_name );

	va_copy( optional, required );

	VIPS_ARGUMENT_FOR_ALL( operation, 
		pspec, argument_class, argument_instance ) {

		g_assert( argument_instance );

		if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) ) {
			VIPS_ARGUMENT_COLLECT_SET( pspec, argument_class, 
				optional );

			VIPS_ARGUMENT_COLLECT_GET( pspec, argument_class, 
				optional );

			VIPS_ARGUMENT_COLLECT_END
		}
	} VIPS_ARGUMENT_FOR_ALL_END

	collect.get = call_get;
	collect.set = call_set;
	result = vips_call_required_optional( &operation, 
		&collect, required, optional );

	va_end( required );
	va_end( optional );

	/* Build failed: junk args.
	 */
	if( result ) 
		vips_object_unref_outputs( VIPS_OBJECT( operation ) );

	/* The operation we have built should now have been reffed by one of 
	 * its arguments or have finished its work. Either way, we can unref.
	 */
	g_object_unref( operation );

	if( result )
		throw VError(); 
}

int
call_split( const char *operation_name, va_list optional, ... ) 
{
	VipsOperation *operation;
	va_list required;
	VipsCollect collect;
	int result;

	if( !(operation = vips_operation_new( operation_name )) )
		throw VError(); 

	va_start( required, optional );

	collect.get = call_get;
	collect.set = call_set;
	result = vips_call_required_optional( &operation, 
		&collect, required, optional );

	va_end( required );

	/* Build failed: junk args.
	 */
	if( result ) 
		vips_object_unref_outputs( VIPS_OBJECT( operation ) );

	/* The operation we have built should now have been reffed by one of 
	 * its arguments or have finished its work. Either way, we can unref.
	 */
	g_object_unref( operation );

	if( result )
		throw VError(); 
}

// see vips_image_new_from_file()
VImage::VImage( const char *name, ... ) 
	throw( VError ) 
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;
	va_list ap;
	int result;

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
	throw( VError )
{
	const char *operation_name;
	VipsBlob *blob;
	va_list ap;
	int result;

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
void VImage::write_to_file( const char *name, ... ) 
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
		ap, this->im, filename );
	va_end( ap );

	if( result )
		throw VError(); 
}

// see vips_image_write_to_buffer()
void *VImage::write_to_buffer( const char *suffix, size_t *size, ... )
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
		ap, this->im, &blob );
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


int
main( int argc, char **argv )
{
	vips8::init( argv[0] ); 

	vips8::VImage x( "/home/john/pics/k2.jpg", NULL );

	printf( "width = %d\n", x.width() ); 

	return( 0 ); 
}
