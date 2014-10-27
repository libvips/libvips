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

#include <vips/vips8>

#include <vips/debug.h>

/*
 */
#define VIPS_DEBUG
#define DEBUG

VIPS_NAMESPACE_START

VOption::~VOption()
{
	std::list<Pair *>::iterator i;

	for( i = options.begin(); i != options.end(); i++ ) 
		delete *i;
}

VOption *VOption::set( const char *name, const char *value )
{
	Pair *pair = new Pair( name );

	pair->input = true;
	g_value_init( &pair->value, G_TYPE_STRING );
	g_value_set_string( &pair->value, value );
	options.push_back( pair );

	return( this );
}

// input int ... this path is used for enums as well
VOption *VOption::set( const char *name, int value )
{
	Pair *pair = new Pair( name );

	pair->input = true;
	g_value_init( &pair->value, G_TYPE_INT );
	g_value_set_int( &pair->value, value );
	options.push_back( pair );

	return( this );
}

// input image
VOption *VOption::set( const char *name, VImage value )
{
	Pair *pair = new Pair( name );

	pair->input = true;
	g_value_init( &pair->value, VIPS_TYPE_IMAGE );
	// we need to unbox
	g_value_set_object( &pair->value, value.get_image() );
	options.push_back( pair );

	return( this );
}

// output image
VOption *VOption::set( const char *name, VImage *value )
{
	Pair *pair = new Pair( name );

	// note where we will write the VImage on success
	pair->input = false;
	pair->vimage = value;
	g_value_init( &pair->value, VIPS_TYPE_IMAGE );

	options.push_back( pair );

	return( this );
}

// walk the options and set props on the operation 
void VOption::set_operation( VipsOperation *operation )
{
	std::list<Pair *>::iterator i;

	for( i = options.begin(); i != options.end(); i++ ) 
		if( (*i)->input ) {
#ifdef DEBUG
			printf( "set_operation: " );
			vips_object_print_name( VIPS_OBJECT( operation ) );
			char *str_value = 
				g_strdup_value_contents( &(*i)->value );
			printf( ".%s = %s\n", (*i)->name, str_value );
			g_free( str_value );
#endif /*DEBUG*/

			g_object_set_property( G_OBJECT( operation ),
				(*i)->name, &(*i)->value );
		}
}

// walk the options and do any processing needed for output objects
void VOption::get_operation( VipsOperation *operation )
{
	std::list<Pair *>::iterator i;

	for( i = options.begin(); i != options.end(); i++ ) 
		if( not (*i)->input ) {
			g_object_get_property( G_OBJECT( operation ),
				(*i)->name, &(*i)->value );

#ifdef DEBUG
			printf( "get_operation: " );
			vips_object_print_name( VIPS_OBJECT( operation ) );
			char *str_value = 
				g_strdup_value_contents( &(*i)->value );
			printf( ".%s = %s\n", (*i)->name, str_value );
			g_free( str_value );
#endif /*DEBUG*/

			// rebox object
			VipsImage *image = VIPS_IMAGE( 
				g_value_get_object( &(*i)->value ) );  
			if( (*i)->vimage )
				*((*i)->vimage) = VImage( image ); 
		}
}

void VImage::call_option_string( const char *operation_name, 
	const char *option_string, VOption *options ) 
	throw( VError )
{
	VipsOperation *operation;

	VIPS_DEBUG_MSG( "vips_call_by_name: starting for %s ...\n", 
		operation_name );

	if( !(operation = vips_operation_new( operation_name )) ) {
		if( options )
			delete options;
		throw( VError() ); 
	}

	/* Set str options before vargs options, so the user can't 
	 * override things we set deliberately.
	 */
	if( option_string &&
		vips_object_set_from_string( VIPS_OBJECT( operation ), 
			option_string ) ) {
		vips_object_unref_outputs( VIPS_OBJECT( operation ) );
		g_object_unref( operation ); 
		delete options; 
		throw( VError() ); 
	}

	if( options )
		options->set_operation( operation );

	/* Build from cache.
	 */
	if( vips_cache_operation_buildp( &operation ) ) {
		vips_object_unref_outputs( VIPS_OBJECT( operation ) );
		delete options; 
		throw( VError() ); 
	}

	/* Walk args again, writing output.
	 */
	if( options )
		options->get_operation( operation );

	/* We're done with options!
	 */
	delete options; 

	/* The operation we have built should now have been reffed by 
	 * one of its arguments or have finished its work. Either 
	 * way, we can unref.
	 */
	g_object_unref( operation );
}

void VImage::call( const char *operation_name, VOption *options ) 
	throw( VError )
{
	call_option_string( operation_name, NULL, options ); 
}

VImage VImage::new_from_file( const char *name, VOption *options )
	throw( VError )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;

	VImage out; 

	vips__filename_split8( name, filename, option_string );
	if( !(operation_name = vips_foreign_find_load( filename )) ) {
		delete options; 
		throw VError(); 
	}

	call_option_string( operation_name, option_string,
		(options ? options : VImage::option())-> 
			set( "filename", filename )->
			set( "out", &out ) );

	return( out ); 
}

void VImage::write_to_file( const char *name, VOption *options )
	throw( VError )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;

	vips__filename_split8( name, filename, option_string );
	if( !(operation_name = vips_foreign_find_save( filename )) ) {
		delete options; 
		throw VError(); 
	}

	call_option_string( operation_name, option_string, 
		(options ? options : VImage::option())-> 
			set( "in", *this )->
			set( "filename", filename ) );
}

#include "vips-operators.cc"

VIPS_NAMESPACE_END
