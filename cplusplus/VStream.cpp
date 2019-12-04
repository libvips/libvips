/* Object part of the VStreamI and VStreamO class
 */

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
#define VIPS_DEBUG
#define VIPS_DEBUG_VERBOSE
 */

VIPS_NAMESPACE_START

VStreamI 
VStreamI::new_from_descriptor( int descriptor )
{
	VipsStreami *input;

	if( !(input = vips_streami_new_from_descriptor( descriptor )) )
		throw VError();

	VStreamI out( input ); 

	return( out ); 
}

VStreamI 
VStreamI::new_from_file( const char *filename )
{
	VipsStreami *input;

	if( !(input = vips_streami_new_from_file( filename )) )
		throw VError();

	VStreamI out( input ); 

	return( out ); 
}

VStreamI 
VStreamI::new_from_blob( VipsBlob *blob )
{
	VipsStreami *input;

	if( !(input = vips_streami_new_from_blob( blob )) )
		throw VError();

	VStreamI out( input ); 

	return( out ); 
}

VStreamI 
VStreamI::new_from_memory( const void *data, 
	size_t size )
{
	VipsStreami *input;

	if( !(input = vips_streami_new_from_memory( data, size )) )
		throw VError();

	VStreamI out( input ); 

	return( out ); 
}

VStreamI 
VStreamI::new_from_options( const char *options )
{
	VipsStreami *input;

	if( !(input = vips_streami_new_from_options( options )) )
		throw VError();

	VStreamI out( input ); 

	return( out ); 
}

VOption *
VOption::set( const char *name, const VStreamI value )
{
	Pair *pair = new Pair( name );

	pair->input = true;
	g_value_init( &pair->value, VIPS_TYPE_STREAMI );
	g_value_set_object( &pair->value, value.get_stream() );
	options.push_back( pair );

	return( this );
}

VStreamO 
VStreamO::new_to_descriptor( int descriptor )
{
	VipsStreamo *output;

	if( !(output = vips_streamo_new_to_descriptor( descriptor )) )
		throw VError();

	VStreamO out( output ); 

	return( out ); 
}

VStreamO 
VStreamO::new_to_file( const char *filename )
{
	VipsStreamo *output;

	if( !(output = vips_streamo_new_to_file( filename )) )
		throw VError();

	VStreamO out( output ); 

	return( out ); 
}

VStreamO 
VStreamO::new_to_memory()
{
	VipsStreamo *output;

	if( !(output = vips_streamo_new_to_memory()) )
		throw VError();

	VStreamO out( output ); 

	return( out ); 
}

VOption *
VOption::set( const char *name, const VStreamO value )
{
	Pair *pair = new Pair( name );

	pair->input = true;
	g_value_init( &pair->value, VIPS_TYPE_STREAMO );
	g_value_set_object( &pair->value, value.get_stream() );
	options.push_back( pair );

	return( this );
}

VIPS_NAMESPACE_END
