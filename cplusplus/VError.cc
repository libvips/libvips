// Code for error type

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

#include <cstdio>
#include <cstdlib>

#include <iostream>

#include <vips/vips.h>

#include <vips/vipscpp.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

VIPS_NAMESPACE_START

void VError::perror() 
{ 
	std::cerr << _what; 
	exit( 1 );
}

void VError::perror( const char *name ) 
{ 
	std::cerr << name << ": " << _what; 
	exit( 1 );
}

// Add a new bit to the end of the error buffer
VError &VError::app( const int i )
{ 
	char buf[ 256 ];

	sprintf( buf, "%d", i );
	_what += buf;

	return( *this );
}

VError &VError::app( std::string txt ) 
{ 
	_what += txt; 

	return( *this );
}; 

void VError::ostream_print( std::ostream &file ) const
{
	file << _what;
}

void verror( std::string str ) throw( VError )
{
	VError err;

	err.app( "VIPS error: " );
	if( str == "" ) {
		err.app( im_error_buffer() );
		im_error_clear();
	}
	else 
		err.app( str ).app( "\n" );

	throw( err );
}

VIPS_NAMESPACE_END
