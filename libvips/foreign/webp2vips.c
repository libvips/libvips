/* read with libwebp
 *
 * 6/8/13
 * 	- from webp2vips.c
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
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_LIBWEBP

#include <webp/decode.h>

#include <vips/vips.h>

#include "webp.h"

int
vips__iswebp( const char *filename )
{
	unsigned char buf[2];

	if( vips__get_bytes( filename, buf, 2 ) )
		if( (int) buf[0] == 0xff && (int) buf[1] == 0xd8 )
			return( 1 );

	return( 0 );
}

int
vips__webp_read_file_header( const char *filename, VipsImage *out ) 
{
	printf( "vips__webp_read_file_header\n" ); 

	return( 0 );
}

int
vips__webp_read_file( const char *filename, VipsImage *out ) 
{
	printf( "vips__webp_read_file\n" ); 

	return( 0 );
}

int
vips__webp_read_buffer_header( void *buf, size_t len, VipsImage *out ) 
{
	printf( "vips__webp_read_buffer_header\n" ); 

	return( 0 );
}

int
vips__webp_read_buffer( void *buf, size_t len, VipsImage *out ) 
{
	printf( "vips__webp_read_buffer\n" ); 

	return( 0 );
}

#endif /*HAVE_LIBWEBP*/


