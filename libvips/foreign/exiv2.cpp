/* load exif metadata from a TIFF file with exiv2
 *
 * 25/5/16
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
 */
#define DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>

#include "tiff.h"

#ifdef HAVE_EXIV2

#include <exiv2/exiv2.hpp>

static void *
copy_field( VipsImage *image, const char *field, GValue *value, void *data )
{
	VipsImage *out = VIPS_IMAGE( data );

	if( vips_isprefix( "exif-", field ) )
		vips_image_set( out, field, value );

	return( NULL ); 
}

int 
vips__exiv2_load_tiff( VipsImage *out, const char *filename )
{
#ifdef DEBUG
	printf( "vips__exiv2_load_tiff:\n" ); 
#endif /*DEBUG*/

	// Load the metadata from the tiff file
	Exiv2::Image::AutoPtr tiff = Exiv2::ImageFactory::open( filename );
	tiff->readMetadata();

	// make an in-memory jpg file and copy the metadata to it
	Exiv2::BasicIo::AutoPtr mem_io( new Exiv2::MemIo() );
	Exiv2::Image::AutoPtr exv( new Exiv2::JpegImage( mem_io, true ) );
	exv->setMetadata( *tiff );
	exv->writeMetadata();

	// serialize the in-memory file into buff
	size_t size = exv->io().size();
	Exiv2::byte buff[size];
	exv->io().seek( 0, Exiv2::BasicIo::beg );
	exv->io().read( buff, size );

#ifdef DEBUG
{
	printf( "vips__exiv2_load_tiff: generated %zd bytes of jpg\n", size ); 
	printf( "vips__exiv2_load_tiff: copy saved to 'test.jpg'\n" ); 

	FILE *fp;
       
	if( !(fp = vips__file_open_write( "test.jpg", FALSE )) )
		return( -1 );
	fwrite( buff, sizeof( Exiv2::byte ), size, fp );
	fclose( fp );
}
#endif /*DEBUG*/

	// load that memory jpg file as a vips image and copy fields from that
	// into our main image
	VipsImage *x;
	if( !(x = vips_image_new_from_buffer( buff, size, "", NULL )) )
		return( -1 );
	(void) vips_image_map( x, copy_field, out );
	g_object_unref( x ); 

	return( 0 );
}

#else /*!HAVE_EXIV2*/

int 
vips__exiv2_load_tiff( VipsImage *out, const char *filename )
{
	return( 0 );
}

#endif /*!HAVE_EXIV2*/
