/* wrap libwebp libray for write
 *
 * 6/8/13
 * 	- from vips2jpeg.c
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_LIBWEBP

#include <stdlib.h>

#include <vips/vips.h>

#include <webp/encode.h>

#include "webp.h"

typedef size_t (*webp_encoder)( const uint8_t *rgb, 
	int width, int height, int stride, 
	float quality_factor, uint8_t **output );

int
vips__webp_write_file( VipsImage *in, const char *filename, int Q )
{
	webp_encoder encoder;
	size_t len;
	uint8_t *buffer;
	FILE *fp;

	if( vips_image_wio_input( in ) )
		return( -1 );

	if( in->Bands == 4 )
		encoder = WebPEncodeRGBA;
	else
		encoder = WebPEncodeRGB;

	if( !(len = encoder( VIPS_IMAGE_ADDR( in, 0, 0 ), 
		in->Xsize, in->Ysize, 
		VIPS_IMAGE_SIZEOF_LINE( in ),
		Q, &buffer )) ) {
		vips_error( "vips2webp", "%s", _( "unable to encode" ) ); 
		return( -1 );
	}

	if( !(fp = vips__file_open_write( filename, FALSE )) ) {
		free( buffer );
		return( -1 );
	}

	if( vips__file_write( buffer, len, 1, fp ) ) {
		fclose( fp );
		free( buffer );
		return( -1 );
	}

	fclose( fp );
	free( buffer );

	return( 0 );
}

int
vips__webp_write_buffer( VipsImage *in, void **obuf, size_t *olen, int Q )
{
	webp_encoder encoder;

	if( vips_image_wio_input( in ) )
		return( -1 );

	if( in->Bands == 4 )
		encoder = WebPEncodeRGBA;
	else
		encoder = WebPEncodeRGB;

	if( !(*olen = encoder( VIPS_IMAGE_ADDR( in, 0, 0 ), 
		in->Xsize, in->Ysize, 
		VIPS_IMAGE_SIZEOF_LINE( in ),
		Q, (uint8_t **) obuf )) ) {
		vips_error( "vips2webp", "%s", _( "unable to encode" ) ); 
		return( -1 );
	}

	return( 0 );
}

#endif /*HAVE_LIBWEBP*/
