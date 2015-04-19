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

typedef size_t (*webp_encoder_lossless)( const uint8_t *rgb, 
	int width, int height, int stride, uint8_t **output );

int
vips__webp_write_file( VipsImage *in, const char *filename, 
	int Q, gboolean lossless )
{
	VipsImage *memory;
	size_t len;
	uint8_t *buffer;
	FILE *fp;

	if( !(memory = vips_image_copy_memory( in )) )
		return( -1 );

	if( lossless ) {
		webp_encoder_lossless encoder;

		if( in->Bands == 4 )
			encoder = WebPEncodeLosslessRGBA;
		else
			encoder = WebPEncodeLosslessRGB;

		if( !(len = encoder( VIPS_IMAGE_ADDR( memory, 0, 0 ), 
			memory->Xsize, memory->Ysize, 
			VIPS_IMAGE_SIZEOF_LINE( memory ),
			&buffer )) ) {
			VIPS_UNREF( memory ); 
			vips_error( "vips2webp", 
				"%s", _( "unable to encode" ) ); 
			return( -1 );
		}
	}
	else {
		webp_encoder encoder;

		if( in->Bands == 4 )
			encoder = WebPEncodeRGBA;
		else
			encoder = WebPEncodeRGB;

		if( !(len = encoder( VIPS_IMAGE_ADDR( memory, 0, 0 ), 
			memory->Xsize, memory->Ysize, 
			VIPS_IMAGE_SIZEOF_LINE( memory ),
			Q, &buffer )) ) {
			VIPS_UNREF( memory ); 
			vips_error( "vips2webp", 
				"%s", _( "unable to encode" ) ); 
			return( -1 );
		}
	}

	VIPS_UNREF( memory ); 

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
vips__webp_write_buffer( VipsImage *in, void **obuf, size_t *olen, 
	int Q, gboolean lossless )
{
	VipsImage *memory;
	webp_encoder encoder;

	if( !(memory = vips_image_copy_memory( in )) )
		return( -1 );

	if( in->Bands == 4 )
		encoder = WebPEncodeRGBA;
	else
		encoder = WebPEncodeRGB;

	if( !(*olen = encoder( VIPS_IMAGE_ADDR( memory, 0, 0 ), 
		memory->Xsize, memory->Ysize, 
		VIPS_IMAGE_SIZEOF_LINE( memory ),
		Q, (uint8_t **) obuf )) ) {
		VIPS_UNREF( memory );
		vips_error( "vips2webp", "%s", _( "unable to encode" ) ); 
		return( -1 );
	}
	VIPS_UNREF( memory );

	return( 0 );
}

#endif /*HAVE_LIBWEBP*/
