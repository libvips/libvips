/* Convert 1 to 4-band 8 or 16-bit VIPS images to/from PNG.
 *
 * 28/11/03 JC
 *	- better no-overshoot on tile loop
 * 22/2/05
 *	- read non-interlaced PNG with a line buffer (thanks Michel Brabants)
 * 11/1/06
 * 	- read RGBA palette-ized images more robustly (thanks Tom)
 * 20/4/06
 * 	- auto convert to sRGB/mono (with optional alpha) for save
 * 1/5/06
 * 	- from vips_png.c
 * 8/5/06
 * 	- set RGB16/GREY16 if appropriate
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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
#include <vips/intl.h>

#ifndef HAVE_PNG

#include <vips/vips.h>

int
im_png2vips( const char *name, IMAGE *out )
{
	im_error( "im_png2vips", _( "PNG support disabled" ) );
	return( -1 );
}

int
im_png2vips_header( const char *name, IMAGE *out )
{
	im_error( "im_png2vips_header", _( "PNG support disabled" ) );
	return( -1 );
}

#else /*HAVE_PNG*/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <vips/vips.h>

#include <png.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#if PNG_LIBPNG_VER < 10003
#error "PNG library too old."
#endif

static void
user_error_function( png_structp png_ptr, png_const_charp error_msg )
{
	im_error( "im_png2vips", _( "PNG error: \"%s\"" ), error_msg );
}

static void
user_warning_function( png_structp png_ptr, png_const_charp warning_msg )
{
	im_error( "im_png2vips", _( "PNG warning: \"%s\"" ), warning_msg );
}

/* What we track during a PNG read.
 */
typedef struct {
	char *name;
	IMAGE *out;

	FILE *fp;
	png_structp pPng;
	png_infop pInfo;
	png_bytep *row_pointer;
	png_bytep data;
} Read;

static void
read_destroy( Read *read )
{
	if( read->name ) {
		im_free( read->name );
		read->name = NULL;
	}
	if( read->fp ) {
		fclose( read->fp );
		read->fp = NULL;
	}
	if( read->pPng )
		png_destroy_read_struct( &read->pPng, &read->pInfo, NULL );
	if( read->row_pointer ) {
		im_free( read->row_pointer );
		read->row_pointer = NULL;
	}
	if( read->data ) {
		im_free( read->data );
		read->data = NULL;
	}

	im_free( read );
}

static Read *
read_new( const char *name, IMAGE *out )
{
	Read *read;

	if( !(read = IM_NEW( NULL, Read )) )
		return( NULL );

	read->name = im_strdup( NULL, name );
	read->out = out;
	read->fp = NULL;
	read->pPng = NULL;
	read->pInfo = NULL;
	read->row_pointer = NULL;
	read->data = NULL;

#ifdef BINARY_OPEN
        if( !(read->fp = fopen( name, "rb" )) ) {
#else /*BINARY_OPEN*/
        if( !(read->fp = fopen( name, "r" )) ) {
#endif /*BINARY_OPEN*/
		read_destroy( read );
		im_error( "im_png2vips", _( "unable to open \"%s\"" ), name );
		return( NULL );
	}

	if( !(read->pPng = png_create_read_struct( 
		PNG_LIBPNG_VER_STRING, NULL,
		user_error_function, user_warning_function )) ) {
		read_destroy( read );
		return( NULL );
	}

	/* Catch PNG errors from png_create_info_struct().
	 */
	if( setjmp( read->pPng->jmpbuf ) ) {
		read_destroy( read );
		return( NULL );
	}

	if( !(read->pInfo = png_create_info_struct( read->pPng )) ) {
		read_destroy( read );
		return( NULL );
	}

	return( read );
}

/* Yuk! Have to malloc enough space for the whole image. Interlaced PNG
 * is not really suitable for large objects ...
 */
static int
png2vips_interlace( Read *read )
{
	const int rowbytes = IM_IMAGE_SIZEOF_LINE( read->out );
	int y;

	if( !(read->row_pointer = IM_ARRAY( NULL, 
		read->pInfo->height, png_bytep )) )
		return( -1 );
	if( !(read->data = (png_bytep) im_malloc( NULL,
		read->pInfo->height * rowbytes ))  )
		return( -1 );

	for( y = 0; y < (int) read->pInfo->height; y++ )
		read->row_pointer[y] = read->data + y * rowbytes;
	if( im_outcheck( read->out ) || 
		im_setupout( read->out ) || 
		setjmp( read->pPng->jmpbuf ) ) 
		return( -1 );

	png_read_image( read->pPng, read->row_pointer );

	for( y = 0; y < (int) read->pInfo->height; y++ )
		if( im_writeline( y, read->out, read->row_pointer[y] ) )
			return( -1 );

	return( 0 );
}

/* Noninterlaced images can be read without needing enough RAM for the whole
 * image.
 */
static int
png2vips_noninterlace( Read *read )
{
	const int rowbytes = IM_IMAGE_SIZEOF_LINE( read->out );
	int y;

	if( !(read->data = (png_bytep) im_malloc( NULL, rowbytes ))  )
		return( -1 );
	if( im_outcheck( read->out ) || 
		im_setupout( read->out ) || 
		setjmp( read->pPng->jmpbuf ) ) 
		return( -1 );

	for( y = 0; y < (int) read->pInfo->height; y++ ) {
		png_read_row( read->pPng, read->data, NULL );

		if( im_writeline( y, read->out, read->data ) )
			return( -1 );
	}

	return( 0 );
}

/* Read a PNG file (header) into a VIPS (header).
 */
static int
png2vips( Read *read, int header_only )
{
	int bands, bpp, type;

	if( setjmp( read->pPng->jmpbuf ) ) 
		return( -1 );

	png_init_io( read->pPng, read->fp );
	png_read_info( read->pPng, read->pInfo );

	/* png_get_channels() gives us 1 band for palette images ... so look
	 * at colour_type for output bands.
	 */
	switch( read->pInfo->color_type ) {
	case PNG_COLOR_TYPE_PALETTE: 
		bands = 3; 

		/* Don't know if this is really correct. If there are
		 * transparent pixels, assume we're going to output RGBA.
		 */
		if( read->pInfo->num_trans )
			bands = 4; 

		break;

	case PNG_COLOR_TYPE_GRAY: bands = 1; break;
	case PNG_COLOR_TYPE_GRAY_ALPHA: bands = 2; break;
	case PNG_COLOR_TYPE_RGB: bands = 3; break;
	case PNG_COLOR_TYPE_RGB_ALPHA: bands = 4; break;

	default:
		im_error( "im_png2vips", _( "unsupported colour type" ) );
		return( -1 );
	}

	/* 8 or 16 bit.
	 */
	bpp = read->pInfo->bit_depth > 8 ? 2 : 1;

	if( bpp > 1 ) {
		if( bands < 3 )
			type = IM_TYPE_GREY16;
		else
			type = IM_TYPE_RGB16;
	}
	else {
		if( bands < 3 )
			type = IM_TYPE_B_W;
		else
			type = IM_TYPE_sRGB;
	}

	/* Expand palette images.
	 */
	if( read->pInfo->color_type == PNG_COLOR_TYPE_PALETTE )
	        png_set_expand( read->pPng );

	/* Expand <8 bit images to full bytes.
	 */
	if( read->pInfo->bit_depth < 8 )
		png_set_packing( read->pPng );

	/* If we're an INTEL byte order machine and this is 16bits, we need
	 * to swap bytes.
	 */
	if( read->pInfo->bit_depth > 8 && !im_amiMSBfirst() )
		png_set_swap( read->pPng );

	/* Set VIPS header.
	 */
	im_initdesc( read->out,
		 read->pInfo->width, read->pInfo->height, bands,
		 bpp == 1 ? IM_BBITS_BYTE : IM_BBITS_SHORT, 
		 bpp == 1 ? IM_BANDFMT_UCHAR : IM_BANDFMT_USHORT,
		 IM_CODING_NONE, type, 1.0, 1.0, 0, 0 );

	if( !header_only ) {
		if( png_set_interlace_handling( read->pPng ) > 1 ) {
			if( png2vips_interlace( read ) )
				return( -1 );
		}
		else {
			if( png2vips_noninterlace( read ) )
				return( -1 );
		}
	}

	return( 0 );
}

/* Read a PNG file header into a VIPS header.
 */
int
im_png2vips_header( const char *name, IMAGE *out )
{
	Read *read;

	if( !(read = read_new( name, out )) )
		return( -1 );

	if( png2vips( read, 1 ) ) {
		read_destroy( read );
		return( -1 );
	}

	read_destroy( read );

	return( 0 );
}

/* Read a PNG file into a VIPS image.
 */
int
im_png2vips( const char *name, IMAGE *out )
{
	Read *read;

#ifdef DEBUG
	printf( "im_png2vips: reading \"%s\"\n", name );
#endif /*DEBUG*/

	if( !(read = read_new( name, out )) )
		return( -1 );

	if( png2vips( read, 0 ) ) {
		read_destroy( read );
		return( -1 );
	}

	read_destroy( read );

	return( 0 );
}

#endif /*HAVE_PNG*/
