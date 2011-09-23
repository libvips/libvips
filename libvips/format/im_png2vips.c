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
 * 28/2/09
 * 	- small cleanups
 * 4/2/10
 * 	- gtkdoc
 * 8/1/11
 * 	- get png resolution (thanks Zhiyu Wu)
 * 17/3/11
 * 	- update for libpng-1.5 API changes
 * 	- better handling of palette and 1-bit images
 * 	- ... but we are now png 1.2.9 and later only :-( argh
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
	im_error( "im_png2vips", "%s", _( "PNG support disabled" ) );
	return( -1 );
}

#else /*HAVE_PNG*/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include <png.h>

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
	IM_FREE( read->name );
	IM_FREEF( fclose, read->fp );
	if( read->pPng )
		png_destroy_read_struct( &read->pPng, &read->pInfo, NULL );
	IM_FREE( read->row_pointer );
	IM_FREE( read->data );

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

        if( !(read->fp = im__file_open_read( name, NULL, FALSE )) ) {
		read_destroy( read );
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
	if( setjmp( png_jmpbuf( read->pPng ) ) ) {
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
	const int height = png_get_image_height( read->pPng, read->pInfo );

	int y;

	if( !(read->row_pointer = IM_ARRAY( NULL, height, png_bytep )) )
		return( -1 );
	if( !(read->data = (png_bytep) im_malloc( NULL, height * rowbytes ))  )
		return( -1 );

	for( y = 0; y < (int) height; y++ )
		read->row_pointer[y] = read->data + y * rowbytes;
	if( im_outcheck( read->out ) || 
		im_setupout( read->out ) || 
		setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( -1 );

	png_read_image( read->pPng, read->row_pointer );

	for( y = 0; y < height; y++ )
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
	const int height = png_get_image_height( read->pPng, read->pInfo );

	int y;

	if( !(read->data = (png_bytep) im_malloc( NULL, rowbytes ))  )
		return( -1 );
	if( im_outcheck( read->out ) || 
		im_setupout( read->out ) || 
		setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( -1 );

	for( y = 0; y < height; y++ ) {
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
	png_uint_32 width, height;
	int bit_depth, color_type, interlace_type;

	png_uint_32 res_x, res_y;
	int unit_type;

	int bands, bpp, type;
	double Xres, Yres;

	if( setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( -1 );

	png_init_io( read->pPng, read->fp );
	png_read_info( read->pPng, read->pInfo );
	png_get_IHDR( read->pPng, read->pInfo, 
		&width, &height, &bit_depth, &color_type,
		&interlace_type, NULL, NULL );

	/* png_get_channels() gives us 1 band for palette images ... so look
	 * at colour_type for output bands.
	 */
	switch( color_type ) {
	case PNG_COLOR_TYPE_PALETTE: 
		bands = 3; 

		/* If there's transparency in the palette, we make an alpha.
		 */
		if( png_get_valid( read->pPng, read->pInfo, PNG_INFO_tRNS ) ) 
			bands = 4; 

		break;

	case PNG_COLOR_TYPE_GRAY: 
		bands = 1; 
		break;

	case PNG_COLOR_TYPE_GRAY_ALPHA: 
		bands = 2; 
		break;

	case PNG_COLOR_TYPE_RGB: 
		bands = 3; 
		break;

	case PNG_COLOR_TYPE_RGB_ALPHA: 
		bands = 4; 
		break;

	default:
		im_error( "im_png2vips", "%s", _( "unsupported color type" ) );
		return( -1 );
	}

	/* 8 or 16 bit.
	 */
	bpp = bit_depth > 8 ? 2 : 1;

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

	/* Expand palette images, expand transparency too.
	 */
	if( color_type == PNG_COLOR_TYPE_PALETTE )
		png_set_palette_to_rgb( read->pPng );
	if( png_get_valid( read->pPng, read->pInfo, PNG_INFO_tRNS ) ) 
		png_set_tRNS_to_alpha( read->pPng );

	/* Expand <8 bit images to full bytes.
	 */
	if( color_type == PNG_COLOR_TYPE_GRAY &&
		bit_depth < 8 ) 
		png_set_expand_gray_1_2_4_to_8( read->pPng );

	/* If we're an INTEL byte order machine and this is 16bits, we need
	 * to swap bytes.
	 */
	if( bit_depth > 8 && !im_amiMSBfirst() )
		png_set_swap( read->pPng );

	/* Get resolution. I'm not sure what we should do for UNKNOWN, since
	 * vips is always pixels/mm.
	 */
	unit_type = PNG_RESOLUTION_METER;
	res_x = 1000;
	res_y = 1000;
	png_get_pHYs( read->pPng, read->pInfo, &res_x, &res_y, &unit_type );
	switch( unit_type ) {
	case PNG_RESOLUTION_METER:
		Xres = res_x / 1000.0;
		Yres = res_y / 1000.0;
		break;
	
	default:
		Xres = res_x;
		Yres = res_y;
		break;
	}

	/* Set VIPS header.
	 */
	im_initdesc( read->out, width, height, bands,
		 bpp == 1 ? IM_BBITS_BYTE : IM_BBITS_SHORT, 
		 bpp == 1 ? IM_BANDFMT_UCHAR : IM_BANDFMT_USHORT,
		 IM_CODING_NONE, type, 
		 Xres, Yres,
		 0, 0 );

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
static int
png2vips_header( const char *name, IMAGE *out )
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

/**
 * im_png2vips:
 * @filename: file to load
 * @out: image to write to
 *
 * Read a PNG file into a VIPS image. It can read all png images, including 8-
 * and 16-bit images, 1 and 3 channel, with and without an alpha channel.
 *
 * There is no support for embedded ICC profiles.
 *
 * See also: #VipsFormat, im_vips2png().
 *
 * Returns: 0 on success, -1 on error.
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

static int
ispng( const char *filename )
{
	unsigned char buf[8];

	return( im__get_bytes( filename, buf, 8 ) &&
		!png_sig_cmp( buf, 0, 8 ) );
}

static const char *png_suffs[] = { ".png", NULL };

/* png format adds no new members.
 */
typedef VipsFormat VipsFormatPng;
typedef VipsFormatClass VipsFormatPngClass;

static void
vips_format_png_class_init( VipsFormatPngClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "png";
	object_class->description = _( "PNG" );

	format_class->is_a = ispng;
	format_class->header = png2vips_header;
	format_class->load = im_png2vips;
	format_class->save = im_vips2png;
	format_class->suffs = png_suffs;
}

static void
vips_format_png_init( VipsFormatPng *object )
{
}

G_DEFINE_TYPE( VipsFormatPng, vips_format_png, VIPS_TYPE_FORMAT );

#endif /*HAVE_PNG*/
