/* Load/save png image with libpng
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
 * 2/11/07
 * 	- use im_wbuffer() API for BG writes
 * 28/2/09
 * 	- small cleanups
 * 4/2/10
 * 	- gtkdoc
 * 	- fixed 16-bit save
 * 12/5/10
 * 	- lololo but broke 8-bit save, fixed again
 * 20/7/10 Tim Elliott
 * 	- added im_vips2bufpng()
 * 8/1/11
 * 	- get set png resolution (thanks Zhiyu Wu)
 * 17/3/11
 * 	- update for libpng-1.5 API changes
 * 	- better handling of palette and 1-bit images
 * 	- ... but we are now png 1.2.9 and later only :-( argh
 * 28/3/11
 * 	- argh gamma was wrong when viewed in firefox
 * 19/12/11
 * 	- rework as a set of fns ready for wrapping as a class
 * 7/2/12
 * 	- mild refactoring
 * 	- add support for sequential reads
 * 23/2/12
 * 	- add a longjmp() to our error handler to stop the default one running
 * 13/3/12
 * 	- add ICC profile read/write
 * 15/3/12
 * 	- better alpha handling
 * 	- sanity check pixel geometry before allowing read
 * 17/6/12
 * 	- more alpha fixes ... some images have no transparency chunk but
 * 	  still set color_type to alpha
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_PNG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include <png.h>

#include "vipspng.h"

#if PNG_LIBPNG_VER < 10003
#error "PNG library too old."
#endif

static void
user_error_function( png_structp png_ptr, png_const_charp error_msg )
{
	vips_error( "vipspng", "%s", error_msg );

	/* This function must not return or the default error handler will be
	 * invoked.
	 */
	longjmp( png_jmpbuf( png_ptr ), -1 ); 
}

static void
user_warning_function( png_structp png_ptr, png_const_charp warning_msg )
{
	vips_error( "vipspng", "%s", warning_msg );
}

/* What we track during a PNG read.
 */
typedef struct {
	char *name;
	VipsImage *out;

	FILE *fp;
	int y_pos;
	png_structp pPng;
	png_infop pInfo;
	png_bytep *row_pointer;
} Read;

static void
read_destroy( VipsImage *out, Read *read )
{
	VIPS_FREEF( fclose, read->fp );
	if( read->pPng )
		png_destroy_read_struct( &read->pPng, &read->pInfo, NULL );
	VIPS_FREE( read->row_pointer );
}

static Read *
read_new( const char *name, VipsImage *out )
{
	Read *read;

	if( !(read = VIPS_NEW( out, Read )) )
		return( NULL );

	read->name = vips_strdup( VIPS_OBJECT( out ), name );
	read->out = out;
	read->fp = NULL;
	read->y_pos = 0;
	read->pPng = NULL;
	read->pInfo = NULL;
	read->row_pointer = NULL;

	g_signal_connect( out, "close", 
		G_CALLBACK( read_destroy ), read ); 

        if( !(read->fp = vips__file_open_read( name, NULL, FALSE )) ) 
		return( NULL );

	if( !(read->pPng = png_create_read_struct( 
		PNG_LIBPNG_VER_STRING, NULL,
		user_error_function, user_warning_function )) ) 
		return( NULL );

	/* Catch PNG errors from png_create_info_struct().
	 */
	if( setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( NULL );

	if( !(read->pInfo = png_create_info_struct( read->pPng )) ) 
		return( NULL );

	/* Read enough of the file that png_get_interlace_type() will start
	 * working.
	 */
	png_init_io( read->pPng, read->fp );
	png_read_info( read->pPng, read->pInfo );

	return( read );
}

/* Read a png header.
 */
static int
png2vips_header( Read *read, VipsImage *out )
{
	png_uint_32 width, height;
	int bit_depth, color_type;
	int interlace_type;

	png_uint_32 res_x, res_y;
	int unit_type;

	png_charp name;
	int compression_type;

	/* Well thank you, libpng.
	 */
#if PNG_LIBPNG_VER < 10400
	png_charp profile;
#else
	png_bytep profile;
#endif

	png_uint_32 proflen;

	int bands; 
	VipsInterpretation interpretation;
	double Xres, Yres;

	if( setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( -1 );

	png_get_IHDR( read->pPng, read->pInfo, 
		&width, &height, &bit_depth, &color_type,
		&interlace_type, NULL, NULL );

	/* png_get_channels() gives us 1 band for palette images ... so look
	 * at colour_type for output bands.
	 *
	 * Ignore alpha, we detect that separately below.
	 */
	switch( color_type ) {
	case PNG_COLOR_TYPE_PALETTE: 
		bands = 3; 
		break;

	case PNG_COLOR_TYPE_GRAY_ALPHA: 
	case PNG_COLOR_TYPE_GRAY: 
		bands = 1; 
		break;

	case PNG_COLOR_TYPE_RGB: 
	case PNG_COLOR_TYPE_RGB_ALPHA: 
		bands = 3; 
		break;

	default:
		vips_error( "png2vips", "%s", _( "unsupported color type" ) );
		return( -1 );
	}

	if( bit_depth > 8 ) {
		if( bands < 3 )
			interpretation = VIPS_INTERPRETATION_GREY16;
		else
			interpretation = VIPS_INTERPRETATION_RGB16;
	}
	else {
		if( bands < 3 )
			interpretation = VIPS_INTERPRETATION_B_W;
		else
			interpretation = VIPS_INTERPRETATION_sRGB;
	}

	/* Expand palette images.
	 */
	if( color_type == PNG_COLOR_TYPE_PALETTE )
		png_set_palette_to_rgb( read->pPng );

	/* Expand transparency.
	 */
	if( png_get_valid( read->pPng, read->pInfo, PNG_INFO_tRNS ) ) {
		png_set_tRNS_to_alpha( read->pPng );
		bands += 1;
	}
	else if( color_type == PNG_COLOR_TYPE_GRAY_ALPHA || 
		color_type == PNG_COLOR_TYPE_RGB_ALPHA ) {
		/* Some images have no transparency chunk, but still set
		 * color_type to alpha.
		 */
		bands += 1;
	}

	/* Expand <8 bit images to full bytes.
	 */
	if( color_type == PNG_COLOR_TYPE_GRAY &&
		bit_depth < 8 ) 
		png_set_expand_gray_1_2_4_to_8( read->pPng );

	/* If we're an INTEL byte order machine and this is 16bits, we need
	 * to swap bytes.
	 */
	if( bit_depth > 8 && !vips_amiMSBfirst() )
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
	vips_image_init_fields( out,
		width, height, bands,
		bit_depth > 8 ? 
			VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, interpretation, 
		Xres, Yres );

	/* Sequential mode needs thinstrip to work with things like
	 * vips_shrink().
	 */
        vips_demand_hint( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	/* Fetch the ICC profile. @name is useless, something like "icc" or
	 * "ICC Profile" etc.  Ignore it.
	 *
	 * @profile was png_charpp in libpngs < 1.5, png_bytepp is the
	 * modern one. Ignore the warning, if any.
	 */
	if( png_get_iCCP( read->pPng, read->pInfo, 
		&name, &compression_type, &profile, &proflen ) ) {
		void *profile_copy;

#ifdef DEBUG
		printf( "png2vips_header: attaching %zd bytes of ICC profile\n",
			proflen );
		printf( "png2vips_header: name = \"%s\"\n", name );
#endif /*DEBUG*/

		if( !(profile_copy = vips_malloc( NULL, proflen )) ) 
			return( -1 );
		memcpy( profile_copy, profile, proflen );
		vips_image_set_blob( out, VIPS_META_ICC_NAME, 
			(VipsCallbackFn) vips_free, profile_copy, proflen );
	}

	/* Sanity-check lines sizes.
	 */
	png_read_update_info( read->pPng, read->pInfo );
	if( png_get_rowbytes( read->pPng, read->pInfo ) != 
		VIPS_IMAGE_SIZEOF_LINE( out ) ) {
		vips_error( "vipspng", 
			"%s", _( "unable to read PNG header" ) );
		return( -1 );
	}

	return( 0 );
}

/* Read a PNG file header into a VIPS header.
 */
int
vips__png_header( const char *name, VipsImage *out )
{
	Read *read;

	if( !(read = read_new( name, out )) ||
		png2vips_header( read, out ) ) 
		return( -1 );

	return( 0 );
}

/* Out is a huge "t" buffer we decompress to.
 */
static int
png2vips_interlace( Read *read, VipsImage *out )
{
	int y;

#ifdef DEBUG
	printf( "png2vips_interlace: reading whole image\n" ); 
#endif /*DEBUG*/

	if( vips_image_write_prepare( out ) )
		return( -1 );

	if( setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( -1 );

	if( !(read->row_pointer = VIPS_ARRAY( NULL, out->Ysize, png_bytep )) )
		return( -1 );
	for( y = 0; y < out->Ysize; y++ )
		read->row_pointer[y] = VIPS_IMAGE_ADDR( out, 0, y );

	png_read_image( read->pPng, read->row_pointer );

	return( 0 );
}

static int
png2vips_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	Read *read = (Read *) a;

	int y;

#ifdef DEBUG
	printf( "png2vips_generate: line %d, %d rows\n", 
		r->top, r->height );
#endif /*DEBUG*/

	/* We're inside a tilecache where tiles are the full image width, so
	 * this should always be true.
	 */
	g_assert( r->left == 0 );
	g_assert( r->width == or->im->Xsize );
	g_assert( VIPS_RECT_BOTTOM( r ) <= or->im->Ysize );

	/* Tiles should always be a strip in height, unless it's the final
	 * strip.
	 */
	g_assert( r->height == VIPS_MIN( 8, or->im->Ysize - r->top ) ); 

	/* And check that y_pos is correct. It should be, since we are inside
	 * a vips_sequential().
	 */
	g_assert( r->top == read->y_pos ); 

	if( setjmp( png_jmpbuf( read->pPng ) ) ) {
#ifdef DEBUG
		printf( "png2vips_generate: failing in setjmp\n" ); 
		printf( "png2vips_generate: line %d, %d rows\n", 
			r->top, r->height );
		printf( "png2vips_generate: file %s\n", read->name );
		printf( "png2vips_generate: thread %p\n", g_thread_self() );
#endif /*DEBUG*/

		return( -1 );
	}

	for( y = 0; y < r->height; y++ ) {
		png_bytep q = (png_bytep) VIPS_REGION_ADDR( or, 0, r->top + y );

		png_read_row( read->pPng, q, NULL );

		read->y_pos += 1;
	}

	return( 0 );
}

/* Interlaced PNGs need to be entirely decompressed into memory then can be
 * served partially from there. Non-interlaced PNGs may be read sequentially.
 */
gboolean
vips__png_isinterlaced( const char *filename )
{
	VipsImage *image;
	Read *read;
	int interlace_type;

	image = vips_image_new();
	if( !(read = read_new( filename, image )) ) {
		g_object_unref( image );
		return( -1 );
	}
	interlace_type = png_get_interlace_type( read->pPng, read->pInfo );
	g_object_unref( image );

	return( interlace_type != PNG_INTERLACE_NONE );
}

int
vips__png_read( const char *filename, VipsImage *out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

	Read *read;
	int interlace_type;

#ifdef DEBUG
	printf( "vips__png_read: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out )) )
		return( -1 );

	interlace_type = png_get_interlace_type( read->pPng, read->pInfo );

	if( interlace_type != PNG_INTERLACE_NONE ) { 
		/* Arg awful interlaced image. We have to load to a huge mem 
		 * buffer, then copy to out.
		 */
		t[0] = vips_image_new_buffer();
		if( png2vips_header( read, t[0] ) ||
			png2vips_interlace( read, t[0] ) ||
			vips_image_write( t[0], out ) )
			return( -1 );
	}
	else {
		t[0] = vips_image_new();
		if( png2vips_header( read, t[0] ) ||
			vips_image_generate( t[0], 
				NULL, png2vips_generate, NULL, 
				read, NULL ) ||
			vips_sequential( t[0], &t[1], 
				"tile_height", 8,
				NULL ) ||
			vips_image_write( t[1], out ) )
			return( -1 );
	}

#ifdef DEBUG
	printf( "vips__png_read: done\n" );
#endif /*DEBUG*/

	return( 0 );
}

int
vips__png_ispng( const char *filename )
{
	unsigned char buf[8];

	return( vips__get_bytes( filename, buf, 8 ) &&
		!png_sig_cmp( buf, 0, 8 ) );
}

const char *vips__png_suffs[] = { ".png", NULL };

/* What we track during a PNG write.
 */
typedef struct {
	VipsImage *in;

	FILE *fp;
	png_structp pPng;
	png_infop pInfo;
	png_bytep *row_pointer;
} Write;

static void
write_finish( Write *write )
{
	VIPS_FREEF( fclose, write->fp );
	if( write->pPng )
		png_destroy_write_struct( &write->pPng, &write->pInfo );
}

static void
write_destroy( VipsImage *out, Write *write )
{
	write_finish( write ); 
}

static Write *
write_new( VipsImage *in )
{
	Write *write;

	if( !(write = VIPS_NEW( in, Write )) )
		return( NULL );
	memset( write, 0, sizeof( Write ) );
	write->in = in;
	g_signal_connect( in, "close", 
		G_CALLBACK( write_destroy ), write ); 

	if( !(write->row_pointer = VIPS_ARRAY( in, in->Ysize, png_bytep )) )
		return( NULL );
	if( !(write->pPng = png_create_write_struct( 
		PNG_LIBPNG_VER_STRING, NULL,
		user_error_function, user_warning_function )) ) 
		return( NULL );

	/* Catch PNG errors from png_create_info_struct().
	 */
	if( setjmp( png_jmpbuf( write->pPng ) ) ) 
		return( NULL );

	if( !(write->pInfo = png_create_info_struct( write->pPng )) ) 
		return( NULL );

	return( write );
}

static int
write_png_block( VipsRegion *region, Rect *area, void *a )
{
	Write *write = (Write *) a;

	int i;

	/* The area to write is always a set of complete scanlines.
	 */
	g_assert( area->left == 0 );
	g_assert( area->width == region->im->Xsize );
	g_assert( area->top + area->height <= region->im->Ysize );

	/* Catch PNG errors. Yuk.
	 */
	if( setjmp( png_jmpbuf( write->pPng ) ) ) 
		return( -1 );

	for( i = 0; i < area->height; i++ ) 
		write->row_pointer[i] = (png_bytep)
			VIPS_REGION_ADDR( region, 0, area->top + i );

	png_write_rows( write->pPng, write->row_pointer, area->height );

	return( 0 );
}

/* Write a VIPS image to PNG.
 */
static int
write_vips( Write *write, int compress, int interlace )
{
	VipsImage *in = write->in;

	int bit_depth;
	int color_type;
	int interlace_type;
	int i, nb_passes;

        g_assert( in->BandFmt == VIPS_FORMAT_UCHAR || 
		in->BandFmt == VIPS_FORMAT_USHORT );
	g_assert( in->Coding == VIPS_CODING_NONE );
        g_assert( in->Bands > 0 && in->Bands < 5 );

	/* Catch PNG errors.
	 */
	if( setjmp( png_jmpbuf( write->pPng ) ) ) 
		return( -1 );

	/* Check input image.
	 */
	if( vips_image_pio_input( in ) )
		return( -1 );
	if( compress < 0 || compress > 9 ) {
		vips_error( "vips2png", 
			"%s", _( "compress should be in [0,9]" ) );
		return( -1 );
	}

	/* Set compression parameters.
	 */
	png_set_compression_level( write->pPng, compress );

	bit_depth = in->BandFmt == VIPS_FORMAT_UCHAR ? 8 : 16;

	switch( in->Bands ) {
	case 1: color_type = PNG_COLOR_TYPE_GRAY; break;
	case 2: color_type = PNG_COLOR_TYPE_GRAY_ALPHA; break;
	case 3: color_type = PNG_COLOR_TYPE_RGB; break;
	case 4: color_type = PNG_COLOR_TYPE_RGB_ALPHA; break;

	default:
		g_assert( 0 );

		/* Keep -Wall happy.
		 */
		return( 0 );
	}

	interlace_type = interlace ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE;

	png_set_IHDR( write->pPng, write->pInfo, 
		in->Xsize, in->Ysize, bit_depth, color_type, interlace_type, 
		PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT );

	/* Set resolution. libpnbg uses pixels per meter.
	 */
	png_set_pHYs( write->pPng, write->pInfo, 
		VIPS_RINT( in->Xres * 1000 ), VIPS_RINT( in->Yres * 1000 ), 
		PNG_RESOLUTION_METER );

	/* Set ICC Profile.
	 */
	if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
		void *profile;
		size_t profile_length;

		if( vips_image_get_blob( in, VIPS_META_ICC_NAME, 
			&profile, &profile_length ) ) 
			return( -1 ); 

#ifdef DEBUG
		printf( "write_vips: attaching %zd bytes of ICC profile\n",
			profile_length );
#endif /*DEBUG*/

		png_set_iCCP( write->pPng, write->pInfo, "icc", 
			PNG_COMPRESSION_TYPE_BASE, profile, profile_length );
	}

	png_write_info( write->pPng, write->pInfo ); 

	/* If we're an intel byte order CPU and this is a 16bit image, we need
	 * to swap bytes.
	 */
	if( bit_depth > 8 && !vips_amiMSBfirst() ) 
		png_set_swap( write->pPng ); 

	if( interlace )	
		nb_passes = png_set_interlace_handling( write->pPng );
	else
		nb_passes = 1;

	/* Write data.
	 */
	for( i = 0; i < nb_passes; i++ ) 
		if( vips_sink_disc( write->in, write_png_block, write ) )
			return( -1 );

	/* The setjmp() was held by our background writer: reset it.
	 */
	if( setjmp( png_jmpbuf( write->pPng ) ) ) 
		return( -1 );

	png_write_end( write->pPng, write->pInfo );

	return( 0 );
}

int
vips__png_write( VipsImage *in, const char *filename, 
	int compress, int interlace )
{
	Write *write;

#ifdef DEBUG
	printf( "vips__png_write: writing \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(write = write_new( in )) )
		return( -1 );

	/* Make output.
	 */
        if( !(write->fp = vips__file_open_write( filename, FALSE )) ) 
		return( -1 );
	png_init_io( write->pPng, write->fp );

	/* Convert it!
	 */
	if( write_vips( write, compress, interlace ) ) {
		vips_error( "vips2png", 
			_( "unable to write \"%s\"" ), filename );

		return( -1 );
	}

	write_finish( write );

#ifdef DEBUG
	printf( "vips__png_write: done\n" ); 
#endif /*DEBUG*/

	return( 0 );
}

typedef struct _WriteBuf {
	char *buf;
	size_t len;
	size_t alloc;
} WriteBuf;

static void
write_buf_free( WriteBuf *wbuf )
{
	VIPS_FREE( wbuf->buf );
	VIPS_FREE( wbuf );
}

static WriteBuf *
write_buf_new( void )
{
	WriteBuf *wbuf;

	if( !(wbuf = VIPS_NEW( NULL, WriteBuf )) )
		return( NULL );

	wbuf->buf = NULL;
	wbuf->len = 0;
	wbuf->alloc = 0;

	return( wbuf );
}

static void
write_buf_grow( WriteBuf *wbuf, size_t grow_len )
{
	size_t new_len = wbuf->len + grow_len;

	if( new_len > wbuf->alloc ) {
		size_t proposed_alloc = (16 + wbuf->alloc) * 3 / 2;

		wbuf->alloc = VIPS_MAX( proposed_alloc, new_len );

		/* There's no vips_realloc(), so we call g_realloc() directly.
		 * This is safe, since vips_malloc() / vips_free() are wrappers 
		 * over g_malloc() / g_free().
		 *
		 * FIXME: add vips_realloc().
		 */
	 	wbuf->buf = g_realloc( wbuf->buf, wbuf->alloc );

		VIPS_DEBUG_MSG( "write_buf_grow: grown to %zd bytes\n",
			wbuf->alloc );
	}
}

static void
user_write_data( png_structp png_ptr, png_bytep data, png_size_t length )
{
	WriteBuf *wbuf = (WriteBuf *) png_get_io_ptr( png_ptr );

	char *write_start;

	write_buf_grow( wbuf, length );

	write_start = wbuf->buf + wbuf->len;
	memcpy( write_start, data, length );

	wbuf->len += length;

	g_assert( wbuf->len <= wbuf->alloc );
}

int
vips__png_write_buf( VipsImage *in, 
	void **obuf, size_t *olen, int compression, int interlace )
{
	WriteBuf *wbuf;
	Write *write;

	if( !(wbuf = write_buf_new()) )
		return( -1 );
	if( !(write = write_new( in )) ) {
		write_buf_free( wbuf );
		return( -1 );
	}

	png_set_write_fn( write->pPng, wbuf, user_write_data, NULL );

	/* Convert it!
	 */
	if( write_vips( write, compression, interlace ) ) {
		write_buf_free( wbuf );
		vips_error( "vips2png", 
			"%s", _( "unable to write to buffer" ) );
	      
		return( -1 );
	}

	*obuf = wbuf->buf;
	wbuf->buf = NULL;
	if( olen )
		*olen = wbuf->len;

	write_buf_free( wbuf );

	return( 0 );
}

#endif /*HAVE_PNG*/
