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
 * 16/7/13
 * 	- more robust error handling from libpng
 * 9/8/14
 * 	- don't check profiles, helps with libpng >=1.6.11
 * 27/10/14 Lovell
 * 	- add @filter option 
 * 26/2/15
 * 	- close the read down early for a header read ... this saves an
 * 	  fd during file read, handy for large numbers of input images 
 * 31/7/16
 * 	- support --strip option
 * 17/1/17
 * 	- invalidate operation on read error
 * 27/2/17
 * 	- use dbuf for buffer output
 * 30/3/17
 * 	- better behaviour for truncated png files, thanks Yury
 * 26/4/17
 * 	- better @fail handling with truncated PNGs
 * 9/4/18
 * 	- set interlaced=1 for interlaced images
 * 20/6/18 [felixbuenemann]
 * 	- support png8 palette write with palette, colours, Q, dither
 * 25/8/18
 * 	- support xmp read/write
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

#ifdef HAVE_PNG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pforeign.h"

#include <png.h>

#if PNG_LIBPNG_VER < 10003
#error "PNG library too old."
#endif

static void
user_error_function( png_structp png_ptr, png_const_charp error_msg )
{
#ifdef DEBUG
	printf( "user_error_function: %s\n", error_msg );
#endif /*DEBUG*/

	g_warning( "%s", error_msg );

	/* This function must not return or the default error handler will be
	 * invoked.
	 */
	longjmp( png_jmpbuf( png_ptr ), -1 ); 
}

static void
user_warning_function( png_structp png_ptr, png_const_charp warning_msg )
{
#ifdef DEBUG
	printf( "user_warning_function: %s\n", warning_msg );
#endif /*DEBUG*/

	g_warning( "%s", warning_msg );
}

/* What we track during a PNG read.
 */
typedef struct {
	char *name;
	VipsImage *out;
	gboolean fail;

	int y_pos;
	png_structp pPng;
	png_infop pInfo;
	png_bytep *row_pointer;

	/* For FILE input.
	 */
	FILE *fp;

	/* For memory input.
	 */
	const void *buffer;
	size_t length;
	size_t read_pos;

} Read;

/* Can be called many times.
 */
static void
read_destroy( Read *read )
{
	VIPS_FREEF( fclose, read->fp );
	if( read->pPng )
		png_destroy_read_struct( &read->pPng, &read->pInfo, NULL );
	VIPS_FREE( read->row_pointer );
}

static void
read_close_cb( VipsImage *out, Read *read )
{
	read_destroy( read ); 
}

static Read *
read_new( VipsImage *out, gboolean fail )
{
	Read *read;

	if( !(read = VIPS_NEW( out, Read )) )
		return( NULL );

	read->name = NULL;
	read->fail = fail;
	read->out = out;
	read->y_pos = 0;
	read->pPng = NULL;
	read->pInfo = NULL;
	read->row_pointer = NULL;
	read->fp = NULL;
	read->buffer = NULL;
	read->length = 0;
	read->read_pos = 0;

	g_signal_connect( out, "close", 
		G_CALLBACK( read_close_cb ), read ); 

	if( !(read->pPng = png_create_read_struct( 
		PNG_LIBPNG_VER_STRING, NULL,
		user_error_function, user_warning_function )) ) 
		return( NULL );

#ifdef PNG_SKIP_sRGB_CHECK_PROFILE
	/* Prevent libpng (>=1.6.11) verifying sRGB profiles.
	 */
	png_set_option( read->pPng, 
		PNG_SKIP_sRGB_CHECK_PROFILE, PNG_OPTION_ON );
#endif /*PNG_SKIP_sRGB_CHECK_PROFILE*/

	/* Catch PNG errors from png_create_info_struct().
	 */
	if( setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( NULL );

	if( !(read->pInfo = png_create_info_struct( read->pPng )) ) 
		return( NULL );

	return( read );
}

static Read *
read_new_filename( VipsImage *out, const char *name, gboolean fail )
{
	Read *read;

	if( !(read = read_new( out, fail )) )
		return( NULL );

	read->name = vips_strdup( VIPS_OBJECT( out ), name );

        if( !(read->fp = vips__file_open_read( name, NULL, FALSE )) ) 
		return( NULL );

	/* Catch PNG errors from png_read_info().
	 */
	if( setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( NULL );

	/* Read enough of the file that png_get_interlace_type() will start
	 * working.
	 */
	png_init_io( read->pPng, read->fp );
	png_read_info( read->pPng, read->pInfo );

	return( read );
}

/* Set the png text data as metadata on the vips image.
 */
static int
vips__set_text( VipsImage *out, int i, const char *key, const char *text ) 
{
	if( strcmp( key, "XML:com.adobe.xmp") == 0 ) {
		/* Save as an XMP tag.
		 */
		size_t len = strlen( text );

		void *text_copy;

		if( !(text_copy = vips_malloc( NULL, len + 1 )) ) 
			return( -1 );
		memcpy( text_copy, text, len + 1 );
		vips_image_set_blob( out, VIPS_META_XMP_NAME, 
			(VipsCallbackFn) vips_free, text_copy, len );
	}
	else {
		/* Save as a comment. Some PNGs have EXIF data as
		 * text segments, but the correct way to support this is with
		 * png_get_eXIf_1().
		 */
		char name[256];

		vips_snprintf( name, 256, "png-comment-%d-%s", i, key );
		vips_image_set_string( out, name, text );
	}

	return( 0 );
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

	png_textp text_ptr;
        int num_text;

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
	if( bit_depth > 8 && 
		!vips_amiMSBfirst() )
		png_set_swap( read->pPng );

	/* Get resolution. Default to 72 pixels per inch, the usual png value. 
	 */
	unit_type = PNG_RESOLUTION_METER;
	res_x = (72 / 2.54 * 100);
	res_y = (72 / 2.54 * 100);
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

	/* Uninterlaced images will be read in seq mode. Interlaced images are
	 * read via a huge memory buffer.
	 */
	if( interlace_type == PNG_INTERLACE_NONE ) 
		/* Sequential mode needs thinstrip to work with things like
		 * vips_shrink().
		 */
		vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );
	else 
		vips_image_pipelinev( out, VIPS_DEMAND_STYLE_ANY, NULL );

	/* Fetch the ICC profile. @name is useless, something like "icc" or
	 * "ICC Profile" etc. Ignore it.
	 *
	 * @profile was png_charpp in libpngs < 1.5, png_bytepp is the
	 * modern one. Ignore the warning, if any.
	 */
	if( png_get_iCCP( read->pPng, read->pInfo, 
		&name, &compression_type, &profile, &proflen ) ) {
		void *profile_copy;

#ifdef DEBUG
		printf( "png2vips_header: attaching %d bytes of ICC profile\n",
			proflen );
		printf( "png2vips_header: name = \"%s\"\n", name );
#endif /*DEBUG*/

		if( !(profile_copy = vips_malloc( NULL, proflen )) ) 
			return( -1 );
		memcpy( profile_copy, profile, proflen );
		vips_image_set_blob( out, VIPS_META_ICC_NAME, 
			(VipsCallbackFn) vips_free, profile_copy, proflen );
	}

	/* Sanity-check line size.
	 */
	png_read_update_info( read->pPng, read->pInfo );
	if( png_get_rowbytes( read->pPng, read->pInfo ) != 
		VIPS_IMAGE_SIZEOF_LINE( out ) ) {
		vips_error( "vipspng", 
			"%s", _( "unable to read PNG header" ) );
		return( -1 );
	}

	/* Let our caller know. These are very expensive to decode.
	 */
	if( interlace_type != PNG_INTERLACE_NONE ) 
		vips_image_set_int( out, "interlaced", 1 ); 

	if( png_get_text( read->pPng, read->pInfo, 
		&text_ptr, &num_text ) > 0 ) {
		int i;

		for( i = 0; i < num_text; i++ ) 
			/* .text is always a null-terminated C string.
			 */
			if( vips__set_text( out, i, 
				text_ptr[i].key, text_ptr[i].text ) ) 
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

	if( !(read = read_new_filename( out, name, TRUE )) ||
		png2vips_header( read, out ) ) 
		return( -1 );

	/* Just a header read: we can free the read early and save an fd.
	 */
	read_destroy( read );

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

	/* Some libpng warn you to call png_set_interlace_handling(); here, but
	 * that can actually break interlace. We have to live with the warning,
	 * unfortunately.
	 */

	png_read_image( read->pPng, read->row_pointer );

	png_read_end( read->pPng, NULL ); 

	read_destroy( read );

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
	printf( "png2vips_generate: line %d, %d rows\n", r->top, r->height );
	printf( "png2vips_generate: y_top = %d\n", read->y_pos );
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
	if( r->top != read->y_pos ) {
		vips_error( "vipspng", 
			_( "out of order read at line %d" ), read->y_pos );
		return( -1 );
	}

	for( y = 0; y < r->height; y++ ) {
		png_bytep q = (png_bytep) VIPS_REGION_ADDR( or, 0, r->top + y );

		/* We need to catch errors from read_row().
		 */
		if( !setjmp( png_jmpbuf( read->pPng ) ) ) 
			png_read_row( read->pPng, q, NULL );
		else { 
			/* We've failed to read some pixels. Knock this 
			 * operation out of cache. 
			 */
			vips_foreign_load_invalidate( read->out );

#ifdef DEBUG
			printf( "png2vips_generate: png_read_row() failed, "
				"line %d\n", r->top + y ); 
			printf( "png2vips_generate: file %s\n", read->name );
			printf( "png2vips_generate: thread %p\n", 
				g_thread_self() );
#endif /*DEBUG*/

			/* And bail if fail is on. We have to add an error
			 * message, since the handler we install just does
			 * g_warning().
			 */
			if( read->fail ) {
				vips_error( "vipspng", 
					"%s", _( "libpng read error" ) ); 
				return( -1 );
			}
		}

		read->y_pos += 1;
	}

	/* Catch errors from png_read_end(). This can fail on a truncated
	 * file. 
	 */
	if( setjmp( png_jmpbuf( read->pPng ) ) ) {
		if( read->fail ) {
			vips_error( "vipspng", "%s", _( "libpng read error" ) ); 
			return( -1 );
		}

		return( 0 );
	}

	/* We need to shut down the reader immediately at the end of read or
	 * we won't detach ready for the next image.
	 */
	if( read->y_pos >= read->out->Ysize ) {
		png_read_end( read->pPng, NULL ); 
		read_destroy( read );
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
	if( !(read = read_new_filename( image, filename, TRUE )) ) {
		g_object_unref( image );
		return( -1 );
	}
	interlace_type = png_get_interlace_type( read->pPng, read->pInfo );
	g_object_unref( image );

	return( interlace_type != PNG_INTERLACE_NONE );
}

static int
png2vips_image( Read *read, VipsImage *out )
{
	int interlace_type = png_get_interlace_type( read->pPng, read->pInfo );
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

	if( interlace_type != PNG_INTERLACE_NONE ) { 
		/* Arg awful interlaced image. We have to load to a huge mem 
		 * buffer, then copy to out.
		 */
		t[0] = vips_image_new_memory();
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

	return( 0 );
}

int
vips__png_read( const char *filename, VipsImage *out, gboolean fail )
{
	Read *read;

#ifdef DEBUG
	printf( "vips__png_read: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new_filename( out, filename, fail )) ||
		png2vips_image( read, out ) )
		return( -1 ); 

#ifdef DEBUG
	printf( "vips__png_read: done\n" );
#endif /*DEBUG*/

	return( 0 );
}

gboolean
vips__png_ispng_buffer( const void *buf, size_t len )
{
	if( len >= 8 &&
		!png_sig_cmp( (png_bytep) buf, 0, 8 ) )
		return( TRUE ); 

	return( FALSE ); 
}

int
vips__png_ispng( const char *filename )
{
	unsigned char buf[8];

	return( vips__get_bytes( filename, buf, 8 ) == 8 &&
		vips__png_ispng_buffer( buf, 8 ) ); 
}

static void
vips_png_read_buffer( png_structp pPng, png_bytep data, png_size_t length )
{
	Read *read = png_get_io_ptr( pPng ); 

#ifdef DEBUG
	printf( "vips_png_read_buffer: read %zd bytes\n", length ); 
#endif /*DEBUG*/

	if( read->read_pos + length > read->length )
		png_error( pPng, "not enough data in buffer" );

	memcpy( data, (VipsPel *) read->buffer + read->read_pos, length );
	read->read_pos += length;
}

static Read *
read_new_buffer( VipsImage *out, const void *buffer, size_t length, 
	gboolean fail )
{
	Read *read;

	if( !(read = read_new( out, fail )) )
		return( NULL );

	read->length = length;
	read->buffer = buffer;

	png_set_read_fn( read->pPng, read, vips_png_read_buffer ); 

	/* Catch PNG errors from png_read_info().
	 */
	if( setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( NULL );

	/* Read enough of the file that png_get_interlace_type() will start
	 * working.
	 */
	png_read_info( read->pPng, read->pInfo );

	return( read );
}

int
vips__png_header_buffer( const void *buffer, size_t length, VipsImage *out )
{
	Read *read;

	if( !(read = read_new_buffer( out, buffer, length, TRUE )) ||
		png2vips_header( read, out ) ) 
		return( -1 );

	return( 0 );
}

int
vips__png_read_buffer( const void *buffer, size_t length, VipsImage *out, 
	gboolean fail )
{
	Read *read;

	if( !(read = read_new_buffer( out, buffer, length, fail )) ||
		png2vips_image( read, out ) )
		return( -1 ); 

	return( 0 );
}

/* Interlaced PNGs need to be entirely decompressed into memory then can be
 * served partially from there. Non-interlaced PNGs may be read sequentially.
 */
gboolean
vips__png_isinterlaced_buffer( const void *buffer, size_t length )
{
	VipsImage *image;
	Read *read;
	int interlace_type;

	image = vips_image_new();

	if( !(read = read_new_buffer( image, buffer, length, TRUE )) ) { 
		g_object_unref( image );
		return( -1 );
	}
	interlace_type = png_get_interlace_type( read->pPng, read->pInfo );
	g_object_unref( image );

	return( interlace_type != PNG_INTERLACE_NONE );
}

const char *vips__png_suffs[] = { ".png", NULL };

/* What we track during a PNG write.
 */
typedef struct {
	VipsImage *in;
	VipsImage *memory;

	FILE *fp;
	VipsDbuf dbuf;

	png_structp pPng;
	png_infop pInfo;
	png_bytep *row_pointer;
} Write;

static void
write_finish( Write *write )
{
	VIPS_FREEF( fclose, write->fp );
	VIPS_UNREF( write->memory );
	vips_dbuf_destroy( &write->dbuf );
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
	write->memory = NULL;
	write->fp = NULL;
	vips_dbuf_init( &write->dbuf );
	g_signal_connect( in, "close", 
		G_CALLBACK( write_destroy ), write ); 

	if( !(write->row_pointer = VIPS_ARRAY( in, in->Ysize, png_bytep )) )
		return( NULL );
	if( !(write->pPng = png_create_write_struct( 
		PNG_LIBPNG_VER_STRING, NULL,
		user_error_function, user_warning_function )) ) 
		return( NULL );

#ifdef PNG_SKIP_sRGB_CHECK_PROFILE
	/* Prevent libpng (>=1.6.11) verifying sRGB profiles.
	 */
	png_set_option( write->pPng, 
		PNG_SKIP_sRGB_CHECK_PROFILE, PNG_OPTION_ON );
#endif /*PNG_SKIP_sRGB_CHECK_PROFILE*/

	/* Catch PNG errors from png_create_info_struct().
	 */
	if( setjmp( png_jmpbuf( write->pPng ) ) ) 
		return( NULL );

	if( !(write->pInfo = png_create_info_struct( write->pPng )) ) 
		return( NULL );

	return( write );
}

static int
write_png_block( VipsRegion *region, VipsRect *area, void *a )
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

static void
vips__png_set_text( png_structp pPng, png_infop pInfo, 
	const char *key, const char *value )
{
	png_text text;

	text.compression = 0;
	text.key = (char *) key;
	text.text = (char *) value;
	text.text_length = strlen( value );

	/* Before 1.4, these fields were only there if explicitly enabled.
	 */
#if PNG_LIBPNG_VER > 10400
	text.itxt_length = 0;
	text.lang = NULL;
#endif

	png_set_text( pPng, pInfo, &text, 1 );
}

static void *
write_png_comment( VipsImage *image, 
	const char *field, GValue *value, void *data )
{
	Write *write = (Write *) data;

	if( vips_isprefix( "png-comment-", field ) ) { 
		const char *str;
		int i;
		char key[80];

		if( vips_image_get_string( write->in, field, &str ) )
			return( image );

		if( sscanf( field, "png-comment-%d-%80s", &i, key ) != 2 ) {
			vips_error( "vips2png", 
				"%s", _( "bad png comment key" ) );
			return( image );
		}

		vips__png_set_text( write->pPng, write->pInfo, key, str );
	}

	return( NULL );
}

/* Write a VIPS image to PNG.
 */
static int
write_vips( Write *write, 
	int compress, int interlace, const char *profile,
	VipsForeignPngFilter filter, gboolean strip,
	gboolean palette, int colours, int Q, double dither )
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

	/* Check input image. If we are writing interlaced, we need to make 7
	 * passes over the image. We advertise ourselves as seq, so to ensure
	 * we only suck once from upstream, switch to WIO. 
	 */
	if( interlace ) {
		if( !(write->memory = vips_image_copy_memory( in )) )
			return( -1 );
		in = write->memory;
	}
	else {
		if( vips_image_pio_input( in ) )
			return( -1 );
	}
	if( compress < 0 || compress > 9 ) {
		vips_error( "vips2png", 
			"%s", _( "compress should be in [0,9]" ) );
		return( -1 );
	}

	/* Set compression parameters.
	 */
	png_set_compression_level( write->pPng, compress );

	/* Set row filter.
	 */
	png_set_filter( write->pPng, 0, filter );

	bit_depth = in->BandFmt == VIPS_FORMAT_UCHAR ? 8 : 16;

	switch( in->Bands ) {
	case 1: color_type = PNG_COLOR_TYPE_GRAY; break;
	case 2: color_type = PNG_COLOR_TYPE_GRAY_ALPHA; break;
	case 3: color_type = PNG_COLOR_TYPE_RGB; break;
	case 4: color_type = PNG_COLOR_TYPE_RGB_ALPHA; break;

	default:
		vips_error( "vips2png", 
			_( "can't save %d band image as png" ), in->Bands );
		return( -1 );
	}

#ifdef HAVE_IMAGEQUANT
	/* Enable image quantisation to paletted 8bpp PNG if colours is set.
	 */
	if( palette ) {
		g_assert( colours >= 2 && 
			colours <= 256 );
		bit_depth = 8;
		color_type = PNG_COLOR_TYPE_PALETTE;
	}
#else
	if( palette )
		g_warning( "%s",
			_( "ignoring palette (no quantisation support)" ) );
#endif /*HAVE_IMAGEQUANT*/

	interlace_type = interlace ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE;

	png_set_IHDR( write->pPng, write->pInfo, 
		in->Xsize, in->Ysize, bit_depth, color_type, interlace_type, 
		PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT );

	/* Set resolution. libpng uses pixels per meter.
	 */
	png_set_pHYs( write->pPng, write->pInfo, 
		VIPS_RINT( in->Xres * 1000 ), VIPS_RINT( in->Yres * 1000 ), 
		PNG_RESOLUTION_METER );

	/* Set ICC Profile.
	 */
	if( profile && 
		!strip ) {
		if( strcmp( profile, "none" ) != 0 ) { 
			void *data;
			size_t length;

			if( !(data = vips__file_read_name( profile, 
				vips__icc_dir(), &length )) ) 
				return( -1 );

#ifdef DEBUG
			printf( "write_vips: "
				"attaching %zd bytes of ICC profile\n",
				length );
#endif /*DEBUG*/

			png_set_iCCP( write->pPng, write->pInfo, "icc", 
				PNG_COMPRESSION_TYPE_BASE, data, length );
		}
	}
	else if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) &&
		!strip ) {
		void *data;
		size_t length;

		if( vips_image_get_blob( in, VIPS_META_ICC_NAME, 
			&data, &length ) ) 
			return( -1 ); 

#ifdef DEBUG
		printf( "write_vips: attaching %zd bytes of ICC profile\n",
			length );
#endif /*DEBUG*/

		png_set_iCCP( write->pPng, write->pInfo, "icc", 
			PNG_COMPRESSION_TYPE_BASE, data, length );
	}

	if( vips_image_get_typeof( in, VIPS_META_XMP_NAME ) ) {
		void *data;
		size_t data_length;

		if( vips_image_get_blob( in, VIPS_META_XMP_NAME, 
			&data, &data_length ) )
			return( -1 );

		/* libpng must have a regular C string.
		 */
		if( ((char *) data)[data_length] != '\0' ) {
			vips_error( "vips2png", "%s", 
				_( "XMP metadata not NULL terminated" ) );
			return( -1 );
		}

		vips__png_set_text( write->pPng, write->pInfo, 
			"XML:com.adobe.xmp", (char *) data );
	}

	/* Set any "png-comment-xx-yyy" metadata items.
	 */
	if( vips_image_map( in, 
		write_png_comment, write ) )
		return( -1 );

#ifdef HAVE_IMAGEQUANT
	if( palette ) {
		VipsImage *im_index;
		VipsImage *im_palette;
		int palette_count;
		png_color *png_palette;
		png_byte *png_trans;
		int trans_count;

		if( vips__quantise_image( in, &im_index, &im_palette, 
			colours, Q, dither ) ) 
			return( -1 );

		palette_count = im_palette->Xsize;

		g_assert( palette_count <= PNG_MAX_PALETTE_LENGTH );

		png_palette = (png_color *) png_malloc( write->pPng,
			palette_count * sizeof( png_color ) );
		png_trans = (png_byte *) png_malloc( write->pPng,
			palette_count * sizeof( png_byte ) );
		trans_count = 0;
		for( i = 0; i < palette_count; i++ ) {
			VipsPel *p = (VipsPel *) 
				VIPS_IMAGE_ADDR( im_palette, i, 0 );
			png_color *col = &png_palette[i];

			col->red = p[0];
			col->green = p[1];
			col->blue = p[2];
			png_trans[i] = p[3];
			if( p[3] != 255 )
				trans_count = i + 1;
#ifdef DEBUG
			printf( "write_vips: palette[%d] %d %d %d %d\n",
				i + 1, p[0], p[1], p[2], p[3] );
#endif /*DEBUG*/
		}

#ifdef DEBUG
		printf( "write_vips: attaching %d color palette\n",
			palette_count );
#endif /*DEBUG*/
		png_set_PLTE( write->pPng, write->pInfo, png_palette,
			palette_count );
		if( trans_count ) {
#ifdef DEBUG
			printf( "write_vips: attaching %d alpha values\n",
				trans_count );
#endif /*DEBUG*/
			png_set_tRNS( write->pPng, write->pInfo, png_trans,
				trans_count, NULL );
		}

		png_free( write->pPng, (void *) png_palette );
		png_free( write->pPng, (void *) png_trans );

		VIPS_UNREF( im_palette );

		VIPS_UNREF( write->memory );
		write->memory = im_index;
		in = write->memory;
	}
#endif /*HAVE_IMAGEQUANT*/

	png_write_info( write->pPng, write->pInfo );

	/* If we're an intel byte order CPU and this is a 16bit image, we need
	 * to swap bytes.
	 */
	if( bit_depth > 8 && 
		!vips_amiMSBfirst() ) 
		png_set_swap( write->pPng ); 

	if( interlace )	
		nb_passes = png_set_interlace_handling( write->pPng );
	else
		nb_passes = 1;

	/* Write data.
	 */
	for( i = 0; i < nb_passes; i++ ) 
		if( vips_sink_disc( in, write_png_block, write ) )
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
	int compress, int interlace, const char *profile,
	VipsForeignPngFilter filter, gboolean strip,
	gboolean palette, int colours, int Q, double dither )
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
	if( write_vips( write, 
		compress, interlace, profile, filter, strip, palette,
		colours, Q, dither ) ) {
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

static void
user_write_data( png_structp png_ptr, png_bytep data, png_size_t length )
{
	Write *write = (Write *) png_get_io_ptr( png_ptr );

	vips_dbuf_write( &write->dbuf, data, length ); 
}

int
vips__png_write_buf( VipsImage *in, 
	void **obuf, size_t *olen, int compression, int interlace,
	const char *profile, VipsForeignPngFilter filter, gboolean strip,
	gboolean palette, int colours, int Q, double dither )
{
	Write *write;

	if( !(write = write_new( in )) ) 
		return( -1 );

	png_set_write_fn( write->pPng, write, user_write_data, NULL );

	/* Convert it!
	 */
	if( write_vips( write, 
		compression, interlace, profile, filter, strip, palette,
		colours, Q, dither ) ) {
		vips_error( "vips2png", 
			"%s", _( "unable to write to buffer" ) );

		return( -1 );
	}

	*obuf = vips_dbuf_steal( &write->dbuf, olen );

	write_finish( write );

	return( 0 );
}

#endif /*HAVE_PNG*/
