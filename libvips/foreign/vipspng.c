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
 * 20/4/19
 * 	- allow huge xmp metadata
 * 7/10/19
 * 	- restart after minimise
 * 14/10/19
 * 	- revise for connection IO
 * 11/5/20
 * 	- only warn for saving bad profiles, don't fail
 * 19/2/21 781545872
 * 	- read out background, if we can
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

#ifndef HAVE_SPNG

#define INPUT_BUFFER_SIZE (4096)

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

	VipsSource *source;

	/* read() to this buffer, copy to png as required. libpng does many
	 * very small reads and we want to avoid a syscall for each one.
	 */
	unsigned char input_buffer[INPUT_BUFFER_SIZE];
	unsigned char *next_byte;
	gint64 bytes_in_buffer;

} Read;

/* Can be called many times.
 */
static void
read_destroy( Read *read )
{
	/* We never call png_read_end(), perhaps we should. It can fail on
	 * truncated files, so we'd need a setjmp().
	 */

	if( read->pPng )
		png_destroy_read_struct( &read->pPng, &read->pInfo, NULL );
	VIPS_UNREF( read->source );
	VIPS_FREE( read->row_pointer );
}

static void
read_close_cb( VipsImage *out, Read *read )
{
	read_destroy( read ); 
}

static void
read_minimise_cb( VipsImage *image, Read *read )
{
	if( read->source )
		vips_source_minimise( read->source );
}

static void
vips_png_read_source( png_structp pPng, png_bytep data, png_size_t length )
{
	Read *read = png_get_io_ptr( pPng ); 

#ifdef DEBUG
	printf( "vips_png_read_source: read %zd bytes\n", length ); 
#endif /*DEBUG*/

	/* libpng makes many small reads, which hurts performance if you do a
	 * syscall for each one. Read via our own buffer.
	 */
	while( length > 0 ) {
		gint64 bytes_available;

		if( read->bytes_in_buffer <= 0 ) {
			gint64 bytes_read;

			bytes_read = vips_source_read( read->source, 
				read->input_buffer, INPUT_BUFFER_SIZE );
			if( bytes_read <= 0 )
				png_error( pPng, "not enough data" );

			read->next_byte = read->input_buffer;
			read->bytes_in_buffer = bytes_read;
		}

		bytes_available = VIPS_MIN( read->bytes_in_buffer, length );
		memcpy( data, read->next_byte, bytes_available );
		data += bytes_available;
		length -= bytes_available;
		read->next_byte += bytes_available;
		read->bytes_in_buffer -= bytes_available;
	}
}

static Read *
read_new( VipsSource *source, VipsImage *out, gboolean fail )
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
	read->source = source;
	g_object_ref( source );

	g_signal_connect( out, "close", 
		G_CALLBACK( read_close_cb ), read ); 
	g_signal_connect( out, "minimise",
		G_CALLBACK( read_minimise_cb ), read ); 

	if( !(read->pPng = png_create_read_struct( 
		PNG_LIBPNG_VER_STRING, NULL,
		user_error_function, user_warning_function )) ) 
		return( NULL );

	/* Prevent libpng (>=1.6.11) verifying sRGB profiles. Many PNGs have
	 * broken profiles, but we still want to be able to open them.
	 */
#ifdef PNG_SKIP_sRGB_CHECK_PROFILE
	png_set_option( read->pPng, 
		PNG_SKIP_sRGB_CHECK_PROFILE, PNG_OPTION_ON );
#endif /*PNG_SKIP_sRGB_CHECK_PROFILE*/

	/* Disable CRC checking in fuzzing mode. Most fuzzed images will have
	 * bad CRCs so this check would break fuzzing.
	 */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	png_set_crc_action( read->pPng,
		PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE );
#endif /*FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION*/

	if( vips_source_rewind( source ) ) 
		return( NULL );
	png_set_read_fn( read->pPng, read, vips_png_read_source ); 

	/* Catch PNG errors from png_read_info() etc.
	 */
	if( setjmp( png_jmpbuf( read->pPng ) ) ) 
		return( NULL );

	if( !(read->pInfo = png_create_info_struct( read->pPng )) ) 
		return( NULL );

	/* By default, libpng refuses to open files with a metadata chunk 
	 * larger than 8mb. We've seen real files with 20mb, so set 50mb.
	 */
#ifdef HAVE_PNG_SET_CHUNK_MALLOC_MAX
	png_set_chunk_malloc_max( read->pPng, 50 * 1024 * 1024 );
#endif /*HAVE_PNG_SET_CHUNK_MALLOC_MAX*/

	png_read_info( read->pPng, read->pInfo );

	return( read );
}

/* Set the png text data as metadata on the vips image. These are always
 * null-terminated strings.
 */
static int
vips__set_text( VipsImage *out, int i, const char *key, const char *text ) 
{
	char name[256];

	if( strcmp( key, "XML:com.adobe.xmp" ) == 0 ) {
		/* Save as an XMP tag. This must be a BLOB, for compatibility
		 * for things like the XMP blob that the tiff loader adds.
		 *
		 * Note that this will remove the null-termination from the
		 * string. We must carefully reattach this.
		 */
		vips_image_set_blob_copy( out, 
			VIPS_META_XMP_NAME, text, strlen( text ) );
	}
	else  {
		/* Save as a string comment. Some PNGs have EXIF data as
		 * text segments, but the correct way to support this is with
		 * png_get_eXIf_1().
		 */
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
	int bitdepth, color_type;
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
		&width, &height, &bitdepth, &color_type,
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

	if( bitdepth > 8 ) {
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
		bitdepth < 8 ) 
		png_set_expand_gray_1_2_4_to_8( read->pPng );

	/* If we're an INTEL byte order machine and this is 16bits, we need
	 * to swap bytes.
	 */
	if( bitdepth > 8 && 
		!vips_amiMSBfirst() )
		png_set_swap( read->pPng );

	/* Get resolution. Default to 72 pixels per inch, the usual png value. 
	 */
	unit_type = PNG_RESOLUTION_METER;
	res_x = 72.0 / 2.54 * 100.0;
	res_y = 72.0 / 2.54 * 100.0;
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
		bitdepth > 8 ? VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, interpretation, 
		Xres, Yres );

	VIPS_SETSTR( out->filename, 
		vips_connection_filename( VIPS_CONNECTION( read->source ) ) );

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
#ifdef DEBUG
		printf( "png2vips_header: attaching %d bytes of ICC profile\n",
			proflen );
		printf( "png2vips_header: name = \"%s\"\n", name );
#endif /*DEBUG*/

		vips_image_set_blob_copy( out, 
			VIPS_META_ICC_NAME, profile, proflen );
	}

	/* Some libpng warn you to call png_set_interlace_handling(); here, but
	 * that can actually break interlace on older libpngs.
	 *
	 * Only set this for libpng 1.6+.
	 */
#if PNG_LIBPNG_VER > 10600
	(void) png_set_interlace_handling( read->pPng );
#endif

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

	/* Attach original palette bit depth, if any, as metadata.
	 */
	if( color_type == PNG_COLOR_TYPE_PALETTE )
		vips_image_set_int( out, "palette-bit-depth", bitdepth );

	/* Note the PNG background colour, if any.
	 */
#ifdef PNG_bKGD_SUPPORTED
{
	png_color_16 *background;

	if( png_get_bKGD( read->pPng, read->pInfo, &background ) ) {
		const int scale = out->BandFmt == VIPS_FORMAT_UCHAR ? 1 : 256;

		double array[3];
		int n;

		switch( color_type ) {
		case PNG_COLOR_TYPE_GRAY:
		case PNG_COLOR_TYPE_GRAY_ALPHA:
			array[0] = background->gray / scale;
			n = 1;
			break;

		case PNG_COLOR_TYPE_RGB:
		case PNG_COLOR_TYPE_RGB_ALPHA:
			array[0] = background->red / scale;
			array[1] = background->green / scale;
			array[2] = background->blue / scale;
			n = 3;
			break;

		case PNG_COLOR_TYPE_PALETTE:
		default:
			/* Not sure what to do here. I suppose we should read
			 * the palette.
			 */
			n = 0;
			break;
		}

		if( n > 0 )
			vips_image_set_array_double( out, "background", 
				array, n );
	}
}
#endif

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
	g_assert( r->height == VIPS_MIN( VIPS__FATSTRIP_HEIGHT, 
		or->im->Ysize - r->top ) ); 

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

	return( 0 );
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
				"tile_height", VIPS__FATSTRIP_HEIGHT, 
				NULL ) ||
			vips_image_write( t[1], out ) )
			return( -1 );
	}

	return( 0 );
}

gboolean
vips__png_ispng_source( VipsSource *source )
{
	const unsigned char *p;

	if( (p = vips_source_sniff( source, 8 )) &&
		!png_sig_cmp( (png_bytep) p, 0, 8 ) )
		return( TRUE ); 

	return( FALSE ); 
}

int
vips__png_header_source( VipsSource *source, VipsImage *out )
{
	Read *read;

	if( !(read = read_new( source, out, TRUE )) ||
		png2vips_header( read, out ) ) {
		vips_error( "png2vips", _( "unable to read source %s" ),
			vips_connection_nick( VIPS_CONNECTION( source ) ) );
		return( -1 );
	}

	vips_source_minimise( source );

	return( 0 );
}

int
vips__png_read_source( VipsSource *source, VipsImage *out, gboolean fail )
{
	Read *read;

	if( !(read = read_new( source, out, fail )) ||
		png2vips_image( read, out ) ||
		vips_source_decode( source ) ) {
		vips_error( "png2vips", _( "unable to read source %s" ),
			vips_connection_nick( VIPS_CONNECTION( source ) ) );
		return( -1 );
	}

	return( 0 );
}

/* Interlaced PNGs need to be entirely decompressed into memory then can be
 * served partially from there. Non-interlaced PNGs may be read sequentially.
 */
gboolean
vips__png_isinterlaced_source( VipsSource *source )
{
	VipsImage *image;
	Read *read;
	int interlace_type;

	image = vips_image_new();

	if( !(read = read_new( source, image, TRUE )) ) { 
		g_object_unref( image );
		return( -1 );
	}
	interlace_type = png_get_interlace_type( read->pPng, read->pInfo );
	g_object_unref( image );

	return( interlace_type != PNG_INTERLACE_NONE );
}

#endif /*!defined(HAVE_SPNG)*/

const char *vips__png_suffs[] = { ".png", NULL };

/* What we track during a PNG write.
 */
typedef struct {
	VipsImage *in;
	VipsImage *memory;

	VipsTarget *target;

	png_structp pPng;
	png_infop pInfo;
	png_bytep *row_pointer;
} Write;

static void
write_destroy( Write *write )
{
#ifdef DEBUG
	printf( "write_destroy: %p\n", write ); 
#endif /*DEBUG*/

	VIPS_UNREF( write->memory );
	if( write->target ) 
		vips_target_finish( write->target );
	if( write->pPng )
		png_destroy_write_struct( &write->pPng, &write->pInfo );
	VIPS_FREE( write->row_pointer );
	VIPS_FREE( write );
}

static void
user_write_data( png_structp pPng, png_bytep data, png_size_t length )
{
	Write *write = (Write *) png_get_io_ptr( pPng );

	if( vips_target_write( write->target, data, length ) ) 
		png_error( pPng, "not enough data" );
}

static Write *
write_new( VipsImage *in, VipsTarget *target )
{
	Write *write;

	if( !(write = VIPS_NEW( NULL, Write )) )
		return( NULL );
	write->in = in;
	write->target = target;

#ifdef DEBUG
	printf( "write_new: %p\n", write ); 
#endif /*DEBUG*/

	if( !(write->row_pointer = VIPS_ARRAY( NULL, in->Ysize, png_bytep )) )
		return( NULL );
	if( !(write->pPng = png_create_write_struct( 
		PNG_LIBPNG_VER_STRING, NULL,
		user_error_function, user_warning_function )) ) {
		write_destroy( write );
		return( NULL );
	}

	/* Prevent libpng (>=1.6.11) verifying sRGB profiles. We are often
	 * asked to copy images containing bad profiles, and this check would
	 * prevent that.
	 */
#ifdef PNG_SKIP_sRGB_CHECK_PROFILE
	png_set_option( write->pPng, 
		PNG_SKIP_sRGB_CHECK_PROFILE, PNG_OPTION_ON );
#endif /*PNG_SKIP_sRGB_CHECK_PROFILE*/

	png_set_write_fn( write->pPng, write, user_write_data, NULL );

	/* Catch PNG errors from png_create_info_struct().
	 */
	if( setjmp( png_jmpbuf( write->pPng ) ) ) {
		write_destroy( write );
		return( NULL );
	}

	if( !(write->pInfo = png_create_info_struct( write->pPng )) ) {
		write_destroy( write );
		return( NULL );
	}

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

	/* Catch PNG errors. 
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
		char key[256];

		if( vips_image_get_string( write->in, field, &str ) )
			return( image );

		if( strlen( field ) > 256 ||
			sscanf( field, "png-comment-%d-%80s", &i, key ) != 2 ) {
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
	gboolean palette, int Q, double dither,
	int bitdepth )
{
	VipsImage *in = write->in;

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
	if( palette ) 
		color_type = PNG_COLOR_TYPE_PALETTE;
#else
	if( palette )
		g_warning( "%s",
			_( "ignoring palette (no quantisation support)" ) );
#endif /*HAVE_IMAGEQUANT*/

	interlace_type = interlace ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE;

	png_set_IHDR( write->pPng, write->pInfo, 
		in->Xsize, in->Ysize, bitdepth, color_type, interlace_type, 
		PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT );

	/* Set resolution. libpng uses pixels per meter.
	 */
	png_set_pHYs( write->pPng, write->pInfo, 
		VIPS_RINT( in->Xres * 1000 ), VIPS_RINT( in->Yres * 1000 ), 
		PNG_RESOLUTION_METER );

	/* Metadata
	 */
	if( !strip ) {
		if( profile ) {
			VipsBlob *blob;

			if( vips_profile_load( profile, &blob, NULL ) )
				return( -1 );
			if( blob ) {
				size_t length;
				const void *data 
					= vips_blob_get( blob, &length );

#ifdef DEBUG
				printf( "write_vips: attaching %zd bytes "
					"of ICC profile\n", length );
#endif /*DEBUG*/

				png_set_iCCP( write->pPng, write->pInfo, 
					"icc", PNG_COMPRESSION_TYPE_BASE, 
					(void *) data, length );

				vips_area_unref( (VipsArea *) blob );
			}
		}
		else if( vips_image_get_typeof( in, VIPS_META_ICC_NAME ) ) {
			const void *data;
			size_t length;

			if( vips_image_get_blob( in, VIPS_META_ICC_NAME,
				&data, &length ) )
				return( -1 );

#ifdef DEBUG
			printf( "write_vips: attaching %zd bytes "
				"of ICC profile\n", length );
#endif /*DEBUG*/

			/* We need to ignore any errors from png_set_iCCP()
			 * since we want to drop incompatible profiles rather
			 * than simply failing.
			 */
			if( setjmp( png_jmpbuf( write->pPng ) ) ) {
				/* Silent ignore of error.
				 */
				g_warning( "bad ICC profile not saved" );
			}
			else {
				/* This will jump back to the line above on
				 * error.
				 */
				png_set_iCCP( write->pPng, write->pInfo, "icc",
					PNG_COMPRESSION_TYPE_BASE, 
					(void *) data, length );
			}

			/* And restore the setjmp.
			 */
			if( setjmp( png_jmpbuf( write->pPng ) ) ) 
				return( -1 );
		}

		if( vips_image_get_typeof( in, VIPS_META_XMP_NAME ) ) {
			const void *data;
			size_t length;
			char *str;

			/* XMP is attached as a BLOB with no null-termination. 
			 * We must re-add this.
			 */
			if( vips_image_get_blob( in,
				VIPS_META_XMP_NAME, &data, &length ) )
				return( -1 );

			str = g_malloc( length + 1 );
			vips_strncpy( str, data, length + 1 );
			vips__png_set_text( write->pPng, write->pInfo,
				"XML:com.adobe.xmp", str );
			g_free( str );
		}

		if( vips_image_map( in,
			write_png_comment, write ) )
			return( -1 );
	}

#ifdef HAVE_IMAGEQUANT
	if( palette ) {
		VipsImage *im_index;
		VipsImage *im_palette;
		int palette_count;
		png_color *png_palette;
		png_byte *png_trans;
		int trans_count;

		if( vips__quantise_image( in, &im_index, &im_palette, 
			1 << bitdepth, Q, dither ) ) 
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
	if( bitdepth > 8 && 
		!vips_amiMSBfirst() ) 
		png_set_swap( write->pPng ); 

	/* If bitdepth is 1/2/4, pack pixels into bytes.
	 */
	png_set_packing( write->pPng );

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
vips__png_write_target( VipsImage *in, VipsTarget *target,
	int compression, int interlace,
	const char *profile, VipsForeignPngFilter filter, gboolean strip,
	gboolean palette, int Q, double dither,
	int bitdepth )
{
	Write *write;

	if( !(write = write_new( in, target )) ) 
		return( -1 );

	if( write_vips( write, 
		compression, interlace, profile, filter, strip, palette,
		Q, dither, bitdepth ) ) {
		write_destroy( write );
		vips_error( "vips2png", _( "unable to write to target %s" ),
			vips_connection_nick( VIPS_CONNECTION( target ) ) );
		return( -1 );
	}

	write_destroy( write );

	return( 0 );
}

#endif /*HAVE_PNG*/
