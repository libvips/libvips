/* read with libwebp
 *
 * 6/8/13
 * 	- from png2vips.c
 * 24/2/14
 * 	- oops, buffer path was broken, thanks Lovell
 * 28/2/16
 * 	- add @shrink
 * 7/11/16
 * 	- support XMP/ICC/EXIF metadata
 * 18/10/17
 * 	- sniff file type from magic number
 * 2/11/18
 * 	- rework for demux API
 * 	- add animation read
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

#include <stdlib.h>
#include <string.h>

#include <webp/decode.h>
#include <webp/demux.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

/* What we track during a read.
 */
typedef struct {
	/* File source.
	 */
	char *filename;

	/* Memory source. We use gint64 rather than size_t since we use
	 * vips_file_length() and vips__mmap() for file sources.
	 */
	const void *data;
	gint64 length;


	/* Load this page (frame number).
	 */
	int page;

	/* Load this many pages.
	 */
	int n;

	/* Shrink-on-load factor. Use this to set scaled_width.
	 */
	int shrink;

	/* Size we are decoding to.
	 */
	int width;
	int height;

	/* If we are opening a file object, the fd.
	 */
	int fd;

	/* Parse with this.
	 */
	WebPDemuxer *demux;

	/* Decoder config.
	 */
	WebPDecoderConfig config;

	/* Incremental decoder state.
	 */
	WebPIDecoder *idec;
} Read;

int
vips__iswebp_buffer( const void *buf, size_t len )
{
	/* WebP is "RIFF xxxx WEBP" at the start, so we need 12 bytes.
	 */
	if( len >= 12 &&
		vips_isprefix( "RIFF", (char *) buf ) &&
		vips_isprefix( "WEBP", (char *) buf + 8 ) )
		return( 1 );

	return( 0 );
}

int
vips__iswebp( const char *filename )
{
	/* Magic number, see above.
	 */
	unsigned char header[12];

	if( vips__get_bytes( filename, header, 12 ) == 12 &&
		vips__iswebp_buffer( header, 12 ) )
		return( 1 );

	return( 0 );
}

static int
read_free( Read *read )
{
	VIPS_FREEF( WebPIDelete, read->idec );
	VIPS_FREEF( WebPDemuxDelete, read->demux );
	WebPFreeDecBuffer( &read->config.output );

	if( read->fd > 0 &&
		read->data &&
		read->length > 0 ) { 
		vips__munmap( read->data, read->length ); 
		read->data = NULL;
		read->length = 0;
	}

	VIPS_FREEF( vips_tracked_close, read->fd ); 
	VIPS_FREE( read->filename );
	VIPS_FREE( read );

	return( 0 );
}

static Read *
read_new( const char *filename, const void *data, size_t length, 
	int page, int n, int shrink )
{
	Read *read;

	if( !(read = VIPS_NEW( NULL, Read )) )
		return( NULL );

	read->filename = g_strdup( filename );
	read->data = data;
	read->length = length;
	read->page = page;
	read->n = n;
	read->shrink = shrink;
	read->fd = 0;
	read->idec = NULL;
	read->demux = NULL;

	if( read->filename ) { 
		/* libwebp makes streaming from a file source very hard. We 
		 * have to read to a full memory buffer, then copy to out.
		 *
		 * mmap the input file, it's slightly quicker.
		 */
		if( (read->fd = vips__open_image_read( read->filename )) < 0 ||
			(read->length = vips_file_length( read->fd )) < 0 ||
			!(read->data = vips__mmap( read->fd, 
				FALSE, read->length, 0 )) ) {
			read_free( read );
			return( NULL );
		}
	}

	WebPInitDecoderConfig( &read->config );
	read->config.options.use_threads = 1;

	return( read );
}

/* Map vips metadata names to webp names.
 */
const VipsWebPNames vips__webp_names[] = {
	{ VIPS_META_ICC_NAME, "ICCP", ICCP_FLAG },
	{ VIPS_META_EXIF_NAME, "EXIF", EXIF_FLAG },
	{ VIPS_META_XMP_NAME, "XMP ", XMP_FLAG }
};
const int vips__n_webp_names = VIPS_NUMBER( vips__webp_names ); 

static int
read_header( Read *read, VipsImage *out )
{
	WebPData data;
	int canvas_width;
	int canvas_height;
	int flags;
	int frame_count;
	WebPIterator iter;
	int i;

	data.bytes = read->data;
	data.size = read->length;
	if( !(read->demux = WebPDemux( &data )) ) {
		vips_error( "webp", "%s", _( "unable to parse image" ) ); 
		return( -1 ); 
	}

	canvas_width = WebPDemuxGetI( read->demux, WEBP_FF_CANVAS_WIDTH );
	canvas_height = WebPDemuxGetI( read->demux, WEBP_FF_CANVAS_HEIGHT );
	read->width = canvas_width / read->shrink;
	read->height = canvas_height / read->shrink;

	if( read->shrink > 1 ) { 
		read->config.options.use_scaling = 1;
		read->config.options.scaled_width = read->width;
		read->config.options.scaled_height = read->height; 
	}

	flags = WebPDemuxGetI( read->demux, WEBP_FF_FORMAT_FLAGS );

	if( flags & ALPHA_FLAG )  
		read->config.output.colorspace = MODE_RGBA;
	else
		read->config.output.colorspace = MODE_RGB;

	if( flags & ANIMATION_FLAG ) { 
		int loop_count;

		loop_count = WebPDemuxGetI( read->demux, WEBP_FF_LOOP_COUNT );
		frame_count = WebPDemuxGetI( read->demux, WEBP_FF_FRAME_COUNT );

		printf( "webp2vips: animation\n" );
		printf( "webp2vips: loop_count = %d\n", loop_count );
		printf( "webp2vips: frame_count = %d\n", frame_count );

		vips_image_set_int( out, "gif-loop", loop_count );
		vips_image_set_int( out, "page-height", read->height );
		read->height *= frame_count;

		/* We must get the first frame to get the delay.
		 */
		if( WebPDemuxGetFrame( read->demux, 1, &iter ) ) {
			printf( "webp2vips: duration = %d\n", iter.duration );

			vips_image_set_int( out, "gif-delay", iter.duration );
			WebPDemuxReleaseIterator( &iter );
		}
	}

	if( read->width <= 0 ||
		read->height <= 0 ) {
		vips_error( "webp", "%s", _( "bad image dimensions" ) ); 
		return( -1 ); 
	}

	for( i = 0; i < vips__n_webp_names; i++ ) { 
		const char *vips = vips__webp_names[i].vips;
		const char *webp = vips__webp_names[i].webp;

		if( flags & vips__webp_names[i].flags ) {
			WebPChunkIterator iter;
			void *blob;

			WebPDemuxGetChunk( read->demux, webp, 1, &iter );

			if( !(blob = vips_malloc( NULL, iter.chunk.size )) ) {
				WebPDemuxReleaseChunkIterator( &iter );
				return( -1 ); 
			}
			memcpy( blob, iter.chunk.bytes, iter.chunk.size );
			vips_image_set_blob( out, vips, 
				(VipsCallbackFn) vips_free, 
				blob, iter.chunk.size );

			WebPDemuxReleaseChunkIterator( &iter );
		}
	}

	vips_image_init_fields( out,
		read->width, read->height,
		(flags & ALPHA_FLAG) ? 4 : 3,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );

	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	return( 0 );
}

int
vips__webp_read_file_header( const char *filename, VipsImage *out, 
	int page, int n, int shrink )
{
	Read *read;

	if( !(read = read_new( filename, NULL, 0, page, n, shrink )) ) {
		vips_error( "webp2vips",
			_( "unable to open \"%s\"" ), filename ); 
		return( -1 );
	}

	if( read_header( read, out ) ) {
		read_free( read );
		return( -1 );
	}

	read_free( read );

	return( 0 );
}

static int
read_image( Read *read, VipsImage *out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

	t[0] = vips_image_new_memory();
	if( read_header( read, t[0] ) )
		return( -1 );
	if( vips_image_write_prepare( t[0] ) ) 
		return( -1 );

	read->config.output.u.RGBA.rgba = VIPS_IMAGE_ADDR( t[0], 0, 0 );
	read->config.output.u.RGBA.stride = VIPS_IMAGE_SIZEOF_LINE( t[0] );
	read->config.output.u.RGBA.size = VIPS_IMAGE_SIZEOF_IMAGE( t[0] );
	read->config.output.is_external_memory = 1;

	if( WebPDecode( (uint8_t *) read->data, read->length, 
		&read->config) != VP8_STATUS_OK ) {
		vips_error( "webp2vips", "%s", _( "unable to read pixels" ) ); 
		return( -1 );
	}

	if( vips_image_write( t[0], out ) )
		return( -1 );

	return( 0 );
}

int
vips__webp_read_file( const char *filename, VipsImage *out, 
	int page, int n, int shrink )
{
	Read *read;

	if( !(read = read_new( filename, NULL, 0, page, n, shrink )) ) {
		vips_error( "webp2vips",
			_( "unable to open \"%s\"" ), filename ); 
		return( -1 );
	}

	if( read_image( read, out ) )
		return( -1 );

	read_free( read );

	return( 0 );
}

int
vips__webp_read_buffer_header( const void *buf, size_t len, VipsImage *out,
	int page, int n, int shrink )
{
	Read *read;

	if( !(read = read_new( NULL, buf, len, page, n, shrink )) ) {
		vips_error( "webp2vips",
			"%s", _( "unable to open buffer" ) ); 
		return( -1 );
	}

	if( read_header( read, out ) ) {
		read_free( read );
		return( -1 );
	}

	read_free( read );

	return( 0 );
}

int
vips__webp_read_buffer( const void *buf, size_t len, VipsImage *out, 
	int page, int n, int shrink )
{
	Read *read;

	if( !(read = read_new( NULL, buf, len, page, n, shrink )) ) {
		vips_error( "webp2vips",
			"%s", _( "unable to open buffer" ) ); 
		return( -1 );
	}

	if( read_image( read, out ) )
		return( -1 );

	read_free( read );

	return( 0 );
}

#endif /*HAVE_LIBWEBP*/
