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
 * 	- add animated read
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
 */
#define DEBUG

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

	/* Size of final output image. 
	 */
	int width;
	int height;

	/* Size of each frame.
	 */
	int frame_width;
	int frame_height;

	/* Background colour as an ink we can paint with.
	 */
	guint32 background;

	/* TRUE for RGBA.
	 */
	int alpha;

	/* Number of frames we will decode.
	 */
	int frame_count;

	/* Delay between frames. We don't let this change between frames.
	 */
	int delay;

	/* If we are opening a file object, the fd.
	 */
	int fd;

	/* Parse with this.
	 */
	WebPDemuxer *demux;

	/* Decoder config.
	 */
	WebPDecoderConfig config;

	/* The current accumulated frame as a VipsImage. These are the pixels
	 * we send to the output. It's a frame_width * frame_height memory
	 * image.
	 */
	VipsImage *frame;

	/* Iterate through the frames with this. iter.frame_num is the number
	 * of the current loaded frame.
	 */
	WebPIterator iter;
} Read;

static void
vips_image_paint_pel( VipsImage *image, const VipsRect *r, const VipsPel *ink )
{
	VipsRect valid = { 0, 0, image->Xsize, image->Ysize };
	VipsRect ovl;

	vips_rect_intersectrect( r, &valid, &ovl );
	if( !vips_rect_isempty( &ovl ) ) {
		int ps = VIPS_IMAGE_SIZEOF_PEL( image );
		int ls = VIPS_IMAGE_SIZEOF_LINE( image );
		int ws = ovl.width * ps;

		VipsPel *to, *q;
		int x, y, z;

		/* We plot the first line pointwise, then memcpy() it for the
		 * subsequent lines. We need to work for RGB and RGBA, so we
		 * can't just write uint32s.
		 */
		to = VIPS_IMAGE_ADDR( image, ovl.left, ovl.top );

		q = to;
		for( x = 0; x < ovl.width; x++ ) {
			/* Faster than memcpy() for about ps < 20.
			 */
			for( z = 0; z < ps; z++ )
				q[z] = ink[z];

			q += ps;
		}

		q = to + ls;
		for( y = 1; y < ovl.height; y++ ) {
			memcpy( q, to, ws );
			q += ls;
		}
	}
}

/* Blend two guint8.
 */
#define BLEND( X, aX, Y, aY, scale ) \
	((X * aX + Y * aY) * scale >> 24)

/* Extract R, G, B, A, assuming little-endian.
 */
#define getR( V ) (V & 0xff)
#define getG( V ) ((V >> 8) & 0xff)
#define getB( V ) ((V >> 16) & 0xff)
#define getA( V ) ((V >> 24) & 0xff)

/* Rebuild RGBA, assuming little-endian.
 */
#define setRGBA( R, G, B, A ) (R | (G << 8) | (B << 16) | (A << 24))

/* OVER blend of two unpremultiplied RGBA guint32
 *
 * We assume little-endian (x86), add a byteswap before this if necessary.
 */
static guint32
blend_pixel( guint32 A, guint32 B )
{
	guint8 aA = getA( A );

	if( aA == 0 )
		return( B );

	guint8 aB = getA( B );

	guint8 fac = (aB * (256 - aA)) >> 8;
	guint8 aR =  aA + fac;
	int scale = (1 << 24) / aR;

	guint8 rR = BLEND( getR( A ), aA, getR( B ), fac, scale );
	guint8 gR = BLEND( getG( A ), aA, getG( B ), fac, scale );
	guint8 bR = BLEND( getB( A ), aA, getB( B ), fac, scale );

	return( setRGBA( rR, gR, bR, aR ) ); 
}

static void
vips_image_paint_image( VipsImage *image, 
	VipsImage *ink, int x, int y, gboolean blend )
{
	VipsRect valid = { 0, 0, image->Xsize, image->Ysize };
	VipsRect sub = { x, y, ink->Xsize, ink->Ysize };
	int ps = VIPS_IMAGE_SIZEOF_PEL( image );

	VipsRect ovl;

	g_assert( VIPS_IMAGE_SIZEOF_PEL( ink ) == ps );

	/* Disable blend if we are not RGBA.
	 */
	if( image->Bands != 4 )
		blend = FALSE;

	vips_rect_intersectrect( &valid, &sub, &ovl );
	if( !vips_rect_isempty( &ovl ) ) {
		VipsPel *p, *q;
		int i;

		p = VIPS_IMAGE_ADDR( ink, ovl.left - x, ovl.top - y );
		q = VIPS_IMAGE_ADDR( image, ovl.left, ovl.top ); 

		for( i = 0; i < ovl.height; i++ ) { 
			if( blend ) {
				guint32 *A = (guint32 *) p;
				guint32 *B = (guint32 *) q;

				for( x = 0; x < ovl.width; x++ )
					B[x] = blend_pixel( A[x], B[x] );
			}
			else
				memcpy( (char *) q, (char *) p, 
					ovl.width * ps );

			p += VIPS_IMAGE_SIZEOF_LINE( ink );
			q += VIPS_IMAGE_SIZEOF_LINE( image );
		}
	}
}

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
	WebPDemuxReleaseIterator( &read->iter );
	VIPS_UNREF( read->frame );
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
	read->delay = 100;
	read->fd = 0;
	read->demux = NULL;
	read->frame = NULL;

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
	read->config.output.is_external_memory = 1;

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

/* libwebp supplies things like background as B, G, R, A, but we need RGBA
 * order for libvips.
 */
static guint32
bgra2rgba( guint32 x )
{
	VipsPel pixel[4];

	*((guint32 *) &pixel) = x;
	VIPS_SWAP( VipsPel, pixel[0], pixel[2] );
	x = *((guint32 *) &pixel);
	
	return( x );
}

static int
read_header( Read *read, VipsImage *out )
{
	WebPData data;
	int canvas_width;
	int canvas_height;
	int flags;
	int i;
	VipsRect area;

	data.bytes = read->data;
	data.size = read->length;
	if( !(read->demux = WebPDemux( &data )) ) {
		vips_error( "webp", "%s", _( "unable to parse image" ) ); 
		return( -1 ); 
	}

	canvas_width = WebPDemuxGetI( read->demux, WEBP_FF_CANVAS_WIDTH );
	canvas_height = WebPDemuxGetI( read->demux, WEBP_FF_CANVAS_HEIGHT );
	read->frame_width = canvas_width / read->shrink;
	read->frame_height = canvas_height / read->shrink;

	if( read->shrink > 1 ) { 
		read->config.options.use_scaling = 1;
		read->config.options.scaled_width = read->frame_width;
		read->config.options.scaled_height = read->frame_height; 
	}

	flags = WebPDemuxGetI( read->demux, WEBP_FF_FORMAT_FLAGS );

	/* background is in B, G, R, A byte order, but we need R, G, B, A for
	 * libvips.
	 */
	read->background = bgra2rgba( 
		WebPDemuxGetI( read->demux, WEBP_FF_BACKGROUND_COLOR ) );

	read->alpha = flags & ALPHA_FLAG;
	if( read->alpha )  
		read->config.output.colorspace = MODE_RGBA;
	else
		read->config.output.colorspace = MODE_RGB;

	if( flags & ANIMATION_FLAG ) { 
		int loop_count;
		WebPIterator iter;

		loop_count = WebPDemuxGetI( read->demux, WEBP_FF_LOOP_COUNT );
		read->frame_count = WebPDemuxGetI( read->demux, 
			WEBP_FF_FRAME_COUNT );

#ifdef DEBUG
		printf( "webp2vips: animation\n" );
		printf( "webp2vips: loop_count = %d\n", loop_count );
		printf( "webp2vips: frame_count = %d\n", read->frame_count );
#endif /*DEBUG*/

		vips_image_set_int( out, "gif-loop", loop_count );
		vips_image_set_int( out, "page-height", read->frame_height );

		/* We must get the first frame to get the delay.
		 */
		if( WebPDemuxGetFrame( read->demux, 1, &iter ) ) {
			read->delay = iter.duration;

#ifdef DEBUG
			printf( "webp2vips: duration = %d\n", read->delay );
#endif /*DEBUG*/

			vips_image_set_int( out, "gif-delay", read->delay );
			WebPDemuxReleaseIterator( &iter );
		}

		if( read->n == -1 )
			read->n = read->frame_count - read->page;

		if( read->page < 0 ||
			read->n <= 0 ||
			read->page + read->n > read->frame_count ) {
			vips_error( "webp", 
				"%s", _( "bad page number" ) ); 
			return( -1 ); 
		}

		/* Note that n-pages is the number of pages in the original,
		 * not the number of pages in the image we are writing.
		 */
		vips_image_set_int( out, "n-pages", read->frame_count );

		read->width = read->frame_width;
		read->height = read->n * read->frame_height;
	}
	else {
		read->width = read->frame_width;
		read->height = read->frame_height;
		read->frame_count = 1;
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

	read->frame = vips_image_new_memory();
	vips_image_init_fields( read->frame,
		read->frame_width, read->frame_height,
		read->alpha ? 4 : 3,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );
	vips_image_pipelinev( read->frame, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	if( vips_image_write_prepare( read->frame ) ) 
		return( -1 );

	area.left = 0;
	area.top = 0;
	area.width = read->frame_width;
	area.height = read->frame_height;
	vips_image_paint_pel( read->frame, 
		&area, (VipsPel *) &read->background );

	vips_image_init_fields( out,
		read->width, read->height,
		read->alpha ? 4 : 3,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );
	vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	if( !WebPDemuxGetFrame( read->demux, 1, &read->iter ) ) {
		vips_error( "webp", 
			"%s", _( "unable to loop through frames" ) ); 
		return( -1 );
	}

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

static VipsImage *
read_frame( Read *read, 
	int width, int height, const guint8 *data, size_t length )
{
	VipsImage *frame;

	frame = vips_image_new_memory();
	vips_image_init_fields( frame,
		width, height,
		read->alpha ? 4 : 3,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );
	vips_image_pipelinev( frame, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	if( vips_image_write_prepare( frame ) ) {
		g_object_unref( frame );
		return( NULL );
	}

	read->config.output.u.RGBA.rgba = VIPS_IMAGE_ADDR( frame, 0, 0 );
	read->config.output.u.RGBA.stride = VIPS_IMAGE_SIZEOF_LINE( frame );
	read->config.output.u.RGBA.size = VIPS_IMAGE_SIZEOF_IMAGE( frame );

	if( WebPDecode( data, length, &read->config ) != VP8_STATUS_OK ) {
		g_object_unref( frame );
		vips_error( "webp2vips", "%s", _( "unable to read pixels" ) ); 
		return( NULL );
	}

	return( frame );
}

static int
read_next_frame( Read *read )
{
	VipsImage *frame;

	/* Any dispose action.
	 */

	if( read->iter.dispose_method == WEBP_MUX_DISPOSE_BACKGROUND ) {
		/* We must clear the pixels occupied by this webp frame (not 
		 * the whole of the read frame) to the background colour.
		 */
		VipsRect area = { 
			read->iter.x_offset, 
			read->iter.y_offset,
			read->iter.width, 
			read->iter.height 
		};

		vips_image_paint_pel( read->frame, 
			&area, (VipsPel *) &read->background );
	}

	/* Fetch the next frame.
	 */

	if( !WebPDemuxNextFrame( &read->iter ) ) {
		vips_error( "webp2vips", "%s", _( "not enough frames" ) ); 
		return( -1 );
	}

#ifdef DEBUG
	printf( "webp2vips: frame_num = %d\n", read->iter.frame_num );
	printf( "   x_offset = %d\n", read->iter.x_offset );
	printf( "   y_offset = %d\n", read->iter.y_offset );
	printf( "   width = %d\n", read->iter.width );
	printf( "   height = %d\n", read->iter.height );
	printf( "   duration = %d\n", read->iter.duration );
	printf( "   dispose = " ); 
	if( read->iter.dispose_method == WEBP_MUX_DISPOSE_BACKGROUND )
		printf( "clear to background\n" ); 
	else
		printf( "none\n" ); 
	printf( "   has_alpha = %d\n", read->iter.has_alpha );
	printf( "   blend_method = " ); 
	if( read->iter.blend_method == WEBP_MUX_BLEND )
		printf( "blend with previous\n" ); 
	else
		printf( "don't blend\n" ); 
#endif /*DEBUG*/

	if( read->iter.duration != read->delay ) 
		g_warning( "webp2vips: "
			"not all frames have equal duration" );

	if( !(frame = read_frame( read, 
		read->iter.width, read->iter.height, 
		read->iter.fragment.bytes, read->iter.fragment.size )) ) 
		return( -1 );

	/* Now blend or copy the new pixels into our accumulator.
	 */

	vips_image_paint_image( read->frame, frame, 
		read->iter.x_offset, read->iter.y_offset, 
		read->iter.blend_method == WEBP_MUX_BLEND );

	g_object_unref( frame );

	return( 0 );
}

static int
read_webp_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	Read *read = (Read *) a;

	int frame = r->top / read->frame_height + read->page;
	int line = r->top % read->frame_height;

#ifdef DEBUG_VERBOSE
	printf( "read_webp_generate: line %d\n", r->top );
#endif /*DEBUG_VERBOSE*/

	g_assert( r->height == 1 );

	while( read->iter.frame_num < frame )
		if( read_next_frame( read ) )
			return( -1 );

	memcpy( VIPS_REGION_ADDR( or, 0, r->top ),
		VIPS_IMAGE_ADDR( read->frame, 0, line ),
		VIPS_IMAGE_SIZEOF_LINE( read->frame ) );

	return( 0 );
}

static int
read_image( Read *read, VipsImage *out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

	t[0] = vips_image_new();
	if( read_header( read, t[0] ) )
		return( -1 );

	if( vips_image_generate( t[0], 
		NULL, read_webp_generate, NULL, read, NULL ) ||
		vips_sequential( t[0], &t[1], NULL ) ||
		vips_image_write( t[1], out ) )
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
