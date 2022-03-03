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
 * 19/4/19
 * 	- could memleak on some read errors
 * 24/4/19
 * 	- fix bg handling in animations
 * 30/4/19
 * 	- deprecate shrink, use scale instead, and make it a double ... this
 * 	  lets us do faster and more accurate thumbnailing
 * 27/6/19
 * 	- disable alpha output if all frame fill the canvas and are solid
 * 6/7/19 [deftomat]
 * 	- support array of delays 
 * 14/10/19
 * 	- revise for source IO
 * 27/10/21
 * 	- disable shrink-on-load if we need subpixel accuracy in animations
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
#include <glib/gi18n-lib.h>

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
	VipsImage *out;
	VipsSource *source;

	/* The data we load, as a webp object.
	 */
	WebPData data;

	/* Load this page (frame number).
	 */
	int page;

	/* Load this many pages.
	 */
	int n;

	/* Scale-on-load factor. Use this to set frame_width.
	 */
	double scale;

	/* Size of each frame in input image coordinates.
	 */
	int canvas_width;
	int canvas_height;

	/* Size of each frame, in scaled output image coordinates,
	 */
	int frame_width;
	int frame_height;

	/* Size of final output image. 
	 */
	int width;
	int height;

	/* TRUE if we will save the final image as RGBA.
	 */
	int alpha;

	/* Number of frames in file.
	 */
	int frame_count;

	/* Delays between frames (in miliseconds).
	 */
	int *delays;

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

	/* The frame number currently in @frame. Numbered from 1, so 0 means
	 * before the first frame.
	 */
	int frame_no;

	/* Iterate through the frames with this. iter.frame_num is the number
	 * of the currently loaded frame.
	 */
	WebPIterator iter;

	/* How to junk the current frame when we move on.
	 */
	WebPMuxAnimDispose dispose_method;
	VipsRect dispose_rect;
} Read;

const char *
vips__error_webp( VP8StatusCode code )
{
	switch( code ) {
	case VP8_STATUS_OK: 
		return( "VP8_STATUS_OK" );

	case VP8_STATUS_OUT_OF_MEMORY:
		return( "VP8_STATUS_OUT_OF_MEMORY" );

	case VP8_STATUS_INVALID_PARAM:
		return( "VP8_STATUS_INVALID_PARAM" );

	case VP8_STATUS_BITSTREAM_ERROR:
		return( "VP8_STATUS_BITSTREAM_ERROR" );

	case VP8_STATUS_UNSUPPORTED_FEATURE:
		return( "VP8_STATUS_UNSUPPORTED_FEATURE" );

	case VP8_STATUS_SUSPENDED:
		return( "VP8_STATUS_SUSPENDED" );

	case VP8_STATUS_USER_ABORT:
		return( "VP8_STATUS_USER_ABORT" );

	case VP8_STATUS_NOT_ENOUGH_DATA:
		return( "VP8_STATUS_NOT_ENOUGH_DATA" );

	default:
		return( "<unkown>" );
	}
}

static void
vips_image_paint_area( VipsImage *image, const VipsRect *r, const VipsPel *ink )
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
	(((X * aX + Y * aY) * scale + (1 << 12)) >> 24)

/* Extract R, G, B, A, assuming little-endian.
 */
#define getR( V ) (V & 0xff)
#define getG( V ) ((V >> 8) & 0xff)
#define getB( V ) ((V >> 16) & 0xff)
#define getA( V ) ((V >> 24) & 0xff)

/* Rebuild RGBA, assuming little-endian.
 */
#define setRGBA( R, G, B, A ) \
	(R | (G << 8) | (B << 16) | ((guint32) A << 24))

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

	guint8 fac = (aB * (255 - aA) + 127) >> 8;
	guint8 aR =  aA + fac;
	int scale = aR == 0 ? 0 : (1 << 24) / aR;

	guint8 rR = BLEND( getR( A ), aA, getR( B ), fac, scale );
	guint8 gR = BLEND( getG( A ), aA, getG( B ), fac, scale );
	guint8 bR = BLEND( getB( A ), aA, getB( B ), fac, scale );

	return( setRGBA( rR, gR, bR, aR ) ); 
}

/* Blend sub into frame at left, top.
 */
static void
vips_image_paint_image( VipsImage *frame, 
	VipsImage *sub, int left, int top, gboolean blend )
{
	VipsRect frame_rect = { 0, 0, frame->Xsize, frame->Ysize };
	VipsRect sub_rect = { left, top, sub->Xsize, sub->Ysize };
	int ps = VIPS_IMAGE_SIZEOF_PEL( frame );

	VipsRect ovl;

	g_assert( VIPS_IMAGE_SIZEOF_PEL( sub ) == ps );

	vips_rect_intersectrect( &frame_rect, &sub_rect, &ovl );
	if( !vips_rect_isempty( &ovl ) ) {
		VipsPel *p, *q;
		int x, y;

		p = VIPS_IMAGE_ADDR( sub, ovl.left - left, ovl.top - top );
		q = VIPS_IMAGE_ADDR( frame, ovl.left, ovl.top ); 

		for( y = 0; y < ovl.height; y++ ) { 
			if( blend ) {
				guint32 *A = (guint32 *) p;
				guint32 *B = (guint32 *) q;

				for( x = 0; x < ovl.width; x++ )
					B[x] = blend_pixel( A[x], B[x] );
			}
			else
				memcpy( (char *) q, (char *) p, 
					ovl.width * ps );

			p += VIPS_IMAGE_SIZEOF_LINE( sub );
			q += VIPS_IMAGE_SIZEOF_LINE( frame );
		}
	}
}

int
vips__iswebp_source( VipsSource *source )
{
	const unsigned char *p;

	/* WebP is "RIFF xxxx WEBP" at the start, so we need 12 bytes.
	 */
	if( (p = vips_source_sniff( source, 12 )) &&
		vips_isprefix( "RIFF", (char *) p ) &&
		vips_isprefix( "WEBP", (char *) p + 8 ) )
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

	VIPS_UNREF( read->source );
	VIPS_FREE( read->delays );
	VIPS_FREE( read );

	return( 0 );
}

static void
read_close_cb( VipsImage *image, Read *read )
{
	read_free( read );
}

static Read *
read_new( VipsImage *out, VipsSource *source, int page, int n, double scale )
{
	Read *read;

	if( !(read = VIPS_NEW( NULL, Read )) )
		return( NULL );

	read->out = out;
	read->source = source;
	g_object_ref( source );
	read->page = page;
	read->n = n;
	read->scale = scale;
	read->delays = NULL;
	read->demux = NULL;
	read->frame = NULL;
	read->dispose_method = WEBP_MUX_DISPOSE_NONE;
	read->frame_no = 0;

	/* Everything has to stay open until read has finished, unfortunately,
	 * since webp relies on us mapping the whole file.
	 */
	g_signal_connect( out, "close", 
		G_CALLBACK( read_close_cb ), read ); 

	WebPInitDecoderConfig( &read->config );
	read->config.options.use_threads = 1;
	read->config.output.is_external_memory = 1;

	if( !(read->data.bytes = 
		vips_source_map( source, &read->data.size )) ) 
		return( NULL );

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
	int flags;
	int i;

	if( !(read->demux = WebPDemux( &read->data )) ) {
		vips_error( "webp", "%s", _( "unable to parse image" ) ); 
		return( -1 ); 
	}

	flags = WebPDemuxGetI( read->demux, WEBP_FF_FORMAT_FLAGS );

	read->alpha = flags & ALPHA_FLAG;

	/* We do everything as RGBA and then, if we can, drop the alpha on
	 * save.
	 */
	read->config.output.colorspace = MODE_RGBA;

	read->canvas_width = 
		WebPDemuxGetI( read->demux, WEBP_FF_CANVAS_WIDTH );
	read->canvas_height = 
		WebPDemuxGetI( read->demux, WEBP_FF_CANVAS_HEIGHT );

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

		vips_image_set_int( out, "loop", loop_count );

		/* DEPRECATED "gif-loop"
		 *
		 * Not the correct behavior as loop=1 became gif-loop=0
		 * but we want to keep the old behavior untouched!
		 */
		vips_image_set_int( out, "gif-loop", 
			loop_count == 0 ? 0 : loop_count - 1 );

		if( WebPDemuxGetFrame( read->demux, 1, &iter ) ) {
			int i;

			read->delays = (int *) 
				g_malloc0( read->frame_count * sizeof( int ) );
			for( i = 0; i < read->frame_count; i++ ) 
				read->delays[i] = 40;

			do {
				g_assert( iter.frame_num >= 1 &&
					iter.frame_num <= read->frame_count );

				read->delays[iter.frame_num - 1] = 
					iter.duration;

				/* We need the alpha in an animation if:
				 *   - any frame has transparent pixels 
				 *   - any frame doesn't fill the whole canvas.
				 */
				if( iter.has_alpha ||
					iter.width != read->canvas_width ||
					iter.height != read->canvas_height ) 
					read->alpha = TRUE;

				/* We must disable shrink-on-load if any frame
				 * does not fill the whole canvas. We won't be
				 * able to shrink-on-load it to the exact
				 * position in a downsized canvas.
				 */
				if( iter.width != read->canvas_width ||
					iter.height != read->canvas_height ) 
					read->scale = 1.0;
			} while( WebPDemuxNextFrame( &iter ) );

			vips_image_set_array_int( out, 
				"delay", read->delays, read->frame_count );

			/* webp uses ms for delays, gif uses centiseconds.
			 */
			vips_image_set_int( out, "gif-delay", 
				VIPS_RINT( read->delays[0] / 10.0 ) );
		}

		WebPDemuxReleaseIterator( &iter );

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
		vips_image_set_int( out, VIPS_META_N_PAGES, read->frame_count );
	}

	/* We round-to-nearest cf. pdfload etc.
	 */
	read->frame_width = VIPS_RINT( read->canvas_width * read->scale );
	read->frame_height = VIPS_RINT( read->canvas_height * read->scale );

#ifdef DEBUG
	printf( "webp2vips: canvas_width = %d\n", read->canvas_width );
	printf( "webp2vips: canvas_height = %d\n", read->canvas_height );
	printf( "webp2vips: frame_width = %d\n", read->frame_width );
	printf( "webp2vips: frame_height = %d\n", read->frame_height );
#endif /*DEBUG*/

	if( flags & ANIMATION_FLAG ) { 
		/* Only set page-height if we have more than one page, or
		 * this could accidentally turn into an animated image later.
		 */
		if( read->n > 1 )
			vips_image_set_int( out, 
				VIPS_META_PAGE_HEIGHT, read->frame_height );

		read->width = read->frame_width;
		read->height = read->n * read->frame_height;
	}
	else {
		read->width = read->frame_width;
		read->height = read->frame_height;
		read->frame_count = 1;
	}

	/* height can be huge if this is an animated webp image.
	 */
	if( read->width <= 0 ||
		read->height <= 0 ||
		read->width > 0x3FFF ||
		read->height >= VIPS_MAX_COORD ||
		read->frame_width <= 0 ||
		read->frame_height <= 0 ||
		read->frame_width > 0x3FFF ||
		read->frame_height > 0x3FFF ) { 
		vips_error( "webp", "%s", _( "bad image dimensions" ) ); 
		return( -1 ); 
	}

	for( i = 0; i < vips__n_webp_names; i++ ) { 
		const char *vips = vips__webp_names[i].vips;
		const char *webp = vips__webp_names[i].webp;

		if( flags & vips__webp_names[i].flags ) {
			WebPChunkIterator iter;

			WebPDemuxGetChunk( read->demux, webp, 1, &iter );
			vips_image_set_blob_copy( out, 
				vips, iter.chunk.bytes, iter.chunk.size );
			WebPDemuxReleaseChunkIterator( &iter );
		}
	}

	/* The canvas is always RGBA, we drop alpha to RGB on output if we
	 * can.
	 */
	read->frame = vips_image_new_memory();
	vips_image_init_fields( read->frame,
		read->frame_width, read->frame_height, 4, 
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );
	if( vips_image_pipelinev( read->frame, 
		VIPS_DEMAND_STYLE_THINSTRIP, NULL ) ||
		vips_image_write_prepare( read->frame ) ) 
		return( -1 );

	vips_image_init_fields( out,
		read->width, read->height,
		read->alpha ? 4 : 3,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );
	if( vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL ) )
		return( -1 );
	VIPS_SETSTR( out->filename, 
		vips_connection_filename( VIPS_CONNECTION( read->source ) ) );

	if( !WebPDemuxGetFrame( read->demux, 1, &read->iter ) ) {
		vips_error( "webp", 
			"%s", _( "unable to loop through frames" ) ); 
		return( -1 );
	}

	return( 0 );
}

/* Read a single frame -- a width * height block of pixels. This will get
 * blended into the accumulator at some offset.
 */
static VipsImage *
read_frame( Read *read, 
	int width, int height, const guint8 *data, size_t length )
{
	VipsImage *frame;

#ifdef DEBUG
	printf( "read_frame:\n" ); 
#endif /*DEBUG*/

	frame = vips_image_new_memory();
	vips_image_init_fields( frame,
		width, height, 4,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );
	if( vips_image_pipelinev( frame, VIPS_DEMAND_STYLE_THINSTRIP, NULL ) ||
		vips_image_write_prepare( frame ) ) {
		g_object_unref( frame );
		return( NULL );
	}

	read->config.output.u.RGBA.rgba = VIPS_IMAGE_ADDR( frame, 0, 0 );
	read->config.output.u.RGBA.stride = VIPS_IMAGE_SIZEOF_LINE( frame );
	read->config.output.u.RGBA.size = VIPS_IMAGE_SIZEOF_IMAGE( frame );
	if( read->scale != 1.0 ) { 
		read->config.options.use_scaling = 1;
		read->config.options.scaled_width = width;
		read->config.options.scaled_height = height; 
	}

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
	VipsRect area;

#ifdef DEBUG
	printf( "read_next_frame:\n" ); 
#endif /*DEBUG*/

	/* Area of this frame, in output image coordinates. We must rint(),
	 * since we need the same rules as the overall image scale, or we'll
	 * sometimes have missing pixels on edges.
	 */
	area.left = VIPS_RINT( read->iter.x_offset * read->scale ); 
	area.top = VIPS_RINT( read->iter.y_offset * read->scale );
	area.width = VIPS_RINT( read->iter.width * read->scale );
	area.height = VIPS_RINT( read->iter.height * read->scale );

	/* Dispose from the previous frame.
	 */
	if( read->dispose_method == WEBP_MUX_DISPOSE_BACKGROUND ) {
		/* We must clear the pixels occupied by the previous webp 
		 * frame (not the whole of the read frame) to 0 (transparent). 
		 *
		 * We do not clear to WEBP_FF_BACKGROUND_COLOR. That's only 
		 * used to composite down to RGB. Perhaps we
		 * should attach background as metadata.
		 */
		guint32 zero = 0;

		vips_image_paint_area( read->frame, 
			&read->dispose_rect, (VipsPel *) &zero );
	}

	/* Note this frame's dispose for next time.
	 */
	read->dispose_method = read->iter.dispose_method;
	read->dispose_rect = area;

#ifdef DEBUG
	printf( "webp2vips: frame_num = %d\n", read->iter.frame_num );
	printf( "   left = %d\n", area.left );
	printf( "   top = %d\n", area.top );
	printf( "   width = %d\n", area.width );
	printf( "   height = %d\n", area.height );
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

	if( !(frame = read_frame( read, 
		area.width, area.height,
		read->iter.fragment.bytes, read->iter.fragment.size )) ) 
		return( -1 );

	/* Now blend or copy the new pixels into our accumulator.
	 */
	vips_image_paint_image( read->frame, frame, 
		area.left, area.top, 
		read->iter.frame_num > 1 &&
			read->iter.blend_method == WEBP_MUX_BLEND );

	g_object_unref( frame );

	/* If there's another frame, move on. 
	 */
	if( read->iter.frame_num < read->frame_count ) {
		if( !WebPDemuxNextFrame( &read->iter ) ) {
			vips_error( "webp2vips", 
				"%s", _( "not enough frames" ) ); 
			return( -1 );
		}
	}

	return( 0 );
}

static int
read_webp_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
        VipsRect *r = &or->valid;
	Read *read = (Read *) a;

	/* iter.frame_num numbers from 1.
	 */
	int frame = 1 + r->top / read->frame_height + read->page;
	int line = r->top % read->frame_height;

#ifdef DEBUG_VERBOSE
	printf( "read_webp_generate: line %d\n", r->top );
#endif /*DEBUG_VERBOSE*/

	g_assert( r->height == 1 );

	while( read->frame_no < frame ) {
		if( read_next_frame( read ) )
			return( -1 );

		read->frame_no += 1;
	}

	if( or->im->Bands == 4 ) 
		memcpy( VIPS_REGION_ADDR( or, 0, r->top ),
			VIPS_IMAGE_ADDR( read->frame, 0, line ),
			VIPS_IMAGE_SIZEOF_LINE( read->frame ) );
	else {
		int x;
		VipsPel *p;
		VipsPel *q;

		/* We know that alpha is solid, so we can just drop the 4th
		 * band.
		 */
		p = VIPS_IMAGE_ADDR( read->frame, 0, line );
		q = VIPS_REGION_ADDR( or, 0, r->top );
		for( x = 0; x < r->width; x++ ) {
			q[0] = p[0];
			q[1] = p[1];
			q[2] = p[2];

			q += 3;
			p += 4;
		}
	}

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
vips__webp_read_header_source( VipsSource *source, VipsImage *out,
	int page, int n, double scale )
{
	Read *read;

	if( !(read = read_new( out, source, page, n, scale )) || 
		read_header( read, out ) )
		return( -1 );

	return( 0 );
}

int
vips__webp_read_source( VipsSource *source, VipsImage *out, 
	int page, int n, double scale )
{
	Read *read;

	if( !(read = read_new( out, source, page, n, scale )) || 
		read_image( read, out ) )
		return( -1 );

	return( 0 );
}

#endif /*HAVE_LIBWEBP*/
