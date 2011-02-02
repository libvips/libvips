/* video grab for linux ... uses the original v4l
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_VIDEODEV

/* Lots of debugging output.
#define DEBUG
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <errno.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <linux/types.h>
#include <linux/videodev.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Zero freed mem to help catch stray pointers.
 */
#ifdef NDEBUG
#define FREE( S ) { if( S ) { (void) im_free( (char *) (S) ); \
        (char *) (S) = NULL; } }
#else
#define FREE( S ) { if( S ) { memset( (char *)(S), 0, sizeof( *(S) ) ); \
        (void) im_free( (char *) (S) ); (S) = NULL; } }
#endif /*NDEBUG*/

#define FREEF( F, S ) { if( S ) { (void) F( S ); (S) = NULL; } }
#define FREEFI( F, S ) { if( S ) { (void) F( S ); (S) = 0; } }
#define SETSTR( S, V ) \
        { const char *sst = (V); FREE( S ); (S) = im_strdup( NULL, sst ); }

/* Max channels on a device.
 */
#define IM_MAXCHANNELS (10)

/* Video input sources, e.g. tuner, svideo, composite.
 */
#define TUNER (0)
#define COMPOSITE (1)
#define SVIDEO (2)

typedef struct lgrab {
	/* Mmap here, plus file descriptor.
	 */
	char *device;
	char *capture_buffer;
	int capture_size;
	int fd;

	/* Current settings.
	 */
	int c_channel;
	int c_width;
	int c_height;
	int c_ngrabs;

	/* Extract capabilities here.
	 */
	struct video_capability capability;
	struct video_channel channel[IM_MAXCHANNELS];
	struct video_window window;
	struct video_picture picture;
	struct video_mbuf mbuf;
	struct video_mmap mmap;
} LGrab;

#ifdef DEBUG
/* Decode various things ... capability bits etc.
 */
typedef struct {
        int value;
        const char *name;
        const char *description;
} Decode;

static const Decode decode_palette[] = {
	{ VIDEO_PALETTE_GREY,
		"VIDEO_PALETTE_GREY", "Linear greyscale" },
	{ VIDEO_PALETTE_HI240, 
		"VIDEO_PALETTE_HI240", "High 240 cube (BT848)" },
	{ VIDEO_PALETTE_RGB565, 
		"VIDEO_PALETTE_RGB565", "565 16 bit RGB" },
	{ VIDEO_PALETTE_RGB24, 
		"VIDEO_PALETTE_RGB24", "24bit RGB" },
	{ VIDEO_PALETTE_RGB32, 
		"VIDEO_PALETTE_RGB32", "32bit RGB" },
	{ VIDEO_PALETTE_RGB555, 
		"VIDEO_PALETTE_RGB555", "555 15bit RGB" },
	{ VIDEO_PALETTE_YUV422, 
		"VIDEO_PALETTE_YUV422", "YUV422 capture" },
	{ VIDEO_PALETTE_YUYV, 
		"VIDEO_PALETTE_YUYV", "" },
	{ VIDEO_PALETTE_UYVY, 
		"VIDEO_PALETTE_UYVY", "" },
	{ VIDEO_PALETTE_YUV420, 
		"VIDEO_PALETTE_YUV420", "" },
	{ VIDEO_PALETTE_YUV411, 
		"VIDEO_PALETTE_YUV411", "YUV411 capture" },
	{ VIDEO_PALETTE_RAW, 
		"VIDEO_PALETTE_RAW", "RAW capture (BT848)" },
	{ VIDEO_PALETTE_YUV422P, 
		"VIDEO_PALETTE_YUV422P", "YUV 4:2:2 Planar" },
	{ VIDEO_PALETTE_YUV411P, 
		"VIDEO_PALETTE_YUV411P", "YUV 4:1:1 Planar" },
	{ VIDEO_PALETTE_YUV420P, 
		"VIDEO_PALETTE_YUV420P", "YUV 4:2:0 Planar" },
	{ VIDEO_PALETTE_YUV410P, 
		"VIDEO_PALETTE_YUV410P", "YUV 4:1:0 Planar" }
};

static const Decode decode_type[] = {
	{ VIDEO_TYPE_TV, 
		"VIDEO_TYPE_TV", "TV" },
	{ VIDEO_TYPE_CAMERA, 
		"VIDEO_TYPE_CAMERA", "Camera" },
};

static const Decode decode_vtype[] = {
	{ VID_TYPE_CAPTURE,
		"VID_TYPE_CAPTURE", "Can capture to memory" },
	{ VID_TYPE_TUNER,
		"VID_TYPE_TUNER", "Has Tuner" },
	{ VID_TYPE_TELETEXT,
		"VID_TYPE_TELETEXT", "Has Teletext" },
	{ VID_TYPE_OVERLAY,
		"VID_TYPE_OVERLAY", "Chromakeyed overlay" },
	{ VID_TYPE_CLIPPING,
		"VID_TYPE_CLIPPING", "Overlay clipping" },
	{ VID_TYPE_FRAMERAM,
		"VID_TYPE_FRAMERAM", "Overlay overwrites frame buffer memory" },
	{ VID_TYPE_SCALES,
		"VID_TYPE_SCALES", "Hardware supports image scaling" },
	{ VID_TYPE_MONOCHROME,
		"VID_TYPE_MONOCHROME", "Image capture is grey scale only" },
	{ VID_TYPE_SUBCAPTURE,
		"VID_TYPE_SUBCAPTURE", "Capture sub-image" },
	{ VID_TYPE_MPEG_DECODER,
		"VID_TYPE_MPEG_DECODER", "Can decode MPEG streams" },
	{ VID_TYPE_MPEG_ENCODER,
		"VID_TYPE_MPEG_ENCODER", "Can encode MPEG streams" },
	{ VID_TYPE_MJPEG_DECODER,
		"VID_TYPE_MJPEG_DECODER", "Can decode MJPEG streams" },
	{ VID_TYPE_MJPEG_ENCODER,
		"VID_TYPE_MJPEG_ENCODER", "Can encode MJPEG streams" }
};

static const Decode decode_ctype[] = {
	{ VIDEO_VC_TUNER,
		"VIDEO_VC_TUNER", "Has tuner" },
	{ VIDEO_VC_AUDIO,
		"VIDEO_VC_AUDIO", "Has audio" }
};

/* Prettyprint a value.
 */
static void
decode_print( const Decode *decode, int ndecode, int value )
{
        int i;

        for( i = 0; i < ndecode; i++ )
                if( decode[i].value == value ) {
                        printf( "%s, %s",
                                decode[i].name, decode[i].description );
                        return;
                }

        printf( "unknown (%p)", value );
}

/* Prettyprint a set of flags.
 */
static void
decode_print_flags( const Decode *decode, int ndecode, int flags )
{
        int i;

        printf( "0x%x ", (unsigned int) flags );

        for( i = 0; i < ndecode; i++ )
                if( decode[i].value & flags ) {
                        printf( "[" );
                        decode_print( decode, ndecode,
                                decode[i].value & flags );
                        printf( "] " );
                        flags &= -1 ^ decode[i].value;
                }

        if( flags )
                printf( "[unknown extra flags 0x%x]", (unsigned int) flags );
}
#endif /*DEBUG*/

static int
lgrab_ioctl( LGrab *lg, int request, void *argp )
{
	if( !lg->fd ) {
		im_error( "lgrab_ioctl", "%s", _( "no file descriptor" ) );
		return( -1 );
	}

	if( ioctl( lg->fd, request, argp ) < 0 ) {
		im_error( "lgrab_ioctl", _( "ioctl(0x%x) failed: %s" ), 
			(unsigned int) request, strerror( errno ) );
		return( -1 );
	}

	return( 0 );
}

static void
lgrab_destroy( LGrab *lg )
{
	if( lg->fd != -1 ) {
		int zero = 0;

		(void) lgrab_ioctl( lg, VIDIOCCAPTURE, &zero );
		close( lg->fd );
		lg->fd = -1;
	}

	if( lg->capture_buffer ) {
		munmap( lg->capture_buffer, lg->capture_size );
		lg->capture_buffer = NULL;
	}

	FREE( lg->device );
	FREE( lg );
}

static LGrab *
lgrab_new( const char *device )
{
	LGrab *lg = IM_NEW( NULL, LGrab );
	int i;

	if( !lg )
		return( NULL );

	lg->device = NULL;
	lg->capture_buffer = NULL;
	lg->capture_size = 0;
	lg->fd = -1;

	lg->c_channel = -1;
	lg->c_width = -1;
	lg->c_height = -1;
	lg->c_ngrabs = 1;

	SETSTR( lg->device, device );
        if( !lg->device || (lg->fd = open( lg->device, O_RDWR )) == -1 ) {
		im_error( "lgrab_new", _( "cannot open video device \"%s\"" ),
			lg->device );
		lgrab_destroy( lg );
		return( NULL );
	}

        if( lgrab_ioctl( lg, VIDIOCGCAP, &lg->capability ) ) {
		im_error( "lgrab_new", 
			"%s", _( "cannot get video capability" ) );
		lgrab_destroy( lg );
		return( NULL );
	}

        /* Check that it can capture to memory.
	 */
        if( !(lg->capability.type & VID_TYPE_CAPTURE) ) {
                im_error( "lgrab_new", 
			"%s", _( "card cannot capture to memory" ) );
		lgrab_destroy( lg );
		return( NULL );
	}

        /* Read channel info.
	 */
        for( i = 0; i < IM_MIN( lg->capability.channels, IM_MAXCHANNELS ); 
		i++ ) {
                lg->channel[i].channel = i;
                if( lgrab_ioctl( lg, VIDIOCGCHAN, &lg->channel[i] ) ) {
			lgrab_destroy( lg );
			return( NULL );
		}
	}

        /* Get other props.
 	 */
        if( lgrab_ioctl( lg, VIDIOCGWIN, &lg->window) ||
		lgrab_ioctl( lg, VIDIOCGPICT, &lg->picture) ) {
		lgrab_destroy( lg );
		return( NULL );
	}

	/* Set 24 bit mode.
	 */
	lg->picture.depth = 24;
	lg->picture.palette = VIDEO_PALETTE_RGB24;
	if( lgrab_ioctl( lg, VIDIOCSPICT, &lg->picture ) ) {
		lgrab_destroy( lg );
		return( NULL );
	}

	return( lg );
}

#ifdef DEBUG
static void
lgrab_dump_capability( struct video_capability *capability )
{
        printf( "capability->name = \"%s\"\n", capability->name );
        printf( "capability->channels = %d\n", capability->channels );
        printf( "capability->audios = %d\n", capability->audios );
        printf( "capability->maxwidth = %d\n", capability->maxwidth );
        printf( "capability->maxheight = %d\n", capability->maxheight );
        printf( "capability->minwidth = %d\n", capability->maxwidth );
        printf( "capability->minheight = %d\n", capability->maxheight );
	printf( "capability->type = " );
	decode_print_flags( decode_vtype, IM_NUMBER( decode_vtype ),
                capability->type );
	printf( "\n" );
}

static void
lgrab_dump_channel( struct video_channel *channel )
{
	printf( "channel->channel = %d\n", channel->channel );
	printf( "channel->name = \"%s\"\n", channel->name );
	printf( "channel->tuners = %d\n", channel->tuners );

	printf( "channel->flags = " );
	decode_print_flags( decode_ctype, IM_NUMBER( decode_ctype ),
		channel->flags );
	printf( "\n" );
	printf( "channel->type = " );
	decode_print( decode_type, IM_NUMBER( decode_type ),
                channel->type );
	printf( "\n" );
	printf( "channel->norm = %d\n", channel->norm );
}

static void
lgrab_dump_picture( struct video_picture *picture )
{
        printf( "picture->brightness = %d\n", picture->brightness );
        printf( "picture->hue = %d\n", picture->hue );
        printf( "picture->colour = %d\n", picture->colour );
        printf( "picture->contrast = %d\n", picture->contrast );
        printf( "picture->whiteness = %d\n", picture->whiteness );
        printf( "picture->depth = %d\n", picture->depth );
        printf( "picture->palette = " );
	decode_print( decode_palette, IM_NUMBER( decode_palette ),
                picture->palette );
	printf( "\n" );
}

static void 
lgrab_dump( LGrab *lg )
{
        int i;

        printf( "lg->device = \"%s\"\n", lg->device );
        printf( "lg->capture_buffer = %p\n",
                lg->capture_buffer );
        printf( "lg->capture_size = 0x%x\n",
                (unsigned int) lg->capture_size );
        printf( "lg->fd = %d\n", lg->fd );

        printf( "lg->c_channel = %d\n", lg->c_channel );
        printf( "lg->c_width = %d\n", lg->c_width );
        printf( "lg->c_height = %d\n", lg->c_height );
        printf( "lg->c_ngrabs = %d\n", lg->c_ngrabs );

	lgrab_dump_capability( &lg->capability );
        for( i = 0; i < lg->capability.channels; i++ ) 
		lgrab_dump_channel( &lg->channel[i] );
	lgrab_dump_picture( &lg->picture );

        printf( "mbuf->size = 0x%x\n", (unsigned int) lg->mbuf.size );
        printf( "mbuf->frames = %d\n", lg->mbuf.frames );
        printf( "mbuf->offsets = " );
	for( i = 0; i < lg->mbuf.frames; i++ )
		printf( "0x%x ", (unsigned int) lg->mbuf.offsets[i] );
        printf( "\n" );
}
#endif /*DEBUG*/

static int
lgrab_set_capture_size( LGrab *lg, int width, int height )
{
	lg->c_width = width;
	lg->c_height = height;

	lg->window.clipcount = 0;
	lg->window.flags = 0;
	lg->window.x = 0;
	lg->window.y = 0;
	lg->window.width = width;
	lg->window.height = height;
	if( lgrab_ioctl( lg, VIDIOCSWIN, &lg->window ) )
		return( -1 );

	/* Make sure the correct amount of memory is mapped.
	 */
	if( lgrab_ioctl( lg, VIDIOCGMBUF, &lg->mbuf ) )
		return( -1 );

	if( lg->capture_buffer ) {
		munmap( lg->capture_buffer, lg->capture_size );
		lg->capture_buffer = NULL;
	}

	lg->capture_size = lg->mbuf.size;
	if( !(lg->capture_buffer = mmap( 0, lg->capture_size, 
		PROT_READ | PROT_WRITE, MAP_SHARED, lg->fd, 0 )) ) {
		im_error( "lgrab_set_capture_size", 
			"%s", _( "unable to map memory" ) );
		return( -1 );
	}

	return( 0 );
}

static int
lgrab_set_channel( LGrab *lg, int channel )
{
	if( channel < 0 || channel >= lg->capability.channels ) {
		im_error( "lgrab_set_channel", 
			_( "channel not between 0 and %d" ),
			lg->capability.channels - 1 );
		return( -1 );
	}

	if( lgrab_ioctl( lg, VIDIOCSCHAN, &lg->channel[channel] ) )
		return( -1 );
	lg->c_channel = channel;

	return( 0 );
}

static int
lgrab_set_brightness( LGrab *lg, int brightness )
{
	lg->picture.brightness = IM_CLIP( 0, brightness, 65535 );
	if( lgrab_ioctl( lg, VIDIOCSPICT, &lg->picture ) )
		return( -1 );

	return( 0 );
}

static int
lgrab_set_colour( LGrab *lg, int colour )
{
	lg->picture.colour = IM_CLIP( 0, colour, 65535 );
	if( lgrab_ioctl( lg, VIDIOCSPICT, &lg->picture ) )
		return( -1 );

	return( 0 );
}

static int
lgrab_set_contrast( LGrab *lg, int contrast )
{
	lg->picture.contrast = IM_CLIP( 0, contrast, 65535 );
	if( lgrab_ioctl( lg, VIDIOCSPICT, &lg->picture ) )
		return( -1 );

	return( 0 );
}

static int
lgrab_set_hue( LGrab *lg, int hue )
{
	lg->picture.hue = IM_CLIP( 0, hue, 65535 );
	if( lgrab_ioctl( lg, VIDIOCSPICT, &lg->picture ) )
		return( -1 );

	return( 0 );
}

static int
lgrab_set_ngrabs( LGrab *lg, int ngrabs )
{
	lg->c_ngrabs = IM_CLIP( 1, ngrabs, 1000 );

	return( 0 );
}

/* Grab a single frame.
 */
static int
lgrab_capture1( LGrab *lg )
{
	lg->mmap.format = lg->picture.palette;
	lg->mmap.frame = 0;
	lg->mmap.width = lg->c_width;
	lg->mmap.height = lg->c_height;
	if( lgrab_ioctl( lg, VIDIOCMCAPTURE, &lg->mmap ) ||
		lgrab_ioctl( lg, VIDIOCSYNC, &lg->mmap.frame ) )
		return( -1 );

	return( 0 );
}

/* Grab and average many frames.
 */
static int
lgrab_capturen( LGrab *lg )
{
	if( lg->c_ngrabs == 1 ) {
		if( lgrab_capture1( lg ) )
			return( -1 );
	}
	else {
		int i, j;
		int npx = lg->c_width * lg->c_height * 3;
		unsigned int *acc;

		if( !(acc = IM_ARRAY( NULL, npx, unsigned int )) )
			return( -1 );
		memset( acc, 0, npx * sizeof( unsigned int ) );

		for( i = 0; i < lg->c_ngrabs; i++ ) {
			if( lgrab_capture1( lg ) ) {
				FREE( acc );
				return( -1 );
			}

			for( j = 0; j < npx; j++ ) 
				acc[j] += (unsigned char) lg->capture_buffer[j];
		}

		for( j = 0; j < npx; j++ ) {
			int avg = (acc[j] + lg->c_ngrabs / 2) / lg->c_ngrabs;

			lg->capture_buffer[j] = IM_CLIP( 0, avg, 255 );
		}

		FREE( acc );
	}

	return( 0 );
}

static int
lgrab_capture( LGrab *lg, IMAGE *im )
{
	int x, y;
	unsigned char *line;

	if( lgrab_capturen( lg ) )
		return( -1 );

	if( im_outcheck( im ) )
		return( -1 );
        im_initdesc( im, lg->c_width, lg->c_height, 3,
                IM_BBITS_BYTE, IM_BANDFMT_UCHAR,
                IM_CODING_NONE, IM_TYPE_MULTIBAND, 1.0, 1.0, 0, 0 );
        if( im_setupout( im ) )
                return( -1 );
	if( !(line = IM_ARRAY( im, 
		IM_IMAGE_SIZEOF_LINE( im ), unsigned char )) )
                return( -1 );

        for( y = 0; y < lg->c_height; y++ ) {
                unsigned char *p = (unsigned char *) lg->capture_buffer + 
			y * IM_IMAGE_SIZEOF_LINE( im );
                unsigned char *q = line;

		for( x = 0; x < lg->c_width; x++ ) {
			q[0] = p[2];
			q[1] = p[1];
			q[2] = p[0];

			p += 3;
			q += 3;
		}

                if( im_writeline( y, im, line ) )
                        return( -1 );
	}

	return( 0 );
}

/**
 * im_video_v4l1:
 * @im: write image here
 * @device: device to grab from
 * @channel: channel to grab
 * @brightness: brightness setting
 * @colour: colour setting
 * @contrast: contrast setting
 * @hue: hue setting
 * @ngrabs: average this many frames
 *
 * Grab an image from a device using the Video4Linux1 interface. It grabs
 * 24-bit RGB at the maximum size your card allows.
 *
 * @device should typically be "/dev/video".
 * @channel selects the channel to acquire: usually 0 is TV, and 1 is 
 * composite video. @brightness, @colour, @contrast and @hue 
 * set grab parameters. Each should be in the range (0 - 32768). 
 * 32768 is usually the value you want. @ngrabs
 * sets the number of frames the card should average. 
 * Higher values are slower, but typically less noisy (and slightly softer).
 *
 * This function needs updating to newer video standards.
 *
 * See also: im_video_test().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_video_v4l1( IMAGE *im, const char *device,
	int channel, int brightness, int colour, int contrast, int hue, 
	int ngrabs )
{
	LGrab *lg;

	if( !(lg = lgrab_new( device )) )
		return( -1 );

	if( lgrab_set_capture_size( lg, 
		lg->capability.maxwidth, lg->capability.maxheight ) ||
		lgrab_set_channel( lg, channel ) ||
		lgrab_set_brightness( lg, brightness ) ||
		lgrab_set_colour( lg, colour ) ||
		lgrab_set_contrast( lg, contrast ) ||
		lgrab_set_hue( lg, hue ) ||
		lgrab_set_ngrabs( lg, ngrabs ) ||
		lgrab_capture( lg, im ) ) {
		lgrab_destroy( lg );
		return( -1 );
	}

#ifdef DEBUG
	printf( "Successful capture with:\n" );
	lgrab_dump( lg );
#endif /*DEBUG*/

	lgrab_destroy( lg );

	return( 0 );
}

#else /*!HAVE_VIDEODEV*/

#include <vips/vips.h>

int
im_video_v4l1( IMAGE *im, const char *device,
	int channel, int brightness, int colour, int contrast, int hue, 
	int ngrabs )
{
	im_error( "im_video_v4l1", 
		"%s", _( "compiled without im_video_v4l1 support" ) );
	return( -1 );
}

#endif /*HAVE_VIDEODEV*/
