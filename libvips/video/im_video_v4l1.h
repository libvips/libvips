/* single frame video capture on linux
 */

/*

    Copyright (C) 1991-2003 The National Gallery

    This program is free software; you can redistribute it and/or modify
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

/* Video input sources, e.g. tuner, svideo, composite.
 */
#define IM_MAXCHANNELS (10)
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

void lgrab_destroy( LGrab *lg );
LGrab *lgrab_new( const char *device );

int lgrab_set_capture_size( LGrab *lg, int width, int height );
int lgrab_set_channel( LGrab *lg, int channel );
int lgrab_set_brightness( LGrab *lg, int brightness );
int lgrab_set_colour( LGrab *lg, int colour );
int lgrab_set_contrast( LGrab *lg, int contrast );
int lgrab_set_hue( LGrab *lg, int hue );
int lgrab_set_ngrabs( LGrab *lg, int ngrabs );
int lgrab_capture( LGrab *lg, IMAGE *im );
int lgrab_grab( IMAGE *im, const char *device, 
	int channel, int brightness, int colour, int contrast, int hue, 
	int ngrabs );

