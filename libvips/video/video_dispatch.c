/* function dispatch tables for video
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

#include <stdio.h>

#include <vips/vips.h>

/** 
 * SECTION: video
 * @short_description: various video grabbers
 * @see_also: <link linkend="libvips-image">image</link>
 * @stability: Stable
 * @include: vips/vips.h
 *
 * Read an image from a video source.
 */

static int
video_v4l1_vec( im_object *argv )
{
        IMAGE *out = argv[0];
        char *device = (char *) argv[1];
        int channel = *((int*)argv[2]);
        int brightness = *((int*)argv[3]);
        int colour = *((int*)argv[4]);
        int contrast = *((int*)argv[5]);
        int hue = *((int*)argv[6]);
        int ngrabs = *((int*)argv[7]);

        return( im_video_v4l1( out, device, 
		channel, brightness, colour, contrast, hue, ngrabs ) );
}

static im_arg_desc video_v4l1_arg_types[] = {
        IM_OUTPUT_IMAGE( "out" ),
        IM_INPUT_STRING( "device" ),
        IM_INPUT_INT( "channel" ),
        IM_INPUT_INT( "brightness" ),
        IM_INPUT_INT( "colour" ),
        IM_INPUT_INT( "contrast" ),
        IM_INPUT_INT( "hue" ),
        IM_INPUT_INT( "ngrabs" )
};

static im_function video_v4l1_desc = {
        "im_video_v4l1",                /* Name */
        "grab a video frame with v4l1",	/* Description */
        IM_FN_NOCACHE,                  /* Flags */
        video_v4l1_vec,                 /* Dispatch function */
        IM_NUMBER( video_v4l1_arg_types ), /* Size of arg list */
        video_v4l1_arg_types            /* Arg list */
};

static int
video_test_vec( im_object *argv )
{
        IMAGE *out = argv[0];
        int brightness = *((int*)argv[1]);
        int error = *((int*)argv[2]);

        return( im_video_test( out, brightness, error ) );
}

static im_arg_desc video_test_arg_types[] = {
        IM_OUTPUT_IMAGE( "out" ),
        IM_INPUT_INT( "brightness" ),
        IM_INPUT_INT( "error" )
};

static im_function video_test_desc = {
        "im_video_test",                /* Name */
        "test video grabber",		/* Description */
        IM_FN_NOCACHE,                  /* Flags */
        video_test_vec,                 /* Dispatch function */
        IM_NUMBER( video_test_arg_types ), /* Size of arg list */
        video_test_arg_types            /* Arg list */
};

static im_function *video_list[] = {
        &video_test_desc,
        &video_v4l1_desc
};

im_package im__video = {
        "video",                        /* Package name */
        IM_NUMBER( video_list ),       	/* Function list */
        video_list
};


