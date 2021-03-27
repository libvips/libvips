/*
 * Copyright 2004 Richard Wilson <richard.wilson@netsurf-browser.org>
 * Copyright 2008 Sean Fox <dyntryx@gmail.com>
 *
 * This file is part of NetSurf's libnsgif, http://www.netsurf-browser.org/
 * Licenced under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 */

/**
 * \file
 * Interface to progressive animated GIF file decoding.
 */

#ifndef _LIBNSGIF_H_
#define _LIBNSGIF_H_

#include <stdbool.h>
#include <inttypes.h>

/* Error return values */
typedef enum {
        GIF_WORKING = 1,
        GIF_OK = 0,
        GIF_INSUFFICIENT_FRAME_DATA = -1,
        GIF_FRAME_DATA_ERROR = -2,
        GIF_INSUFFICIENT_DATA = -3,
        GIF_DATA_ERROR = -4,
        GIF_INSUFFICIENT_MEMORY = -5,
        GIF_FRAME_NO_DISPLAY = -6,
        GIF_END_OF_FRAME = -7
} gif_result;

/** GIF frame data */
typedef struct gif_frame {
        /** whether the frame should be displayed/animated */
        bool display;
        /** delay (in cs) before animating the frame */
        unsigned int frame_delay;

        /* Internal members are listed below */

        /** offset (in bytes) to the GIF frame data */
        unsigned int frame_pointer;
        /** whether the frame has previously been used */
        bool virgin;
        /** whether the frame is totally opaque */
        bool opaque;
        /** whether a forcable screen redraw is required */
        bool redraw_required;
        /** how the previous frame should be disposed; affects plotting */
        unsigned char disposal_method;
        /** whether we acknoledge transparency */
        bool transparency;
        /** the index designating a transparent pixel */
        unsigned char transparency_index;
        /** x co-ordinate of redraw rectangle */
        unsigned int redraw_x;
        /** y co-ordinate of redraw rectangle */
        unsigned int redraw_y;
        /** width of redraw rectangle */
        unsigned int redraw_width;
        /** height of redraw rectangle */
        unsigned int redraw_height;
} gif_frame;

/* API for Bitmap callbacks */
typedef void* (*gif_bitmap_cb_create)(int width, int height);
typedef void (*gif_bitmap_cb_destroy)(void *bitmap);
typedef unsigned char* (*gif_bitmap_cb_get_buffer)(void *bitmap);
typedef void (*gif_bitmap_cb_set_opaque)(void *bitmap, bool opaque);
typedef bool (*gif_bitmap_cb_test_opaque)(void *bitmap);
typedef void (*gif_bitmap_cb_modified)(void *bitmap);

/** Bitmap callbacks function table */
typedef struct gif_bitmap_callback_vt {
        /** Create a bitmap. */
        gif_bitmap_cb_create bitmap_create;
        /** Free a bitmap. */
        gif_bitmap_cb_destroy bitmap_destroy;
        /** Return a pointer to the pixel data in a bitmap. */
        gif_bitmap_cb_get_buffer bitmap_get_buffer;

        /* Members below are optional */

        /** Sets whether a bitmap should be plotted opaque. */
        gif_bitmap_cb_set_opaque bitmap_set_opaque;
        /** Tests whether a bitmap has an opaque alpha channel. */
        gif_bitmap_cb_test_opaque bitmap_test_opaque;
        /** The bitmap image has changed, so flush any persistant cache. */
        gif_bitmap_cb_modified bitmap_modified;
} gif_bitmap_callback_vt;

/** GIF animation data */
typedef struct gif_animation {
        /** LZW decode context */
        void *lzw_ctx;
        /** callbacks for bitmap functions */
        gif_bitmap_callback_vt bitmap_callbacks;
        /** pointer to GIF data */
        unsigned char *gif_data;
        /** width of GIF (may increase during decoding) */
        unsigned int width;
        /** heigth of GIF (may increase during decoding) */
        unsigned int height;
        /** number of frames decoded */
        unsigned int frame_count;
        /** number of frames partially decoded */
        unsigned int frame_count_partial;
        /** decoded frames */
        gif_frame *frames;
        /** current frame decoded to bitmap */
        int decoded_frame;
        /** currently decoded image; stored as bitmap from bitmap_create callback */
        void *frame_image;
        /** number of times to loop animation */
        int loop_count;

        /* Internal members are listed below */

        /** current index into GIF data */
        unsigned int buffer_position;
        /** total number of bytes of GIF data available */
        unsigned int buffer_size;
        /** current number of frame holders */
        unsigned int frame_holders;
        /** index in the colour table for the background colour */
        unsigned int background_index;
        /** image aspect ratio (ignored) */
        unsigned int aspect_ratio;
        /** size of colour table (in entries) */
        unsigned int colour_table_size;
        /** whether the GIF has a global colour table */
        bool global_colours;
        /** global colour table */
        unsigned int *global_colour_table;
        /** local colour table */
        unsigned int *local_colour_table;

        /** previous frame for GIF_FRAME_RESTORE */
        void *prev_frame;
        /** previous frame index */
        int prev_index;
        /** previous frame width */
        unsigned prev_width;
        /** previous frame height */
        unsigned prev_height;
} gif_animation;

/**
 * Initialises necessary gif_animation members.
 */
void gif_create(gif_animation *gif, gif_bitmap_callback_vt *bitmap_callbacks);

/**
 * Initialises any workspace held by the animation and attempts to decode
 * any information that hasn't already been decoded.
 * If an error occurs, all previously decoded frames are retained.
 *
 * @return Error return value.
 *         - GIF_FRAME_DATA_ERROR for GIF frame data error
 *         - GIF_INSUFFICIENT_FRAME_DATA for insufficient data to process
 *                                     any more frames
 *         - GIF_INSUFFICIENT_MEMORY for memory error
 *         - GIF_DATA_ERROR for GIF error
 *         - GIF_INSUFFICIENT_DATA for insufficient data to do anything
 *         - GIF_OK for successful decoding
 *         - GIF_WORKING for successful decoding if more frames are expected
 */
gif_result gif_initialise(gif_animation *gif, size_t size, unsigned char *data);

/**
 * Decodes a GIF frame.
 *
 * @return Error return value. If a frame does not contain any image data,
 *		GIF_OK is returned and gif->current_error is set to
 *		GIF_FRAME_NO_DISPLAY
 *         - GIF_FRAME_DATA_ERROR for GIF frame data error
 *         - GIF_INSUFFICIENT_FRAME_DATA for insufficient data to complete the frame
 *         - GIF_DATA_ERROR for GIF error (invalid frame header)
 *         - GIF_INSUFFICIENT_DATA for insufficient data to do anything
 *         - GIF_INSUFFICIENT_MEMORY for insufficient memory to process
 *         - GIF_OK for successful decoding
 */
gif_result gif_decode_frame(gif_animation *gif, unsigned int frame);

/**
 * Releases any workspace held by a gif
 */
void gif_finalise(gif_animation *gif);

#endif
