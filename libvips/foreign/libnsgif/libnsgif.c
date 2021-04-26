/*
 * Copyright 2004 Richard Wilson <richard.wilson@netsurf-browser.org>
 * Copyright 2008 Sean Fox <dyntryx@gmail.com>
 *
 * This file is part of NetSurf's libnsgif, http://www.netsurf-browser.org/
 * Licenced under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "libnsgif.h"
#include "utils/log.h"

#include "lzw.h"

/**
 *
 * \file
 * \brief GIF image decoder
 *
 * The GIF format is thoroughly documented; a full description can be found at
 * http://www.w3.org/Graphics/GIF/spec-gif89a.txt
 *
 * \todo Plain text and comment extensions should be implemented.
 */


/** Maximum colour table size */
#define GIF_MAX_COLOURS 256

/** Internal flag that the colour table needs to be processed */
#define GIF_PROCESS_COLOURS 0xaa000000

/** Internal flag that a frame is invalid/unprocessed */
#define GIF_INVALID_FRAME -1

/** Transparent colour */
#define GIF_TRANSPARENT_COLOUR 0x00

/** No transparency */
#define GIF_NO_TRANSPARENCY (0xFFFFFFFFu)

/* GIF Flags */
#define GIF_FRAME_COMBINE 1
#define GIF_FRAME_CLEAR 2
#define GIF_FRAME_RESTORE 3
#define GIF_FRAME_QUIRKS_RESTORE 4

#define GIF_IMAGE_SEPARATOR 0x2c
#define GIF_INTERLACE_MASK 0x40
#define GIF_COLOUR_TABLE_MASK 0x80
#define GIF_COLOUR_TABLE_SIZE_MASK 0x07
#define GIF_EXTENSION_INTRODUCER 0x21
#define GIF_EXTENSION_GRAPHIC_CONTROL 0xf9
#define GIF_DISPOSAL_MASK 0x1c
#define GIF_TRANSPARENCY_MASK 0x01
#define GIF_EXTENSION_COMMENT 0xfe
#define GIF_EXTENSION_PLAIN_TEXT 0x01
#define GIF_EXTENSION_APPLICATION 0xff
#define GIF_BLOCK_TERMINATOR 0x00
#define GIF_TRAILER 0x3b

/** standard GIF header size */
#define GIF_STANDARD_HEADER_SIZE 13


/**
 * Updates the sprite memory size
 *
 * \param gif The animation context
 * \param width The width of the sprite
 * \param height The height of the sprite
 * \return GIF_INSUFFICIENT_MEMORY for a memory error GIF_OK for success
 */
static gif_result
gif_initialise_sprite(gif_animation *gif,
		      unsigned int width,
		      unsigned int height)
{
	/* Already allocated? */
	if (gif->frame_image) {
		return GIF_OK;
	}

	assert(gif->bitmap_callbacks.bitmap_create);
	gif->frame_image = gif->bitmap_callbacks.bitmap_create(width, height);
	if (gif->frame_image == NULL) {
		return GIF_INSUFFICIENT_MEMORY;
	}

	return GIF_OK;
}


/**
 * Attempts to initialise the frame's extensions
 *
 * \param gif The animation context
 * \param frame The frame number
 * @return GIF_INSUFFICIENT_FRAME_DATA for insufficient data to complete the
 *         frame GIF_OK for successful initialisation.
 */
static gif_result
gif_initialise_frame_extensions(gif_animation *gif, const int frame)
{
	unsigned char *gif_data, *gif_end;
	int gif_bytes;
	unsigned int block_size;

	/* Get our buffer position etc.	*/
	gif_data = (unsigned char *)(gif->gif_data + gif->buffer_position);
	gif_end = (unsigned char *)(gif->gif_data + gif->buffer_size);

	/* Initialise the extensions */
	while (gif_data < gif_end && gif_data[0] == GIF_EXTENSION_INTRODUCER) {
		++gif_data;
		if ((gif_bytes = (gif_end - gif_data)) < 1) {
			return GIF_INSUFFICIENT_FRAME_DATA;
		}

		/* Switch on extension label */
		switch (gif_data[0]) {
		case GIF_EXTENSION_GRAPHIC_CONTROL:
			/* 6-byte Graphic Control Extension is:
			 *
			 *  +0  CHAR    Graphic Control Label
			 *  +1  CHAR    Block Size
			 *  +2  CHAR    __Packed Fields__
			 *              3BITS   Reserved
			 *              3BITS   Disposal Method
			 *              1BIT    User Input Flag
			 *              1BIT    Transparent Color Flag
			 *  +3  SHORT   Delay Time
			 *  +5  CHAR    Transparent Color Index
			 */
			if (gif_bytes < 6) {
				return GIF_INSUFFICIENT_FRAME_DATA;
			}

			gif->frames[frame].frame_delay = gif_data[3] | (gif_data[4] << 8);
			if (gif_data[2] & GIF_TRANSPARENCY_MASK) {
				gif->frames[frame].transparency = true;
				gif->frames[frame].transparency_index = gif_data[5];
			}
			gif->frames[frame].disposal_method = ((gif_data[2] & GIF_DISPOSAL_MASK) >> 2);
			/* I have encountered documentation and GIFs in the
			 * wild that use 0x04 to restore the previous frame,
			 * rather than the officially documented 0x03.  I
			 * believe some (older?)  software may even actually
			 * export this way.  We handle this as a type of
			 * "quirks" mode.
			 */
			if (gif->frames[frame].disposal_method == GIF_FRAME_QUIRKS_RESTORE) {
				gif->frames[frame].disposal_method = GIF_FRAME_RESTORE;
			}
			gif_data += (2 + gif_data[1]);
			break;

		case GIF_EXTENSION_APPLICATION:
			/* 14-byte+ Application Extension is:
			 *
			 *  +0    CHAR    Application Extension Label
			 *  +1    CHAR    Block Size
			 *  +2    8CHARS  Application Identifier
			 *  +10   3CHARS  Appl. Authentication Code
			 *  +13   1-256   Application Data (Data sub-blocks)
			 */
			if (gif_bytes < 17) {
				return GIF_INSUFFICIENT_FRAME_DATA;
			}
			if ((gif_data[1] == 0x0b) &&
			    (strncmp((const char *) gif_data + 2,
				     "NETSCAPE2.0", 11) == 0) &&
			    (gif_data[13] == 0x03) &&
			    (gif_data[14] == 0x01)) {
				gif->loop_count = gif_data[15] | (gif_data[16] << 8);
			}
			gif_data += (2 + gif_data[1]);
			break;

		case GIF_EXTENSION_COMMENT:
			/* Move the pointer to the first data sub-block Skip 1
			 * byte for the extension label
			 */
			++gif_data;
			break;

		default:
			/* Move the pointer to the first data sub-block Skip 2
			 * bytes for the extension label and size fields Skip
			 * the extension size itself
			 */
			if (gif_bytes < 2) {
				return GIF_INSUFFICIENT_FRAME_DATA;
			}
			gif_data += (2 + gif_data[1]);
		}

		/* Repeatedly skip blocks until we get a zero block or run out
		 * of data This data is ignored by this gif decoder
		 */
		gif_bytes = (gif_end - gif_data);
		block_size = 0;
		while (gif_data < gif_end && gif_data[0] != GIF_BLOCK_TERMINATOR) {
			block_size = gif_data[0] + 1;
			if ((gif_bytes -= block_size) < 0) {
				return GIF_INSUFFICIENT_FRAME_DATA;
			}
			gif_data += block_size;
		}
		++gif_data;
	}

	/* Set buffer position and return */
	gif->buffer_position = (gif_data - gif->gif_data);
	return GIF_OK;
}


/**
 * Attempts to initialise the next frame
 *
 * \param gif The animation context
 * \return error code
 *         - GIF_INSUFFICIENT_DATA for insufficient data to do anything
 *         - GIF_FRAME_DATA_ERROR for GIF frame data error
 *         - GIF_INSUFFICIENT_MEMORY for insufficient memory to process
 *         - GIF_INSUFFICIENT_FRAME_DATA for insufficient data to complete the frame
 *         - GIF_DATA_ERROR for GIF error (invalid frame header)
 *         - GIF_OK for successful decoding
 *         - GIF_WORKING for successful decoding if more frames are expected
*/
static gif_result gif_initialise_frame(gif_animation *gif)
{
	int frame;
	gif_frame *temp_buf;

	unsigned char *gif_data, *gif_end;
	int gif_bytes;
	unsigned int flags = 0;
	unsigned int width, height, offset_x, offset_y;
	unsigned int block_size, colour_table_size;
	bool first_image = true;
	gif_result return_value;

	/* Get the frame to decode and our data position */
	frame = gif->frame_count;

	/* Get our buffer position etc. */
	gif_data = (unsigned char *)(gif->gif_data + gif->buffer_position);
	gif_end = (unsigned char *)(gif->gif_data + gif->buffer_size);
	gif_bytes = (gif_end - gif_data);

	/* Check if we've finished */
	if ((gif_bytes > 0) && (gif_data[0] == GIF_TRAILER)) {
		return GIF_OK;
	}

	/* Check if there is enough data remaining. The shortest block of data
	 * is a 4-byte comment extension + 1-byte block terminator + 1-byte gif
	 * trailer
	 */
	if (gif_bytes < 6) {
		return GIF_INSUFFICIENT_DATA;
	}

	/* We could theoretically get some junk data that gives us millions of
	 * frames, so we ensure that we don't have a silly number
	 */
	if (frame > 4096) {
		return GIF_FRAME_DATA_ERROR;
	}

	/* Get some memory to store our pointers in etc. */
	if ((int)gif->frame_holders <= frame) {
		/* Allocate more memory */
		temp_buf = (gif_frame *)realloc(gif->frames, (frame + 1) * sizeof(gif_frame));
		if (temp_buf == NULL) {
			return GIF_INSUFFICIENT_MEMORY;
		}
		gif->frames = temp_buf;
		gif->frame_holders = frame + 1;
	}

	/* Store our frame pointer. We would do it when allocating except we
	 * start off with one frame allocated so we can always use realloc.
	 */
	gif->frames[frame].frame_pointer = gif->buffer_position;
	gif->frames[frame].display = false;
	gif->frames[frame].virgin = true;
	gif->frames[frame].disposal_method = 0;
	gif->frames[frame].transparency = false;
	gif->frames[frame].frame_delay = 100;
	gif->frames[frame].redraw_required = false;

	/* Invalidate any previous decoding we have of this frame */
	if (gif->decoded_frame == frame) {
		gif->decoded_frame = GIF_INVALID_FRAME;
	}

	/* We pretend to initialise the frames, but really we just skip over
	 * all the data contained within. This is all basically a cut down
	 * version of gif_decode_frame that doesn't have any of the LZW bits in
	 * it.
	 */

	/* Initialise any extensions */
	gif->buffer_position = gif_data - gif->gif_data;
	return_value = gif_initialise_frame_extensions(gif, frame);
	if (return_value != GIF_OK) {
		return return_value;
	}
	gif_data = (gif->gif_data + gif->buffer_position);
	gif_bytes = (gif_end - gif_data);

	/* Check if we've finished */
	if ((gif_bytes = (gif_end - gif_data)) < 1) {
		return GIF_INSUFFICIENT_FRAME_DATA;
	}

	if (gif_data[0] == GIF_TRAILER) {
		gif->buffer_position = (gif_data - gif->gif_data);
		gif->frame_count = frame + 1;
		return GIF_OK;
	}

	/* If we're not done, there should be an image descriptor */
	if (gif_data[0] != GIF_IMAGE_SEPARATOR) {
		return GIF_FRAME_DATA_ERROR;
	}

	/* Do some simple boundary checking */
	if (gif_bytes < 10) {
		return GIF_INSUFFICIENT_FRAME_DATA;
	}
	offset_x = gif_data[1] | (gif_data[2] << 8);
	offset_y = gif_data[3] | (gif_data[4] << 8);
	width = gif_data[5] | (gif_data[6] << 8);
	height = gif_data[7] | (gif_data[8] << 8);

	/* Set up the redraw characteristics. We have to check for extending
	 * the area due to multi-image frames.
	 */
	if (!first_image) {
		if (gif->frames[frame].redraw_x > offset_x) {
			gif->frames[frame].redraw_width += (gif->frames[frame].redraw_x - offset_x);
			gif->frames[frame].redraw_x = offset_x;
		}

		if (gif->frames[frame].redraw_y > offset_y) {
			gif->frames[frame].redraw_height += (gif->frames[frame].redraw_y - offset_y);
			gif->frames[frame].redraw_y = offset_y;
		}

		if ((offset_x + width) > (gif->frames[frame].redraw_x + gif->frames[frame].redraw_width)) {
			gif->frames[frame].redraw_width = (offset_x + width) - gif->frames[frame].redraw_x;
		}

		if ((offset_y + height) > (gif->frames[frame].redraw_y + gif->frames[frame].redraw_height)) {
			gif->frames[frame].redraw_height = (offset_y + height) - gif->frames[frame].redraw_y;
		}
	} else {
		first_image = false;
		gif->frames[frame].redraw_x = offset_x;
		gif->frames[frame].redraw_y = offset_y;
		gif->frames[frame].redraw_width = width;
		gif->frames[frame].redraw_height = height;
	}

	/* if we are clearing the background then we need to redraw enough to
	 * cover the previous frame too
	 */
	gif->frames[frame].redraw_required =
			((gif->frames[frame].disposal_method == GIF_FRAME_CLEAR) ||
			 (gif->frames[frame].disposal_method == GIF_FRAME_RESTORE));

	/* Frame size may have grown.
	 */
	gif->width = (offset_x + width > gif->width) ?
			offset_x + width : gif->width;
	gif->height = (offset_y + height > gif->height) ?
			offset_y + height : gif->height;

	/* Decode the flags */
	flags = gif_data[9];
	colour_table_size = 2 << (flags & GIF_COLOUR_TABLE_SIZE_MASK);

	/* Move our data onwards and remember we've got a bit of this frame */
	gif_data += 10;
	gif_bytes = (gif_end - gif_data);
	gif->frame_count_partial = frame + 1;

	/* Skip the local colour table */
	if (flags & GIF_COLOUR_TABLE_MASK) {
		gif_data += 3 * colour_table_size;
		if ((gif_bytes = (gif_end - gif_data)) < 0) {
			return GIF_INSUFFICIENT_FRAME_DATA;
		}
	}

	/* Ensure we have a correct code size */
	if (gif_bytes < 1) {
		return GIF_INSUFFICIENT_FRAME_DATA;
	}
	if (gif_data[0] >= LZW_CODE_MAX) {
		return GIF_DATA_ERROR;
	}

	/* Move our pointer to the actual image data */
	gif_data++;
	--gif_bytes;

	/* Repeatedly skip blocks until we get a zero block or run out of data
	 * These blocks of image data are processed later by gif_decode_frame()
	 */
	block_size = 0;
	while (block_size != 1) {
		if (gif_bytes < 1) return GIF_INSUFFICIENT_FRAME_DATA;
		block_size = gif_data[0] + 1;
		/* Check if the frame data runs off the end of the file	*/
		if ((int)(gif_bytes - block_size) < 0) {
			/* jcupitt 15/9/19
			 *
			 * There was code here to set a TRAILER tag. But this
			 * wrote to the input buffer, which will not work for
			 * libvips, where buffers can be mmaped read only files.
			 *
			 * Instead, just signal insufficient frame data.
			 */
			return GIF_INSUFFICIENT_FRAME_DATA;
		} else {
			gif_bytes -= block_size;
			gif_data += block_size;
		}
	}

	/* Add the frame and set the display flag */
	gif->buffer_position = gif_data - gif->gif_data;
	gif->frame_count = frame + 1;
	gif->frames[frame].display = true;

	/* Check if we've finished */
	if (gif_bytes < 1) {
		return GIF_INSUFFICIENT_FRAME_DATA;
	} else {
		if (gif_data[0] == GIF_TRAILER) {
			return GIF_OK;
		}
	}
	return GIF_WORKING;
}


/**
 * Skips the frame's extensions (which have been previously initialised)
 *
 * \param gif The animation context
 * \return GIF_INSUFFICIENT_FRAME_DATA for insufficient data to complete the
 *         frame GIF_OK for successful decoding
 */
static gif_result gif_skip_frame_extensions(gif_animation *gif)
{
	unsigned char *gif_data, *gif_end;
	int gif_bytes;
	unsigned int block_size;

	/* Get our buffer position etc.	*/
	gif_data = (unsigned char *)(gif->gif_data + gif->buffer_position);
	gif_end = (unsigned char *)(gif->gif_data + gif->buffer_size);
	gif_bytes = (gif_end - gif_data);

	/* Skip the extensions */
	while (gif_data < gif_end && gif_data[0] == GIF_EXTENSION_INTRODUCER) {
		++gif_data;
		if (gif_data >= gif_end) {
			return GIF_INSUFFICIENT_FRAME_DATA;
		}

		/* Switch on extension label */
		switch(gif_data[0]) {
		case GIF_EXTENSION_COMMENT:
			/* Move the pointer to the first data sub-block
			 * 1 byte for the extension label
			 */
			++gif_data;
			break;

		default:
			/* Move the pointer to the first data sub-block 2 bytes
			 * for the extension label and size fields Skip the
			 * extension size itself
			 */
			if (gif_data + 1 >= gif_end) {
				return GIF_INSUFFICIENT_FRAME_DATA;
			}
			gif_data += (2 + gif_data[1]);
		}

		/* Repeatedly skip blocks until we get a zero block or run out
		 * of data This data is ignored by this gif decoder
		 */
		gif_bytes = (gif_end - gif_data);
		block_size = 0;
		while (gif_data < gif_end && gif_data[0] != GIF_BLOCK_TERMINATOR) {
			block_size = gif_data[0] + 1;
			if ((gif_bytes -= block_size) < 0) {
				return GIF_INSUFFICIENT_FRAME_DATA;
			}
			gif_data += block_size;
		}
		++gif_data;
	}

	/* Set buffer position and return */
	gif->buffer_position = (gif_data - gif->gif_data);
	return GIF_OK;
}

static unsigned int gif_interlaced_line(int height, int y) {
	if ((y << 3) < height) {
		return (y << 3);
	}
	y -= ((height + 7) >> 3);
	if ((y << 3) < (height - 4)) {
		return (y << 3) + 4;
	}
	y -= ((height + 3) >> 3);
	if ((y << 2) < (height - 2)) {
		return (y << 2) + 2;
	}
	y -= ((height + 1) >> 2);
	return (y << 1) + 1;
}


static gif_result gif_error_from_lzw(lzw_result l_res)
{
	static const gif_result g_res[] = {
		[LZW_OK]	= GIF_OK,
		[LZW_OK_EOD]    = GIF_END_OF_FRAME,
		[LZW_NO_MEM]    = GIF_INSUFFICIENT_MEMORY,
		[LZW_NO_DATA]   = GIF_INSUFFICIENT_FRAME_DATA,
		[LZW_EOI_CODE]  = GIF_FRAME_DATA_ERROR,
		[LZW_BAD_ICODE] = GIF_FRAME_DATA_ERROR,
		[LZW_BAD_CODE]  = GIF_FRAME_DATA_ERROR,
	};
	return g_res[l_res];
}

static void gif__record_previous_frame(gif_animation *gif)
{
	bool need_alloc = gif->prev_frame == NULL;
	const uint32_t *frame_data;
	uint32_t *prev_frame;

	if (gif->decoded_frame == GIF_INVALID_FRAME ||
	    gif->decoded_frame == gif->prev_index) {
		/* No frame to copy, or already have this frame recorded. */
		return;
	}

	assert(gif->bitmap_callbacks.bitmap_get_buffer);
	frame_data = (void *)gif->bitmap_callbacks.bitmap_get_buffer(gif->frame_image);
	if (!frame_data) {
		return;
	}

	if (gif->prev_frame != NULL &&
	    gif->width * gif->height > gif->prev_width * gif->prev_height) {
		need_alloc = true;
	}

	if (need_alloc) {
		prev_frame = realloc(gif->prev_frame,
				gif->width * gif->height * 4);
		if (prev_frame == NULL) {
			return;
		}
	} else {
		prev_frame = gif->prev_frame;
	}

	memcpy(prev_frame, frame_data, gif->width * gif->height * 4);

	gif->prev_frame  = prev_frame;
	gif->prev_width  = gif->width;
	gif->prev_height = gif->height;
	gif->prev_index  = gif->decoded_frame;
}

static gif_result gif__recover_previous_frame(const gif_animation *gif)
{
	const uint32_t *prev_frame = gif->prev_frame;
	unsigned height = gif->height < gif->prev_height ? gif->height : gif->prev_height;
	unsigned width  = gif->width  < gif->prev_width  ? gif->width  : gif->prev_width;
	uint32_t *frame_data;

	if (prev_frame == NULL) {
		return GIF_FRAME_DATA_ERROR;
	}

	assert(gif->bitmap_callbacks.bitmap_get_buffer);
	frame_data = (void *)gif->bitmap_callbacks.bitmap_get_buffer(gif->frame_image);
	if (!frame_data) {
		return GIF_INSUFFICIENT_MEMORY;
	}

	for (unsigned y = 0; y < height; y++) {
		memcpy(frame_data, prev_frame, width * 4);

		frame_data += gif->width;
		prev_frame += gif->prev_width;
	}

	return GIF_OK;
}

static gif_result
gif__decode_complex(gif_animation *gif,
		unsigned int frame,
		unsigned int width,
		unsigned int height,
		unsigned int offset_x,
		unsigned int offset_y,
		unsigned int interlace,
		uint8_t minimum_code_size,
		unsigned int *restrict frame_data,
		unsigned int *restrict colour_table)
{
	unsigned int transparency_index;
	uint32_t available = 0;
	gif_result ret = GIF_OK;
	lzw_result res;

	/* Initialise the LZW decoding */
	res = lzw_decode_init(gif->lzw_ctx, gif->gif_data,
			gif->buffer_size, gif->buffer_position,
			minimum_code_size);
	if (res != LZW_OK) {
		return gif_error_from_lzw(res);
	}

	transparency_index = gif->frames[frame].transparency ?
			gif->frames[frame].transparency_index :
			GIF_NO_TRANSPARENCY;

	for (unsigned int y = 0; y < height; y++) {
		unsigned int x;
		unsigned int decode_y;
		unsigned int *frame_scanline;

		if (interlace) {
			decode_y = gif_interlaced_line(height, y) + offset_y;
		} else {
			decode_y = y + offset_y;
		}
		frame_scanline = frame_data + offset_x + (decode_y * gif->width);

		x = width;
		while (x > 0) {
			const uint8_t *uncompressed;
			unsigned row_available;
			if (available == 0) {
				if (res != LZW_OK) {
					/* Unexpected end of frame, try to recover */
					if (res == LZW_OK_EOD) {
						ret = GIF_OK;
					} else {
						ret = gif_error_from_lzw(res);
					}
					break;
				}
				res = lzw_decode_continuous(gif->lzw_ctx,
						&uncompressed, &available);
			}

			row_available = x < available ? x : available;
			x -= row_available;
			available -= row_available;
			while (row_available-- > 0) {
				register unsigned int colour;
				colour = *uncompressed++;
				if (colour != transparency_index) {
					*frame_scanline = colour_table[colour];
				}
				frame_scanline++;
			}
		}
	}
	return ret;
}

static gif_result
gif__decode_simple(gif_animation *gif,
		unsigned int frame,
		unsigned int height,
		unsigned int offset_y,
		uint8_t minimum_code_size,
		unsigned int *restrict frame_data,
		unsigned int *restrict colour_table)
{
	unsigned int transparency_index;
	uint32_t pixels = gif->width * height;
	uint32_t written = 0;
	gif_result ret = GIF_OK;
	lzw_result res;

	/* Initialise the LZW decoding */
	res = lzw_decode_init(gif->lzw_ctx, gif->gif_data,
			gif->buffer_size, gif->buffer_position,
			minimum_code_size);
	if (res != LZW_OK) {
		return gif_error_from_lzw(res);
	}

	transparency_index = gif->frames[frame].transparency ?
			gif->frames[frame].transparency_index :
			GIF_NO_TRANSPARENCY;

	frame_data += (offset_y * gif->width);

	while (pixels > 0) {
		res = lzw_decode_map_continuous(gif->lzw_ctx,
				transparency_index, colour_table,
				frame_data, pixels, &written);
		pixels -= written;
		frame_data += written;
		if (res != LZW_OK) {
			/* Unexpected end of frame, try to recover */
			if (res == LZW_OK_EOD) {
				ret = GIF_OK;
			} else {
				ret = gif_error_from_lzw(res);
			}
			break;
		}
	}

	if (pixels == 0) {
		ret = GIF_OK;
	}

	return ret;
}

static inline gif_result
gif__decode(gif_animation *gif,
		unsigned int frame,
		unsigned int width,
		unsigned int height,
		unsigned int offset_x,
		unsigned int offset_y,
		unsigned int interlace,
		uint8_t minimum_code_size,
		unsigned int *restrict frame_data,
		unsigned int *restrict colour_table)
{
	gif_result ret;

	if (interlace == false && width == gif->width && offset_x == 0) {
		ret = gif__decode_simple(gif, frame, height, offset_y,
				minimum_code_size, frame_data, colour_table);
	} else {
		ret = gif__decode_complex(gif, frame, width, height,
				offset_x, offset_y, interlace,
				minimum_code_size, frame_data, colour_table);
	}

	return ret;
}

/**
 * decode a gif frame
 *
 * \param gif gif animation context.
 * \param frame The frame number to decode.
 * \param clear_image flag for image data being cleared instead of plotted.
 */
static gif_result
gif_internal_decode_frame(gif_animation *gif,
			  unsigned int frame,
			  bool clear_image)
{
	gif_result err;
	unsigned int index = 0;
	unsigned char *gif_data, *gif_end;
	int gif_bytes;
	unsigned int width, height, offset_x, offset_y;
	unsigned int flags, colour_table_size, interlace;
	unsigned int *colour_table;
	unsigned int *frame_data = 0; // Set to 0 for no warnings
	unsigned int save_buffer_position;
	unsigned int return_value = 0;

	/* Ensure this frame is supposed to be decoded */
	if (gif->frames[frame].display == false) {
		return GIF_OK;
	}

	/* Ensure the frame is in range to decode */
	if (frame > gif->frame_count_partial) {
		return GIF_INSUFFICIENT_DATA;
	}

	/* done if frame is already decoded */
	if ((!clear_image) &&
	    ((int)frame == gif->decoded_frame)) {
		return GIF_OK;
	}

	/* Get the start of our frame data and the end of the GIF data */
	gif_data = gif->gif_data + gif->frames[frame].frame_pointer;
	gif_end = gif->gif_data + gif->buffer_size;
	gif_bytes = (gif_end - gif_data);

	/*
	 * Ensure there is a minimal amount of data to proceed.  The shortest
	 * block of data is a 10-byte image descriptor + 1-byte gif trailer
	 */
	if (gif_bytes < 12) {
		return GIF_INSUFFICIENT_FRAME_DATA;
	}

	/* Save the buffer position */
	save_buffer_position = gif->buffer_position;
	gif->buffer_position = gif_data - gif->gif_data;

	/* Skip any extensions because they have already been processed */
	if ((return_value = gif_skip_frame_extensions(gif)) != GIF_OK) {
		goto gif_decode_frame_exit;
	}
	gif_data = (gif->gif_data + gif->buffer_position);
	gif_bytes = (gif_end - gif_data);

	/* Ensure we have enough data for the 10-byte image descriptor + 1-byte
	 * gif trailer
	 */
	if (gif_bytes < 12) {
		return_value = GIF_INSUFFICIENT_FRAME_DATA;
		goto gif_decode_frame_exit;
	}

	/* 10-byte Image Descriptor is:
	 *
	 *  +0   CHAR   Image Separator (0x2c)
	 *  +1   SHORT  Image Left Position
	 *  +3   SHORT  Image Top Position
	 *  +5   SHORT  Width
	 *  +7   SHORT  Height
	 *  +9   CHAR   __Packed Fields__
	 *              1BIT    Local Colour Table Flag
	 *              1BIT    Interlace Flag
	 *              1BIT    Sort Flag
	 *              2BITS   Reserved
	 *              3BITS   Size of Local Colour Table
	 */
	if (gif_data[0] != GIF_IMAGE_SEPARATOR) {
		return_value = GIF_DATA_ERROR;
		goto gif_decode_frame_exit;
	}
	offset_x = gif_data[1] | (gif_data[2] << 8);
	offset_y = gif_data[3] | (gif_data[4] << 8);
	width = gif_data[5] | (gif_data[6] << 8);
	height = gif_data[7] | (gif_data[8] << 8);

	/* Boundary checking - shouldn't ever happen except unless the data has
	 * been modified since initialisation.
	 */
	if ((offset_x + width > gif->width) ||
	    (offset_y + height > gif->height)) {
		return_value = GIF_DATA_ERROR;
		goto gif_decode_frame_exit;
	}

	/* Make sure we have a buffer to decode to.
	 */
	if (gif_initialise_sprite(gif, gif->width, gif->height)) {
		return GIF_INSUFFICIENT_MEMORY;
	}

	/* Decode the flags */
	flags = gif_data[9];
	colour_table_size = 2 << (flags & GIF_COLOUR_TABLE_SIZE_MASK);
	interlace = flags & GIF_INTERLACE_MASK;

	/* Advance data pointer to next block either colour table or image
	 * data.
	 */
	gif_data += 10;
	gif_bytes = (gif_end - gif_data);

	/* Set up the colour table */
	if (flags & GIF_COLOUR_TABLE_MASK) {
		if (gif_bytes < (int)(3 * colour_table_size)) {
			return_value = GIF_INSUFFICIENT_FRAME_DATA;
			goto gif_decode_frame_exit;
		}
		colour_table = gif->local_colour_table;
		if (!clear_image) {
			for (index = 0; index < colour_table_size; index++) {
				/* Gif colour map contents are r,g,b.
				 *
				 * We want to pack them bytewise into the
				 * colour table, such that the red component
				 * is in byte 0 and the alpha component is in
				 * byte 3.
				 */
				unsigned char *entry =
					(unsigned char *) &colour_table[index];

				entry[0] = gif_data[0]; /* r */
				entry[1] = gif_data[1]; /* g */
				entry[2] = gif_data[2]; /* b */
				entry[3] = 0xff;        /* a */

				gif_data += 3;
			}
		} else {
			gif_data += 3 * colour_table_size;
		}
		gif_bytes = (gif_end - gif_data);
	} else {
		colour_table = gif->global_colour_table;
	}

	/* Ensure sufficient data remains */
	if (gif_bytes < 1) {
		return_value = GIF_INSUFFICIENT_FRAME_DATA;
		goto gif_decode_frame_exit;
	}

	/* check for an end marker */
	if (gif_data[0] == GIF_TRAILER) {
		return_value = GIF_OK;
		goto gif_decode_frame_exit;
	}

	/* Get the frame data */
	assert(gif->bitmap_callbacks.bitmap_get_buffer);
	frame_data = (void *)gif->bitmap_callbacks.bitmap_get_buffer(gif->frame_image);
	if (!frame_data) {
		return GIF_INSUFFICIENT_MEMORY;
	}

	/* If we are clearing the image we just clear, if not decode */
	if (!clear_image) {
		/* Ensure we have enough data for a 1-byte LZW code size +
		 * 1-byte gif trailer
		 */
		if (gif_bytes < 2) {
			return_value = GIF_INSUFFICIENT_FRAME_DATA;
			goto gif_decode_frame_exit;
		}

		/* If we only have a 1-byte LZW code size + 1-byte gif trailer,
		 * we're finished
		 */
		if ((gif_bytes == 2) && (gif_data[1] == GIF_TRAILER)) {
			return_value = GIF_OK;
			goto gif_decode_frame_exit;
		}

		/* If the previous frame's disposal method requires we restore
		 * the background colour or this is the first frame, clear
		 * the frame data
		 */
		if ((frame == 0) || (gif->decoded_frame == GIF_INVALID_FRAME)) {
			memset((char*)frame_data,
			       GIF_TRANSPARENT_COLOUR,
			       gif->width * gif->height * sizeof(int));
			gif->decoded_frame = frame;
			/* The line below would fill the image with its
			 * background color, but because GIFs support
			 * transparency we likely wouldn't want to do that. */
			/* memset((char*)frame_data, colour_table[gif->background_index], gif->width * gif->height * sizeof(int)); */
		} else if ((frame != 0) &&
			   (gif->frames[frame - 1].disposal_method == GIF_FRAME_CLEAR)) {
			return_value = gif_internal_decode_frame(gif,
								 (frame - 1),
								 true);
			if (return_value != GIF_OK) {
				goto gif_decode_frame_exit;
			}

		} else if ((frame != 0) &&
			   (gif->frames[frame - 1].disposal_method == GIF_FRAME_RESTORE)) {
			/*
			 * If the previous frame's disposal method requires we
			 * restore the previous image, restore our saved image.
			 */
			err = gif__recover_previous_frame(gif);
			if (err != GIF_OK) {
				/* see notes above on transparency
				 * vs. background color
				 */
				memset((char*)frame_data,
				       GIF_TRANSPARENT_COLOUR,
				       gif->width * gif->height * sizeof(int));
			}
		}

		if (gif->frames[frame].disposal_method == GIF_FRAME_RESTORE) {
			/* Store the previous frame for later restoration */
			gif__record_previous_frame(gif);
		}

		gif->decoded_frame = frame;
		gif->buffer_position = (gif_data - gif->gif_data) + 1;

		return_value = gif__decode(gif, frame, width, height,
				offset_x, offset_y, interlace, gif_data[0],
				frame_data, colour_table);
	} else {
		/* Clear our frame */
		if (gif->frames[frame].disposal_method == GIF_FRAME_CLEAR) {
			unsigned int y;
			for (y = 0; y < height; y++) {
				unsigned int *frame_scanline;
				frame_scanline = frame_data + offset_x + ((offset_y + y) * gif->width);
				if (gif->frames[frame].transparency) {
					memset(frame_scanline,
					       GIF_TRANSPARENT_COLOUR,
					       width * 4);
				} else {
					memset(frame_scanline,
					       colour_table[gif->background_index],
					       width * 4);
				}
			}
		}
	}
gif_decode_frame_exit:

	/* Check if we should test for optimisation */
	if (gif->frames[frame].virgin) {
		if (gif->bitmap_callbacks.bitmap_test_opaque) {
			gif->frames[frame].opaque = gif->bitmap_callbacks.bitmap_test_opaque(gif->frame_image);
		} else {
			gif->frames[frame].opaque = false;
		}
		gif->frames[frame].virgin = false;
	}

	if (gif->bitmap_callbacks.bitmap_set_opaque) {
		gif->bitmap_callbacks.bitmap_set_opaque(gif->frame_image, gif->frames[frame].opaque);
	}

	if (gif->bitmap_callbacks.bitmap_modified) {
		gif->bitmap_callbacks.bitmap_modified(gif->frame_image);
	}

	/* Restore the buffer position */
	gif->buffer_position = save_buffer_position;

	return return_value;
}


/* exported function documented in libnsgif.h */
void gif_create(gif_animation *gif, gif_bitmap_callback_vt *bitmap_callbacks)
{
	memset(gif, 0, sizeof(gif_animation));
	gif->bitmap_callbacks = *bitmap_callbacks;
	gif->decoded_frame = GIF_INVALID_FRAME;
	gif->prev_index = GIF_INVALID_FRAME;
}


/* exported function documented in libnsgif.h */
gif_result gif_initialise(gif_animation *gif, size_t size, unsigned char *data)
{
	unsigned char *gif_data;
	unsigned int index;
	gif_result return_value;

	/* Initialize values */
	gif->buffer_size = size;
	gif->gif_data = data;

	if (gif->lzw_ctx == NULL) {
		lzw_result res = lzw_context_create(
				(struct lzw_ctx **)&gif->lzw_ctx);
		if (res != LZW_OK) {
			return gif_error_from_lzw(res);
		}
	}

	/* Check for sufficient data to be a GIF (6-byte header + 7-byte
	 * logical screen descriptor)
	 */
	if (gif->buffer_size < GIF_STANDARD_HEADER_SIZE) {
		return GIF_INSUFFICIENT_DATA;
	}

	/* Get our current processing position */
	gif_data = gif->gif_data + gif->buffer_position;

	/* See if we should initialise the GIF */
	if (gif->buffer_position == 0) {
		/* We want everything to be NULL before we start so we've no
		 * chance of freeing bad pointers (paranoia)
		 */
		gif->frame_image = NULL;
		gif->frames = NULL;
		gif->local_colour_table = NULL;
		gif->global_colour_table = NULL;

		/* The caller may have been lazy and not reset any values */
		gif->frame_count = 0;
		gif->frame_count_partial = 0;
		gif->decoded_frame = GIF_INVALID_FRAME;

		/* 6-byte GIF file header is:
		 *
		 *  +0   3CHARS   Signature ('GIF')
		 *  +3   3CHARS   Version ('87a' or '89a')
		 */
		if (strncmp((const char *) gif_data, "GIF", 3) != 0) {
			return GIF_DATA_ERROR;
		}
		gif_data += 3;

		/* Ensure GIF reports version 87a or 89a */
		/*
		if ((strncmp(gif_data, "87a", 3) != 0) &&
		    (strncmp(gif_data, "89a", 3) != 0))
			       LOG(("Unknown GIF format - proceeding anyway"));
		*/
		gif_data += 3;

		/* 7-byte Logical Screen Descriptor is:
		 *
		 *  +0   SHORT   Logical Screen Width
		 *  +2   SHORT   Logical Screen Height
		 *  +4   CHAR    __Packed Fields__
		 *               1BIT    Global Colour Table Flag
		 *               3BITS   Colour Resolution
		 *               1BIT    Sort Flag
		 *               3BITS   Size of Global Colour Table
		 *  +5   CHAR    Background Colour Index
		 *  +6   CHAR    Pixel Aspect Ratio
		 */
		gif->width = gif_data[0] | (gif_data[1] << 8);
		gif->height = gif_data[2] | (gif_data[3] << 8);
		gif->global_colours = (gif_data[4] & GIF_COLOUR_TABLE_MASK);
		gif->colour_table_size = (2 << (gif_data[4] & GIF_COLOUR_TABLE_SIZE_MASK));
		gif->background_index = gif_data[5];
		gif->aspect_ratio = gif_data[6];
		gif->loop_count = 1;
		gif_data += 7;

		/* Some broken GIFs report the size as the screen size they
		 * were created in. As such, we detect for the common cases and
		 * set the sizes as 0 if they are found which results in the
		 * GIF being the maximum size of the frames.
		 */
		if (((gif->width == 640) && (gif->height == 480)) ||
		    ((gif->width == 640) && (gif->height == 512)) ||
		    ((gif->width == 800) && (gif->height == 600)) ||
		    ((gif->width == 1024) && (gif->height == 768)) ||
		    ((gif->width == 1280) && (gif->height == 1024)) ||
		    ((gif->width == 1600) && (gif->height == 1200)) ||
		    ((gif->width == 0) || (gif->height == 0)) ||
		    ((gif->width > 2048) || (gif->height > 2048))) {
			gif->width = 1;
			gif->height = 1;
		}

		/* Allocate some data irrespective of whether we've got any
		 * colour tables. We always get the maximum size in case a GIF
		 * is lying to us. It's far better to give the wrong colours
		 * than to trample over some memory somewhere.
		*/
		gif->global_colour_table = calloc(GIF_MAX_COLOURS, sizeof(unsigned int));
		gif->local_colour_table = calloc(GIF_MAX_COLOURS, sizeof(unsigned int));
		if ((gif->global_colour_table == NULL) ||
		    (gif->local_colour_table == NULL)) {
			gif_finalise(gif);
			return GIF_INSUFFICIENT_MEMORY;
		}

		/* Set the first colour to a value that will never occur in
		 * reality so we know if we've processed it
		*/
		gif->global_colour_table[0] = GIF_PROCESS_COLOURS;

		/* Check if the GIF has no frame data (13-byte header + 1-byte
		 * termination block) Although generally useless, the GIF
		 * specification does not expressly prohibit this
		 */
		if (gif->buffer_size == (GIF_STANDARD_HEADER_SIZE + 1)) {
			if (gif_data[0] == GIF_TRAILER) {
				return GIF_OK;
			} else {
				return GIF_INSUFFICIENT_DATA;
			}
		}

		/* Initialise enough workspace for a frame */
		if ((gif->frames = (gif_frame *)malloc(sizeof(gif_frame))) == NULL) {
			gif_finalise(gif);
			return GIF_INSUFFICIENT_MEMORY;
		}
		gif->frame_holders = 1;

		/* Remember we've done this now */
		gif->buffer_position = gif_data - gif->gif_data;
	}

	/*  Do the colour map if we haven't already. As the top byte is always
	 *  0xff or 0x00 depending on the transparency we know if it's been
	 *  filled in.
	 */
	if (gif->global_colour_table[0] == GIF_PROCESS_COLOURS) {
		/* Check for a global colour map signified by bit 7 */
		if (gif->global_colours) {
			if (gif->buffer_size < (gif->colour_table_size * 3 + GIF_STANDARD_HEADER_SIZE)) {
				return GIF_INSUFFICIENT_DATA;
			}
			for (index = 0; index < gif->colour_table_size; index++) {
				/* Gif colour map contents are r,g,b.
				 *
				 * We want to pack them bytewise into the
				 * colour table, such that the red component
				 * is in byte 0 and the alpha component is in
				 * byte 3.
				 */
				unsigned char *entry = (unsigned char *) &gif->
						       global_colour_table[index];

				entry[0] = gif_data[0]; /* r */
				entry[1] = gif_data[1]; /* g */
				entry[2] = gif_data[2]; /* b */
				entry[3] = 0xff;        /* a */

				gif_data += 3;
			}
			gif->buffer_position = (gif_data - gif->gif_data);
		} else {
			/* Create a default colour table with the first two
			 * colours as black and white
			 */
			unsigned int *entry = gif->global_colour_table;

			entry[0] = 0x00000000;
			/* Force Alpha channel to opaque */
			((unsigned char *) entry)[3] = 0xff;

			entry[1] = 0xffffffff;
		}
	}

	/* Repeatedly try to initialise frames */
	while ((return_value = gif_initialise_frame(gif)) == GIF_WORKING);

	/* If there was a memory error tell the caller */
	if ((return_value == GIF_INSUFFICIENT_MEMORY) ||
	    (return_value == GIF_DATA_ERROR)) {
		return return_value;
	}

	/* If we didn't have some frames then a GIF_INSUFFICIENT_DATA becomes a
	 * GIF_INSUFFICIENT_FRAME_DATA
	 */
	if ((return_value == GIF_INSUFFICIENT_DATA) &&
	    (gif->frame_count_partial > 0)) {
		return GIF_INSUFFICIENT_FRAME_DATA;
	}

	/* Return how many we got */
	return return_value;
}


/* exported function documented in libnsgif.h */
gif_result gif_decode_frame(gif_animation *gif, unsigned int frame)
{
	return gif_internal_decode_frame(gif, frame, false);
}


/* exported function documented in libnsgif.h */
void gif_finalise(gif_animation *gif)
{
	/* Release all our memory blocks */
	if (gif->frame_image) {
		assert(gif->bitmap_callbacks.bitmap_destroy);
		gif->bitmap_callbacks.bitmap_destroy(gif->frame_image);
	}

	gif->frame_image = NULL;
	free(gif->frames);
	gif->frames = NULL;
	free(gif->local_colour_table);
	gif->local_colour_table = NULL;
	free(gif->global_colour_table);
	gif->global_colour_table = NULL;

	free(gif->prev_frame);
	gif->prev_frame = NULL;

	lzw_context_destroy(gif->lzw_ctx);
	gif->lzw_ctx = NULL;
}
