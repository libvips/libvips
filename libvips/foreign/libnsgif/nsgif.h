/*
 * Copyright 2004 Richard Wilson <richard.wilson@netsurf-browser.org>
 * Copyright 2008 Sean Fox <dyntryx@gmail.com>
 * Copyright 2013-2022 Michael Drake <tlsa@netsurf-browser.org>
 *
 * This file is part of NetSurf's libnsgif, http://www.netsurf-browser.org/
 * Licenced under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 */

/**
 * \file
 * Interface to progressive animated GIF file decoding.
 */

#ifndef NSNSGIF_H
#define NSNSGIF_H

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

/** Representation of infinity. */
#define NSGIF_INFINITE (UINT32_MAX)

/**
 * Opaque type used by LibNSGIF to represent a GIF object in memory.
 */
typedef struct nsgif nsgif_t;

/**
 * LibNSGIF rectangle structure.
 *
 * * Top left coordinate is `(x0, y0)`.
 * * Width is `x1 - x0`.
 * * Height is `y1 - y0`.
 * * Units are pixels.
 */
typedef struct nsgif_rect {
	/** x co-ordinate of redraw rectangle, left */
	uint32_t x0;
	/** y co-ordinate of redraw rectangle, top */
	uint32_t y0;
	/** x co-ordinate of redraw rectangle, right */
	uint32_t x1;
	/** y co-ordinate of redraw rectangle, bottom */
	uint32_t y1;
} nsgif_rect_t;

/**
 * LibNSGIF return codes.
 */
typedef enum {
	/**
	 * Success.
	 */
	NSGIF_OK,

	/**
	 * Out of memory error.
	 */
	NSGIF_ERR_OOM,

	/**
	 * GIF source data is invalid, and no frames are recoverable.
	 */
	NSGIF_ERR_DATA,

	/**
	 * Frame number is not valid.
	 */
	NSGIF_ERR_BAD_FRAME,

	/**
	 * GIF source data contained an error in a frame.
	 */
	NSGIF_ERR_DATA_FRAME,

	/**
	 * Too many frames.
	 */
	NSGIF_ERR_FRAME_COUNT,

	/**
	 * Unexpected end of GIF source data.
	 */
	NSGIF_ERR_END_OF_DATA,

	/**
	 * The current frame cannot be displayed.
	 */
	NSGIF_ERR_FRAME_DISPLAY,

	/**
	 * Indicates an animation is complete, and \ref nsgif_reset must be
	 * called to restart the animation from the beginning.
	 */
	NSGIF_ERR_ANIMATION_END,
} nsgif_error;

/**
 * Client bitmap type.
 *
 * These are client-created and destroyed, via the \ref bitmap callbacks,
 * but they are owned by a \ref nsgif_t.
 *
 * The pixel buffer is is 32bpp, treated as individual bytes in the component
 * order RR GG BB AA. For example, a 1x1 image with a single orange pixel would
 * be encoded as the following sequence of bytes: 0xff, 0x88, 0x00, 0x00.
 */
typedef void nsgif_bitmap_t;

/** Bitmap callbacks function table */
typedef struct nsgif_bitmap_cb_vt {
	/**
	 * Callback to create a bitmap with the given dimensions.
	 *
	 * \param[in]  width   Required bitmap width in pixels.
	 * \param[in]  height  Required bitmap height in pixels.
	 * \return pointer to client's bitmap structure or NULL on error.
	 */
	nsgif_bitmap_t* (*create)(int width, int height);

	/**
	 * Callback to free a bitmap.
	 *
	 * \param[in]  bitmap  The bitmap to destroy.
	 */
	void (*destroy)(nsgif_bitmap_t *bitmap);

	/**
	 * Get pointer to pixel buffer in a bitmap.
	 *
	 * The pixel buffer must be `width * height * sizeof(uint32_t)`.
	 * Note that the returned pointer to uint8_t must be 4-byte aligned.
	 *
	 * \param[in]  bitmap  The bitmap.
	 * \return pointer to bitmap's pixel buffer.
	 */
	uint8_t* (*get_buffer)(nsgif_bitmap_t *bitmap);

	/* The following functions are optional. */

	/**
	 * Set whether a bitmap can be plotted opaque.
	 *
	 * \param[in]  bitmap  The bitmap.
	 * \param[in]  opaque  Whether the current frame is opaque.
	 */
	void (*set_opaque)(nsgif_bitmap_t *bitmap, bool opaque);

	/**
	 * Tests whether a bitmap has an opaque alpha channel.
	 *
	 * \param[in]  bitmap  The bitmap.
	 * \return true if the bitmap is opaque, false otherwise.
	 */
	bool (*test_opaque)(nsgif_bitmap_t *bitmap);

	/**
	 * Bitmap modified notification.
	 *
	 * \param[in]  bitmap  The bitmap.
	 */
	void (*modified)(nsgif_bitmap_t *bitmap);
} nsgif_bitmap_cb_vt;

/**
 * Convert an error code to a string.
 *
 * \param[in]  err  The error code to convert.
 * \return String representation of given error code.
 */
const char *nsgif_strerror(nsgif_error err);

/**
 * Create the NSGIF object.
 *
 * \param[in]  bitmap_vt  Bitmap operation functions v-table.
 * \param[out] gif_out    Return \ref nsgif_t object on success.
 *
 * \return NSGIF_OK on success, or appropriate error otherwise.
 */
nsgif_error nsgif_create(
		const nsgif_bitmap_cb_vt *bitmap_vt,
		nsgif_t **gif_out);

/**
 * Free a NSGIF object.
 *
 * \param[in]  gif  The NSGIF to free.
 */
void nsgif_destroy(nsgif_t *gif);

/**
 * Scan the source image data.
 *
 * This is used to feed the source data into LibNSGIF. This must be called
 * before calling \ref nsgif_frame_decode.
 *
 * It can be called multiple times with, with increasing sizes. If it is called
 * several times, as more data is available (e.g. slow network fetch) the data
 * already given to \ref nsgif_data_scan must be provided each time.
 *
 * For example, if you call \ref nsgif_data_scan with 25 bytes of data, and then
 * fetch another 10 bytes, you would need to call \ref nsgif_data_scan with a
 * size of 35 bytes, and the whole 35 bytes must be contiguous memory. It is
 * safe to `realloc` the source buffer between calls to \ref nsgif_data_scan.
 * (The actual data pointer is allowed to be different.)
 *
 * If an error occurs, all previously scanned frames are retained.
 *
 * Note that an error returned from this function is purely informational.
 * So long as at least one frame is available, you can display frames.
 *
 * \param[in]  gif     The \ref nsgif_t object.
 * \param[in]  size    Number of bytes in data.
 * \param[in]  data    Raw source GIF data.
 *
 * \return NSGIF_OK on success, or appropriate error otherwise.
 */
nsgif_error nsgif_data_scan(
		nsgif_t *gif,
		size_t size,
		const uint8_t *data);

/**
 * Prepare to show a frame.
 *
 * If this is the last frame of an animation with a finite loop count, the
 * returned `delay_cs` will be \ref NSGIF_INFINITE, indicating that the frame
 * should be shown forever.
 *
 * \param[in]  gif        The \ref nsgif_t object.
 * \param[out] area       The area in pixels that must be redrawn.
 * \param[out] delay_cs   Time to wait after frame_new before next frame in cs.
 * \param[out] frame_new  The frame to decode.
 *
 * \return NSGIF_OK on success, or appropriate error otherwise.
 */
nsgif_error nsgif_frame_prepare(
		nsgif_t *gif,
		nsgif_rect_t *area,
		uint32_t *delay_cs,
		uint32_t *frame_new);

/**
 * Decodes a GIF frame.
 *
 * \param[in]  gif     The \ref nsgif_t object.
 * \param[in]  frame   The frame number to decode.
 * \param[out] bitmap  On success, returns pointer to the client-allocated,
 *                     nsgif-owned client bitmap structure.
 *
 * \return NSGIF_OK on success, or appropriate error otherwise.
 */
nsgif_error nsgif_frame_decode(
		nsgif_t *gif,
		uint32_t frame,
		nsgif_bitmap_t **bitmap);

/**
 * Reset a GIF animation.
 *
 * Some animations are only meant to loop N times, and then show the
 * final frame forever. This function resets the loop and frame counters,
 * so that the animation can be replayed without the overhead of recreating
 * the \ref nsgif_t object and rescanning the raw data.
 *
 * \param[in]  gif  A \ref nsgif_t object.
 *
 * \return NSGIF_OK on success, or appropriate error otherwise.
 */
nsgif_error nsgif_reset(
		nsgif_t *gif);

/**
 * Information about a GIF.
 */
typedef struct nsgif_info {
	/** width of GIF (may increase during decoding) */
	uint32_t width;
	/** height of GIF (may increase during decoding) */
	uint32_t height;
	/** number of frames decoded */
	uint32_t frame_count;
	/** number of times to loop animation */
	int loop_max;
	/** number of animation loops so far */
	int loop_count;
	/** background colour in same pixel format as \ref nsgif_bitmap_t. */
	uint8_t background[4];
} nsgif_info_t;

/**
 * Frame disposal method.
 *
 * Clients do not need to know about this, it is provided purely for dumping
 * raw information about GIF frames.
 */
enum nsgif_disposal {
	NSGIF_DISPOSAL_UNSPECIFIED,   /**< No disposal method specified. */
	NSGIF_DISPOSAL_NONE,          /**< Frame remains. */
	NSGIF_DISPOSAL_RESTORE_BG,    /**< Clear frame to background colour. */
	NSGIF_DISPOSAL_RESTORE_PREV,  /**< Restore previous frame. */
	NSGIF_DISPOSAL_RESTORE_QUIRK, /**< Alias for NSGIF_DISPOSAL_RESTORE_PREV. */
};

/**
 * Convert a disposal method to a string.
 *
 * \param[in]  disposal  The disposal method to convert.
 * \return String representation of given disposal method.
 */
const char *nsgif_str_disposal(enum nsgif_disposal disposal);

/**
 * Information about a GIF frame.
 */
typedef struct nsgif_frame_info {
	/** whether the frame should be displayed/animated */
	bool display;
	/** whether the frame may have transparency */
	bool transparency;

	/** Disposal method for previous frame; affects plotting */
	uint8_t disposal;
	/** delay (in cs) before animating the frame */
	uint32_t delay;

	/** Frame's redraw rectangle. */
	nsgif_rect_t rect;
} nsgif_frame_info_t;

/**
 * Get information about a GIF from an \ref nsgif_t object.
 *
 * \param[in]  gif  The \ref nsgif_t object to get info for.
 *
 * \return The gif info, or NULL on error.
 */
const nsgif_info_t *nsgif_get_info(const nsgif_t *gif);

/**
 * Get information about a GIF from an \ref nsgif_t object.
 *
 * \param[in]  gif    The \ref nsgif_t object to get frame info for.
 * \param[in]  frame  The frame number to get info for.
 *
 * \return The gif frame info, or NULL on error.
 */
const nsgif_frame_info_t *nsgif_get_frame_info(
		const nsgif_t *gif,
		uint32_t frame);

#endif
