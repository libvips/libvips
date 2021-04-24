/*
 * This file is part of NetSurf's LibNSGIF, http://www.netsurf-browser.org/
 * Licensed under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 *
 * Copyright 2017 Michael Drake <michael.drake@codethink.co.uk>
 */

#ifndef LZW_H_
#define LZW_H_

/**
 * \file
 * \brief LZW decompression (interface)
 *
 * Decoder for GIF LZW data.
 */


/** Maximum LZW code size in bits */
#define LZW_CODE_MAX 12


/* Declare lzw internal context structure */
struct lzw_ctx;


/** LZW decoding response codes */
typedef enum lzw_result {
	LZW_OK,        /**< Success */
	LZW_OK_EOD,    /**< Success; reached zero-length sub-block */
	LZW_NO_MEM,    /**< Error: Out of memory */
	LZW_NO_DATA,   /**< Error: Out of data */
	LZW_EOI_CODE,  /**< Error: End of Information code */
	LZW_BAD_ICODE, /**< Error: Bad initial LZW code */
	LZW_BAD_CODE,  /**< Error: Bad LZW code */
} lzw_result;


/**
 * Create an LZW decompression context.
 *
 * \param[out] ctx  Returns an LZW decompression context.  Caller owned,
 *                  free with lzw_context_destroy().
 * \return LZW_OK on success, or appropriate error code otherwise.
 */
lzw_result lzw_context_create(
		struct lzw_ctx **ctx);

/**
 * Destroy an LZW decompression context.
 *
 * \param[in] ctx  The LZW decompression context to destroy.
 */
void lzw_context_destroy(
		struct lzw_ctx *ctx);

/**
 * Initialise an LZW decompression context for decoding.
 *
 * Caller owns neither `stack_base_out` or `stack_pos_out`.
 *
 * \param[in]  ctx                  The LZW decompression context to initialise.
 * \param[in]  compressed_data      The compressed data.
 * \param[in]  compressed_data_len  Byte length of compressed data.
 * \param[in]  compressed_data_pos  Start position in data.  Must be position
 *                                  of a size byte at sub-block start.
 * \param[in]  minimum_code_size    The LZW Minimum Code Size.
 * \param[out] stack_base_out       Returns base of decompressed data stack.
 * \return LZW_OK on success, or appropriate error code otherwise.
 */
lzw_result lzw_decode_init(
		struct lzw_ctx *ctx,
		const uint8_t *compressed_data,
		uint32_t compressed_data_len,
		uint32_t compressed_data_pos,
		uint8_t minimum_code_size);

/**
 * Read input codes until end of lzw context owned output buffer.
 *
 * Ensure anything in output is used before calling this, as anything
 * on the there before this call will be trampled.
 *
 * \param[in]  ctx   LZW reading context, updated.
 * \param[out] data  Returns pointer to array of output values.
 * \param[out] used  Returns the number of values written to data.
 * \return LZW_OK on success, or appropriate error code otherwise.
 */
lzw_result lzw_decode_continuous(struct lzw_ctx *ctx,
		const uint8_t *restrict *const restrict data,
		uint32_t *restrict used);

/**
 * Read LZW codes into client buffer, mapping output to colours.
 *
 * Ensure anything in output is used before calling this, as anything
 * on the there before this call will be trampled.
 *
 * For transparency to work correctly, the given client buffer must have
 * the values from the previous frame.  The transparency_idx should be a value
 * of 256 or above, if the frame does not have transparency.
 *
 * \param[in]  ctx              LZW reading context, updated.
 * \param[in]  transparency_idx Index representing transparency.
 * \param[in]  colour_map       Index to pixel colour mapping
 * \param[in]  data             Client buffer to fill with colour mapped values.
 * \param[in]  length           Size of output array.
 * \param[out] used             Returns the number of values written to data.
 * \return LZW_OK on success, or appropriate error code otherwise.
 */
lzw_result lzw_decode_map_continuous(struct lzw_ctx *ctx,
		uint32_t transparency_idx,
		uint32_t *restrict colour_table,
		uint32_t *restrict data,
		uint32_t length,
		uint32_t *restrict used);

#endif
