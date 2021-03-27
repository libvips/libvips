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
 * \param[in]  code_size            The initial LZW code size to use.
 * \param[out] stack_base_out       Returns base of decompressed data stack.
 * \param[out] stack_pos_out        Returns current stack position.
 *                                  There are `stack_pos_out - stack_base_out`
 *                                  current stack entries.
 * \return LZW_OK on success, or appropriate error code otherwise.
 */
lzw_result lzw_decode_init(
		struct lzw_ctx *ctx,
		const uint8_t *compressed_data,
		uint32_t compressed_data_len,
		uint32_t compressed_data_pos,
		uint8_t code_size,
		const uint8_t ** const stack_base_out,
		const uint8_t ** const stack_pos_out);

/**
 * Fill the LZW stack with decompressed data
 *
 * Ensure anything on the stack is used before calling this, as anything
 * on the stack before this call will be trampled.
 *
 * Caller does not own `stack_pos_out`.
 *
 * \param[in]  ctx            LZW reading context, updated.
 * \param[out] stack_pos_out  Returns current stack position.
 *                            Use with `stack_base_out` value from previous
 *                            lzw_decode_init() call.
 *                            There are `stack_pos_out - stack_base_out`
 *                            current stack entries.
 * \return LZW_OK on success, or appropriate error code otherwise.
 */
lzw_result lzw_decode(
		struct lzw_ctx *ctx,
		const uint8_t ** const stack_pos_out);


#endif
