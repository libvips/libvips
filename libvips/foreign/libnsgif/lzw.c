/*
 * This file is part of NetSurf's LibNSGIF, http://www.netsurf-browser.org/
 * Licensed under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 *
 * Copyright 2017 Michael Drake <michael.drake@codethink.co.uk>
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "lzw.h"

/**
 * \file
 * \brief LZW decompression (implementation)
 *
 * Decoder for GIF LZW data.
 */


/**
 * Context for reading LZW data.
 *
 * LZW data is split over multiple sub-blocks.  Each sub-block has a
 * byte at the start, which says the sub-block size, and then the data.
 * Zero-size sub-blocks have no data, and the biggest sub-block size is
 * 255, which means there are 255 bytes of data following the sub-block
 * size entry.
 *
 * Note that an individual LZW code can be split over up to three sub-blocks.
 */
struct lzw_read_ctx {
	const uint8_t *data;    /**< Pointer to start of input data */
	uint32_t data_len;      /**< Input data length */
	uint32_t data_sb_next;  /**< Offset to sub-block size */

	const uint8_t *sb_data; /**< Pointer to current sub-block in data */
	uint32_t sb_bit;        /**< Current bit offset in sub-block */
	uint32_t sb_bit_count;  /**< Bit count in sub-block */
};

/**
 * LZW dictionary entry.
 *
 * Records in the dictionary are composed of 1 or more entries.
 * Entries point to previous entries which can be followed to compose
 * the complete record.  To compose the record in reverse order, take
 * the `last_value` from each entry, and move to the previous entry.
 * If the previous_entry's index is < the current clear_code, then it
 * is the last entry in the record.
 */
struct lzw_dictionary_entry {
	uint8_t last_value;      /**< Last value for record ending at entry. */
	uint8_t first_value;     /**< First value for entry's record. */
	uint16_t previous_entry; /**< Offset in dictionary to previous entry. */
};

/**
 * LZW decompression context.
 */
struct lzw_ctx {
	/** Input reading context */
	struct lzw_read_ctx input;

	uint32_t previous_code;       /**< Code read from input previously. */
	uint32_t previous_code_first; /**< First value of previous code. */

	uint32_t initial_code_size;     /**< Starting LZW code size. */
	uint32_t current_code_size;     /**< Current LZW code size. */
	uint32_t current_code_size_max; /**< Max code value for current size. */

	uint32_t clear_code; /**< Special Clear code value */
	uint32_t eoi_code;   /**< Special End of Information code value */

	uint32_t current_entry; /**< Next position in table to fill. */

	/** Output value stack. */
	uint8_t stack_base[1 << LZW_CODE_MAX];

	/** LZW decode dictionary. Generated during decode. */
	struct lzw_dictionary_entry table[1 << LZW_CODE_MAX];
};


/* Exported function, documented in lzw.h */
lzw_result lzw_context_create(struct lzw_ctx **ctx)
{
	struct lzw_ctx *c = malloc(sizeof(*c));
	if (c == NULL) {
		return LZW_NO_MEM;
	}

	*ctx = c;
	return LZW_OK;
}


/* Exported function, documented in lzw.h */
void lzw_context_destroy(struct lzw_ctx *ctx)
{
	free(ctx);
}


/**
 * Advance the context to the next sub-block in the input data.
 *
 * \param[in] ctx  LZW reading context, updated on success.
 * \return LZW_OK or LZW_OK_EOD on success, appropriate error otherwise.
 */
static lzw_result lzw__block_advance(struct lzw_read_ctx *ctx)
{
	uint32_t block_size;
	uint32_t next_block_pos = ctx->data_sb_next;
	const uint8_t *data_next = ctx->data + next_block_pos;

	if (next_block_pos >= ctx->data_len) {
		return LZW_NO_DATA;
	}

	block_size = *data_next;

	if ((next_block_pos + block_size) >= ctx->data_len) {
		return LZW_NO_DATA;
	}

	ctx->sb_bit = 0;
	ctx->sb_bit_count = block_size * 8;

	if (block_size == 0) {
		ctx->data_sb_next += 1;
		return LZW_OK_EOD;
	}

	ctx->sb_data = data_next + 1;
	ctx->data_sb_next += block_size + 1;

	return LZW_OK;
}


/**
 * Get the next LZW code of given size from the raw input data.
 *
 * Reads codes from the input data stream coping with GIF data sub-blocks.
 *
 * \param[in]  ctx        LZW reading context, updated.
 * \param[in]  code_size  Size of LZW code to get from data.
 * \param[out] code_out   Returns an LZW code on success.
 * \return LZW_OK or LZW_OK_EOD on success, appropriate error otherwise.
 */
static inline lzw_result lzw__next_code(
		struct lzw_read_ctx *ctx,
		uint8_t code_size,
		uint32_t *code_out)
{
	uint32_t code = 0;
	uint8_t current_bit = ctx->sb_bit & 0x7;
	uint8_t byte_advance = (current_bit + code_size) >> 3;

	assert(byte_advance <= 2);

	if (ctx->sb_bit + code_size <= ctx->sb_bit_count) {
		/* Fast path: code fully inside this sub-block */
		const uint8_t *data = ctx->sb_data + (ctx->sb_bit >> 3);
		switch (byte_advance) {
			case 2: code |= data[2] << 16; /* Fall through */
			case 1: code |= data[1] <<  8; /* Fall through */
			case 0: code |= data[0] <<  0;
		}
		ctx->sb_bit += code_size;
	} else {
		/* Slow path: code spans sub-blocks */
		uint8_t byte = 0;
		uint8_t bits_remaining_0 = (code_size < (8 - current_bit)) ?
				code_size : (8 - current_bit);
		uint8_t bits_remaining_1 = code_size - bits_remaining_0;
		uint8_t bits_used[3] = {
			[0] = bits_remaining_0,
			[1] = bits_remaining_1 < 8 ? bits_remaining_1 : 8,
			[2] = bits_remaining_1 - 8,
		};

		while (true) {
			const uint8_t *data = ctx->sb_data;
			lzw_result res;

			/* Get any data from end of this sub-block */
			while (byte <= byte_advance &&
					ctx->sb_bit < ctx->sb_bit_count) {
				code |= data[ctx->sb_bit >> 3] << (byte << 3);
				ctx->sb_bit += bits_used[byte];
				byte++;
			}

			/* Check if we have all we need */
			if (byte > byte_advance) {
				break;
			}

			/* Move to next sub-block */
			res = lzw__block_advance(ctx);
			if (res != LZW_OK) {
				return res;
			}
		}
	}

	*code_out = (code >> current_bit) & ((1 << code_size) - 1);
	return LZW_OK;
}


/**
 * Clear LZW code dictionary.
 *
 * \param[in]  ctx            LZW reading context, updated.
 * \param[out] stack_pos_out  Returns current stack position.
 * \return LZW_OK or error code.
 */
static lzw_result lzw__clear_codes(
		struct lzw_ctx *ctx,
		const uint8_t ** const stack_pos_out)
{
	uint32_t code;
	uint8_t *stack_pos;

	/* Reset dictionary building context */
	ctx->current_code_size = ctx->initial_code_size + 1;
	ctx->current_code_size_max = (1 << ctx->current_code_size) - 1;;
	ctx->current_entry = (1 << ctx->initial_code_size) + 2;

	/* There might be a sequence of clear codes, so process them all */
	do {
		lzw_result res = lzw__next_code(&ctx->input,
				ctx->current_code_size, &code);
		if (res != LZW_OK) {
			return res;
		}
	} while (code == ctx->clear_code);

	/* The initial code must be from the initial dictionary. */
	if (code > ctx->clear_code) {
		return LZW_BAD_ICODE;
	}

	/* Record this initial code as "previous" code, needed during decode. */
	ctx->previous_code = code;
	ctx->previous_code_first = code;

	/* Reset the stack, and add first non-clear code added as first item. */
	stack_pos = ctx->stack_base;
	*stack_pos++ = code;

	*stack_pos_out = stack_pos;
	return LZW_OK;
}


/* Exported function, documented in lzw.h */
lzw_result lzw_decode_init(
		struct lzw_ctx *ctx,
		const uint8_t *compressed_data,
		uint32_t compressed_data_len,
		uint32_t compressed_data_pos,
		uint8_t code_size,
		const uint8_t ** const stack_base_out,
		const uint8_t ** const stack_pos_out)
{
	struct lzw_dictionary_entry *table = ctx->table;

	/* Initialise the input reading context */
	ctx->input.data = compressed_data;
	ctx->input.data_len = compressed_data_len;
	ctx->input.data_sb_next = compressed_data_pos;

	ctx->input.sb_bit = 0;
	ctx->input.sb_bit_count = 0;

	/* Initialise the dictionary building context */
	ctx->initial_code_size = code_size;

	ctx->clear_code = (1 << code_size) + 0;
	ctx->eoi_code   = (1 << code_size) + 1;

	/* Initialise the standard dictionary entries */
	for (uint32_t i = 0; i < ctx->clear_code; ++i) {
		table[i].first_value = i;
		table[i].last_value  = i;
	}

	*stack_base_out = ctx->stack_base;
	return lzw__clear_codes(ctx, stack_pos_out);
}


/* Exported function, documented in lzw.h */
lzw_result lzw_decode(struct lzw_ctx *ctx,
		const uint8_t ** const stack_pos_out)
{
	lzw_result res;
	uint32_t code_new;
	uint32_t code_out;
	uint8_t last_value;
	uint8_t *stack_pos = ctx->stack_base;
	uint32_t clear_code = ctx->clear_code;
	uint32_t current_entry = ctx->current_entry;
	struct lzw_dictionary_entry * const table = ctx->table;

	/* Get a new code from the input */
	res = lzw__next_code(&ctx->input, ctx->current_code_size, &code_new);
	if (res != LZW_OK) {
		return res;
	}

	/* Handle the new code */
	if (code_new == clear_code) {
		/* Got Clear code */
		return lzw__clear_codes(ctx, stack_pos_out);

	} else if (code_new == ctx->eoi_code) {
		/* Got End of Information code */
		return LZW_EOI_CODE;

	} else if (code_new > current_entry) {
		/* Code is invalid */
		return LZW_BAD_CODE;

	} else if (code_new < current_entry) {
		/* Code is in table */
		code_out = code_new;
		last_value = table[code_new].first_value;
	} else {
		/* Code not in table */
		*stack_pos++ = ctx->previous_code_first;
		code_out = ctx->previous_code;
		last_value = ctx->previous_code_first;
	}

	/* Add to the dictionary, only if there's space */
	if (current_entry < (1 << LZW_CODE_MAX)) {
		struct lzw_dictionary_entry *entry = table + current_entry;
		entry->last_value     = last_value;
		entry->first_value    = ctx->previous_code_first;
		entry->previous_entry = ctx->previous_code;
		ctx->current_entry++;
	}

	/* Ensure code size is increased, if needed. */
	if (current_entry == ctx->current_code_size_max) {
		if (ctx->current_code_size < LZW_CODE_MAX) {
			ctx->current_code_size++;
			ctx->current_code_size_max =
					(1 << ctx->current_code_size) - 1;
		}
	}

	/* Store details of this code as "previous code" to the context. */
	ctx->previous_code_first = table[code_new].first_value;
	ctx->previous_code = code_new;

	/* Put rest of data for this code on output stack.
	 * Note, in the case of "code not in table", the last entry of the
	 * current code has already been placed on the stack above. */
	while (code_out > clear_code) {
		struct lzw_dictionary_entry *entry = table + code_out;
		*stack_pos++ = entry->last_value;
		code_out = entry->previous_entry;
	}
	*stack_pos++ = table[code_out].last_value;

	*stack_pos_out = stack_pos;
	return LZW_OK;
}
