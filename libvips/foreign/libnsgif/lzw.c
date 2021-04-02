/*
 * This file is part of NetSurf's LibNSGIF, http://www.netsurf-browser.org/
 * Licensed under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 *
 * Copyright 2017 Michael Drake <michael.drake@codethink.co.uk>
 * Copyright 2021 Michael Drake <tlsa@netsurf-browser.org>
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

/** Maximum number of lzw table entries. */
#define LZW_TABLE_ENTRY_MAX (1u << LZW_CODE_MAX)

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
 * LZW table entry.
 *
 * Records in the table are composed of 1 or more entries.
 * Entries refer to the entry they extend which can be followed to compose
 * the complete record.  To compose the record in reverse order, take
 * the `value` from each entry, and move to the entry it extends.
 * If the extended entries index is < the current clear_code, then it
 * is the last entry in the record.
 */
struct lzw_table_entry {
	uint8_t  value;   /**< Last value for record ending at entry. */
	uint8_t  first;   /**< First value in entry's entire record. */
	uint16_t count;   /**< Count of values in this entry's record. */
	uint16_t extends; /**< Offset in table to previous entry. */
};

/**
 * LZW decompression context.
 */
struct lzw_ctx {
	struct lzw_read_ctx input; /**< Input reading context */

	uint32_t prev_code;       /**< Code read from input previously. */
	uint32_t prev_code_first; /**< First value of previous code. */
	uint32_t prev_code_count; /**< Total values for previous code. */

	uint32_t initial_code_size; /**< Starting LZW code size. */

	uint32_t code_size; /**< Current LZW code size. */
	uint32_t code_max;  /**< Max code value for current code size. */

	uint32_t clear_code; /**< Special Clear code value */
	uint32_t eoi_code;   /**< Special End of Information code value */

	uint32_t table_size; /**< Next position in table to fill. */

	/** Output value stack. */
	uint8_t stack_base[LZW_TABLE_ENTRY_MAX];

	/** LZW code table. Generated during decode. */
	struct lzw_table_entry table[LZW_TABLE_ENTRY_MAX];
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
static inline lzw_result lzw__read_code(
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
 * Clear LZW code table.
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

	/* Reset table building context */
	ctx->code_size = ctx->initial_code_size;
	ctx->code_max = (1 << ctx->initial_code_size) - 1;
	ctx->table_size = ctx->eoi_code + 1;

	/* There might be a sequence of clear codes, so process them all */
	do {
		lzw_result res = lzw__read_code(&ctx->input,
				ctx->code_size, &code);
		if (res != LZW_OK) {
			return res;
		}
	} while (code == ctx->clear_code);

	/* The initial code must be from the initial table. */
	if (code > ctx->clear_code) {
		return LZW_BAD_ICODE;
	}

	/* Record this initial code as "previous" code, needed during decode. */
	ctx->prev_code = code;
	ctx->prev_code_first = code;
	ctx->prev_code_count = 1;

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
		uint8_t minimum_code_size,
		const uint8_t ** const stack_base_out,
		const uint8_t ** const stack_pos_out)
{
	struct lzw_table_entry *table = ctx->table;

	if (minimum_code_size >= LZW_CODE_MAX) {
		return LZW_BAD_ICODE;
	}

	/* Initialise the input reading context */
	ctx->input.data = compressed_data;
	ctx->input.data_len = compressed_data_len;
	ctx->input.data_sb_next = compressed_data_pos;

	ctx->input.sb_bit = 0;
	ctx->input.sb_bit_count = 0;

	/* Initialise the table building context */
	ctx->initial_code_size = minimum_code_size + 1;

	ctx->clear_code = (1 << minimum_code_size) + 0;
	ctx->eoi_code   = (1 << minimum_code_size) + 1;

	/* Initialise the standard table entries */
	for (uint32_t i = 0; i < ctx->clear_code; ++i) {
		table[i].first = i;
		table[i].value = i;
		table[i].count = 1;
	}

	*stack_base_out = ctx->stack_base;
	return lzw__clear_codes(ctx, stack_pos_out);
}

/**
 * Create new table entry.
 *
 * \param[in]  ctx   LZW reading context, updated.
 * \param[in]  code  Last value code for new table entry.
 */
static inline void lzw__table_add_entry(
		struct lzw_ctx *ctx,
		uint32_t code)
{
	struct lzw_table_entry *entry = &ctx->table[ctx->table_size];

	entry->value = code;
	entry->first = ctx->prev_code_first;
	entry->count = ctx->prev_code_count + 1;
	entry->extends = ctx->prev_code;

	ctx->table_size++;
}

/**
 * Write values for this code to the output stack.
 *
 * \param[in]  ctx            LZW reading context, updated.
 * \param[in]  code           LZW code to output values for.
 * \param[out] stack_pos_out  Returns current stack position.
 *                            There are `stack_pos_out - ctx->stack_base`
 *                            current stack entries.
 */
static inline void lzw__write_pixels(struct lzw_ctx *ctx,
		uint32_t code,
		const uint8_t ** const stack_pos_out)
{
	uint8_t *stack_pos = ctx->stack_base;
	uint32_t clear_code = ctx->clear_code;
	struct lzw_table_entry * const table = ctx->table;

	while (code > clear_code) {
		struct lzw_table_entry *entry = table + code;
		*stack_pos++ = entry->value;
		code = entry->extends;
	}
	*stack_pos++ = table[code].value;

	*stack_pos_out = stack_pos;
	return;
}

/* Exported function, documented in lzw.h */
lzw_result lzw_decode(struct lzw_ctx *ctx,
		const uint8_t ** const stack_pos_out)
{
	lzw_result res;
	uint32_t code;

	/* Get a new code from the input */
	res = lzw__read_code(&ctx->input, ctx->code_size, &code);
	if (res != LZW_OK) {
		return res;
	}

	/* Handle the new code */
	if (code == ctx->clear_code) {
		/* Got Clear code */
		return lzw__clear_codes(ctx, stack_pos_out);

	} else if (code == ctx->eoi_code) {
		/* Got End of Information code */
		return LZW_EOI_CODE;

	} else if (code > ctx->table_size) {
		/* Code is invalid */
		return LZW_BAD_CODE;
	}

	if (ctx->table_size < LZW_TABLE_ENTRY_MAX) {
		uint32_t size = ctx->table_size;
		lzw__table_add_entry(ctx, (code < size) ?
				ctx->table[code].first :
				ctx->prev_code_first);

		/* Ensure code size is increased, if needed. */
		if (size == ctx->code_max && ctx->code_size < LZW_CODE_MAX) {
			ctx->code_size++;
			ctx->code_max = (1 << ctx->code_size) - 1;
		}
	}

	/* Store details of this code as "previous code" to the context. */
	ctx->prev_code_first = ctx->table[code].first;
	ctx->prev_code_count = ctx->table[code].count;
	ctx->prev_code = code;

	lzw__write_pixels(ctx, code, stack_pos_out);
	return LZW_OK;
}
