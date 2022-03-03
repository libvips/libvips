/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (C) 2021 Michael Drake <tlsa@netsurf-browser.org>
 */

/**
 * \file
 * \brief Command line argument handling API.
 */

#ifndef _PELTAR_CLI_H_
#define _PELTAR_CLI_H_

#include <stdint.h>
#include <stdbool.h>

/**
 * Helper to get element count for an array,
 *
 * \param[in]  _a  Array to get number of elements for.
 */
#define CLI_ARRAY_LEN(_a) ((sizeof(_a))/(sizeof(*(_a))))

/**
 * CLI argument type.
 */
enum cli_arg_type {
	CLI_CMD,    /**< A sub-command. Must match long argument name. */
	CLI_BOOL,   /**< Has no value; presence of flag indicates true. */
	CLI_INT,    /**< Has signed integer value. */
	CLI_UINT,   /**< Has unsigned integer value. */
	CLI_ENUM,   /**< Has enumeration value. */
	CLI_STRING, /**< Has string value. */
};

struct cli_str_val {
	const char *str;
	int64_t val;
};

struct cli_enum {
	const struct cli_str_val *desc;
	int64_t *e; /**< Location to store \ref CLI_ENUM value. */
};

/**
 * Client description for a command line argument.
 */
struct cli_table_entry {
	const char *l; /**< Long argument name. */
	const char  s; /**< Short flag name. (Non-positional arguments.) */
	bool p; /**< Whether the argument is a positional argument. */
	enum cli_arg_type t; /**< Argument type. */
	union {
		bool *b;        /**< Location to store \ref CLI_BOOL value. */
		int64_t *i;     /**< Location to store \ref CLI_INT value. */
		uint64_t *u;    /**< Location to store \ref CLI_UINT value. */
		const char **s; /**< Location to store \ref CLI_STRING value. */
		struct cli_enum e;
	} v; /**< Where to store type-specific values. */
	const char *d; /**< Description. */
};

/**
 * Client command line interface specification.
 */
struct cli_table {
	const struct cli_table_entry *entries;
	size_t count;
	size_t min_positional;
};

/**
 * Parse the command line arguments.
 *
 * \param[in]  cli   Client command line interface specification.
 * \param[in]  argc  Number of command line arguments.
 * \param[in]  argv  String vector containing command line arguments.
 * \return true on success, false on error.
 */
bool cli_parse(const struct cli_table *cli, int argc, const char **argv);

/**
 * Print usage and help output.
 *
 * Note: Assumes non-Unicode. (One byte per character.)
 *
 * \param[in]  cli        Client command line interface specification.
 * \param[in]  prog_name  Program name.
 */
void cli_help(const struct cli_table *cli, const char *prog_name);

#endif
