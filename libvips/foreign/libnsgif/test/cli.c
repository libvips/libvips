/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (C) 2021 Michael Drake <tlsa@netsurf-browser.org>
 */

/**
 * \file
 * \brief Command line argument handling.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"

/**
 * Check whether a CLI argument type should have a numerical value.
 *
 * \param[in]  type  An argument type.
 * \return true if the argument needs a numerical value, or false otherwise.
 */
static inline bool cli__arg_is_numerical(enum cli_arg_type type)
{
	return (type != CLI_STRING && type != CLI_BOOL);
}

/**
 * Parse a signed integer value from an argument.
 *
 * \param[in]     str  String containing value to parse.
 * \param[out]    i    Pointer to place to store parsed value.
 * \param[in,out] pos  Current position in str, updated on exit.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_value_int(
		const char *str,
		int64_t *i,
		size_t *pos)
{
	long long temp;
	char *end = NULL;

	str += *pos;
	errno = 0;
	temp = strtoll(str, &end, 0);

	if (end == str || errno == ERANGE ||
	    temp > INT64_MAX || temp < INT64_MIN) {
		fprintf(stderr, "Failed to parse integer from '%s'\n", str);
		return false;
	}

	*i = (int64_t)temp;
	*pos += (size_t)(end - str);
	return true;
}

/**
 * Parse an unsigned integer value from an argument.
 *
 * \param[in]     str  String containing value to parse.
 * \param[out]    u    Pointer to place to store parsed value.
 * \param[in,out] pos  Current position in str, updated on exit.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_value_uint(
		const char *str,
		uint64_t *u,
		size_t *pos)
{
	unsigned long long temp;
	char *end = NULL;

	str += *pos;
	errno = 0;
	temp = strtoull(str, &end, 0);

	if (end == str || errno == ERANGE || temp > UINT64_MAX) {
		fprintf(stderr, "Failed to parse unsigned from '%s'\n", str);
		return false;
	}

	*u = (uint64_t)temp;
	*pos += (size_t)(end - str);
	return true;
}

/**
 * Parse an enum value from an argument.
 *
 * \param[in]     str  String containing value to parse.
 * \param[out]    e    Enum details.
 * \param[in,out] pos  Current position in str, updated on exit.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_value_enum(
		const char *str,
		const struct cli_enum *e,
		size_t *pos)
{
	str += *pos;
	*pos += strlen(str);

	for (const struct cli_str_val *sv = e->desc; sv->str != NULL; sv++) {
		if (strcmp(str, sv->str) == 0) {
			*e->e = sv->val;
			return true;
		}
	}

	return false;
}

/**
 * Parse a string value from an argument.
 *
 * \param[in]     str  String containing value to parse.
 * \param[out]    s    Pointer to place to store parsed value.
 * \param[in,out] pos  Current position in str, updated on exit.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_value_string(
		const char *str,
		const char **s,
		size_t *pos)
{
	*s = str + *pos;
	*pos += strlen(*s);
	return true;
}

/**
 * Parse a value from an argument.
 *
 * \param[in]     entry  Client command line interface argument specification.
 * \param[in]     arg    Argument to parse a value from.
 * \param[in,out] pos    Current position in argument, updated on exit.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_value(
		const struct cli_table_entry *entry,
		const char *arg,
		size_t *pos)
{
	switch (entry->t) {
	case CLI_CMD:
		if (strcmp(arg + *pos, entry->l) == 0) {
			*pos += strlen(arg);
			return true;
		}
		return false;

	case CLI_INT:
		return cli__parse_value_int(arg, entry->v.i, pos);

	case CLI_UINT:
		return cli__parse_value_uint(arg, entry->v.u, pos);

	case CLI_ENUM:
		return cli__parse_value_enum(arg, &entry->v.e, pos);

	case CLI_STRING:
		return cli__parse_value_string(arg, entry->v.s, pos);

	default:
		fprintf(stderr, "Unexpected value for '%s': %s\n",
				entry->l, arg);
		break;
	}

	return false;
}

/**
 * Parse a value from an argument.
 *
 * \param[in]     entry    Client command line interface argument specification.
 * \param[in]     argc     Number of command line arguments.
 * \param[in]     argv     String vector containing command line arguments.
 * \param[in]     arg_pos  Current position in argv.
 * \param[in,out] pos      Current pos in current argument, updated on exit.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_argv_value(const struct cli_table_entry *entry,
		int argc, const char **argv,
		int arg_pos, size_t *pos)
{
	const char *arg = argv[arg_pos];

	if (arg_pos >= argc) {
		fprintf(stderr, "Value not given for '%s'\n", entry->l);
		return false;
	}

	return cli__parse_value(entry, arg, pos);
}

/**
 * Check whether a CLI argument is a positional value.
 *
 * \param[in]  entry    Client command line interface argument specification.
 * \return true if the argument is positional, or false otherwise.
 */
static inline bool cli__entry_is_positional(const struct cli_table_entry *entry)
{
	return entry->p;
}

/**
 * Look up a short argument flag.
 *
 * \param[in]  cli  Client command line interface specification.
 * \param[in]  s    Argument flag to look up in client CLI spec.
 * \return Client CLI spec entry on success, or NULL otherwise.
 */
static const struct cli_table_entry *cli__lookup_short(
		const struct cli_table *cli, char s)
{
	for (size_t i = 0; i < cli->count; i++) {
		if (cli__entry_is_positional(&cli->entries[i])) {
			continue;
		}
		if (cli->entries[i].s == s) {
			return &cli->entries[i];
		}
	}

	fprintf(stderr, "Unknown flag: '%c'\n", s);
	return NULL;
}

/**
 * Handle an argument with a type that requires a value.
 *
 * This can handle the value being in the current argument, optionally split by
 * a separator, or in the next argument.
 *
 * \param[in]     entry    Client command line interface argument specification.
 * \param[in]     argc     Number of command line arguments.
 * \param[in]     argv     String vector containing command line arguments.
 * \param[in,out] arg_pos  Current position in argv, updated on exit.
 * \param[in]     pos      Current position in current argument string.
 * \param[in]     sep      Name/value separator character, or '\0' if none.
 * \return true on success, or false otherwise.
 */
static bool cli__handle_arg_value(const struct cli_table_entry *entry,
		int argc, const char **argv, int *arg_pos, size_t pos, char sep)
{
	const char *arg = argv[*arg_pos];
	size_t orig_pos;
	bool ret;

	if (arg[pos] == '\0') {
		(*arg_pos)++;
		pos = 0;
	} else if (arg[pos] == sep) {
		pos++;
	} else if (cli__arg_is_numerical(entry->t) == false) {
		fprintf(stderr, "Separator required for non-numerical value\n");
		return false;
	}

	if (isspace(argv[*arg_pos][pos])) {
		fprintf(stderr, "Unexpected white space in '%s' "
				"for argument '%s'\n",
				&argv[*arg_pos][pos], entry->l);
		return false;
	}

	orig_pos = pos;
	ret = cli__parse_argv_value(entry, argc, argv, *arg_pos, &pos);
	if (ret != true) {
		return ret;
	}

	if (argv[*arg_pos][pos] != '\0') {
		fprintf(stderr, "Invalid value '%s' for argument '%s'\n",
				&argv[*arg_pos][orig_pos], entry->l);
		return false;
	}

	return true;
}

/**
 * Parse a flags argument.
 *
 * \param[in]  cli      Client command line interface specification.
 * \param[in]  argc     Number of command line arguments.
 * \param[in]  argv     String vector containing command line arguments.
 * \param[out] arg_pos  Current position in argv, updated on exit.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_short(const struct cli_table *cli,
		int argc, const char **argv, int *arg_pos)
{
	const char *arg = argv[*arg_pos];
	size_t pos = 1;

	if (arg[0] != '-') {
		return false;
	}

	while (arg[pos] != '\0') {
		const struct cli_table_entry *entry;

		entry = cli__lookup_short(cli, arg[pos]);
		if (entry == NULL) {
			return false;
		}

		if (entry->t == CLI_BOOL) {
			*entry->v.b = true;
		} else {
			return cli__handle_arg_value(entry, argc, argv,
					arg_pos, pos + 1, '\0');
		}

		pos++;
	}

	return true;
}

/**
 * Look up a long argument name.
 *
 * \param[in]     cli  Client command line interface specification.
 * \param[in]     arg  Argument name to look up in cli spec.
 * \param[in,out] pos  Current position in arg, updated on exit.
 * \return Client CLI spec entry on success, or NULL otherwise.
 */
static const struct cli_table_entry *cli__lookup_long(
		const struct cli_table *cli,
		const char *arg,
		size_t *pos)
{
	arg += *pos;

	for (size_t i = 0; i < cli->count; i++) {
		if (cli__entry_is_positional(&cli->entries[i]) == false) {
			const char *name = cli->entries[i].l;
			size_t name_len = strlen(cli->entries[i].l);

			if (strncmp(name, arg, name_len) == 0) {
				if (arg[name_len] != '\0' &&
				    arg[name_len] != '=') {
					continue;
				}
				*pos += name_len;
				return &cli->entries[i];
			}
		}
	}

	fprintf(stderr, "Unknown argument: '%s'\n", arg);
	return NULL;
}

/**
 * Parse a long argument.
 *
 * \param[in]  cli      Client command line interface specification.
 * \param[in]  argc     Number of command line arguments.
 * \param[in]  argv     String vector containing command line arguments.
 * \param[out] arg_pos  Current position in argv, updated on exit.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_long(const struct cli_table *cli,
		int argc, const char **argv, int *arg_pos)
{
	const struct cli_table_entry *entry;
	const char *arg = argv[*arg_pos];
	size_t pos = 2;

	if (arg[0] != '-' ||
	    arg[1] != '-') {
		return false;
	}

	entry = cli__lookup_long(cli, arg, &pos);
	if (entry == NULL) {
		return false;
	}

	if (entry->t == CLI_BOOL) {
		if (arg[pos] != '\0') {
			fprintf(stderr, "Unexpected value for argument '%s'\n",
					arg);
			return false;
		}
		*entry->v.b = true;
	} else {
		bool ret;

		ret = cli__handle_arg_value(entry, argc, argv,
				arg_pos, pos, '=');
		if (ret != true) {
			return ret;
		}
	}

	return true;
}

/**
 * Parse a positional argument according to the given CLI spec entry.
 *
 * \param[in] entry  Client command line interface argument specification.
 * \param[in] arg    Argument to parse.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_positional_entry(
		const struct cli_table_entry *entry,
		const char *arg)
{
	size_t pos = 0;
	bool ret;

	ret = cli__parse_value(entry, arg, &pos);
	if (ret != true) {
		return ret;
	} else if (arg[pos] != '\0') {
		fprintf(stderr, "Failed to parse value '%s' for arg '%s'\n",
				arg, entry->l);
		return false;
	}

	return true;
}

/**
 * Parse a positional argument.
 *
 * \param[in] cli    Client command line interface specification.
 * \param[in] arg    Argument to parse.
 * \param[in] count  Number of positional arguments parsed already.
 * \return true on success, or false otherwise.
 */
static bool cli__parse_positional(const struct cli_table *cli,
		const char *arg, size_t count)
{
	size_t positional = 0;

	for (size_t i = 0; i < cli->count; i++) {
		if (cli__entry_is_positional(&cli->entries[i])) {
			if (positional == count) {
				return cli__parse_positional_entry(
						&cli->entries[i], arg);
			}

			positional++;
		}
	}

	fprintf(stderr, "Unexpected positional argument: '%s'\n", arg);
	return false;
}

/**
 * Get the string to indicate type of value expected for an argument.
 *
 * \param[in] type  The argument type.
 * \return String for value type.
 */
static const char *cli__string_from_type(enum cli_arg_type type)
{
	static const char *const strings[] = {
		[CLI_BOOL]   = "",
		[CLI_INT]    = "INT",
		[CLI_UINT]   = "UINT",
		[CLI_ENUM]   = "ENUM",
		[CLI_STRING] = "STRING",
	};

	if (type >= CLI_ARRAY_LEN(strings) || strings[type] == NULL) {
		return "";
	}

	return strings[type];
}

/**
 * Helper to update a maximum adjusted string length if new values is greater.
 *
 * \param[in]  str         String to check.
 * \param[in]  adjustment  Amount to modify length of string by (bytes).
 * \param[out] len         Returns the maximum of existing and this length.
 */
static void cli__max_len(const char *str, size_t adjustment, size_t *len)
{
	size_t str_len = strlen(str) + adjustment;

	if (str_len > *len) {
		*len = str_len;
	}
}

/**
 * Count up various properties of the client CLI interface specification.
 *
 * \param[in]  cli        Client command line interface specification.
 * \param[out] count      Returns number of non-positional arguments.
 * \param[out] pcount     Returns number of positional arguments.
 * \param[out] max_len    Returns max string length of non-positional arguments.
 * \param[out] pmax_len   Returns max string length of positional arguments.
 * \param[out] phas_desc  Returns number of positional args with descriptions.
 */
static void cli__count(const struct cli_table *cli,
		size_t *count,
		size_t *pcount,
		size_t *max_len,
		size_t *pmax_len,
		size_t *phas_desc)
{
	if (count != NULL) *count = 0;
	if (pcount != NULL) *pcount = 0;
	if (max_len != NULL) *max_len = 0;
	if (pmax_len != NULL) *pmax_len = 0;
	if (phas_desc != NULL) *phas_desc = 0;

	for (size_t i = 0; i < cli->count; i++) {
		const struct cli_table_entry *entry = &cli->entries[i];

		if (cli__entry_is_positional(entry)) {
			if (pcount != NULL) {
				(*pcount)++;
			}
			if (pmax_len != NULL) {
				cli__max_len(entry->l, 0, pmax_len);
			}
			if (phas_desc != NULL) {
				(*phas_desc)++;
			}
		} else {
			if (count != NULL) {
				(*count)++;
			}
			if (max_len != NULL) {
				const char *type_str;
				size_t type_len;

				type_str = cli__string_from_type(entry->t);
				type_len = strlen(type_str);

				cli__max_len(entry->l, type_len, max_len);
			}
		}
	}
}

static inline bool cli__is_negative(const char *arg)
{
	int64_t i;
	size_t pos = 0;

	return cli__parse_value_int(arg, &i, &pos)
			&& pos == strlen(arg)
			&& i < 0;
}

/* Documented in cli.h */
bool cli_parse(const struct cli_table *cli, int argc, const char **argv)
{
	size_t pos_count = 0;
	enum {
		ARG_PROG_NAME,
		ARG_FIRST,
	};

	for (int i = ARG_FIRST; i < argc; i++) {
		const char *arg = argv[i];
		size_t pos_inc = 0;
		bool ret;

		if (arg[0] == '-') {
			if (arg[1] == '-') {
				ret = cli__parse_long(cli, argc, argv, &i);
			} else {
				ret = cli__parse_short(cli, argc, argv, &i);
				if (ret != true) {
					if (cli__is_negative(argv[i])) {
						pos_inc = 1;
						ret = cli__parse_positional(
								cli, argv[i],
								pos_count);
					}
				}
			}
		} else {
			pos_inc = 1;
			ret = cli__parse_positional(cli, argv[i], pos_count);
		}

		if (ret != true) {
			return ret;
		}

		pos_count += pos_inc;
	}

	if (pos_count < cli->min_positional) {
		fprintf(stderr, "Insufficient positional arguments found.\n");
		return false;
	}

	return true;
}

/**
 * Get terminal width.
 *
 * \return terminal width in characters.
 */
static size_t cli__terminal_width(void)
{
	return 80;
}

/**
 * Print an entry's description, with a given indent.
 *
 * The indent is assumed to already be applied for the first line of the
 * output by the caller.
 * 
 * \param[in] entry   The entry to print the description for.
 * \param[in] indent  The number of spaces to pad the left margin with.
 */
static void cli__print_description(const struct cli_table_entry *entry,
		size_t indent)
{
	size_t terminal_width = cli__terminal_width();
	size_t avail = (indent > terminal_width) ? 0 : terminal_width - indent;
	size_t space = avail;
	const char *desc = entry->d;

	if (desc != NULL) {
		while (*desc != '\0') {
			size_t word_len = strcspn(desc, " \n\t");
			if (word_len <= space || space == avail) {
				fprintf(stderr, "%*.*s",
						(int)word_len,
						(int)word_len, desc);
				desc += word_len;
				if (word_len <= space) {
					space -= word_len;
				}
				if (space > 0) {
					fprintf(stderr, " ");
					space--;
				}
			} else {
				fprintf(stderr, "\n%*s", (int)indent, "");
				space = avail;
			}
			desc += strspn(desc, " \n\t");
		}
	}

	fprintf(stderr, "\n");
}

/* Documented in cli.h */
void cli_help(const struct cli_table *cli, const char *prog_name)
{
	size_t count;
	size_t pcount;
	size_t max_len;
	size_t pmax_len;
	size_t phas_desc;
	size_t required = 0;
	enum {
		ARG_PROG_NAME,
	};

	cli__count(cli, &count, &pcount, &max_len, &pmax_len, &phas_desc);

	fprintf(stderr, "\nUsage: %s", prog_name);

	if (pcount > 0) {
		for (size_t i = 0; i < cli->count; i++) {
			if (cli__entry_is_positional(&cli->entries[i])) {
				const char *punctuation =
					(required == cli->min_positional) ?
					" [" : " ";

				if (cli->entries[i].t == CLI_CMD) {
					fprintf(stderr, "%s%s", punctuation,
							cli->entries[i].l);
				} else {
					fprintf(stderr, "%s<%s>", punctuation,
							cli->entries[i].l);
				}
				required++;
			}
		}
		if (required == pcount && required > cli->min_positional) {
			fprintf(stderr, "]");
		}
	}

	if (count > 0) {
		fprintf(stderr, " [options]");
	}

	fprintf(stderr, "\n\n");

	if (phas_desc > 0) {
		fprintf(stderr, "Where:\n\n");

		for (size_t i = 0; i < cli->count; i++) {
			const struct cli_table_entry *entry = &cli->entries[i];

			if (entry->d == NULL) {
				continue;
			}

			if (cli__entry_is_positional(entry)) {
				fprintf(stderr, "  %*.*s  ",
						(int)pmax_len,
						(int)pmax_len,
						entry->l);
				cli__print_description(entry, pmax_len + 4);
				fprintf(stderr, "\n");
			}
		}
	}

	if (count > 0) {
		fprintf(stderr, "Options:\n\n");

		for (size_t i = 0; i < cli->count; i++) {
			const struct cli_table_entry *entry = &cli->entries[i];
			const char *type_str;
			size_t type_len;
			size_t arg_len;

			if (cli__entry_is_positional(entry)) {
				continue;
			}

			if (entry->s != '\0') {
				fprintf(stderr, "  -%c", entry->s);
			} else {
				fprintf(stderr, "    ");
			}

			type_str = cli__string_from_type(entry->t);
			type_len = strlen(type_str);
			arg_len = strlen(entry->l);

			fprintf(stderr, "  --%s %s%*.s  ", entry->l, type_str,
					(int)(max_len - arg_len - type_len),
					"");
			cli__print_description(entry, max_len + 11);
			fprintf(stderr, "\n");
		}
	}
}
