/* Various useful definitions.
 *
 * J.Cupitt, 8/4/93
 * 15/7/96 JC
 *	- C++ stuff added
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
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
	02110-1301  USA

 */

/*

	These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_UTIL_H
#define VIPS_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <math.h>

/* Some platforms don't have M_PI :-(
 */
#define VIPS_PI (3.14159265358979323846)

/* Convert degrees->rads and vice-versa.
 */
#define VIPS_RAD(R) (((R) / 360.0) * 2.0 * VIPS_PI)
#define VIPS_DEG(A) (((A) / (2.0 * VIPS_PI)) * 360.0)

#define VIPS_MAX(A, B) ((A) > (B) ? (A) : (B))
#define VIPS_MIN(A, B) ((A) < (B) ? (A) : (B))

#define VIPS_FMAX(A, B) fmax((A), (B)) VIPS_DEPRECATED_MACRO_FOR(fmax)
#define VIPS_FMIN(A, B) fmin((A), (B)) VIPS_DEPRECATED_MACRO_FOR(fmin)

#define VIPS_CLIP(A, V, B) VIPS_MAX((A), VIPS_MIN((B), (V)))
#define VIPS_FCLIP(A, V, B) fmax((A), fmin((B), (V)))

#define VIPS_NUMBER(R) ((int) (sizeof(R) / sizeof(R[0])))

#define VIPS_ABS(V) (((V) >= 0) ? (V) : -(V))
#define VIPS_FABS(V) fabs((V)) VIPS_DEPRECATED_MACRO_FOR(fabs)

// is something (eg. a pointer) N aligned
#define VIPS_ALIGNED(P, N) ((((guint64) (P)) & ((N) - 1)) == 0)

#define VIPS_ISNAN(V) isnan(V) VIPS_DEPRECATED_MACRO_FOR(isnan)
#define VIPS_FLOOR(V) floor(V) VIPS_DEPRECATED_MACRO_FOR(floor)
#define VIPS_CEIL(V) ceil(V) VIPS_DEPRECATED_MACRO_FOR(ceil)
#define VIPS_RINT(V) rint(V) VIPS_DEPRECATED_MACRO_FOR(rint)
#define VIPS_ROUND(V) round(V) VIPS_DEPRECATED_MACRO_FOR(round)

/* Testing status before the function call saves a lot of time.
 */
#define VIPS_ONCE(ONCE, FUNC, CLIENT) \
	G_STMT_START \
	{ \
		if (G_UNLIKELY((ONCE)->status != G_ONCE_STATUS_READY)) \
			(void) g_once(ONCE, FUNC, CLIENT); \
	} \
	G_STMT_END

/* rint() does "bankers rounding", it rounds to the nearest even integer.
 * For things like image geometry, we want strict nearest int.
 *
 * If you know it's unsigned, _UINT is a little faster.
 */
#define VIPS_ROUND_INT(R) ((int) ((R) > 0 ? ((R) + 0.5) : ((R) -0.5)))
#define VIPS_ROUND_UINT(R) ((int) ((R) + 0.5))

/* Round N down and up to the nearest multiple of P.
 */
#define VIPS_ROUND_DOWN(N, P) ((N) - ((N) % (P)))
#define VIPS_ROUND_UP(N, P) (VIPS_ROUND_DOWN((N) + (P) -1, (P)))

#define VIPS_SWAP(TYPE, A, B) \
	G_STMT_START \
	{ \
		TYPE t = (A); \
		(A) = (B); \
		(B) = t; \
	} \
	G_STMT_END

/* Duff's device. Do OPERation N times in a 16-way unrolled loop.
 */
#define VIPS_UNROLL(N, OPER) \
	G_STMT_START \
	{ \
		if ((N)) { \
			int duff_count = ((N) + 15) / 16; \
			\
			switch ((N) % 16) { \
			case 0: \
				do { \
					OPER; \
				case 15: \
					OPER; \
				case 14: \
					OPER; \
				case 13: \
					OPER; \
				case 12: \
					OPER; \
				case 11: \
					OPER; \
				case 10: \
					OPER; \
				case 9: \
					OPER; \
				case 8: \
					OPER; \
				case 7: \
					OPER; \
				case 6: \
					OPER; \
				case 5: \
					OPER; \
				case 4: \
					OPER; \
				case 3: \
					OPER; \
				case 2: \
					OPER; \
				case 1: \
					OPER; \
				} while (--duff_count > 0); \
			} \
		} \
	} \
	G_STMT_END

/* Various integer range clips. Record over/under flows.
 */
#define VIPS_CLIP_UCHAR(V, SEQ) \
	G_STMT_START \
	{ \
		if ((V) < 0) { \
			(SEQ)->underflow++; \
			(V) = 0; \
		} \
		else if ((V) > UCHAR_MAX) { \
			(SEQ)->overflow++; \
			(V) = UCHAR_MAX; \
		} \
	} \
	G_STMT_END

#define VIPS_CLIP_CHAR(V, SEQ) \
	G_STMT_START \
	{ \
		if ((V) < SCHAR_MIN) { \
			(SEQ)->underflow++; \
			(V) = SCHAR_MIN; \
		} \
		else if ((V) > SCHAR_MAX) { \
			(SEQ)->overflow++; \
			(V) = SCHAR_MAX; \
		} \
	} \
	G_STMT_END

#define VIPS_CLIP_USHORT(V, SEQ) \
	G_STMT_START \
	{ \
		if ((V) < 0) { \
			(SEQ)->underflow++; \
			(V) = 0; \
		} \
		else if ((V) > USHRT_MAX) { \
			(SEQ)->overflow++; \
			(V) = USHRT_MAX; \
		} \
	} \
	G_STMT_END

#define VIPS_CLIP_SHORT(V, SEQ) \
	G_STMT_START \
	{ \
		if ((V) < SHRT_MIN) { \
			(SEQ)->underflow++; \
			(V) = SHRT_MIN; \
		} \
		else if ((V) > SHRT_MAX) { \
			(SEQ)->overflow++; \
			(V) = SHRT_MAX; \
		} \
	} \
	G_STMT_END

#define VIPS_CLIP_UINT(V, SEQ) \
	G_STMT_START \
	{ \
		if ((V) < 0) { \
			(SEQ)->underflow++; \
			(V) = 0; \
		} \
	} \
	G_STMT_END

#define VIPS_CLIP_NONE(V, SEQ) \
	{ \
	}

/* Not all platforms have PATH_MAX (eg. Hurd) and we don't need a platform one
 * anyway, just a static buffer big enough for almost any path.
 */
#define VIPS_PATH_MAX (4096)

/* Create multiple copies of a function targeted at groups of SIMD intrinsics,
 * with the most suitable selected at runtime via dynamic dispatch.
 */
#ifdef HAVE_TARGET_CLONES
#define VIPS_TARGET_CLONES(TARGETS) \
	__attribute__((target_clones(TARGETS)))
#else
#define VIPS_TARGET_CLONES(TARGETS)
#endif

VIPS_API
const char *vips_enum_string(GType enm, int value);
VIPS_API
const char *vips_enum_nick(GType enm, int value);
VIPS_API
int vips_enum_from_nick(const char *domain, GType type, const char *str);
VIPS_API
int vips_flags_from_nick(const char *domain, GType type, const char *nick);

VIPS_API
gboolean vips_slist_equal(GSList *l1, GSList *l2);
VIPS_API
void *vips_slist_map2(GSList *list, VipsSListMap2Fn fn, void *a, void *b);
VIPS_API
void *vips_slist_map2_rev(GSList *list, VipsSListMap2Fn fn, void *a, void *b);
VIPS_API
void *vips_slist_map4(GSList *list,
	VipsSListMap4Fn fn, void *a, void *b, void *c, void *d);
VIPS_API
void *vips_slist_fold2(GSList *list, void *start,
	VipsSListFold2Fn fn, void *a, void *b);
VIPS_API
GSList *vips_slist_filter(GSList *list, VipsSListMap2Fn fn, void *a, void *b);
VIPS_API
void vips_slist_free_all(GSList *list);
VIPS_API
void *vips_map_equal(void *a, void *b);

VIPS_API
void *vips_hash_table_map(GHashTable *hash,
	VipsSListMap2Fn fn, void *a, void *b);

VIPS_API
gboolean vips_iscasepostfix(const char *a, const char *b);
VIPS_API
gboolean vips_isprefix(const char *a, const char *b);
VIPS_API
char *vips_break_token(char *str, const char *brk);

VIPS_API
int vips_filename_suffix_match(const char *path, const char *suffixes[]);

VIPS_API
gint64 vips_file_length(int fd);

VIPS_API
int vips_existsf(const char *name, ...)
	G_GNUC_PRINTF(1, 2);
VIPS_API
int vips_isdirf(const char *name, ...)
	G_GNUC_PRINTF(1, 2);
VIPS_API
int vips_mkdirf(const char *name, ...)
	G_GNUC_PRINTF(1, 2);
VIPS_API
int vips_rmdirf(const char *name, ...)
	G_GNUC_PRINTF(1, 2);
VIPS_API
int vips_rename(const char *old_name, const char *new_name);

/**
 * VipsToken: (skip)
 * @VIPS_TOKEN_LEFT: left bracket
 * @VIPS_TOKEN_RIGHT: right bracket
 * @VIPS_TOKEN_STRING: string constant
 * @VIPS_TOKEN_EQUALS: equals sign
 * @VIPS_TOKEN_COMMA: comma
 *
 * Tokens returned by the vips lexical analyzer, see vips__token_get(). This
 * is used to parse option strings for arguments.
 *
 * Left and right brackets can be any of (, {, [, <.
 *
 * Strings may be in double quotes, and may contain escaped quote characters,
 * for example string, "string" and "str\"ing".
 */
typedef enum {
	VIPS_TOKEN_LEFT = 1,
	VIPS_TOKEN_RIGHT,
	VIPS_TOKEN_STRING,
	VIPS_TOKEN_EQUALS,
	VIPS_TOKEN_COMMA
} VipsToken;

#ifndef __GI_SCANNER__

// we expose this one in the API for testing
VIPS_API
const char *vips__token_get(const char *buffer,
	VipsToken *token, char *string, int size);

#endif /* !__GI_SCANNER__ */

VIPS_API
int vips_ispoweroftwo(int p);
VIPS_API
int vips_amiMSBfirst(void);

VIPS_API
char *vips_realpath(const char *path);

VIPS_API
int vips_strtod(const char *str, double *out);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_UTIL_H*/
