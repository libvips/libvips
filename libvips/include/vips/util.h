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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_UTIL_H
#define VIPS_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <stdio.h>

/* Some platforms don't have M_PI :-(
 */
#define VIPS_PI (3.14159265358979323846)

/* Convert degrees->rads and vice-versa. 
 */
#define VIPS_RAD( R ) (((R) / 360.0) * 2.0 * VIPS_PI)
#define VIPS_DEG( A ) (((A) / (2.0 * VIPS_PI)) * 360.0)

#define VIPS_MAX( A, B ) ((A) > (B) ? (A) : (B))
#define VIPS_MIN( A, B ) ((A) < (B) ? (A) : (B))
#define VIPS_ABS( X ) (((X) >= 0) ? (X) : -(X))

#define VIPS_CLIP( A, V, B ) VIPS_MAX( (A), VIPS_MIN( (B), (V) ) )
#define VIPS_NUMBER( R ) ((int) (sizeof(R) / sizeof(R[0])))

#define VIPS_SWAP( TYPE, A, B ) \
G_STMT_START { \
	TYPE t = (A); \
	(A) = (B); \
	(B) = t; \
} G_STMT_END

/* Duff's device. Do OPERation N times in a 16-way unrolled loop.
 */
#define VIPS_UNROLL( N, OPER ) \
G_STMT_START { \
	if( (N) ) { \
		int duff_count = ((N) + 15) / 16; \
		\
		switch( (N) % 16 ) { \
		case 0:  do {   OPER;  \
		case 15:        OPER;  \
		case 14:        OPER;  \
		case 13:        OPER;  \
		case 12:        OPER;  \
		case 11:        OPER;  \
		case 10:        OPER;  \
		case 9:         OPER;  \
		case 8:         OPER;  \
		case 7:         OPER;  \
		case 6:         OPER;  \
		case 5:         OPER;  \
		case 4:         OPER;  \
		case 3:         OPER;  \
		case 2:         OPER;  \
		case 1: 	OPER;  \
			 } while( --duff_count > 0 ); \
		} \
	} \
} G_STMT_END

/* Round a float to the nearest integer. Much faster than rint(). 
 */
#define VIPS_RINT( R ) ((int) ((R) > 0 ? ((R) + 0.5) : ((R) - 0.5)))

/* Various integer range clips. Record over/under flows.
 */
#define VIPS_CLIP_UCHAR( V, SEQ ) \
G_STMT_START { \
	if( (V) < 0 ) {   \
		(SEQ)->underflow++;   \
		(V) = 0;   \
	}  \
	else if( (V) > UCHAR_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = UCHAR_MAX;   \
	}  \
} G_STMT_END

#define VIPS_CLIP_USHORT( V, SEQ ) \
G_STMT_START { \
	if( (V) < 0 ) {   \
		(SEQ)->underflow++;   \
		(V) = 0;   \
	}  \
	else if( (V) > USHRT_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = USHRT_MAX;   \
	}  \
} G_STMT_END

#define VIPS_CLIP_CHAR( V, SEQ ) \
G_STMT_START { \
	if( (V) < SCHAR_MIN ) {   \
		(SEQ)->underflow++;   \
		(V) = SCHAR_MIN;   \
	}  \
	else if( (V) > SCHAR_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = SCHAR_MAX;   \
	}  \
} G_STMT_END

#define VIPS_CLIP_SHORT( V, SEQ ) \
G_STMT_START { \
	if( (V) < SHRT_MIN ) {   \
		(SEQ)->underflow++;   \
		(V) = SHRT_MIN;   \
	}  \
	else if( (V) > SHRT_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = SHRT_MAX;   \
	}  \
} G_STMT_END

#define VIPS_CLIP_NONE( V, SEQ ) {}

/* Look up the const char * for an enum value.
 */
#define VIPS_ENUM_STRING( ENUM, VALUE ) \
	(g_enum_get_value( g_type_class_ref( ENUM ), VALUE )->value_name)
#define VIPS_ENUM_NICK( ENUM, VALUE ) \
	(g_enum_get_value( g_type_class_ref( ENUM ), VALUE )->value_nick)

/* Given a string, look up the value. Look up as a nick first, then try as a
 * name.
 */
#define VIPS_ENUM_VALUE( ENUM, STR ) \
	(g_enum_get_value_by_nick( g_type_class_ref( ENUM ), STR ) || \
	g_enum_get_value_by_name( g_type_class_ref( ENUM ), STR )) 

/* strtok replacement.
 */
char *im__break_token( char *str, char *brk );

/* Like GFunc, but return a value.
 */
typedef void *(*VSListMap2Fn)( void *, void *, void * );
typedef void *(*VSListMap4Fn)( void *, void *, void *, void *, void * );
typedef void *(*VSListFold2Fn)( void *, void *, void *, void * );

gboolean im_slist_equal( GSList *l1, GSList *l2 );
void *im_slist_map2( GSList *list, VSListMap2Fn fn, void *a, void *b );
void *im_slist_map2_rev( GSList *list, VSListMap2Fn fn, void *a, void *b );
void *im_slist_map4( GSList *list, 
	VSListMap4Fn fn, void *a, void *b, void *c, void *d );
void *im_slist_fold2( GSList *list, void *start, 
	VSListFold2Fn fn, void *a, void *b );
GSList *im_slist_filter( GSList *list, VSListMap2Fn fn, void *a, void *b );
void im_slist_free_all( GSList *list );

void *im_map_equal( void *a, void *b );

void *im_hash_table_map( GHashTable *hash, VSListMap2Fn fn, void *a, void *b );

char *im_strncpy( char *dest, const char *src, int n );
char *im_strrstr( const char *haystack, const char *needle );
gboolean im_ispostfix( const char *a, const char *b );
gboolean im_isprefix( const char *a, const char *b );
int im_vsnprintf( char *str, size_t size, const char *format, va_list ap );
int im_snprintf( char *str, size_t size, const char *format, ... )
	__attribute__((format(printf, 3, 4)));
char *im_break_token( char *str, const char *brk );

const char *im_skip_dir( const char *filename );
void im_filename_split( const char *path, char *name, char *mode );
void im_filename_suffix( const char *path, char *suffix );
int im_filename_suffix_match( const char *path, const char *suffixes[] );
char *im_getnextoption( char **in );
char *im_getsuboption( const char *buf );

gint64 im_file_length( int fd );
int im__write( int fd, const void *buf, size_t count );

FILE *im__file_open_read( const char *filename, 
	const char *fallback_dir, gboolean text_mode );
FILE *im__file_open_write( const char *filename, 
	gboolean text_mode );
char *im__file_read( FILE *fp, const char *name, unsigned int *length_out );
char *im__file_read_name( const char *name, const char *fallback_dir, 
	unsigned int *length_out );
int im__file_write( void *data, size_t size, size_t nmemb, FILE *stream );

typedef enum {
 	VIPS_TOKEN_LEFT = 1,	/* ({[ */
	VIPS_TOKEN_RIGHT,	/* ]}) */
	VIPS_TOKEN_STRING,	/* string or "str\"ing" */
	VIPS_TOKEN_EQUALS,	/* = */
	VIPS_TOKEN_COMMA	/* , */
} VipsToken;

const char *vips__token_get( const char *buffer, 
	VipsToken *token, char *string, int size );
const char *vips__token_must( const char *buffer, VipsToken *token, 
	char *string, int size );
const char *vips__token_need( const char *buffer, VipsToken need_token, 
	char *string, int size );

int im_existsf( const char *name, ... )
	__attribute__((format(printf, 1, 2)));
FILE *im_popenf( const char *fmt, const char *mode, ... )
	__attribute__((format(printf, 1, 3)));
int im_ispoweroftwo( int p );
int im_isvips( const char *filename );
int im_amiMSBfirst( void );

char *im__temp_name( const char *format );

void vips__change_suffix( const char *name, char *out, int mx,
        const char *new_suff, const char **olds, int nolds );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_UTIL_H*/
