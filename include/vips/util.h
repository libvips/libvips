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

#ifndef IM_UTIL_H
#define IM_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Some platforms don't have M_PI in math.h :-(
 */
#define IM_PI (3.14159265358979323846)

/* Only define if IM_ENABLE_DEPRECATED is set.
 */
#ifdef IM_ENABLE_DEPRECATED

#ifndef MAX
#define MAX(A,B) ((A)>(B)?(A):(B))
#define MIN(A,B) ((A)<(B)?(A):(B))
#endif /*MAX*/

#define CLIP(A,V,B) MAX( (A), MIN( (B), (V) ) )
#define NEW(IM,A) ((A *)im_malloc((IM),sizeof(A)))
#define NUMBER(R) (sizeof(R)/sizeof(R[0]))
#define ARRAY(IM,N,T) ((T *)im_malloc((IM),(N) * sizeof(T)))

/* Duff's device. Do OPERation N times in a 16-way unrolled loop.
 */
#define UNROLL( N, OPER ) { \
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
}

/* Round a float to the nearest integer. This should give an identical result 
 * to the math.h rint() function (and the old SunOS nint() function), but be
 * much faster. Beware: it evaluates its argument more than once, so don't use
 * ++!
 */
#define RINT( R ) ((int)((R)>0?((R)+0.5):((R)-0.5)))

/* Various integer range clips. Record over/under flows.
 */
#define CLIP_UCHAR( V, SEQ ) { \
	if( (V) & (UCHAR_MAX ^ -1) ) { \
		if( (V) < 0 ) {   \
			(SEQ)->underflow++;   \
			(V) = 0;   \
		}  \
		if( (V) > UCHAR_MAX ) {   \
			(SEQ)->overflow++;   \
			(V) = UCHAR_MAX;   \
		}  \
	} \
}

#define CLIP_USHORT( V, SEQ ) { \
	if( (V) & (USHRT_MAX ^ -1) ) { \
		if( (V) < 0 ) {   \
			(SEQ)->underflow++;   \
			(V) = 0;   \
		}  \
		if( (V) > USHRT_MAX ) {   \
			(SEQ)->overflow++;   \
			(V) = USHRT_MAX;   \
		}  \
	} \
}

#define CLIP_CHAR( V, SEQ ) { \
	if( (V) < SCHAR_MIN ) {   \
		(SEQ)->underflow++;   \
		(V) = SCHAR_MIN;   \
	}  \
	if( (V) > SCHAR_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = SCHAR_MAX;   \
	}  \
}

#define CLIP_SHORT( V, SEQ ) { \
	if( (V) < SHRT_MIN ) {   \
		(SEQ)->underflow++;   \
		(V) = SHRT_MIN;   \
	}  \
	if( (V) > SHRT_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = SHRT_MAX;   \
	}  \
}

#define CLIP_NONE( V, SEQ ) {}

#endif /*IM_ENABLE_DEPRECATED*/

#define IM_MAX(A,B) ((A)>(B)?(A):(B))
#define IM_MIN(A,B) ((A)<(B)?(A):(B))
#define IM_ABS(x) (((x) >= 0) ? (x) : -(x))

#define IM_CLIP(A,V,B) IM_MAX( (A), IM_MIN( (B), (V) ) )
#define IM_NEW(IM,A) ((A *)im_malloc((IM),sizeof(A)))
#define IM_NUMBER(R) ((int)(sizeof(R)/sizeof(R[0])))
#define IM_ARRAY(IM,N,T) ((T *)im_malloc((IM),(N) * sizeof(T)))
#define IM_FREEF( F, S ) do { \
        if( S ) { \
                (void) F( (S) ); \
                (S) = 0; \
        } \
} while( 0 )
#define IM_FREE( A ) IM_FREEF( im_free, A )
#define IM_SETSTR( S, V ) do { \
        const char *sst = (V); \
	\
        if( (S) != sst ) { \
                if( !(S) || !sst || strcmp( (S), sst ) != 0 ) { \
                        IM_FREE( S ); \
                        if( sst ) \
                                (S) = im_strdup( NULL, sst ); \
                } \
        } \
} while( 0 ) 

/* Duff's device. Do OPERation N times in a 16-way unrolled loop.
 */
#define IM_UNROLL( N, OPER ) { \
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
}

/* Round a float to the nearest integer. This should give an identical result 
 * to the math.h rint() function (and the old SunOS nint() function), but be
 * much faster. Beware: it evaluates its argument more than once, so don't use
 * ++!
 */
#define IM_RINT( R ) ((int)((R)>0?((R)+0.5):((R)-0.5)))

/* Various integer range clips. Record over/under flows.
 */
#define IM_CLIP_UCHAR( V, SEQ ) { \
	if( (V) < 0 ) {   \
		(SEQ)->underflow++;   \
		(V) = 0;   \
	}  \
	else if( (V) > UCHAR_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = UCHAR_MAX;   \
	}  \
}

#define IM_CLIP_USHORT( V, SEQ ) { \
	if( (V) < 0 ) {   \
		(SEQ)->underflow++;   \
		(V) = 0;   \
	}  \
	else if( (V) > USHRT_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = USHRT_MAX;   \
	}  \
}

#define IM_CLIP_CHAR( V, SEQ ) { \
	if( (V) < SCHAR_MIN ) {   \
		(SEQ)->underflow++;   \
		(V) = SCHAR_MIN;   \
	}  \
	else if( (V) > SCHAR_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = SCHAR_MAX;   \
	}  \
}

#define IM_CLIP_SHORT( V, SEQ ) { \
	if( (V) < SHRT_MIN ) {   \
		(SEQ)->underflow++;   \
		(V) = SHRT_MIN;   \
	}  \
	else if( (V) > SHRT_MAX ) {   \
		(SEQ)->overflow++;   \
		(V) = SHRT_MAX;   \
	}  \
}

#define IM_CLIP_NONE( V, SEQ ) {}

/* Now implemented as macros.
 */
#define im_open_local( IM, NAME, MODE ) \
	((IMAGE *) im_local( (IM), \
		(im_construct_fn) im_open, (im_callback_fn) im_close, \
		(void *) (NAME), (void *) (MODE), NULL ))

/* Strange double cast stops bogus warnings from gcc 4.1
 */
#define im_open_local_array( IM, OUT, N, NAME, MODE ) \
	(im_local_array( (IM), (void **)((void*)(OUT)), (N),\
		(im_construct_fn) im_open, (im_callback_fn) im_close, \
		(void *) (NAME), (void *) (MODE), NULL ))

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
char *im_strdup( IMAGE *im, const char *str );
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

void *im_local( IMAGE *im, 
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c );
int im_local_array( IMAGE *im, void **out, int n,
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c );

gint64 im_file_length( int fd );
int im__write( int fd, const void *buf, size_t count );

char *im__file_read( FILE *fp, const char *name, unsigned int *length_out );
char *im__file_read_name( const char *name, unsigned int *length_out );
int im__file_write( void *data, size_t size, size_t nmemb, FILE *stream );

gboolean im_isnative( im_arch_type arch );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_UTIL_H*/
