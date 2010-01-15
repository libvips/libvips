/* Some basic util functions.
 */

/*

    Copyright (C) 1991-2003 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <fcntl.h>

#ifdef OS_WIN32
#include <windows.h>
#endif /*OS_WIN32*/

#include <assert.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Temp buffer for snprintf() layer on old systems.
 */
#define MAX_BUF (32768)

/* Test two lists for eqality.
 */
gboolean
im_slist_equal( GSList *l1, GSList *l2 )
{
	while( l1 && l2 ) {
		if( l1->data != l2->data )
			return( FALSE );

		l1 = l1->next;
		l2 = l2->next;
	}

	if( l1 || l2 )
		return( FALSE );
	
	return( TRUE );
}

/* Map over an slist. _copy() the list in case the callback changes it.
 */
void *
im_slist_map2( GSList *list, VSListMap2Fn fn, void *a, void *b )
{
	GSList *copy;
	GSList *i;
	void *result;

	copy = g_slist_copy( list );
	result = NULL;
	for( i = copy; i && !(result = fn( i->data, a, b )); i = i->next ) 
		;
	g_slist_free( copy );

	return( result );
}

void *
im_slist_map4( GSList *list, 
	VSListMap4Fn fn, void *a, void *b, void *c, void *d )
{
	GSList *copy;
	GSList *i;
	void *result;

	copy = g_slist_copy( list );
	result = NULL;
	for( i = copy; 
		i && !(result = fn( i->data, a, b, c, d )); i = i->next ) 
		;
	g_slist_free( copy );

	return( result );
}

/* Map backwards. We _reverse() rather than recurse and unwind to save stack.
 */
void *
im_slist_map2_rev( GSList *list, VSListMap2Fn fn, void *a, void *b )
{
	GSList *copy;
	GSList *i;
	void *result;

	copy = g_slist_copy( list );
	copy = g_slist_reverse( copy );
	result = NULL;
	for( i = copy; i && !(result = fn( i->data, a, b )); i = i->next ) 
		;
	g_slist_free( copy );

	return( result );
}

void *
im_map_equal( void *a, void *b )
{
	if( a == b )
		return( a );

	return( NULL );
}

void *
im_slist_fold2( GSList *list, void *start, VSListFold2Fn fn, void *a, void *b )
{
        void *c;
        GSList *this, *next;

        for( c = start, this = list; this; this = next ) {
                next = this->next;

                if( !(c = fn( this->data, c, a, b )) )
			return( NULL );
        }

        return( c );
}

static void
im_slist_free_all_cb( void * thing, void * dummy )
{
	im_free( thing );
}

/* Free a g_slist of things which need im_free()ing.
 */
void
im_slist_free_all( GSList *list )
{
	g_slist_foreach( list, im_slist_free_all_cb, NULL );
	g_slist_free( list );
}

/* Remove all occurences of an item from a list.
 */
GSList *
im_slist_filter( GSList *list, VSListMap2Fn fn, void *a, void *b )
{
	GSList *tmp;
	GSList *prev;

	prev = NULL;
	tmp = list;

	while( tmp ) {
		if( fn( tmp->data, a, b ) ) {
			GSList *next = tmp->next;

			if( prev )
				prev->next = next;
			if( list == tmp )
				list = next;

			tmp->next = NULL;
			g_slist_free( tmp );
			tmp = next;
		}
		else {
			prev = tmp;
			tmp = tmp->next;
		}
	}

	return( list );
}

typedef struct {
	void *a;
	void *b;
	VSListMap2Fn fn;
	void *result;
} Pair;

static gboolean
im_hash_table_predicate( const char *key, void *value, Pair *pair )
{
	return( (pair->result == pair->fn( value, pair->a, pair->b )) );
}

/* Like slist map, but for a hash table.
 */
void *
im_hash_table_map( GHashTable *hash, VSListMap2Fn fn, void *a, void *b )
{
	Pair pair;

	pair.a = a;
	pair.b = b;
	pair.fn = fn;
	pair.result = NULL;

	g_hash_table_find( hash, (GHRFunc) im_hash_table_predicate, &pair ); 

	return( pair.result );
}

/* Map over all a type's children.
 */
void *
vips_type_map( GType base, VipsTypeMap2 fn, void *a, void *b )
{
	GType *child;
	guint n_children;
	unsigned int i;
	void *result;

	child = g_type_children( base, &n_children );
	result = NULL;
	for( i = 0; i < n_children && !result; i++ )
		result = fn( child[i], a, b );
	g_free( child );

	return( result );
}

/* Loop over all the concrete subtypes of a base type.
 */
void *
vips_type_map_concrete_all( GType base, VipsTypeMap fn, void *a )
{
	void *result;

	result = NULL;
	if( !G_TYPE_IS_ABSTRACT( base ) )
		result = fn( base, a );
	if( !result )
		result = vips_type_map( base, 
			(VipsTypeMap2) vips_type_map_concrete_all, fn, a );

	return( result );
}

/* Loop over all the subclasses of a base type.
 */
void *
vips_class_map_concrete_all( GType type, VipsClassMap fn, void *a )
{
	void *result;

	result = NULL;
	if( !G_TYPE_IS_ABSTRACT( type ) ) {
		GTypeClass *class;

		/* Does this class exist? Try to create if not.
		 */
		if( !(class = g_type_class_peek( type )) ) 
			/* We don't unref, so the class is never finalized. 
			 * This will make the peek work next time around and 
			 * save us from constantly building and destroying 
			 * classes.
			 */
			if( !(class = g_type_class_ref( type )) ) {
				im_error( "vips_class_map_concrete_all",
					"%s", _( "unable to build class" ) );
				return( NULL );
			}

		result = fn( VIPS_OBJECT_CLASS( class ), a );
	}
	if( !result )
		result = vips_type_map( type, 
			(VipsTypeMap2) vips_class_map_concrete_all, fn, a );

	return( result );
}

static void *
test_name( VipsObjectClass *class, const char *nickname )
{
	if( strcasecmp( class->nickname, nickname ) == 0 )
		return( class );

	/* Check the class name too, why not.
	 */
	if( strcasecmp( G_OBJECT_CLASS_NAME( class ), nickname ) == 0 )
		return( class );

	return( NULL );
}

/* Find a class ... search below base, return the first match on a nickname or
 * a name.
 */
VipsObjectClass *
vips_class_find( const char *basename, const char *nickname )
{
	VipsObjectClass *class;
	GType base;

	if( !(base = g_type_from_name( basename )) ) {
		im_error( "vips_class_find", 
			_( "base class \"%s\" not found" ), basename ); 
		return( NULL );
	}

	if( !(class = vips_class_map_concrete_all( base, 
		(VipsClassMap) test_name, (void *) nickname )) ) {
		im_error( "vips_class_find", 
			_( "class \"%s\" not found" ), nickname ); 
		return( NULL );
	}

	return( class );
}

GType
vips_type_find( const char *basename, const char *nickname )
{
	VipsObjectClass *class;

	if( !(class = vips_class_find( "VipsInterpolate", nickname )) )
		return( 0 );

	/* FIXME ... we've not supposed to use G_TYPE_FROM_CLASS(), I think. 
	 * I'm not * sure what the alternative is.
	 */
	return( G_TYPE_FROM_CLASS( class ) );
}

/* Like strncpy(), but always NULL-terminate, and don't pad with NULLs.
 */
char *
im_strncpy( char *dest, const char *src, int n )
{
        int i;

        assert( n > 0 );

        for( i = 0; i < n - 1; i++ )
                if( !(dest[i] = src[i]) )
                        break;
        dest[i] = '\0';

        return( dest );
}

/* Find the rightmost occurrence of needle in haystack.
 */
char *
im_strrstr( const char *haystack, const char *needle )
{
	int haystack_len = strlen( haystack );
	int needle_len = strlen( needle );
	int i;

	for( i = haystack_len - needle_len; i >= 0; i-- )
		if( strncmp( needle, haystack + i, needle_len ) == 0 )
			return( (char *) haystack + i );
	
	return( NULL );
}

/* strdup local to a descriptor.
 */
char *
im_strdup( IMAGE *im, const char *str )
{
	int l = strlen( str );
	char *buf;

	if( !(buf = (char *) im_malloc( im, l + 1 )) )
		return( NULL );
	strcpy( buf, str );

	return( buf );
}

/* Test for string b ends string a. 
 */
gboolean
im_ispostfix( const char *a, const char *b )
{	
	int m = strlen( a );
	int n = strlen( b );

	if( n > m )
		return( FALSE );

	return( strcmp( a + m - n, b ) == 0 );
}

/* Test for string a starts string b. 
 */
gboolean
im_isprefix( const char *a, const char *b )
{
	int n = strlen( a );
	int m = strlen( b );
	int i;

	if( m < n )
		return( FALSE );
	for( i = 0; i < n; i++ )
		if( a[i] != b[i] )
			return( FALSE );
	
	return( TRUE );
}

/* Like strtok(). Give a string and a list of break characters. Then:
 * - skip initial break characters
 * - EOS? return NULL
 * - skip a series of non-break characters
 * - write a '\0' over the next break character and return a pointer to the
 *   char after that
 *
 * The idea is that this can be used in loops as the iterator. Example:
 *
 * char *p = " 1 2 3   "; // mutable 
 * char *q;
 * int i;
 * int v[...];
 *
 * for( i = 0; (q = im_break_token( p, " " )); i++, p = q )
 * 	v[i] = atoi( p );
 *
 * will set
 * 	v[0] = 1;
 * 	v[1] = 2;
 * 	v[2] = 3;
 *
 * or with just one pointer, provided your atoi() is OK with trailing chars
 * and you know there is at least one item there
 *
 * char *p = " 1 2 3   "; // mutable
 * int i;
 * int v[...];
 *
 * for( i = 0; p; p = im_break_token( p, " " ) )
 *   v[i] = atoi( p );
 */
char *
im_break_token( char *str, const char *brk )
{
        char *p;

        /* Is the string empty? If yes, return NULL immediately.
         */
        if( !str || !*str )
                return( NULL );

        /* Skip initial break characters.
         */
        p = str + strspn( str, brk );

	/* No item?
	 */
        if( !*p ) 
		return( NULL );

        /* We have a token ... search for the first break character after the 
	 * token.
         */
        p += strcspn( p, brk );

        /* Is there string left?
         */
        if( *p ) {
                /* Write in an end-of-string mark and return the start of the
                 * next token.
                 */
                *p++ = '\0';
                p += strspn( p, brk );
        }

        return( p );
}

/* Wrapper over (v)snprintf() ... missing on old systems.
 */
int
im_vsnprintf( char *str, size_t size, const char *format, va_list ap )
{
#ifdef HAVE_VSNPRINTF
	return( vsnprintf( str, size, format, ap ) );
#else /*HAVE_VSNPRINTF*/
	/* Bleurg!
	 */
	int n;
	static char buf[MAX_BUF];

	if( size > MAX_BUF )
		error_exit( "panic: buffer overflow "
			"(request to write %d bytes to buffer of %d bytes)",
			size, MAX_BUF );
	n = vsprintf( buf, format, ap );
	if( n > MAX_BUF )
		error_exit( "panic: buffer overflow "
			"(%d bytes written to buffer of %d bytes)",
			n, MAX_BUF );

	im_strncpy( str, buf, size );

	return( n );
#endif /*HAVE_VSNPRINTF*/
}

int
im_snprintf( char *str, size_t size, const char *format, ... )
{
	va_list ap;
	int n;

	va_start( ap, format );
	n = im_vsnprintf( str, size, format, ap );
	va_end( ap );

	return( n );
}

/* Split filename into name / mode components. name and mode should both be
 * FILENAME_MAX chars.
 *
 * We look for the ':' splitting the name and mode by searching for the
 * rightmost occurence of the regexp ".[A-Za-z0-9]+:". Example: consider the
 * horror that is
 *
 * 	c:\silly:dir:name\fr:ed.tif:jpeg:95,,,,c:\icc\srgb.icc
 *
 */
void
im_filename_split( const char *path, char *name, char *mode )
{
        char *p;

        im_strncpy( name, path, FILENAME_MAX );

	/* Search back towards start stopping at each ':' char.
	 */
	for( p = name + strlen( name ) - 1; p > name; p -= 1 )
		if( *p == ':' ) {
			char *q;

			for( q = p - 1; isalnum( *q ) && q > name; q -= 1 )
				;

			if( *q == '.' )
				break;
		}

	if( *p == ':' ) {
                im_strncpy( mode, p + 1, FILENAME_MAX );
                *p = '\0';
        }
        else
                strcpy( mode, "" );
}

/* Skip any leading path stuff. Horrible: if this is a filename which came
 * from win32 and we're a *nix machine, it'll have '\\' not '/' as the
 * separator :-(
 *
 * Try to fudge this ... if the file doesn't contain any of our native
 * separators, look for the opposite one as well. If there are none of those
 * either, just return the filename.
 */
const char *
im_skip_dir( const char *path )
{
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
        const char *p;
        const char *q;

	const char native_dir_sep = G_DIR_SEPARATOR;
	const char non_native_dir_sep = native_dir_sep == '/' ? '\\' : '/';

	/* Remove any trailing save modifiers: we don't want '/' or '\' in the
	 * modifier confusing us.
	 */
	im_filename_split( path, name, mode );

	/* The '\0' char at the end of the string.
	 */
	p = name + strlen( name );

	/* Search back for the first native dir sep, or failing that, the first
	 * non-native dir sep.
	 */
	for( q = p; q > name && q[-1] != native_dir_sep; q-- )
		;
	if( q == name )
		for( q = p; q > name && q[-1] != non_native_dir_sep; q-- )
			;

        return( path + (q - name) );
}

/* Extract suffix from filename, ignoring any mode string. Suffix should be
 * FILENAME_MAX chars. Include the "." character, if any.
 */
void
im_filename_suffix( const char *path, char *suffix )
{
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
        char *p;

	im_filename_split( path, name, mode );
        if( (p = strrchr( name, '.' )) ) 
                strcpy( suffix, p );
        else
                strcpy( suffix, "" );
}

/* Does a filename have one of a set of suffixes. Ignore case.
 */
int
im_filename_suffix_match( const char *path, const char *suffixes[] )
{
	char suffix[FILENAME_MAX];
	const char **p;

	im_filename_suffix( path, suffix );
	for( p = suffixes; *p; p++ )
		if( g_ascii_strcasecmp( suffix, *p ) == 0 )
			return( 1 );

	return( 0 );
}

/* p points to the start of a buffer ... move it on through the buffer (ready
 * for the next call), and return the current option (or NULL for option
 * missing). ',' characters inside options can be escaped with a '\'.
 */
char *
im_getnextoption( char **in )
{
        char *p = *in;
        char *q = p;

        if( !p || !*p )
                return( NULL );

	/* Find the next ',' not prefixed with a '\'.
	 */
	while( (p = strchr( p, ',' )) && p[-1] == '\\' )
		p += 1;

        if( p ) {
                /* Another option follows this one .. set up to pick that out
                 * next time.
                 */
                *p = '\0';
                *in = p + 1;
        }
        else {
                /* This is the last one.
                 */
                *in = NULL;
        }

        if( strlen( q ) > 0 )
                return( q );
        else
                return( NULL );
}

/* Get a suboption string, or NULL.
 */
char *
im_getsuboption( const char *buf )
{
        char *p, *q, *r;

        if( !(p = strchr( buf, ':' )) ) 
		/* No suboption.
		 */
		return( NULL );

	/* Step over the ':'.
	 */
	p += 1;

	/* Need to unescape any \, pairs. Shift stuff down one if we find one.
	 */
	for( q = p; *q; q++ ) 
		if( q[0] == '\\' && q[1] == ',' )
			for( r = q; *r; r++ )
				r[0] = r[1];

        return( p );
}

/* Make something local to an image descriptor ... pass in a constructor
 * and a destructor, plus three args.
 */
void *
im_local( IMAGE *im, 
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c )
{
	void *obj;

	if( !im ) {
		im_error( "im_local", "%s", _( "NULL image descriptor" ) );
		return( NULL );
	}

        if( !(obj = cons( a, b, c )) )
                return( NULL );
        if( im_add_close_callback( im, (im_callback_fn) dest, obj, a ) ) {
                dest( obj, a );
                return( NULL );
        }
 
        return( obj );
}

/* Make an array of things local to a descriptor ... eg. make 6 local temp
 * images.
 */
int
im_local_array( IMAGE *im, void **out, int n,
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c )
{
	int i;

	for( i = 0; i < n; i++ )
		if( !(out[i] = im_local( im, cons, dest, a, b, c )) )
			return( -1 );

	return( 0 );
}

/* Get file length ... 64-bitally. -1 for error.
 */
gint64
im_file_length( int fd )
{
#ifdef OS_WIN32
	struct _stati64 st;

	if( _fstati64( fd, &st ) == -1 ) {
#else /*!OS_WIN32*/
	struct stat st;

	if( fstat( fd, &st ) == -1 ) {
#endif /*OS_WIN32*/
		im_error_system( errno, "im_file_length", 
			"%s", _( "unable to get file stats" ) );
		return( -1 );
	}

	return( st.st_size );
}

/* Wrap write() up
 */
int
im__write( int fd, const void *buf, size_t count )
{
	do {
		size_t nwritten = write( fd, buf, count );

		if( nwritten == (size_t) -1 ) {
                        im_error_system( errno, "im__write", 
				"%s", _( "write failed" ) );
                        return( -1 ); 
		}

		buf = (void *) ((char *) buf + nwritten);
		count -= nwritten;
	} while( count > 0 );

	return( 0 );
}

/* Load up a file as a string.
 */
char *
im__file_read( FILE *fp, const char *name, unsigned int *length_out )
{
        long len;
	size_t read;
        char *str;

        /* Find length.
         */
        fseek( fp, 0L, 2 );
        len = ftell( fp );
	if( len > 20 * 1024 * 1024 ) {
		/* Seems crazy!
		 */
                im_error( "im__file_read", _( "\"%s\" too long" ), name );
                return( NULL );
        }

	if( len == -1 ) {
		int size;

		/* Can't get length: read in chunks and realloc() to end of
		 * file.
		 */
		str = NULL;
		len = 0;
		size = 0;
		do {
			size += 1024;
			if( !(str = realloc( str, size )) ) {
				im_error( "im__file_read", 
					"%s", _( "out of memory" ) );
				return( NULL );
			}

			/* -1 to allow space for an extra NULL we add later.
			 */
			read = fread( str + len, sizeof( char ), 
				(size - len - 1) / sizeof( char ),
				fp );
			len += read;
		} while( !feof( fp ) );

#ifdef DEBUG
		printf( "read %ld bytes from unseekable stream\n", len );
#endif /*DEBUG*/
	}
	else {
		/* Allocate memory and fill.    
		 */
		if( !(str = im_malloc( NULL, len + 1 )) )
			return( NULL );
		rewind( fp );
		read = fread( str, sizeof( char ), (size_t) len, fp );
		if( read != (size_t) len ) {
			im_free( str );
			im_error( "im__file_read", 
				_( "error reading from file \"%s\"" ), name );
			return( NULL );
		}
	}

	str[len] = '\0';

	if( length_out )
		*length_out = len;

        return( str );
}

FILE *
im__file_open_read( const char *filename )
{
	FILE *fp;

#ifdef BINARY_OPEN
        if( !(fp = fopen( filename, "rb" )) ) {
#else /*BINARY_OPEN*/
        if( !(fp = fopen( filename, "r" )) ) {
#endif /*BINARY_OPEN*/
		im_error( "im__file_open_read", 
			_( "unable to open file \"%s\" for reading" ), 
			filename );
		return( NULL );
	}

	return( fp );
}

FILE *
im__file_open_write( const char *filename )
{
	FILE *fp;

#ifdef BINARY_OPEN
        if( !(fp = fopen( filename, "wb" )) ) {
#else /*BINARY_OPEN*/
        if( !(fp = fopen( filename, "w" )) ) {
#endif /*BINARY_OPEN*/
		im_error( "im__file_open_write", 
			_( "unable to open file \"%s\" for writing" ), 
			filename );
		return( NULL );
	}

	return( fp );
}

/* Load from a filename as a string.
 */
char *
im__file_read_name( const char *name, unsigned int *length_out )
{
	FILE *fp;
	char *buffer;

        if( !(fp = im__file_open_read( name )) ) 
		return( NULL );
	if( !(buffer = im__file_read( fp, name, length_out )) ) {
		fclose( fp );
		return( NULL );
	}
	fclose( fp );

	return( buffer );
}

/* Alloc/free a GValue.
 */
static GValue *
im__gvalue_new( GType type )
{
	GValue *value;

	value = g_new0( GValue, 1 );
	g_value_init( value, type );

	return( value );
}

static GValue *
im__gvalue_copy( GValue *value )
{
	GValue *value_copy;

	value_copy = im__gvalue_new( G_VALUE_TYPE( value ) );
	g_value_copy( value, value_copy );

	return( value_copy );
}

static void
im__gvalue_free( GValue *value )
{
	g_value_unset( value );
	g_free( value );
}

GValue *
im__gvalue_ref_string_new( const char *text )
{
	GValue *value;

	value = im__gvalue_new( IM_TYPE_REF_STRING );
	im_ref_string_set( value, text );

	return( value );
}

/* Free a GSList of GValue.
 */
void
im__gslist_gvalue_free( GSList *list )
{
	g_slist_foreach( list, (GFunc) im__gvalue_free, NULL );
	g_slist_free( list );
}

/* Copy a GSList of GValue.
 */
GSList *
im__gslist_gvalue_copy( const GSList *list )
{
	GSList *copy;
	const GSList *p;

	copy = NULL;

	for( p = list; p; p = p->next ) 
		copy = g_slist_prepend( copy, 
			im__gvalue_copy( (GValue *) p->data ) );

	copy = g_slist_reverse( copy );

	return( copy );
}

/* Merge two GSList of GValue ... append to a all elements in b which are not 
 * in a. Return the new value of a. Works for any vips refcounted type 
 * (string, blob, etc.).
 */
GSList *
im__gslist_gvalue_merge( GSList *a, const GSList *b )
{
	const GSList *i, *j;
	GSList *tail;

	tail = NULL;

	for( i = b; i; i = i->next ) {
		GValue *value = (GValue *) i->data;

		assert( G_VALUE_TYPE( value ) == IM_TYPE_REF_STRING );

		for( j = a; j; j = j->next ) {
			GValue *value2 = (GValue *) j->data;

			assert( G_VALUE_TYPE( value2 ) == IM_TYPE_REF_STRING );

			/* Just do a pointer compare ... good enough 99.9% of 
			 * the time.
			 */
			if( im_ref_string_get( value ) ==
				im_ref_string_get( value2 ) )
				break;
		}

		if( !j )
			tail = g_slist_prepend( tail, 
				im__gvalue_copy( value ) );
	}

	a = g_slist_concat( a, g_slist_reverse( tail ) );

	return( a );
}

/* Make a char* from GSList of GValue. Each GValue should be a ref_string.
 * free the result. Empty list -> "", not NULL. Join strings with '\n'.
 */
char *
im__gslist_gvalue_get( const GSList *list )
{
	const GSList *p;
	size_t length;
	char *all;
	char *q;

	/* Need to estimate length first.
	 */
	length = 0;
	for( p = list; p; p = p->next ) {
		GValue *value = (GValue *) p->data;

		assert( G_VALUE_TYPE( value ) == IM_TYPE_REF_STRING );

		/* +1 for the newline we will add for each item.
		 */
		length += im_ref_string_get_length( value ) + 1;
	}

	if( length == 0 )
		return( NULL );

	/* More than 10MB of history? Madness!
	 */
	assert( length < 10 * 1024 * 1024 );

	/* +1 for '\0'.
	 */
	if( !(all = im_malloc( NULL, length + 1 )) )
		return( NULL );

	q = all;
	for( p = list; p; p = p->next ) {
		GValue *value = (GValue *) p->data;

		strcpy( q, im_ref_string_get( value ) );
		q += im_ref_string_get_length( value );
		strcpy( q, "\n" );
		q += 1;
	}

	g_assert( (size_t) (q - all) == length );

	return( all );
}

/* Need our own seek(), since lseek() on win32 can't do long files.
 */
int
im__seek( int fd, gint64 pos )
{
#ifdef OS_WIN32
{
	HANDLE hFile = (HANDLE) _get_osfhandle( fd );
	LARGE_INTEGER p;

	p.QuadPart = pos;
	if( !SetFilePointerEx( hFile, p, NULL, FILE_BEGIN ) ) {
                im_error_system( GetLastError(), "im__seek", 
			"%s", _( "unable to seek" ) );
		return( -1 );
	}
}
#else /*!OS_WIN32*/
	if( lseek( fd, pos, SEEK_SET ) == (off_t) -1 ) {
		im_error( "im__seek", "%s", _( "unable to seek" ) );
		return( -1 );
	}
#endif /*OS_WIN32*/

	return( 0 );
}

/* Need our own ftruncate(), since ftruncate() on win32 can't do long files.

	DANGER ... this moves the file pointer to the end of file on win32,
	but not on *nix; don't make any assumptions about the file pointer
	position after calling this

 */
int
im__ftruncate( int fd, gint64 pos )
{
#ifdef OS_WIN32
{
	HANDLE hFile = (HANDLE) _get_osfhandle( fd );
	LARGE_INTEGER p;

	p.QuadPart = pos;
	if( im__seek( fd, pos ) )
		return( -1 );
	if( !SetEndOfFile( hFile ) ) {
                im_error_system( GetLastError(), "im__ftruncate", 
			"%s", _( "unable to truncate" ) );
		return( -1 );
	}
}
#else /*!OS_WIN32*/
	if( ftruncate( fd, pos ) ) {
		im_error_system( errno, "im__ftruncate", 
			"%s", _( "unable to truncate" ) );
		return( -1 );
	}
#endif /*OS_WIN32*/

	return( 0 );
}

/* Like fwrite(), but returns non-zero on error and sets error message.
 */
int
im__file_write( void *data, size_t size, size_t nmemb, FILE *stream )
{
	size_t n;

	if( !data ) 
		return( 0 );

	if( (n = fwrite( data, size, nmemb, stream )) != nmemb ) {
		im_error( "im__file_write", 
			_( "writing error (%zd out of %zd blocks written) "
			"... disc full?" ), n, nmemb );
		return( -1 );
	}

	return( 0 );
}

/* Check whether arch corresponds to native byte order.
 */
gboolean
im_isnative( im_arch_type arch )
{
	switch( arch ) {
	case IM_ARCH_NATIVE: 		
		return( TRUE );
	case IM_ARCH_BYTE_SWAPPED: 	
		return( FALSE );
	case IM_ARCH_LSB_FIRST: 	
		return( !im_amiMSBfirst() );
	case IM_ARCH_MSB_FIRST: 	
		return( im_amiMSBfirst() );

	default:
		g_assert( 0 );
	}  
}

/* Read a few bytes from the start of a file. For sniffing file types.
 */
int
im__get_bytes( const char *filename, unsigned char buf[], int len )
{
	int fd;

	/* File may not even exist (for tmp images for example!)
	 * so no hasty messages. And the file might be truncated, so no error
	 * on read either.
	 */
#ifdef BINARY_OPEN
	if( (fd = open( filename, O_RDONLY | O_BINARY )) == -1 )
#else /*BINARY_OPEN*/
	if( (fd = open( filename, O_RDONLY )) == -1 )
#endif /*BINARY_OPEN*/
		return( 0 );
	if( read( fd, buf, len ) != len ) {
		close( fd );
		return( 0 );
	}
	close( fd );

	return( 1 );
}

/* Break a command-line argument into tokens separated by whitespace. Strings
 * can't be adjacent, so "hello world" (without quotes) is a single string.
 * Strings are written (with \" escaped) into string, which must be size 
 * characters large.
 */
const char *
vips__token_get( const char *p, VipsToken *token, char *string, int size )
{
	const char *q;
	int ch;
	int n;

	/* Parse this token with p.
	 */
	if( !p )
		return( NULL );

	/* Skip initial whitespace.
	 */
        p += strspn( p, " \t\n\r" );
	if( !p[0] )
		return( NULL );

	switch( (ch = p[0]) ) {
	case '{':
	case '[':
	case '(':
		*token = VIPS_TOKEN_LEFT;
		p += 1;
		break;

	case ')':
	case ']':
	case '}':
		*token = VIPS_TOKEN_RIGHT;
		p += 1;
		break;

	case '=':
		*token = VIPS_TOKEN_EQUALS;
		p += 1;
		break;

	case ',':
		*token = VIPS_TOKEN_COMMA;
		p += 1;
		break;

	case '"':
	case '\'':
		/* Parse a quoted string. Copy up to ", interpret any \",
		 * error if no closing ".
		 */
		*token = VIPS_TOKEN_STRING;

		do {
			/* Number of characters until the next quote
			 * character or end of string.
			 */
			if( (q = strchr( p + 1, ch )) )
				n = q - p + 1;
			else
				n = strlen( p + 1 );

			g_assert( size > n + 1 );
			memcpy( string, p + 1, n );
			string[n] = '\0';

			/* p[n + 1] might not be " if there's no closing ".
			 */
			if( p[n + 1] == ch && p[n] == '\\' ) 
				/* An escaped ": overwrite the '\' with '"'
				 */
				string[n - 1] = ch;

			string += n;
			size -= n;
			p += n + 1;
		} while( p[0] && p[-1] == '\\' );

		p += 1;

		break;

	default:
		/* It's an unquoted string: read up to the next non-string
		 * character. We don't allow two strings next to each other,
		 * so the next break must be bracket, equals, comma.
		 */
		*token = VIPS_TOKEN_STRING;
		n = strcspn( p, "[{()}]=," );
		g_assert( size > n + 1 );
		memcpy( string, p, n );
		string[n] = '\0';
		p += n;

		/* We remove leading whitespace, so we trim trailing
		 * whitespace from unquoted strings too.
		 */
		while( isspace( string[n - 1] ) ) {
			string[n - 1] = '\0';
			n -= 1;
		}

		break;
	}

	return( p );
}

/* We expect a token.
 */
const char *
vips__token_must( const char *p, VipsToken *token, 
	char *string, int size )
{
	if( !(p = vips__token_get( p, token, string, size )) ) {
		im_error( "get_token", "%s", _( "unexpected end of string" ) );
		return( NULL );
	}

	return( p );
}

/* Turn a VipsToken into a string.
 */
static const char *
vips__token_string( VipsToken token )
{
	switch( token ) {
 	case VIPS_TOKEN_LEFT:	return( _( "opening brace" ) );
	case VIPS_TOKEN_RIGHT:	return( _( "closing brace" ) );
	case VIPS_TOKEN_STRING:	return( _( "string" ) );
	case VIPS_TOKEN_EQUALS:	return( "=" );
	case VIPS_TOKEN_COMMA:	return( "," );

	default:
		g_assert( 0 );
	}
}

/* We expect a certain token.
 */
const char *
vips__token_need( const char *p, VipsToken need_token, 
	char *string, int size )
{
	VipsToken token;

	if( !(p = vips__token_must( p, &token, string, size )) ) 
		return( NULL );
	if( token != need_token ) {
		im_error( "get_token", _( "expected %s, saw %s" ), 
			vips__token_string( need_token ), 
			vips__token_string( token ) );
		return( NULL );
	}

	return( p );
}

/* Test for file exists.
 */
int
im_existsf( const char *name, ... )
{
        va_list ap;
        char buf1[PATH_MAX];

        va_start( ap, name );
        (void) im_vsnprintf( buf1, PATH_MAX - 1, name, ap );
        va_end( ap );

        /* Try that.
         */
        if( !access( buf1, R_OK ) )
                return( 1 );

        return( 0 );
}

#ifdef OS_WIN32
#define popen(b,m) _popen(b,m)
#define pclose(f) _pclose(f)
#endif /*OS_WIN32*/

/* Do popen(), with printf-style args.
 */
FILE *
im_popenf( const char *fmt, const char *mode, ... )
{
        va_list args;
	char buf[4096];
	FILE *fp;

        va_start( args, mode );
        (void) im_vsnprintf( buf, 4096, fmt, args );
        va_end( args );

#ifdef DEBUG
	printf( "im_popenf: running: %s\n", buf );
#endif /*DEBUG*/

        if( !(fp = popen( buf, mode )) ) {
		im_error( "popenf", "%s", strerror( errno ) );
		return( NULL );
	}

	return( fp );
}

/* True if an int is a power of two ... 1, 2, 4, 8, 16, 32, etc. Do with just
 * integer arithmetic for portability. A previous Nicos version using doubles
 * and log/log failed on x86 with rounding problems. Return 0 for not
 * power of two, otherwise return the position of the set bit (numbering with
 * bit 1 as the lsb).
 */
int
im_ispoweroftwo( int p )
{
	int i, n;

	/* Count set bits. Could use a LUT, I guess.
	 */
	for( i = 0, n = 0; p; i++, p >>= 1 )
		if( p & 1 )
			n++;

	/* Should be just one set bit.
	 */
	if( n == 1 )
		/* Return position of bit.
		 */
		return( i );
	else
		return( 0 );
}

int
im_isvips( const char *filename )
{
	unsigned char buf[4];

	if( im__get_bytes( filename, buf, 4 ) ) {
		if( buf[0] == 0x08 && buf[1] == 0xf2 &&
			buf[2] == 0xa6 && buf[3] == 0xb6 )
			/* SPARC-order VIPS image.
			 */
			return( 1 );
		else if( buf[3] == 0x08 && buf[2] == 0xf2 &&
			buf[1] == 0xa6 && buf[0] == 0xb6 )
			/* INTEL-order VIPS image.
			 */
			return( 1 );
	}

	return( 0 );
}

/* Test this processor for endianness. True for SPARC order.
 */
int
im_amiMSBfirst( void )
{
        int test;
        unsigned char *p = (unsigned char *) &test;

        test = 0;
        p[0] = 255;

        if( test == 255 )
                return( 0 );
        else
                return( 1 );
}

/* Make a temporary file name. The format parameter is something like "%s.jpg" 
 * and will be expanded to something like "/tmp/vips-12-34587.jpg".
 *
 * You need to free the result. A real file will also be created, though we
 * delete it for you.
 */
char *
im__temp_name( const char *format )
{
	static int serial = 1;

	const char *tmpd;
	char file[FILENAME_MAX];
	char file2[FILENAME_MAX];

	char *name;
	int fd;

	if( !(tmpd = g_getenv( "TMPDIR" )) )
		tmpd = "/tmp";

	im_snprintf( file, FILENAME_MAX, "vips-%d-XXXXXX", serial++ );
	im_snprintf( file2, FILENAME_MAX, format, file );
	name = g_build_filename( tmpd, file2, NULL );

	if( (fd = g_mkstemp( name )) == -1 ) {
		im_error( "tempfile", 
			_( "unable to make temporary file %s" ), name );
		g_free( name );
		return( NULL );
	}
	close( fd );
	g_unlink( name );

	return( name );
}

/* Make a disc IMAGE which will be automatically unlinked on im_close().
 * Format is something like "%s.v" for a vips file.
 */
IMAGE *
im__open_temp( const char *format )
{
	char *name;
	IMAGE *disc;

	if( !(name = im__temp_name( format )) )
		return( NULL );

	if( !(disc = im_open( name, "w" )) ) {
		g_free( name );
		return( NULL );
	}
	g_free( name );

	/* Needs to be postclose so we can rewind after write without
	 * deleting the file.
	 */
	if( im_add_postclose_callback( disc, 
		(im_callback_fn) unlink, disc->filename, NULL ) ) {
		im_close( disc );
		g_unlink( name );
	}

	return( disc );
}

/* This gets indexed by (eg.) IM_IMAGE_SIZEOF_ELEMENT() to calculate object
 * size.
 */
const size_t im__sizeof_bandfmt[] = {
	IM_BBITS_BYTE >> 3,
	IM_BBITS_BYTE >> 3,
	IM_BBITS_SHORT >> 3,
	IM_BBITS_SHORT >> 3,
	IM_BBITS_INT >> 3,
	IM_BBITS_INT >> 3,
	IM_BBITS_FLOAT >> 3,
	IM_BBITS_COMPLEX >> 3,
	IM_BBITS_DOUBLE >> 3,
	IM_BBITS_DPCOMPLEX >> 3
};

/* Return number of pel bits for band format, or -1 on error.
 */
int 
im_bits_of_fmt( VipsBandFmt fmt )
{
	return( fmt < 0 || fmt > IM_BANDFMT_DPCOMPLEX ?
		im_error( "im_bits_of_fmt", 
			_( "unsupported band format: %d" ), fmt ),
		-1 :
		im__sizeof_bandfmt[fmt] << 3 );
}

