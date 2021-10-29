/* Some basic util functions.
 */

/*

    Copyright (C) 1991-2003 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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
#ifdef HAVE_IO_H
#include <io.h>
#endif /*HAVE_IO_H*/
#include <fcntl.h>

#include <vips/vips.h>

#ifdef G_OS_WIN32
#include <windows.h>
#endif /*G_OS_WIN32*/

#include <vips/debug.h>
#include <vips/internal.h>

/* Temp buffer for snprintf() layer on old systems.
 */
#define MAX_BUF (100000)

#define MODE_READ CLOEXEC (BINARYIZE (O_RDONLY))

/* Test two lists for eqality.
 */
gboolean
vips_slist_equal( GSList *l1, GSList *l2 )
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
vips_slist_map2( GSList *list, VipsSListMap2Fn fn, void *a, void *b )
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

/* Map backwards. We _reverse() rather than recurse and unwind to save stack.
 */
void *
vips_slist_map2_rev( GSList *list, VipsSListMap2Fn fn, void *a, void *b )
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
vips_slist_map4( GSList *list, 
	VipsSListMap4Fn fn, void *a, void *b, void *c, void *d )
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

void *
vips_slist_fold2( GSList *list, void *start, 
	VipsSListFold2Fn fn, void *a, void *b )
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

/* Remove all occurences of an item from a list.
 */
GSList *
vips_slist_filter( GSList *list, VipsSListMap2Fn fn, void *a, void *b )
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

static void
vips_slist_free_all_cb( void * thing, void * dummy )
{
	g_free( thing );
}

/* Free a g_slist of things which need g_free()ing.
 */
void
vips_slist_free_all( GSList *list )
{
	g_slist_foreach( list, vips_slist_free_all_cb, NULL );
	g_slist_free( list );
}

void *
vips_map_equal( void *a, void *b )
{
	if( a == b )
		return( a );

	return( NULL );
}

typedef struct {
	void *a;
	void *b;
	VipsSListMap2Fn fn;
	void *result;
} Pair;

static gboolean
vips_hash_table_predicate( const char *key, void *value, Pair *pair )
{
	return( (pair->result = pair->fn( value, pair->a, pair->b )) != NULL );
}

/* Like slist map, but for a hash table.
 */
void *
vips_hash_table_map( GHashTable *hash, VipsSListMap2Fn fn, void *a, void *b )
{
	Pair pair;

	pair.a = a;
	pair.b = b;
	pair.fn = fn;
	pair.result = NULL;

	g_hash_table_find( hash, (GHRFunc) vips_hash_table_predicate, &pair ); 

	return( pair.result );
}

/* Like strncpy(), but always NULL-terminate, and don't pad with NULLs.
 * If @n is 100 and @src is more than 99 characters, 99 are copied and the
 * final byte of @dest is set to '\0'.
 */
char *
vips_strncpy( char *dest, const char *src, int n )
{
        int i;

        g_assert( n > 0 );

        for( i = 0; i < n - 1; i++ )
                if( !(dest[i] = src[i]) )
                        break;
        dest[i] = '\0';

        return( dest );
}

/* Find the rightmost occurrence of needle in haystack.
 */
char *
vips_strrstr( const char *haystack, const char *needle )
{
	int haystack_len = strlen( haystack );
	int needle_len = strlen( needle );
	int i;

	for( i = haystack_len - needle_len; i >= 0; i-- )
		if( strncmp( needle, haystack + i, needle_len ) == 0 )
			return( (char *) haystack + i );
	
	return( NULL );
}

/* Test for string b ends string a. 
 */
gboolean
vips_ispostfix( const char *a, const char *b )
{	
	int m = strlen( a );
	int n = strlen( b );

	if( n > m )
		return( FALSE );

	return( strcmp( a + m - n, b ) == 0 );
}

/* Case-insensitive test for string b ends string a. ASCII strings only. 
 */
gboolean
vips_iscasepostfix( const char *a, const char *b )
{	
	int m = strlen( a );
	int n = strlen( b );

	if( n > m )
		return( FALSE );

	return( g_ascii_strcasecmp( a + m - n, b ) == 0 );
}

/* Test for string a starts string b. a is a known-good string, b may be
 * random data. 
 */
gboolean
vips_isprefix( const char *a, const char *b )
{
	int i;

	for( i = 0; a[i] && b[i]; i++ )
		if( a[i] != b[i] )
			return( FALSE );

	/* If there's stuff left in a but b has finished, we must have a
	 * mismatch.
	 */
	if( a[i] && !b[i] )
		return( FALSE );

	return( TRUE );
}

/* Exactly like strcspn(), but allow \ as an escape character.
 *
 * strspne( "hello world", " " ) == 5
 * strspne( "hello\\ world", " " ) == 12
 */
static size_t
strcspne( const char *s, const char *reject )
{
	size_t skip;

	/* If \ is one of the reject chars, no need for any looping.
	 */
	if( strchr( reject, '\\' ) )
		return( strcspn( s, reject ) );

	skip = 0;
	for(;;) { 
		skip += strcspn( s + skip, reject );

		/* s[skip] is at the start of the string, or the end, or on a
		 * break character.
		 */
		if( skip == 0 ||
			!s[skip] ||
			s[skip - 1] != '\\' )
			break;

		/* So skip points at break char and we have a '\' in the char
		 * before. Step over the break.
		 */
		skip += 1;
	}

	return( skip );
}

/* Like strtok(). Give a string and a list of break characters. Then:
 * - skip initial break characters
 * - EOS? return NULL
 * - skip a series of non-break characters, allow `\` as a break escape
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
 * for( i = 0; (q = vips_break_token( p, " " )); i++, p = q )
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
 * for( i = 0; p; p = vips_break_token( p, " " ) )
 *   v[i] = atoi( p );
 *
 * You can use \ to escape breaks, for example:
 *
 * vips_break_token( "hello\ world", " " ) will see a single token containing
 * a space. The \ characters are squashed out.
 */
char *
vips_break_token( char *str, const char *brk )
{
        char *p;
        char *q;

        /* Is the string empty? If yes, return NULL immediately.
         */
        if( !str || 
		!*str )
                return( NULL );

        /* Skip initial break characters.
         */
        p = str + strspn( str, brk );

	/* No item?
	 */
        if( !*p ) 
		return( NULL );

        /* We have a token ... search for the first break character after the 
	 * token. strcspne() allows '\' to escape breaks, see above.
         */
        p += strcspne( p, brk );

        /* Is there string left?
         */
        if( *p ) {
                /* Write in an end-of-string mark and return the start of the
                 * next token.
                 */
                *p++ = '\0';
                p += strspn( p, brk );
        }

	/* There may be escaped break characters in str. Loop, squashing them
	 * out.
	 */
	for( q = strchr( str, '\\' ); q && *q; q = strchr( q, '\\' ) ) {
		memmove( q, q + 1, strlen( q ) );

		/* If there's \\, we don't want to squash out the second \.
		 */
		q += 1;
	}

        return( p );
}

/* Wrapper over (v)snprintf() ... missing on old systems.
 */
int
vips_vsnprintf( char *str, size_t size, const char *format, va_list ap )
{
#ifdef HAVE_VSNPRINTF
	return( vsnprintf( str, size, format, ap ) );
#else /*HAVE_VSNPRINTF*/
	/* Bleurg!
	 */
	int n;
	static char buf[MAX_BUF];

	/* We can't return an error code, we may already have trashed the
	 * stack. We must stop immediately.
	 */
	if( size > MAX_BUF )
		vips_error_exit( "panic: buffer overflow "
			"(request to write %lu bytes to buffer of %d bytes)",
			(unsigned long) size, MAX_BUF );
	n = vsprintf( buf, format, ap );
	if( n > MAX_BUF )
		vips_error_exit( "panic: buffer overflow "
			"(%d bytes written to buffer of %d bytes)",
			n, MAX_BUF );

	vips_strncpy( str, buf, size );

	return( n );
#endif /*HAVE_VSNPRINTF*/
}

int
vips_snprintf( char *str, size_t size, const char *format, ... )
{
	va_list ap;
	int n;

	va_start( ap, format );
	n = vips_vsnprintf( str, size, format, ap );
	va_end( ap );

	return( n );
}

/* Does a filename have one of a set of suffixes. Ignore case and any trailing
 * options.
 */
int
vips_filename_suffix_match( const char *path, const char *suffixes[] )
{
	char *basename;
	char *q;
	int result;
	const char **p;

	/* Drop any directory components.
	 */
	basename = g_path_get_basename( path );

	/* Zap any trailing [] options.
	 */
	if( (q = (char *) vips__find_rightmost_brackets( basename )) ) 
		*q = '\0';

	result = 0;
	for( p = suffixes; *p; p++ ) 
		if( vips_iscasepostfix( basename, *p ) ) {
			result = 1;
			break;
		}

	g_free( basename );

	return( result );
}

/* Get file length ... 64-bitally. -1 for error.
 */
gint64
vips_file_length( int fd )
{
#ifdef G_OS_WIN32
	struct _stati64 st;

	if( _fstati64( fd, &st ) == -1 ) {
#else /*!G_OS_WIN32*/
	struct stat st;

	if( fstat( fd, &st ) == -1 ) {
#endif /*G_OS_WIN32*/
		vips_error_system( errno, "vips_file_length", 
			"%s", _( "unable to get file stats" ) );
		return( -1 );
	}

	return( st.st_size );
}

/* Wrap write() up
 */
int
vips__write( int fd, const void *buf, size_t count )
{
	do {
		size_t nwritten = write( fd, buf, count );

		if( nwritten == (size_t) -1 ) {
                        vips_error_system( errno, "vips__write", 
				"%s", _( "write failed" ) );
                        return( -1 ); 
		}

		buf = (void *) ((char *) buf + nwritten);
		count -= nwritten;
	} while( count > 0 );

	return( 0 );
}

#ifdef G_OS_WIN32
/* Set the create date on a file. On Windows, the create date may be copied 
 * over from an existing file of the same name, unless you reset it. 
 *
 * See https://blogs.msdn.microsoft.com/oldnewthing/20050715-14/?p=34923
 */
void
vips__set_create_time( int fd )
{
	HANDLE handle;
	SYSTEMTIME st;
	FILETIME ft;

	if( (handle = (HANDLE) _get_osfhandle( fd )) == INVALID_HANDLE_VALUE )
		return;
	GetSystemTime( &st );
	SystemTimeToFileTime( &st, &ft );
	SetFileTime( handle, &ft, &ft, &ft );
}
#endif /*G_OS_WIN32*/

/* open() with a utf8 filename, setting errno.
 */
int
vips__open( const char *filename, int flags, int mode )
{
	int fd;

	/* Various bad things happen if you accidentally open a directory as a
	 * file.
	 */
	if( g_file_test( filename, G_FILE_TEST_IS_DIR ) ) {
		errno = EISDIR;
		return( -1 );
	}

	fd = g_open( filename, flags, mode );

#ifdef G_OS_WIN32
	if( mode & O_CREAT )
		vips__set_create_time( fd ); 
#endif /*G_OS_WIN32*/

	return( fd );
}

int 
vips__open_read( const char *filename )
{
	return( vips__open( filename, MODE_READ, 0 ) );
}

/* fopen() with utf8 filename and mode, setting errno.
 */
FILE *
vips__fopen( const char *filename, const char *mode )
{
	FILE *fp;

	fp = g_fopen( filename, mode );

#ifdef G_OS_WIN32
	if( mode[0] == 'w' )
		vips__set_create_time( _fileno( fp ) ); 
#endif /*G_OS_WIN32*/

	return( fp );
}

/* Does a filename contain a directory separator?
 */
static gboolean 
filename_hasdir( const char *filename )
{
	char *dirname;
	gboolean hasdir;

	dirname = g_path_get_dirname( filename );
	hasdir = (strcmp( dirname, "." ) != 0);
	g_free( dirname );

	return( hasdir );
}

/* Open a file. We take an optional fallback dir as well and will try opening
 * there if opening directly fails.
 *
 * This is used for things like finding ICC profiles. We try to open the file
 * directly first, and if that fails and the filename does not contain a
 * directory separator, we try looking in the fallback dir.
 */
FILE *
vips__file_open_read( const char *filename, const char *fallback_dir, 
	gboolean text_mode )
{
	char *mode;
	FILE *fp;

#if defined(G_PLATFORM_WIN32) || defined(G_WITH_CYGWIN)
	if( text_mode )
		mode = "rN";
	else
		mode = "rbN";
#else /*!defined(G_PLATFORM_WIN32) && !defined(G_WITH_CYGWIN)*/
	mode = "re";
#endif /*defined(G_PLATFORM_WIN32) || defined(G_WITH_CYGWIN)*/

	if( (fp = vips__fopen( filename, mode )) )
		return( fp );

	if( fallback_dir && 
		!filename_hasdir( filename ) ) {
		char *path;

		path = g_build_filename( fallback_dir, filename, NULL );
	        fp = vips__fopen( path, mode );
		g_free( path );

		if( fp )
			return( fp );
	}

	vips_error_system( errno, "vips__file_open_read", 
		_( "unable to open file \"%s\" for reading" ), filename );

	return( NULL );
}

FILE *
vips__file_open_write( const char *filename, gboolean text_mode )
{
	char *mode;
	FILE *fp;

#if defined(G_PLATFORM_WIN32) || defined(G_WITH_CYGWIN)
	if( text_mode )
		mode = "wN";
	else
		mode = "wbN";
#else /*!defined(G_PLATFORM_WIN32) && !defined(G_WITH_CYGWIN)*/
	mode = "we";
#endif /*defined(G_PLATFORM_WIN32) || defined(G_WITH_CYGWIN)*/

        if( !(fp = vips__fopen( filename, mode )) ) {
		vips_error_system( errno, "vips__file_open_write", 
			_( "unable to open file \"%s\" for writing" ), 
			filename );
		return( NULL );
	}

	return( fp );
}

/* Load up a file as a string.
 */
char *
vips__file_read( FILE *fp, const char *filename, size_t *length_out )
{
        gint64 len;
	size_t read;
        char *str;

	len = vips_file_length( fileno( fp ) ); 
	if( len > 1024 * 1024 * 1024 ) {
		/* Over a gb? Seems crazy!
		 */
                vips_error( "vips__file_read", 
			_( "\"%s\" too long" ), filename );
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
			char *str2;

			/* Again, a 1gb sanity limit.
			 */
			size += 1024;
			if( size > 1024 * 1024 * 1024 ||
				!(str2 = realloc( str, size )) ) {
				free( str ); 
				vips_error( "vips__file_read", 
					"%s", _( "out of memory" ) );
				return( NULL );
			}
			str = str2;

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
		if( !(str = vips_malloc( NULL, len + 1 )) )
			return( NULL );
		rewind( fp );
		read = fread( str, sizeof( char ), (size_t) len, fp );
		if( read != (size_t) len ) {
			g_free( str );
			vips_error( "vips__file_read", 
				_( "error reading from file \"%s\"" ), 
				filename );
			return( NULL );
		}
	}

	str[len] = '\0';

	if( length_out )
		*length_out = len;

        return( str );
}

/* Load from a filename as a string. Used for things like reading in ICC
 * profiles, ie. binary objects.
 */
char *
vips__file_read_name( const char *filename, const char *fallback_dir, 
	size_t *length_out )
{
	FILE *fp;
	char *buffer;

        if( !(fp = vips__file_open_read( filename, fallback_dir, FALSE )) ) 
		return( NULL );
	if( !(buffer = vips__file_read( fp, filename, length_out )) ) {
		fclose( fp );
		return( NULL );
	}
	fclose( fp );

	return( buffer );
}

/* Like fwrite(), but returns non-zero on error and sets error message.
 */
int
vips__file_write( void *data, size_t size, size_t nmemb, FILE *stream )
{
	size_t n;

	if( !data ) 
		return( 0 );

	if( (n = fwrite( data, size, nmemb, stream )) != nmemb ) {
		vips_error_system( errno, "vips__file_write", 
			_( "write error (%zd out of %zd blocks written)" ),
			n, nmemb );
		return( -1 );
	}

	return( 0 );
}

/* Read a few bytes from the start of a file. This is used for sniffing file 
 * types, so we must read binary. 
 *
 * Return the number of bytes actually read (the file might be shorter than
 * len), or -1 for error.
 */
gint64
vips__get_bytes( const char *filename, unsigned char buf[], gint64 len )
{
	int fd;
	gint64 bytes_read;

	/* File may not even exist (for tmp images for example!)
	 * so no hasty messages. And the file might be truncated, so no error
	 * on read either.
	 */
	if( (fd = vips__open_read( filename )) == -1 )
		return( 0 );
	bytes_read = read( fd, buf, len );
	close( fd );

	return( bytes_read );
}

/* We try to support stupid DOS files too. These have \r\n (13, 10) as line
 * separators. Strategy: an fgetc() that swaps \r\n for \n. 
 *
 * On Windows, stdio will automatically swap \r\n for \n, but on Linux we have
 * to do this by hand. 
 */
int
vips__fgetc( FILE *fp )
{
	int ch;

	ch = fgetc( fp );
	if( ch == '\r' ) {
		ch = fgetc( fp );
		if( ch != '\n' ) {
			ungetc( ch, fp );
			ch = '\r';
		}
	}

	return( ch ); 
}

/* Alloc/free a GValue.
 */
static GValue *
vips__gvalue_new( GType type )
{
	GValue *value;

	value = g_new0( GValue, 1 );
	g_value_init( value, type );

	return( value );
}

static GValue *
vips__gvalue_copy( GValue *value )
{
	GValue *value_copy;

	value_copy = vips__gvalue_new( G_VALUE_TYPE( value ) );
	g_value_copy( value, value_copy );

	return( value_copy );
}

static void
vips__gvalue_free( GValue *value, void *user_data )
{
	g_value_unset( value );
	g_free( value );
}

GValue *
vips__gvalue_ref_string_new( const char *text )
{
	GValue *value;

	value = vips__gvalue_new( VIPS_TYPE_REF_STRING );
	vips_value_set_ref_string( value, text );

	return( value );
}

/* Free a GSList of GValue.
 */
void
vips__gslist_gvalue_free( GSList *list )
{
	g_slist_foreach( list, (GFunc) vips__gvalue_free, NULL );
	g_slist_free( list );
}

/* Copy a GSList of GValue.
 */
GSList *
vips__gslist_gvalue_copy( const GSList *list )
{
	GSList *copy;
	const GSList *p;

	copy = NULL;

	for( p = list; p; p = p->next ) 
		copy = g_slist_prepend( copy, 
			vips__gvalue_copy( (GValue *) p->data ) );

	copy = g_slist_reverse( copy );

	return( copy );
}

/* Merge two GSList of GValue ... append to a all elements in b which are not 
 * in a. Return the new value of a. Works for any vips refcounted type 
 * (string, blob, etc.).
 */
GSList *
vips__gslist_gvalue_merge( GSList *a, const GSList *b )
{
	const GSList *i, *j;
	GSList *tail;

	tail = NULL;

	for( i = b; i; i = i->next ) {
		GValue *value = (GValue *) i->data;

		g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_REF_STRING );

		for( j = a; j; j = j->next ) {
			GValue *value2 = (GValue *) j->data;

			g_assert( G_VALUE_TYPE( value2 ) == 
				VIPS_TYPE_REF_STRING );

			/* Just do a pointer compare ... good enough 99.9% of 
			 * the time.
			 */
			if( vips_value_get_ref_string( value, NULL ) ==
				vips_value_get_ref_string( value2, NULL ) )
				break;
		}

		if( !j )
			tail = g_slist_prepend( tail, 
				vips__gvalue_copy( value ) );
	}

	a = g_slist_concat( a, g_slist_reverse( tail ) );

	return( a );
}

/* Make a char * from GSList of GValue. Each GValue should be a ref_string.
 * free the result. Empty list -> "", not NULL. Join strings with '\n'.
 */
char *
vips__gslist_gvalue_get( const GSList *list )
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
		size_t l2;

		g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_REF_STRING );

		/* +1 for the newline we will add for each item.
		 */
		(void) vips_value_get_ref_string( value, &l2 );
		length += l2 + 1;
	}

	if( length == 0 )
		return( NULL );

	/* More than 10MB of history? Madness!
	 */
	g_assert( length < 10 * 1024 * 1024 );

	/* +1 for '\0'.
	 */
	if( !(all = vips_malloc( NULL, length + 1 )) )
		return( NULL );

	q = all;
	for( p = list; p; p = p->next ) {
		GValue *value = (GValue *) p->data;
		size_t l2;

		strcpy( q, vips_value_get_ref_string( value, &l2 ) );
		q += l2;
		strcpy( q, "\n" );
		q += 1;
	}

	g_assert( (size_t) (q - all) == length );

	return( all );
}

gint64
vips__seek_no_error( int fd, gint64 pos, int whence )
{
	gint64 new_pos;

#ifdef G_OS_WIN32
	new_pos = _lseeki64( fd, pos, whence );
#else /*!G_OS_WIN32*/
	/* On error, eg. opening a directory and seeking to the end, lseek() 
	 * on linux seems to return 9223372036854775807 ((1 << 63) - 1)
	 * rather than (off_t) -1 for reasons I don't understand. 
	 */
	new_pos = lseek( fd, pos, whence );
#endif /*G_OS_WIN32*/

	return( new_pos );
}

/* Need our own seek(), since lseek() on win32 can't do long files.
 */
gint64
vips__seek( int fd, gint64 pos, int whence )
{
	gint64 new_pos;

	if( (new_pos = vips__seek_no_error( fd, pos, whence )) == -1 ) {
		vips_error_system( errno, "vips__seek", 
			"%s", _( "unable to seek" ) );
		return( -1 );
	}

	return( new_pos );
}

/* Need our own ftruncate(), since ftruncate() on win32 can't do long files.

	DANGER ... this moves the file pointer to the end of file on win32,
	but not on *nix; don't make any assumptions about the file pointer
	position after calling this

 */
int
vips__ftruncate( int fd, gint64 pos )
{
#ifdef G_OS_WIN32
{
	HANDLE hFile = (HANDLE) _get_osfhandle( fd );

	if( vips__seek( fd, pos, SEEK_SET ) == -1 )
		return( -1 );
	if( !SetEndOfFile( hFile ) ) {
                vips_error_system( GetLastError(), "vips__ftruncate", 
			"%s", _( "unable to truncate" ) );
		return( -1 );
	}
}
#else /*!G_OS_WIN32*/
	if( ftruncate( fd, pos ) ) {
		vips_error_system( errno, "vips__ftruncate", 
			"%s", _( "unable to truncate" ) );
		return( -1 );
	}
#endif /*G_OS_WIN32*/

	return( 0 );
}

/* TRUE if file exists. True for directories as well.
 */
gboolean
vips_existsf( const char *name, ... )
{
        va_list ap;
	char *path; 
        gboolean result; 

        va_start( ap, name );
	path = g_strdup_vprintf( name, ap ); 
        va_end( ap );

	result = g_file_test( path, G_FILE_TEST_EXISTS );

	g_free( path ); 

	return( result ); 
}

/* TRUE if file exists and is a directory.
 */
gboolean
vips_isdirf( const char *name, ... )
{
        va_list ap;
	char *path; 
        gboolean result; 

        va_start( ap, name );
	path = g_strdup_vprintf( name, ap ); 
        va_end( ap );

	result = g_file_test( path, G_FILE_TEST_IS_DIR );

	g_free( path ); 

	return( result ); 
}

/* Make a directory.
 */
int
vips_mkdirf( const char *name, ... )
{
        va_list ap;
	char *path; 

        va_start( ap, name );
	path = g_strdup_vprintf( name, ap ); 
        va_end( ap );

	if( g_mkdir( path, 0755 ) ) { 
		vips_error( "mkdirf", 
			_( "unable to create directory \"%s\", %s" ), 
			path, strerror( errno ) );
		g_free( path ); 
                return( -1 );
	}
	g_free( path ); 

        return( 0 );
}

/* Remove a directory.
 */
int
vips_rmdirf( const char *name, ... )
{
        va_list ap;
	char *path; 

        va_start( ap, name );
	path = g_strdup_vprintf( name, ap ); 
        va_end( ap );

	if( g_rmdir( path ) ) { 
		vips_error( "rmdir", 
			_( "unable to remove directory \"%s\", %s" ), 
			path, strerror( errno ) );
		g_free( path ); 
                return( -1 );
	}
	g_free( path ); 

        return( 0 );
}

/* Rename a file. 
 */
int
vips_rename( const char *old_name, const char *new_name )
{
	if( g_rename( old_name, new_name ) ) { 
		vips_error( "rename", 
			_( "unable to rename file \"%s\" as \"%s\", %s" ), 
			old_name, new_name, strerror( errno ) );
                return( -1 );
	}

        return( 0 );
}

/* Chop off any trailing whitespace.
 */
void
vips__chomp( char *str )
{
	char *p;

	for( p = str + strlen( str ); p > str && isspace( p[-1] ); p-- )
		p[-1] = '\0';
}

/* Break a command-line argument into tokens separated by whitespace. 
 *
 * Strings can't be adjacent, so "hello world" (without quotes) is a single 
 * string.  Strings are written (with \" escaped) into @string. If the string
 * is larger than @size, it is silently null-terminated and truncated. 
 *
 * Return NULL for end of tokens.
 */
const char *
vips__token_get( const char *p, VipsToken *token, char *string, int size )
{
	const char *q;
	int ch;
	int n;
	int i;

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
	case '[':
		*token = VIPS_TOKEN_LEFT;
		p += 1;
		break;

	case ']':
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

			/* How much can we copy to the buffer?
			 */
			i = VIPS_MIN( n, size );
			vips_strncpy( string, p + 1, i );

			/* We might have stopped at an escaped quote. If the
			 * string was not truncated, swap the preceding 
			 * backslash for a quote.
			 */
			if( p[n + 1] == ch && p[n] == '\\' && i == n )
				string[i - 1] = ch;

			string += i;
			size -= i;
			p += n + 1;
		} while( p[0] && p[-1] == '\\' );

		p += 1;

		break;

	default:
		/* It's an unquoted string: read up to the next non-string
		 * character. We don't allow two strings next to each other,
		 * so the next break must be brackets, equals, comma.
		 */
		*token = VIPS_TOKEN_STRING;
		q = p + strcspn( p, "[]=," );

		i = VIPS_MIN( q - p, size );
		vips_strncpy( string, p, i + 1 );
		p = q;

		/* We remove leading whitespace, so we trim trailing
		 * whitespace from unquoted strings too. Only if the string
		 * hasn't been truncated.
		 */
		if( i != size ) 
			while( i > 0 && isspace( string[i - 1] ) ) {
				string[i - 1] = '\0';
				i--;
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
		vips_error( "get_token", 
			"%s", _( "unexpected end of string" ) );
		return( NULL );
	}

	return( p );
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
		vips_error( "get_token", _( "expected %s, saw %s" ), 
			vips_enum_nick( VIPS_TYPE_TOKEN, need_token ),
			vips_enum_nick( VIPS_TYPE_TOKEN, token ) );
		return( NULL );
	}

	return( p );
}

/* Fetch a token. If it's a string token terminated by a '[', fetch up to the
 * matching ']' as well, for example ".jpg[Q=90]".
 *
 * Return NULL for end of tokens.
 */
const char *
vips__token_segment( const char *p, VipsToken *token, 
	char *string, int size )
{
	const char *q;

	if( !(q = vips__token_must( p, token, string, size )) )
		return( NULL ); 

	/* If we stopped on [, read up to the matching ]. 
	 */
	if( *token == VIPS_TOKEN_STRING &&
		q[0] == '[' ) {
		VipsToken sub_token;
		char sub_string[VIPS_PATH_MAX];
		int depth;
		int i; 

		depth = 0;
		do {
			if( !(q = vips__token_must( q, &sub_token, 
				sub_string, VIPS_PATH_MAX )) )
				return( NULL ); 

			switch( sub_token ) {
			case VIPS_TOKEN_LEFT:
				depth += 1;
				break;

			case VIPS_TOKEN_RIGHT:
				depth -= 1;
				break;

			default:
				break;
			}
		} while( !(sub_token == VIPS_TOKEN_RIGHT && depth == 0) );

		i = VIPS_MIN( q - p, size );
		vips_strncpy( string, p, i + 1 );
	}

	return( q ); 
}

/* We expect a certain segment.
 */
const char *
vips__token_segment_need( const char *p, VipsToken need_token, 
	char *string, int size )
{
	VipsToken token;

	if( !(p = vips__token_segment( p, &token, string, size )) ) 
		return( NULL );
	if( token != need_token ) {
		vips_error( "get_token", _( "expected %s, saw %s" ), 
			vips_enum_nick( VIPS_TYPE_TOKEN, need_token ),
			vips_enum_nick( VIPS_TYPE_TOKEN, token ) );
		return( NULL );
	}

	return( p );
}

/* Maximum number of tokens we allow in a filename. Surely this will be
 * plenty.
 */
#define MAX_TOKENS (1000)

/* Find the start of the right-most pair of brackets in the string.
 *
 * A string can be of the form:
 *
 * 	"hello world! (no really).tif[fred=12]"
 *
 * we need to be able to find the fred=12 at the end.
 *
 * We lex the whole string noting the position of each token, then, if the 
 * final token is a right-bracket, search left for the matching left-bracket.
 *
 * This can get confused if the lefts are hidden inside another token :-( But
 * a fixing that would require us to write a separate right-to-left lexer, 
 * argh.
 */
const char *
vips__find_rightmost_brackets( const char *p )
{
	const char *start[MAX_TOKENS + 1];
	VipsToken tokens[MAX_TOKENS];
	char str[VIPS_PATH_MAX];
	int n, i;
	int nest;

	start[0] = p;
	for( n = 0; 
		n < MAX_TOKENS &&
		(p = vips__token_get( start[n], &tokens[n], 
			str, VIPS_PATH_MAX )); 
		n++, start[n] = p )
		;

	/* Too many tokens?
	 */
	if( n >= MAX_TOKENS )
		return( NULL );

	/* No rightmost close bracket?
	 */
	if( n == 0 ||
		tokens[n - 1] != VIPS_TOKEN_RIGHT ) 
		return( NULL );

	nest = 0;
	for( i = n - 1; i >= 0; i-- ) {
		if( tokens[i] == VIPS_TOKEN_RIGHT )
			nest += 1;
		else if( tokens[i] == VIPS_TOKEN_LEFT )
			nest -= 1;

		if( nest == 0 )
			break;
	}

	/* No matching left bracket?
	 */
	if( nest != 0 )
		return( NULL );

	/* This should be the matching left.
	 */
	return( start[i] );
}

/* Split a vips8-style filename + options.
 *
 * filename and option_string must be VIPS_PATH_MAX in length. 
 */
void
vips__filename_split8( const char *name, char *filename, char *option_string )
{
	char *p;

	vips_strncpy( filename, name, VIPS_PATH_MAX );
	if( (p = (char *) vips__find_rightmost_brackets( filename )) ) {
		vips_strncpy( option_string, p, VIPS_PATH_MAX );
		*p = '\0';
	}
	else
		vips_strncpy( option_string, "", VIPS_PATH_MAX );
}

/* True if an int is a power of two ... 1, 2, 4, 8, 16, 32, etc. Do with just
 * integer arithmetic for portability. A previous Nicos version using doubles
 * and log/log failed on x86 with rounding problems. Return 0 for not
 * power of two, otherwise return the position of the set bit (numbering with
 * bit 1 as the lsb).
 */
int
vips_ispoweroftwo( int p )
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

/* Test this processor for endianness. True for SPARC order.
 */
int
vips_amiMSBfirst( void )
{
#if G_BYTE_ORDER == G_BIG_ENDIAN
	return( 1 );
#elif G_BYTE_ORDER == G_LITTLE_ENDIAN
	return( 0 );
#else
#error "Byte order not recognised"
#endif
}

/* Return the tmp dir. On Windows, GetTempPath() will also check the values of 
 * TMP, TEMP and USERPROFILE.
 */
static const char *
vips__temp_dir( void )
{
	const char *tmpd;

	if( !(tmpd = g_getenv( "TMPDIR" )) ) {
#ifdef G_OS_WIN32
		static gboolean done = FALSE;
		static char buf[256];

		if( !done ) {
			if( !GetTempPath( 256, buf ) )
				strcpy( buf, "C:\\temp" );
		}
		tmpd = buf;
#else /*!G_OS_WIN32*/
		tmpd = "/tmp";
#endif /*!G_OS_WIN32*/
	}

	return( tmpd );
}

/* Make a temporary file name. The format parameter is something like "%s.jpg" 
 * and will be expanded to something like "/tmp/vips-12-34587.jpg".
 *
 * You need to free the result. 
 */
char *
vips__temp_name( const char *format )
{
	static int global_serial = 0;

	char file[FILENAME_MAX];
	char file2[FILENAME_MAX];
	char *name;

	int serial = g_atomic_int_add( &global_serial, 1 );

	vips_snprintf( file, FILENAME_MAX, "vips-%d-%u", 
		serial, g_random_int() );
	vips_snprintf( file2, FILENAME_MAX, format, file );
	name = g_build_filename( vips__temp_dir(), file2, NULL );

	/* We could use something like g_mkstemp() to guarantee uniqueness
	 * across processes, but the extra FS calls can be difficult for 
	 * selinux.
	 *
	 * g_random_int() should be safe enough -- it's seeded from time(), so
	 * it ought not to collide often -- and on linux at least we never 
	 * actually use these filenames in the filesystem anyway.
	 */

	return( name );
}

/* Strip off any of a set of old suffixes (eg. [".v", ".jpg"]), add a single 
 * new suffix (eg. ".tif"). 
 */
void
vips__change_suffix( const char *name, char *out, int mx,
        const char *new, const char **olds, int nolds )
{
        char *p;
        int i;
	int len;

        /* Copy start string.
         */
        vips_strncpy( out, name, mx );

        /* Drop all matching suffixes.
         */
        while( (p = strrchr( out, '.' )) ) {
                /* Found suffix - test against list of alternatives. Ignore
                 * case.
                 */
                for( i = 0; i < nolds; i++ )
                        if( g_ascii_strcasecmp( p, olds[i] ) == 0 ) {
                                *p = '\0';
                                break;
                        }

                /* Found match? If not, break from loop.
                 */
                if( *p )
                        break;
        }

        /* Add new suffix.
         */
	len = strlen( out );
	vips_strncpy( out + len, new, mx - len );
}

typedef struct {
	const char unit;
	int multiplier;
} Unit;

guint64
vips__parse_size( const char *size_string )
{
	static Unit units[] = {
		{ 'k', 1024 },
		{ 'm', 1024 * 1024 },
		{ 'g', 1024 * 1024 * 1024 }
	};

	guint64 size;
	int n;
	int i;
	char *unit;

	/* An easy way to alloc a buffer large enough.
	 */
	unit = g_strdup( size_string );
	n = sscanf( size_string, "%d %s", &i, unit );
	size = i;
	if( n > 1 ) {
		int j;

		for( j = 0; j < VIPS_NUMBER( units ); j++ )
			if( tolower( unit[0] ) == units[j].unit ) {
				size *= units[j].multiplier;
				break;
			}
	}
	g_free( unit );

	VIPS_DEBUG_MSG( "parse_size: parsed \"%s\" as %" G_GUINT64_FORMAT "\n", 
		size_string, size );

	return( size );
}

/* Look up the const char * for an enum value.
 */
const char *
vips_enum_string( GType enm, int v )
{
	GEnumValue *value;

	if( !(value = g_enum_get_value( g_type_class_ref( enm ), v )) )
		return( "(null)" );

	return( value->value_name );
}

const char *
vips_enum_nick( GType enm, int v )
{
	GEnumValue *value;

	if( !(value = g_enum_get_value( g_type_class_ref( enm ), v )) )
		return( "(null)" );

	return( value->value_nick );
}

int
vips_enum_from_nick( const char *domain, GType type, const char *nick )
{
	GTypeClass *class;
	GEnumClass *genum;
	GEnumValue *enum_value;
	int i;
	char str[1000];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	if( !(class = g_type_class_ref( type )) ) {
		vips_error( domain, "%s", _( "no such enum type" ) ); 
		return( -1 );
	}
	genum = G_ENUM_CLASS( class );

	if( (enum_value = g_enum_get_value_by_name( genum, nick )) ) 
		return( enum_value->value );
	if( (enum_value = g_enum_get_value_by_nick( genum, nick )) ) 
		return( enum_value->value );

	/* -1 since we always have a "last" member.
	 */
	for( i = 0; i < genum->n_values - 1; i++ ) {
		if( i > 0 )
			vips_buf_appends( &buf, ", " );
		vips_buf_appends( &buf, genum->values[i].value_nick );
	}

	vips_error( domain, _( "enum '%s' has no member '%s', " 
		"should be one of: %s" ),
		g_type_name( type ), nick, vips_buf_all( &buf ) );

	return( -1 );
}

int
vips_flags_from_nick( const char *domain, GType type, const char *nick )
{
	GTypeClass *class;
	GFlagsClass *gflags;
	GFlagsValue *flags_value;
	int i;
	char str[1000];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	if( !(class = g_type_class_ref( type )) ) {
		vips_error( domain, "%s", _( "no such flag type" ) ); 
		return( -1 );
	}
	gflags = G_FLAGS_CLASS( class );

	if( (flags_value = g_flags_get_value_by_name( gflags, nick )) ) 
		return( flags_value->value );
	if( (flags_value = g_flags_get_value_by_nick( gflags, nick )) ) 
		return( flags_value->value );

	for( i = 0; i < gflags->n_values; i++ ) {
		if( i > 0 )
			vips_buf_appends( &buf, ", " );
		vips_buf_appends( &buf, gflags->values[i].value_nick );
	}

	vips_error( domain, _( "flags '%s' has no member '%s', " 
		"should be one of: %s" ),
		g_type_name( type ), nick, vips_buf_all( &buf ) );

	return( -1 );
}

/* Scan @buf for the first "%ns" (eg. "%12s") and substitute the 
 * lowest-numbered one for @sub. @buf is @len bytes in size.
 *
 * If there are no %ns, use the first %s.
 */
int
vips__substitute( char *buf, size_t len, char *sub )
{
	size_t buflen = strlen( buf ); 
	size_t sublen = strlen( sub ); 

	int lowest_n;
	char *sub_start;
	char *p;
	char *sub_end;
	size_t before_len, marker_len, after_len, final_len;

	g_assert( buflen < len ); 

	lowest_n = -1;
	sub_start = NULL;
	sub_end = NULL;
	for( p = buf; (p = strchr( p, '%' )); p++ )  
		if( isdigit( p[1] ) ) {
			char *q;

			for( q = p + 1; isdigit( *q ); q++ )
				;
			if( q[0] == 's' ) {
				int n;

				n = atoi( p + 1 );
				if( lowest_n == -1 ||
					n < lowest_n ) {
					lowest_n = n;
					sub_start = p;
					sub_end = q + 1;
				}
			}
		}

	if( !sub_start ) 
		for( p = buf; (p = strchr( p, '%' )); p++ )  
			if( p[1] == 's' ) {
				sub_start = p;
				sub_end = p + 2;
				break;
			}

	if( !sub_start ) 
		return( -1 ); 

	before_len = sub_start - buf;
	marker_len = sub_end - sub_start;
	after_len = buflen - (before_len + marker_len);
	final_len = before_len + sublen + after_len + 1;
	if( final_len > len )  
		return( -1 ); 

	memmove( buf + before_len + sublen, buf + before_len + marker_len, 
		after_len + 1 );  
	memmove( buf + before_len, sub, sublen ); 

	return( 0 ); 
}

/* Absoluteize a path. Free the result with g_free().
 */
char *
vips_realpath( const char *path ) 
{
	char *real;

	/* It'd be nice to use realpath here, but sadly that won't work on
	 * linux systems with grsec, since it works by opening /proc/self/fd.
	 */

	if( !g_path_is_absolute( path ) ) {
		char *cwd;

		cwd = g_get_current_dir();
		real = g_build_filename( cwd, path, NULL );
		g_free( cwd );
	}
	else
		real = g_strdup( path );

	return( real );
}

/* A very simple random number generator. See:
 * http://isthe.com/chongo/tech/comp/fnv/#FNV-source
 */
guint32
vips__random( guint32 seed )
{
	return( 1103515245u * seed + 12345 );
}

guint32 
vips__random_add( guint32 seed, int value )
{
	seed = ((2166136261u ^ seed) * 16777619u) ^ value;

	return( vips__random( seed ) ); 
}

static void *
vips_icc_dir_once( void *null )
{
#ifdef G_OS_WIN32
	/* From glib get_windows_directory_root()
	 */
	wchar_t wwindowsdir[MAX_PATH];

	if( GetWindowsDirectoryW( wwindowsdir, G_N_ELEMENTS( wwindowsdir ) ) ) {
		/* Usually X:\Windows, but in terminal server environments
		 * might be an UNC path, AFAIK.
		 */
		char *windowsdir;

		if( (windowsdir = g_utf16_to_utf8( wwindowsdir, 
			-1, NULL, NULL, NULL)) ) {
			gchar *full_path;

			full_path = g_build_filename( windowsdir, 
				"system32", "spool", "drivers", "color", NULL );
			g_free( windowsdir );

			return( (void *) full_path );
		}
	}
#endif /*G_OS_WIN32*/

	return( (void *) VIPS_ICC_DIR );
}

const char *
vips__icc_dir( void )
{
	static GOnce once = G_ONCE_INIT;

	return( (const char *) g_once( &once, 
		vips_icc_dir_once, NULL ) );
}

#ifdef G_OS_WIN32
static HMODULE vips__dll = NULL;
#ifdef DLL_EXPORT
BOOL WINAPI
DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
	if( fdwReason == DLL_PROCESS_ATTACH )
		vips__dll = hinstDLL;

	return( TRUE );
}
#endif
#endif /*G_OS_WIN32*/

static void *
vips__windows_prefix_once( void *null )
{
	char *prefix;

#ifdef G_OS_WIN32
	prefix = g_win32_get_package_installation_directory_of_module( 
		vips__dll );
#else /*!G_OS_WIN32*/
        prefix = (char *) g_getenv( "VIPSHOME" );
#endif /*G_OS_WIN32*/

	return( (void *) prefix ); 
}

const char *
vips__windows_prefix( void )
{
	static GOnce once = G_ONCE_INIT;

	return( (const char *) g_once( &once, 
		vips__windows_prefix_once, NULL ) );
}

char *
vips__get_iso8601( void )
{
	char *date;

#ifdef HAVE_DATE_TIME_FORMAT_ISO8601
{
	GDateTime *now;

	now = g_date_time_new_now_local();
	date = g_date_time_format_iso8601( now );
	g_date_time_unref( now );
}
#else /*!HAVE_DATE_TIME_FORMAT_ISO8601*/
{
	GTimeVal now;

	g_get_current_time( &now );
	date = g_time_val_to_iso8601( &now ); 
}
#endif /*HAVE_DATE_TIME_FORMAT_ISO8601*/

	return( date );
}

/* Convert a string to a double in the ASCII locale (ie. decimal point is
 * ".").
 */
int
vips_strtod( const char *str, double *out )
{
	const char *p;

	*out = 0;

	/* The str we fetched must contain at least 1 digit. This 
	 * helps stop us trying to convert "MATLAB" (for example) to 
	 * a number and getting zero.
	 */
	for( p = str; *p; p++ )
		if( isdigit( *p ) )
			break;
	if( !*p ) 
		return( -1 );

	/* This will fail for out of range numbers, like 1e343434, but
	 * is quite happy with eg. "banana".
	 */
	*out = g_ascii_strtod( str, NULL );
	if( errno ) 
		return( -1 );

	return( 0 );
}
