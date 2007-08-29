/* im_system(): run a command on an image
 *
 * 7/3/00 JC
 *	- hacked it in
 * 21/10/02 JC
 *	- use mktemp() if mkstemp() is not available
 * 10/3/03 JC
 *	- out can be NULL
 * 23/12/04
 *	- use g_mkstemp()
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define IM_MAX_STRSIZE (4096)

#ifdef OS_WIN32
#define popen(b,m) _popen(b,m)
#define pclose(f) _pclose(f)
#define mktemp(f) _mktemp(f)
#endif /*OS_WIN32*/

/* A string being written to ... multiple calls to buf_append add to it, on
 * overflow append "..." and block further writes.
 */
typedef struct {
        char *base;             /* String base */
        int mx;                 /* Maximum length */
        int i;                  /* Current write point */
        int full;              	/* String has filled, block writes */
        int lasti;              /* For read-recent */
} BufInfo;

/* Set to start state.
 */
static void
buf_rewind( BufInfo *buf )
{
        buf->i = 0;
        buf->lasti = 0;
        buf->full = 0;

        strcpy( buf->base, "" );
}

/* Init a buf struct.
 */
static void
buf_init( BufInfo *buf, char *base, int mx )
{
        buf->base = base;
        buf->mx = mx;
        buf_rewind( buf );
}

/* Append string to buf. Error on overflow.
 */
static int
buf_appends( BufInfo *buf, const char *str )
{
        int len;
        int avail;
        int cpy;

        if( buf->full )
                return( 0 );

        /* Amount we want to copy.
         */
        len = strlen( str );

        /* Space available.
         */
        avail = buf->mx - buf->i - 4;

        /* Amount we actually copy.
         */
        cpy = IM_MIN( len, avail );

        strncpy( buf->base + buf->i, str, cpy );
        buf->i += cpy;

        if( buf->i >= buf->mx - 4 ) {
                buf->full = 1;
                strcpy( buf->base + buf->mx - 4, "..." );
                buf->i = buf->mx - 1;
                return( 0 );
        }

        return( 1 );
}

/* Read all text from buffer.
 */
static char *
buf_all( BufInfo *buf )
{
        buf->base[buf->i] = '\0';
        return( buf->base );
}

/* Do popen(), with printf-style args.
 */
static FILE *
popenf( const char *fmt, const char *mode, ... )
{
        va_list args;
	char buf[IM_MAX_STRSIZE];

        va_start( args, mode );
        (void) im_vsnprintf( buf, IM_MAX_STRSIZE, fmt, args );
        va_end( args );

        return( popen( buf, mode ) );
}

/* Run a command on an IMAGE ... copy to tmp (if necessary), run 
 * command on it, unlink (if we copied), return stdout from command.
 */
int
im_system( IMAGE *im, const char *cmd, char **out )
{
	char *filename = im->filename;
	int delete = 0;
	FILE *fp;

	if( !im_isfile( im ) ) {
		const char *tmpd;
		char name[IM_MAX_STRSIZE];
		IMAGE *disc;

		if( !(tmpd = g_getenv( "TMPDIR" )) )
			tmpd = "/tmp";
		strcpy( name, tmpd );
		strcat( name, "/vips_XXXXXX" );

		close( g_mkstemp( name ) );
		filename = im_strdup( NULL, name );

		if( !(disc = im_open( filename, "w" )) ) {
			unlink( filename );
			free( filename );
			return( -1 );
		}
		if( im_copy( im, disc ) ) {
			im_close( disc );
			unlink( filename );
			free( filename );
			return( -1 );
		}
		im_close( disc );
		delete = 1;
	}

	if( (fp = popenf( cmd, "r", filename )) ) {
		char line[IM_MAX_STRSIZE];
		BufInfo buf;
		char txt_buffer[IM_MAX_STRSIZE];

		buf_init( &buf, txt_buffer, IM_MAX_STRSIZE );
		while( fgets( line, IM_MAX_STRSIZE, fp ) ) 
			if( !buf_appends( &buf, line ) )
				break; 
		pclose( fp );

		if( out )
			*out = im_strdup( NULL, buf_all( &buf ) );
	}

	if( delete ) {
		unlink( filename );
		im_free( filename );
	}

	if( !fp ) {
		im_errormsg( "popen: %s", strerror( errno ) );
		return( -1 );
	}

	return( 0 );
}
