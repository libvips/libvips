/* guess the install prefix
 * 
 * Written on: 5/2/01 
 * Modified on:
 * 3/3/01 JC
 * 	- better behaviour for relative paths in argv0
 * 22/9/01 JC
 * 	- oops, SEGV in some cases for argv0 contains relative path
 * 26/9/01 JC
 * 	- reworked for new prefix scheme
 * 9/11/01 JC
 *	- grr! added strdup() on putenv() for newer linuxes
 * 14/12/01 JC
 *	- now uses realpath() for better relative pathname guessing
 * 21/10/02 JC
 * 	- turn off realpath() if not available
 * 	- path_is_absolute() from glib
 * 	- append ".exe" to name on w32
 * 	- prefix cwd() to path on w32
 * 31/7/03 JC
 *	- better relative path handling
 * 23/12/04
 *	- use g_setenv()/g_getenv()
 * 29/4/05
 *	- gah, back to plain setenv() so we work with glib-2.2
 * 5/10/05
 * 	- phew, now we can use g_setenv() again
 * 18/8/06
 * 	- use IM_EXEEXT
 * 6/2/07 CB
 * 	- move trailing '\0' too in extract_prefix
 * 21/7/07
 * 	- fall back to configure-time prefix rather than returning an error
 * 	  (thanks Jay)
 * 5/8/08
 * 	- added im_guess_libdir()
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

/* 
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif /*HAVE_SYS_PARAM_H*/
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif /*HAVE_DIRECT_H*/
#include <string.h>
#include <limits.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Strip off any of a set of old suffixes (eg. [".v", ".jpg"]), add a single 
 * new suffix (eg. ".tif"). 
 */
void
im__change_suffix( const char *name, char *out, int mx,
        const char *new, const char **olds, int nolds )
{
        char *p;
        int i;
	int len;

        /* Copy start string.
         */
        im_strncpy( out, name, mx );

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
	im_strncpy( out + len, new, mx - len );
}

static char *
get_current_dir( void )
{
	static char buffer[PATH_MAX];
	char *dir;

	/* We don't use getcwd(3) on SUNOS, because, it does a popen("pwd")
	 * and, if that wasn't bad enough, hangs in doing so.
	 */
#if defined( sun ) && !defined( __SVR4 )
	dir = getwd( buffer );
#else   /* !sun */
	dir = getcwd( buffer, PATH_MAX );
#endif  /* !sun */

	if( !dir ) {
		buffer[0] = G_DIR_SEPARATOR;
		buffer[1] = '\0';
		dir = buffer;
	}

	return( dir );
}

/* Find the prefix part of a dir ... name is the name of this prog from argv0.
 *
 * dir					name		guess prefix
 *
 * /home/john/vips-7.6.4/bin/vips-7.6	vips-7.6	/home/john/vips-7.6.4
 * /usr/local/bin/ip			ip		/usr/local
 *
 * all other forms ... return NULL.
 */
static char *
extract_prefix( const char *dir, const char *name )
{
	char edir[PATH_MAX];
	char vname[PATH_MAX];
	int i;

#ifdef DEBUG
	printf( "extract_prefix: trying for dir = \"%s\", name = \"%s\"\n", 
		dir, name );
#endif /*DEBUG*/

	/* Is dir relative? Prefix with cwd.
	 */
	if( !g_path_is_absolute( dir ) ) {
		im_snprintf( edir, PATH_MAX, "%s" G_DIR_SEPARATOR_S "%s",
			get_current_dir(), dir );
	}
	else {
		im_strncpy( edir, dir, PATH_MAX );
	}

	/* Chop off the trailing prog name, plus the trailing
	 * G_DIR_SEPARATOR_S.
	 */
	if( !im_ispostfix( edir, name ) ) 
		return( NULL );
	im_strncpy( vname, edir, PATH_MAX );
	vname[strlen( edir ) - strlen( name ) - 1] = '\0';

	/* Remove any "/./", any trailing "/.", any trailing "/".
	 */
	for( i = 0; i < (int) strlen( vname ); i++ ) 
		if( im_isprefix( G_DIR_SEPARATOR_S "." G_DIR_SEPARATOR_S, 
			vname + i ) )
			memcpy( vname + i, vname + i + 2, 
				strlen( vname + i + 2 ) + 1 );
	if( im_ispostfix( vname, G_DIR_SEPARATOR_S "." ) )
		vname[strlen( vname ) - 2] = '\0';
	if( im_ispostfix( vname, G_DIR_SEPARATOR_S ) )
		vname[strlen( vname ) - 1] = '\0';

#ifdef DEBUG
	printf( "extract_prefix: canonicalised path = \"%s\"\n", vname );
#endif /*DEBUG*/

	/* Ought to be a "/bin" at the end now.
	 */
	if( !im_ispostfix( vname, G_DIR_SEPARATOR_S "bin" ) ) 
		return( NULL );
	vname[strlen( vname ) - strlen( G_DIR_SEPARATOR_S "bin" )] = '\0';

#ifdef DEBUG
	printf( "extract_prefix: found \"%s\"\n", vname );
#endif /*DEBUG*/

	return( im_strdup( NULL, vname ) );
}

/* Search a path for a file ... we overwrite the PATH string passed in.
 */
static char *
scan_path( char *path, const char *name )
{
	char *p, *q;
	char *prefix;

	for( p = path; 
		(q = im_break_token( p, G_SEARCHPATH_SEPARATOR_S )); p = q ) {
		char str[PATH_MAX];

		/* Form complete path.
		 */
		im_snprintf( str, PATH_MAX, 
			"%s" G_DIR_SEPARATOR_S "%s", p, name );

#ifdef DEBUG
		printf( "scan_path: looking in \"%s\" for \"%s\"\n", 
			p, name );
#endif /*DEBUG*/

		if( im_existsf( "%s", str ) && 
			(prefix = extract_prefix( str, name )) ) {
			return( prefix );
		}
	}

	return( NULL );
}

/* Look for a file along PATH. If we find it, look for an enclosing prefix.
 */
static char *
find_file( const char *name )
{
	const char *path = g_getenv( "PATH" );
	char *prefix;
	char full_path[PATH_MAX];

	if( !path )
		return( NULL );

#ifdef DEBUG
	printf( "im_guess_prefix: g_getenv( \"PATH\" ) == \"%s\"\n", path );
#endif /*DEBUG*/

#ifdef OS_WIN32
	/* Windows always searches '.' first, so prepend cwd to path.
	 */
	im_snprintf( full_path, PATH_MAX, "%s" G_SEARCHPATH_SEPARATOR_S "%s",
		get_current_dir(), path );
#else /*!OS_WIN32*/
	im_strncpy( full_path, path, PATH_MAX );
#endif /*OS_WIN32*/

	if( (prefix = scan_path( full_path, name )) ) 
		return( prefix );

	return( NULL );
}

/* Guess a value for the install PREFIX.
 */
static const char *
guess_prefix( const char *argv0, const char *name )
{
        char *prefix;

	/* Try to guess from argv0.
	 */
	if( argv0 ) {
		if( g_path_is_absolute( argv0 ) ) {
			/* Must point to our executable.
			 */
			if( (prefix = extract_prefix( argv0, name )) ) {
#ifdef DEBUG
				printf( "im_guess_prefix: found \"%s\" from "
					"argv0\n", prefix );
#endif /*DEBUG*/
				return( prefix );
			} 
		}

		/* Look along path for name.
		 */
		if( (prefix = find_file( name )) ) {
#ifdef DEBUG
			printf( "im_guess_prefix: found \"%s\" from "
				"PATH\n", prefix );
#endif /*DEBUG*/
			return( prefix );
		}
        }

#ifdef HAVE_REALPATH
	/* Try to guess from cwd. Only if this is a relative path, though. No
 	 * realpath on winders, but fortunately it seems to always generate
 	 * a full path in argv[0].
	 */
	if( !g_path_is_absolute( argv0 ) ) {
		char full_path[PATH_MAX];
		char resolved[PATH_MAX];

		im_snprintf( full_path, PATH_MAX, "%s" G_DIR_SEPARATOR_S "%s", 
			get_current_dir(), argv0 );

		if( realpath( full_path, resolved ) ) {
			if( (prefix = extract_prefix( resolved, name )) ) {

#ifdef DEBUG
				printf( "im_guess_prefix: found \"%s\" "
					"from cwd\n", prefix );
#endif /*DEBUG*/
				return( prefix );
			}
		}
	}
#endif /*HAVE_REALPATH*/

	/* Fall back to the configure-time prefix.
	 */
	return( IM_PREFIX );
}

/** 
 * im_guess_prefix:
 * @argv0: program name (typically argv[0])
 * @env_name: save prefix in this environment variable
 *
 * im_guess_prefix() tries to guess the install directory. You should pass 
 * in the value of argv[0] (the name your program was run as) as a clue to 
 * help it out, plus the name of the environment variable you let the user 
 * override your package install area with (eg. "VIPSHOME"). 
 *
 * On success, im_guess_prefix() returns the prefix it discovered, and as a 
 * side effect, sets the environment variable (if it's not set).
 *
 * Don't free the return string!
 * 
 * See also: im_guess_libdir().
 *
 * Returns: the install prefix as a static string, do not free.
 */
const char *
im_guess_prefix( const char *argv0, const char *env_name )
{
        const char *prefix;
        const char *p;
        char name[PATH_MAX];

	/* Already set?
	 */
        if( (prefix = g_getenv( env_name )) ) {
#ifdef DEBUG
		printf( "im_guess_prefix: found \"%s\" in environment\n", 
			prefix );
#endif /*DEBUG*/
                return( prefix );
	}

	/* Get the program name from argv0.
	 */
	p = im_skip_dir( argv0 );

	/* Add the exe suffix, if it's missing.
	 */
	if( strlen( IM_EXEEXT ) > 0 ) {
		const char *olds[] = { IM_EXEEXT };

		im__change_suffix( p, name, PATH_MAX, IM_EXEEXT, olds, 1 );
	}
	else
		im_strncpy( name, p, PATH_MAX );

#ifdef DEBUG
	printf( "im_guess_prefix: argv0 = %s\n", argv0 );
	printf( "im_guess_prefix: name = %s\n", name );
	printf( "im_guess_prefix: cwd = %s\n", get_current_dir() );
#endif /*DEBUG*/

	prefix = guess_prefix( argv0, name );
	g_setenv( env_name, prefix, TRUE );

	return( prefix );
}

/** 
 * im_guess_libdir:
 * @argv0: program name (typically argv[0])
 * @env_name: save prefix in this environment variable
 *
 * im_guess_libdir() tries to guess the install directory (usually the 
 * configure libdir, or $prefix/lib). You should pass 
 * in the value of argv[0] (the name your program was run as) as a clue to 
 * help it out, plus the name of the environment variable you let the user 
 * override your package install area with (eg. "VIPSHOME"). 
 *
 * On success, im_guess_libdir() returns the libdir it discovered, and as a 
 * side effect, sets the prefix environment variable (if it's not set).
 *
 * Don't free the return string!
 * 
 * See also: im_guess_prefix().
 *
 * Returns: the libdir as a static string, do not free.
 */
const char *
im_guess_libdir( const char *argv0, const char *env_name )
{
	const char *prefix = im_guess_prefix( argv0, env_name );
        static char *libdir = NULL;

	if( libdir )
		return( libdir );

	/* Have we been moved since configure? If not, use the configure-time
	 * libdir.
	 */
	if( strcmp( prefix, IM_PREFIX ) == 0 ) 
		libdir = IM_LIBDIR;
	else
		libdir = g_strdup_printf( "%s/lib", prefix );

#ifdef DEBUG
	printf( "im_guess_libdir: IM_PREFIX = %s\n", IM_PREFIX );
	printf( "im_guess_libdir: IM_LIBDIR = %s\n", IM_LIBDIR );
	printf( "im_guess_libdir: prefix = %s\n", prefix );
	printf( "im_guess_libdir: libdir = %s\n", libdir );
#endif /*DEBUG*/

	return( libdir );
}

