/* Start up the world of vips.
 *
 * 7/1/04 JC
 *	- 1st version
 * 7/6/05
 * 	- g_type_init() too, so we can use gobject
 * 2/9/06
 * 	- also set g_prg_name() and load plugins
 * 8/12/06
 * 	- add liboil support
 * 5/2/07
 * 	- stop a loop if we're called recursively during VIPS startup ... it
 * 	  can happen if (for example) vips_guess_prefix() fails and tries to
 * 	  i18n an error message (thanks Christian)
 * 8/6/07
 * 	- just warn if plugins fail to load correctly: too annoying to have
 * 	  VIPS refuse to start because of a dodgy plugin
 * 7/11/07
 * 	- progress feedback option
 * 5/8/08
 * 	- load plugins from libdir/vips-x.x
 * 5/10/09
 * 	- gtkdoc comments
 * 14/3/10
 * 	- init image and region before we start, we need all types to be fully
 * 	  constructed before we go parallel
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
#include <limits.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/internal.h>
#include <vips/vector.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Use in various small places where we need a mutex and it's not worth 
 * making a private one.
 */
GMutex *vips__global_lock = NULL;

/* Keep a copy of the argv0 here.
 */
static char *vips__argv0 = NULL;

/**
 * vips_get_argv0:
 *
 * See also: vips_init().
 *
 * Returns: a pointer to an internal copy of the argv0 string passed to
 * vips_init(). Do not free this value
 */
const char *
vips_get_argv0( void )
{
	return( vips__argv0 );
}

/**
 * vips_init:
 * @argv0: name of application
 *
 * vips_init() starts up the world of VIPS. You should call this on
 * program startup before using any other VIPS operations. If you do not call
 * vips_init(), VIPS will call it for you when you use your first VIPS 
 * operation, but
 * it may not be able to get hold of @argv0 and VIPS may therefore be unable
 * to find its data files. It is much better to call this function yourself.
 *
 * vips_init() does approximately the following:
 *
 * <itemizedlist>
 *   <listitem> 
 *     <para>initialises any libraries that VIPS is using, including GObject
 *     and the threading system, if neccessary</para>
 *   </listitem>
 *   <listitem> 
 *     <para>guesses where the VIPS data files are and sets up
 *     internationalisation --- see vips_guess_prefix()
 *     </para>
 *   </listitem>
 *   <listitem> 
 *     <para>creates the main vips types, including VipsImage and friends
 *     </para>
 *   </listitem>
 *   <listitem> 
 *     <para>loads any plugins from $libdir/vips-x.y, where x and y are the
 *     major and minor version numbers for this VIPS.
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * Example:
 *
 * |[
 * int main( int argc, char **argv )
 * {
 *   if( vips_init( argv[0] ) )
 *     vips_error_exit( "unable to start VIPS" );
 *
 *   return( 0 );
 * }
 * ]|
 *
 * See also: vips_get_option_group(), vips_version(), vips_guess_prefix(),
 * vips_guess_libdir().
 *
 * Returns: 0 on success, -1 otherwise
 */
int
vips_init( const char *argv0 )
{
	static gboolean started = FALSE;
	static gboolean done = FALSE;
	char *prgname;
	const char *prefix;
	const char *libdir;
	char name[256];

	/* Two stage done handling: 'done' means we've completed, 'started'
	 * means we're currently initialising. Use this to prevent recursive
	 * invocation.
	 */
	if( done )
		/* Called more than once, we succeeded, just return OK.
		 */
		return( 0 );
	if( started ) 
		/* Recursive invocation, something has broken horribly.
		 * Hopefully the first init will handle it.
		 */
		return( 0 );
	started = TRUE;

	VIPS_SETSTR( vips__argv0, argv0 );

	/* Need gobject etc.
	 */
	g_type_init();

#ifdef G_THREADS_ENABLED
	if( !g_thread_supported() ) 
		g_thread_init( NULL );
#endif /*G_THREADS_ENABLED*/

	if( !vips__global_lock )
		vips__global_lock = g_mutex_new();

	prgname = g_path_get_basename( argv0 );
	g_set_prgname( prgname );
	g_free( prgname );

	/* Try to discover our prefix. 
	 */
	if( !(prefix = vips_guess_prefix( argv0, "VIPSHOME" )) || 
		!(libdir = vips_guess_libdir( argv0, "VIPSHOME" )) ) 
		return( -1 );

	/* Get i18n .mo files from $VIPSHOME/share/locale/.
	 */
	vips_snprintf( name, 256,
		"%s" G_DIR_SEPARATOR_S "share" G_DIR_SEPARATOR_S "locale",
		prefix );
	bindtextdomain( GETTEXT_PACKAGE, name );
	bind_textdomain_codeset( GETTEXT_PACKAGE, "UTF-8" );

	/* Register base vips types.
	 */
	(void) vips_image_get_type();
	(void) vips_region_get_type();
	vips__meta_init_types();
	vips__interpolate_init();
	im__format_init();

	/* Start up packages.
	 */
	vips_arithmetic_operation_init();

	/* Load up any plugins in the vips libdir. We don't error on failure,
	 * it's too annoying to have VIPS refuse to start because of a broken
	 * plugin.
	 */
	if( im_load_plugins( "%s/vips-%d.%d", 
		libdir, VIPS_MAJOR_VERSION, VIPS_MINOR_VERSION ) ) {
		vips_warn( "vips_init", "%s", vips_error_buffer() );
		vips_error_clear();
	}

	/* Also load from libdir. This is old and slightly broken behaviour
	 * :-( kept for back compat convenience.
	 */
	if( im_load_plugins( "%s", libdir ) ) {
		vips_warn( "vips_init", "%s", vips_error_buffer() );
		vips_error_clear();
	}

	/* Build classes which wrap old vips7 operations.
	 */
	vips__init_wrap7_classes();

	/* Start up the buffer cache.
	 */
	vips__buffer_init();

	/* Get the run-time compiler going.
	 */
	vips_vector_init();

	done = TRUE;

	return( 0 );
}

/* Call this before vips stuff that uses stuff we need to have inited.
 */
void
vips_check_init( void )
{
	/* Pass in a nonsense name for argv0 ... this init path is only here
	 * for old programs which are missing an vips_init() call. We need
	 * i18n set up before we can translate.
	 */
	if( vips_init( "giant_banana" ) )
		vips_error_clear();
}

const char *
vips__gettext( const char *msgid )
{
	vips_check_init();

	return( dgettext( GETTEXT_PACKAGE, msgid ) );
}

const char *
vips__ngettext( const char *msgid, const char *plural, unsigned long int n )
{
	vips_check_init();

	return( dngettext( GETTEXT_PACKAGE, msgid, plural, n ) );
}

static GOptionEntry option_entries[] = {
	{ "vips-concurrency", 'c', 0, G_OPTION_ARG_INT, &vips__concurrency, 
		N_( "evaluate with N concurrent threads" ), "N" },
	{ "vips-tile-width", 'w', 0, G_OPTION_ARG_INT, &vips__tile_width, 
		N_( "set tile width to N (DEBUG)" ), "N" },
	{ "vips-tile-height", 'h', 0, G_OPTION_ARG_INT, &vips__tile_height, 
		N_( "set tile height to N (DEBUG)" ), "N" },
	{ "vips-thinstrip-height", 't', 0, 
		G_OPTION_ARG_INT, &vips__thinstrip_height, 
		N_( "set thinstrip height to N (DEBUG)" ), "N" },
	{ "vips-fatstrip-height", 'f', 0, 
		G_OPTION_ARG_INT, &vips__fatstrip_height, 
		N_( "set fatstrip height to N (DEBUG)" ), "N" },
	{ "vips-progress", 'p', 0, G_OPTION_ARG_NONE, &vips__progress, 
		N_( "show progress feedback" ), NULL },
	{ "vips-disc-threshold", 'd', 0, G_OPTION_ARG_STRING, 
		&vips__disc_threshold, 
		N_( "image size above which to decompress to disc" ), NULL },
	{ "vips-novector", 't', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, 
			&vips__vector_enabled, 
		N_( "disable vectorised versions of operations" ), NULL },
	{ NULL }
};

/**
 * vips_get_option_group:
 *
 * vips_get_option_group()  returns  a GOptionGroup containing various VIPS
 * command-line options. It  can  be  used  with  GOption  to  help
 * parse argc/argv.
 *
 * See also: vips_version(), vips_guess_prefix(),
 * vips_guess_libdir(), vips_init().
 *
 * Returns: a GOptionGroup for VIPS, see GOption
 */
GOptionGroup *
vips_get_option_group( void )
{
	static GOptionGroup *option_group = NULL;

	if( !option_group ) {
		option_group = g_option_group_new( 
			"vips", _( "VIPS Options" ), _( "Show VIPS options" ),
			NULL, NULL );
		g_option_group_add_entries( option_group, option_entries );
	}

	return( option_group );
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
		vips_snprintf( edir, PATH_MAX, "%s" G_DIR_SEPARATOR_S "%s",
			get_current_dir(), dir );
	}
	else {
		vips_strncpy( edir, dir, PATH_MAX );
	}

	/* Chop off the trailing prog name, plus the trailing
	 * G_DIR_SEPARATOR_S.
	 */
	if( !vips_ispostfix( edir, name ) ) 
		return( NULL );
	vips_strncpy( vname, edir, PATH_MAX );
	vname[strlen( edir ) - strlen( name ) - 1] = '\0';

	/* Remove any "/./", any trailing "/.", any trailing "/".
	 */
	for( i = 0; i < (int) strlen( vname ); i++ ) 
		if( vips_isprefix( G_DIR_SEPARATOR_S "." G_DIR_SEPARATOR_S, 
			vname + i ) )
			memcpy( vname + i, vname + i + 2, 
				strlen( vname + i + 2 ) + 1 );
	if( vips_ispostfix( vname, G_DIR_SEPARATOR_S "." ) )
		vname[strlen( vname ) - 2] = '\0';
	if( vips_ispostfix( vname, G_DIR_SEPARATOR_S ) )
		vname[strlen( vname ) - 1] = '\0';

#ifdef DEBUG
	printf( "extract_prefix: canonicalised path = \"%s\"\n", vname );
#endif /*DEBUG*/

	/* Ought to be a "/bin" at the end now.
	 */
	if( !vips_ispostfix( vname, G_DIR_SEPARATOR_S "bin" ) ) 
		return( NULL );
	vname[strlen( vname ) - strlen( G_DIR_SEPARATOR_S "bin" )] = '\0';

#ifdef DEBUG
	printf( "extract_prefix: found \"%s\"\n", vname );
#endif /*DEBUG*/

	return( vips_strdup( NULL, vname ) );
}

/* Search a path for a file ... we overwrite the PATH string passed in.
 */
static char *
scan_path( char *path, const char *name )
{
	char *p, *q;
	char *prefix;

	for( p = path; 
		(q = vips_break_token( p, G_SEARCHPATH_SEPARATOR_S )); p = q ) {
		char str[PATH_MAX];

		/* Form complete path.
		 */
		vips_snprintf( str, PATH_MAX, 
			"%s" G_DIR_SEPARATOR_S "%s", p, name );

#ifdef DEBUG
		printf( "scan_path: looking in \"%s\" for \"%s\"\n", 
			p, name );
#endif /*DEBUG*/

		if( vips_existsf( "%s", str ) && 
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
	printf( "vips_guess_prefix: g_getenv( \"PATH\" ) == \"%s\"\n", path );
#endif /*DEBUG*/

#ifdef OS_WIN32
	/* Windows always searches '.' first, so prepend cwd to path.
	 */
	vips_snprintf( full_path, PATH_MAX, "%s" G_SEARCHPATH_SEPARATOR_S "%s",
		get_current_dir(), path );
#else /*!OS_WIN32*/
	vips_strncpy( full_path, path, PATH_MAX );
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
				printf( "vips_guess_prefix: found \"%s\" from "
					"argv0\n", prefix );
#endif /*DEBUG*/
				return( prefix );
			} 
		}

		/* Look along path for name.
		 */
		if( (prefix = find_file( name )) ) {
#ifdef DEBUG
			printf( "vips_guess_prefix: found \"%s\" from "
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

		vips_snprintf( full_path, PATH_MAX, 
			"%s" G_DIR_SEPARATOR_S "%s", get_current_dir(), argv0 );

		if( realpath( full_path, resolved ) ) {
			if( (prefix = extract_prefix( resolved, name )) ) {

#ifdef DEBUG
				printf( "vips_guess_prefix: found \"%s\" "
					"from cwd\n", prefix );
#endif /*DEBUG*/
				return( prefix );
			}
		}
	}
#endif /*HAVE_REALPATH*/

	/* Fall back to the configure-time prefix.
	 */
	return( VIPS_PREFIX );
}

/** 
 * vips_guess_prefix:
 * @argv0: program name (typically argv[0])
 * @env_name: save prefix in this environment variable
 *
 * vips_guess_prefix() tries to guess the install directory. You should pass 
 * in the value of argv[0] (the name your program was run as) as a clue to 
 * help it out, plus the name of the environment variable you let the user 
 * override your package install area with (eg. "VIPSHOME"). 
 *
 * On success, vips_guess_prefix() returns the prefix it discovered, and as a 
 * side effect, sets the environment variable (if it's not set).
 *
 * Don't free the return string!
 * 
 * See also: vips_guess_libdir().
 *
 * Returns: the install prefix as a static string, do not free.
 */
const char *
vips_guess_prefix( const char *argv0, const char *env_name )
{
        const char *prefix;
        const char *p;
        char name[PATH_MAX];

	/* Already set?
	 */
        if( (prefix = g_getenv( env_name )) ) {
#ifdef DEBUG
		printf( "vips_guess_prefix: found \"%s\" in environment\n", 
			prefix );
#endif /*DEBUG*/
                return( prefix );
	}

	/* Get the program name from argv0.
	 */
	p = vips_skip_dir( argv0 );

	/* Add the exe suffix, if it's missing.
	 */
	if( strlen( VIPS_EXEEXT ) > 0 ) {
		const char *olds[] = { VIPS_EXEEXT };

		vips__change_suffix( p, name, PATH_MAX, VIPS_EXEEXT, olds, 1 );
	}
	else
		vips_strncpy( name, p, PATH_MAX );

#ifdef DEBUG
	printf( "vips_guess_prefix: argv0 = %s\n", argv0 );
	printf( "vips_guess_prefix: name = %s\n", name );
	printf( "vips_guess_prefix: cwd = %s\n", get_current_dir() );
#endif /*DEBUG*/

	prefix = guess_prefix( argv0, name );
	g_setenv( env_name, prefix, TRUE );

	return( prefix );
}

/** 
 * vips_guess_libdir:
 * @argv0: program name (typically argv[0])
 * @env_name: save prefix in this environment variable
 *
 * vips_guess_libdir() tries to guess the install directory (usually the 
 * configure libdir, or $prefix/lib). You should pass 
 * in the value of argv[0] (the name your program was run as) as a clue to 
 * help it out, plus the name of the environment variable you let the user 
 * override your package install area with (eg. "VIPSHOME"). 
 *
 * On success, vips_guess_libdir() returns the libdir it discovered, and as a 
 * side effect, sets the prefix environment variable (if it's not set).
 *
 * Don't free the return string!
 * 
 * See also: vips_guess_prefix().
 *
 * Returns: the libdir as a static string, do not free.
 */
const char *
vips_guess_libdir( const char *argv0, const char *env_name )
{
	const char *prefix = vips_guess_prefix( argv0, env_name );
        static char *libdir = NULL;

	if( libdir )
		return( libdir );

	/* Have we been moved since configure? If not, use the configure-time
	 * libdir.
	 */
	if( strcmp( prefix, VIPS_PREFIX ) == 0 ) 
		libdir = VIPS_LIBDIR;
	else
		libdir = g_strdup_printf( "%s/lib", prefix );

#ifdef DEBUG
	printf( "vips_guess_libdir: VIPS_PREFIX = %s\n", VIPS_PREFIX );
	printf( "vips_guess_libdir: VIPS_LIBDIR = %s\n", VIPS_LIBDIR );
	printf( "vips_guess_libdir: prefix = %s\n", prefix );
	printf( "vips_guess_libdir: libdir = %s\n", libdir );
#endif /*DEBUG*/

	return( libdir );
}

