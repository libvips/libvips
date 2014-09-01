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

#ifdef HAVE_GSF
#include <gsf/gsf.h>
#endif /*HAVE_GSF*/

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/internal.h>
#include <vips/vector.h>

/* abort() on the first warning or error.
 */
int vips__fatal = 0;

/* Use in various small places where we need a mutex and it's not worth 
 * making a private one.
 */
GMutex *vips__global_lock = NULL;

/* Keep a copy of the argv0 here.
 */
static char *vips__argv0 = NULL;

/* Leak check on exit.
 */
int vips__leak = 0;

/**
 * vips_get_argv0:
 *
 * See also: VIPS_INIT().
 *
 * Returns: a pointer to an internal copy of the argv0 string passed to
 * VIPS_INIT(). Do not free this value
 */
const char *
vips_get_argv0( void )
{
	return( vips__argv0 );
}

/**
 * VIPS_INIT:
 * @argv0: name of application
 *
 * VIPS_INIT() starts up the world of VIPS. You should call this on
 * program startup before using any other VIPS operations. If you do not call
 * VIPS_INIT(), VIPS will call it for you when you use your first VIPS 
 * operation, but it may not be able to get hold of @argv0 and VIPS may 
 * therefore be unable to find its data files. It is much better to call 
 * this macro yourself.
 *
 * VIPS_INIT() is a macro, since it tries to check binary compatibility
 * between the caller and the library. 
 *
 * VIPS_INIT() does approximately the following:
 *
 * + checks that the libvips your program is expecting is 
 *   binary-compatible with the vips library you're running against
 *
 * + initialises any libraries that VIPS is using, including GObject
 *   and the threading system, if neccessary
 *
 * + guesses where the VIPS data files are and sets up
 *   internationalisation --- see vips_guess_prefix()
 *
 * + creates the main vips types, including #VipsImage and friends
 *
 * + loads any plugins from $libdir/vips-x.y/, where x and y are the
 *   major and minor version numbers for this VIPS.
 *
 * Example:
 *
 * |[
 * int main (int argc, char **argv)
 * {
 *   if (VIPS_INIT (argv[0]))
 *     vips_error_exit ("unable to start VIPS");
 *
 *   vips_shutdown ();
 *
 *   return 0;
 * }
 * ]|
 *
 * See also: vips_shutdown(), vips_get_option_group(), vips_version(), 
 * vips_guess_prefix(), vips_guess_libdir().
 *
 * Returns: 0 on success, -1 otherwise
 */

/**
 * vips_init:
 * @argv0: name of application
 *
 * This function starts up libvips, see VIPS_INIT(). 
 *
 * This function is for bindings which need to start up vips. C programs
 * should use the VIPS_INIT() macro, which does some extra checks. 
 *
 * See also: VIPS_INIT(). 
 *
 * Returns: 0 on success, -1 otherwise
 */

int
vips_init( const char *argv0 )
{
	extern GType vips_system_get_type( void );

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

#ifdef NEED_TYPE_INIT
	/* Before glib 2.36 you have to call this on startup.
	 */
	g_type_init();
#endif /*NEED_TYPE_INIT*/

	/* Older glibs need this.
	 */
#ifndef HAVE_THREAD_NEW
	if( !g_thread_supported() ) 
		g_thread_init( NULL );
#endif 

	if( !vips__global_lock )
		vips__global_lock = vips_g_mutex_new();

	VIPS_SETSTR( vips__argv0, argv0 );

	prgname = g_path_get_basename( argv0 );
	g_set_prgname( prgname );
	g_free( prgname );

	vips__thread_profile_attach( "main" );

	/* We can't do VIPS_GATE_START() until command-line processing
	 * happens, since vips__thread_profile may not be set yet. Call
	 * directly. 
	 */
	vips__thread_gate_start( "init: main" ); 
	vips__thread_gate_start( "init: startup" ); 

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

	/* Default info setting from env.
	 */
	if( g_getenv( "VIPS_INFO" ) || 
		g_getenv( "IM_INFO" ) ) 
		vips__info = 1;

	/* Register base vips types.
	 */
	(void) vips_image_get_type();
	(void) vips_region_get_type();
	vips__meta_init_types();
	vips__interpolate_init();
	im__format_init();

	/* Start up operator cache.
	 */
	vips__cache_init();

	/* Start up packages.
	 */
	(void) vips_system_get_type();
	vips_arithmetic_operation_init();
	vips_conversion_operation_init();
	vips_create_operation_init();
	vips_foreign_operation_init();
	vips_resample_operation_init();
	vips_colour_operation_init();
	vips_histogram_operation_init();
	vips_convolution_operation_init();
	vips_freqfilt_operation_init();
	vips_morphology_operation_init();
	vips_draw_operation_init();
	vips_mosaicing_operation_init();

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

#ifdef HAVE_GSF
	/* Use this for structured file write.
	 */
	gsf_init();
#endif /*HAVE_GSF*/

	/* Register vips_shutdown(). This may well not get called and many
	 * platforms don't support it anyway.
	 */
#ifdef HAVE_ATEXIT
	atexit( vips_shutdown );
#endif /*HAVE_ATEXIT*/

	done = TRUE;

	vips__thread_gate_stop( "init: startup" ); 

	return( 0 );
}

/* Return the sizeof() various important data structures. These are checked
 * against the headers used to build our caller by vips_init().
 *
 * We allow direct access to members of VipsImage and VipsRegion (mostly for
 * reasons of history), so any change to a superclass of either of these
 * objects will break our ABI.
 */

size_t
vips__get_sizeof_vipsobject( void )
{
	return( sizeof( VipsObject ) ); 
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
	if( vips_init( "vips" ) )
		vips_error_clear();
}

static void
vips_leak( void ) 
{
	char txt[1024];
	VipsBuf buf = VIPS_BUF_STATIC( txt );

	vips_object_print_all();

	if( vips_tracked_get_allocs() || 
		vips_tracked_get_mem() ||
		vips_tracked_get_files() ) {
		vips_buf_appendf( &buf, "memory: %d allocations, %zd bytes\n",
			vips_tracked_get_allocs(), vips_tracked_get_mem() );
		vips_buf_appendf( &buf, "files: %d open\n",
			vips_tracked_get_files() );
	}

	vips_buf_appendf( &buf, "memory: high-water mark " );
	vips_buf_append_size( &buf, vips_tracked_get_mem_highwater() );
	vips_buf_appends( &buf, "\n" );

	fprintf( stderr, "%s", vips_buf_all( &buf ) );

	vips__type_leak();

#ifdef DEBUG
#endif /*DEBUG*/
	vips_buffer_dump_all();
}

/**
 * vips_thread_shutdown: 
 *
 * Free any thread-private data and flush any profiling information.
 *
 * This function needs to be called when a thread that has been using vips
 * exits. It is called for you by vips_shutdown() and for any threads created
 * by vips_g_thread_new(). 
 *
 * You will need to call it from threads created in
 * other ways or there will be memory leaks. If you do not call it, vips 
 * will generate a warning message.
 *
 * It may be called many times, and you can continue using vips after 
 * calling it. Calling it too often will reduce performance. 
 */
void
vips_thread_shutdown( void )
{
	vips__buffer_shutdown();
	vips__thread_profile_detach();
}

/**
 * vips_shutdown:
 *
 * Call this to drop caches and close plugins. Run with "--vips-leak" to do 
 * a leak check too. May be called many times.
 */
void
vips_shutdown( void )
{
#ifdef DEBUG
	printf( "vips_shutdown:\n" );
#endif /*DEBUG*/

	vips_cache_drop_all();

	im_close_plugins();

	/* Mustn't run this more than once. Don't use the VIPS_GATE macro,
	 * since we don't for gate start.
	 */
{
	static gboolean done = FALSE;

	if( !done ) 
		vips__thread_gate_stop( "init: main" ); 
}

	vips__render_shutdown();

	vips_thread_shutdown();

	vips__thread_profile_stop();

#ifdef HAVE_GSF
	gsf_shutdown(); 
#endif /*HAVE_GSF*/

	/* In dev releases, always show leaks. But not more than once, it's
	 * annoying.
	 */
#ifndef DEBUG_LEAK
	if( vips__leak ) 
#endif /*DEBUG_LEAK*/
	{
		static gboolean done = FALSE;

		if( !done ) 
			vips_leak();

		done = TRUE;
	}
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

static gboolean
vips_lib_version_cb( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	printf( "libvips %s\n", VIPS_VERSION_STRING );
	vips_shutdown();
	exit( 0 );
}

static gboolean
vips_set_fatal_cb( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	vips__fatal = 1; 

	/* Set masks for debugging ... stop on any problem. 
	 */
	g_log_set_always_fatal(
		G_LOG_FLAG_RECURSION |
		G_LOG_FLAG_FATAL |
		G_LOG_LEVEL_ERROR |
		G_LOG_LEVEL_CRITICAL |
		G_LOG_LEVEL_WARNING );

	return( TRUE );
}

static GOptionEntry option_entries[] = {
	{ "vips-info", 0, G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_NONE, &vips__info, 
		N_( "show informative messages" ), NULL },
	{ "vips-fatal", 0, G_OPTION_FLAG_HIDDEN | G_OPTION_FLAG_NO_ARG, 
		G_OPTION_ARG_CALLBACK, (gpointer) &vips_set_fatal_cb, 
		N_( "abort on first error or warning" ), NULL },
	{ "vips-concurrency", 0, 0, 
		G_OPTION_ARG_INT, &vips__concurrency, 
		N_( "evaluate with N concurrent threads" ), "N" },
	{ "vips-tile-width", 0, G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_INT, &vips__tile_width, 
		N_( "set tile width to N (DEBUG)" ), "N" },
	{ "vips-tile-height", 0, G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_INT, &vips__tile_height, 
		N_( "set tile height to N (DEBUG)" ), "N" },
	{ "vips-thinstrip-height", 0, G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_INT, &vips__thinstrip_height, 
		N_( "set thinstrip height to N (DEBUG)" ), "N" },
	{ "vips-fatstrip-height", 0, G_OPTION_FLAG_HIDDEN, 
		G_OPTION_ARG_INT, &vips__fatstrip_height, 
		N_( "set fatstrip height to N (DEBUG)" ), "N" },
	{ "vips-progress", 0, 0, 
		G_OPTION_ARG_NONE, &vips__progress, 
		N_( "show progress feedback" ), NULL },
	{ "vips-leak", 0, 0, 
		G_OPTION_ARG_NONE, &vips__leak, 
		N_( "leak-check on exit" ), NULL },
	{ "vips-profile", 0, 0, 
		G_OPTION_ARG_NONE, &vips__thread_profile, 
		N_( "profile and dump timing on exit" ), NULL },
	{ "vips-disc-threshold", 0, 0, 
		G_OPTION_ARG_STRING, &vips__disc_threshold, 
		N_( "images larger than N are decompressed to disc" ), "N" },
	{ "vips-novector", 0, G_OPTION_FLAG_REVERSE, 
		G_OPTION_ARG_NONE, &vips__vector_enabled, 
		N_( "disable vectorised versions of operations" ), NULL },
	{ "vips-cache-max", 0, 0, 
		G_OPTION_ARG_STRING, &vips__cache_max, 
		N_( "cache at most N operations" ), "N" },
	{ "vips-cache-max-memory", 0, 0, 
		G_OPTION_ARG_STRING, &vips__cache_max_mem, 
		N_( "cache at most N bytes in memory" ), "N" },
	{ "vips-cache-max-files", 0, 0, 
		G_OPTION_ARG_STRING, &vips__cache_max_files, 
		N_( "allow at most N open files" ), "N" },
	{ "vips-cache-trace", 0, 0, 
		G_OPTION_ARG_NONE, &vips__cache_trace, 
		N_( "trace operation cache" ), NULL },
	{ "vips-cache-dump", 0, 0, 
		G_OPTION_ARG_NONE, &vips__cache_dump, 
		N_( "dump operation cache on exit" ), NULL },
	{ "vips-version", 0, G_OPTION_FLAG_NO_ARG, 
		G_OPTION_ARG_CALLBACK, (gpointer) &vips_lib_version_cb, 
		N_( "print libvips version" ), NULL },
	{ NULL }
};

/**
 * vips_get_option_group: (skip)
 *
 * vips_get_option_group() returns a %GOptionGroup containing various VIPS
 * command-line options. It can be used with %GOption to help
 * parse argc/argv.
 *
 * See also: vips_version(), vips_guess_prefix(),
 * vips_guess_libdir(), vips_init().
 *
 * Returns: a %GOptionGroup for VIPS, see %GOption
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
	char edir[VIPS_PATH_MAX];
	char vname[VIPS_PATH_MAX];
	int i;

#ifdef DEBUG
	printf( "extract_prefix: trying for dir = \"%s\", name = \"%s\"\n", 
		dir, name );
#endif /*DEBUG*/

	/* Is dir relative? Prefix with cwd.
	 */
	if( !g_path_is_absolute( dir ) ) {
		char *cwd; 

		cwd = g_get_current_dir();
		vips_snprintf( edir, VIPS_PATH_MAX, 
			"%s" G_DIR_SEPARATOR_S "%s", cwd, dir );
		g_free( cwd );
	}
	else {
		vips_strncpy( edir, dir, VIPS_PATH_MAX );
	}

	/* Chop off the trailing prog name, plus the trailing
	 * G_DIR_SEPARATOR_S.
	 */
	if( !vips_ispostfix( edir, name ) ) 
		return( NULL );
	vips_strncpy( vname, edir, VIPS_PATH_MAX );
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
		char str[VIPS_PATH_MAX];

		/* Form complete path.
		 */
		vips_snprintf( str, VIPS_PATH_MAX, 
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
	char full_path[VIPS_PATH_MAX];

	if( !path )
		return( NULL );

#ifdef DEBUG
	printf( "vips_guess_prefix: g_getenv( \"PATH\" ) == \"%s\"\n", path );
#endif /*DEBUG*/

#ifdef OS_WIN32
{
	char *dir; 

	/* Windows always searches '.' first, so prepend cwd to path.
	 */
	dir = g_get_current_dir();
	vips_snprintf( full_path, VIPS_PATH_MAX, 
		"%s" G_SEARCHPATH_SEPARATOR_S "%s", dir, path );
	g_free( dir ); 
}
#else /*!OS_WIN32*/
	vips_strncpy( full_path, path, VIPS_PATH_MAX );
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
		char full_path[VIPS_PATH_MAX];
		char *resolved;
		char *dir;

		dir = g_get_current_dir(); 
		vips_snprintf( full_path, VIPS_PATH_MAX, 
			"%s" G_DIR_SEPARATOR_S "%s", dir, argv0 );
		g_free( dir ); 

		if( (resolved = realpath( full_path, NULL )) ) {
			prefix = extract_prefix( resolved, name );
			free( resolved ); 
			if( prefix ) { 
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
 * Returns: (transfer none): the install prefix as a static string, do not free.
 */
const char *
vips_guess_prefix( const char *argv0, const char *env_name )
{
        const char *prefix;
        char *basename;
        char name[VIPS_PATH_MAX];

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
	basename = g_path_get_basename( argv0 );

	/* Add the exe suffix, if it's missing.
	 */
	if( strlen( VIPS_EXEEXT ) > 0 ) {
		const char *olds[] = { VIPS_EXEEXT };

		vips__change_suffix( basename, name, 
			VIPS_PATH_MAX, VIPS_EXEEXT, olds, 1 );
	}
	else
		vips_strncpy( name, basename, VIPS_PATH_MAX );

	g_free( basename ); 

#ifdef DEBUG
	printf( "vips_guess_prefix: argv0 = %s\n", argv0 );
	printf( "vips_guess_prefix: name = %s\n", name );
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
 * Returns: (transfer none): the libdir as a static string, do not free.
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

/**
 * vips_version_string:
 *
 * Get the VIPS version as a static string, including a build date and time.
 * Do not free.
 *
 * Returns: (transfer none): a static version string
 */
const char *
vips_version_string( void )
{
	return( VIPS_VERSION_STRING );
}

/**
 * vips_version:
 * @flag: which field of the version to get
 *
 * Get the major, minor or micro library version, with @flag values 0, 1 and
 * 2.
 *
 * Returns: library version number
 */
int
vips_version( int flag )
{
	switch( flag ) {
	case 0:
		return( VIPS_MAJOR_VERSION );
	
	case 1:
		return( VIPS_MINOR_VERSION );
	
	case 2:
		return( VIPS_MICRO_VERSION );

	default:
		vips_error( "vips_version", "%s", _( "flag not 0, 1, 2" ) );
		return( -1 );
	}
}
