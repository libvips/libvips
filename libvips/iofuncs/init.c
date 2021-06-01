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
 * 18/9/16
 * 	- call _setmaxstdio() on win32
 * 4/8/17
 * 	- hide warnings is VIPS_WARNING is set
 * 20/4/19
 * 	- set the min stack, if we can
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

/* pthread_setattr_default_np() is a non-portable GNU extension.
 */
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_PTHREAD_DEFAULT_NP
#include <pthread.h>
#endif /*HAVE_PTHREAD_DEFAULT_NP*/

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

/* Disable deprecation warnings from gsf. There are loads, and still not
 * patched as of 12/2020.
 */
#ifdef HAVE_GSF
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <gsf/gsf.h>
#pragma GCC diagnostic pop
#endif /*HAVE_GSF*/

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/internal.h>
#include <vips/vector.h>

#if ENABLE_DEPRECATED
#include <vips/vips7compat.h>
#endif

/* abort() on the first warning or error.
 */
int vips__fatal = 0;

/* Use in various small places where we need a mutex and it's not worth 
 * making a private one.
 */
GMutex *vips__global_lock = NULL;

/* A debugging timer, zero at library init.
 */
GTimer *vips__global_timer = NULL;

/* Keep a copy of the argv0 here.
 */
static char *vips__argv0 = NULL;

/* Keep a copy of the last component of argv0 here.
 */
static char *vips__prgname = NULL;

/* Leak check on exit.
 */
int vips__leak = 0;

#ifdef DEBUG_LEAK
/* Count pixels processed per image here.
 */
GQuark vips__image_pixels_quark = 0; 
#endif /*DEBUG_LEAK*/

static gint64 vips_pipe_read_limit = 1024 * 1024 * 1024;

/**
 * vips_get_argv0:
 *
 * See also: VIPS_INIT().
 *
 * Returns: (transfer none): a pointer to an internal copy of the 
 * argv0 string passed to
 * VIPS_INIT(). Do not free this value
 */
const char *
vips_get_argv0( void )
{
	return( vips__argv0 );
}

/**
 * vips_get_prgname:
 *
 * Return the program name. This can be useful for the user tio see,.
 *
 * See also: VIPS_INIT().
 *
 * Returns: (transfer none): a pointer to an internal copy of the program 
 * name. Do not free this value
 */
const char *
vips_get_prgname( void )
{
	const char *prgname;

	if( (prgname = g_get_prgname()) )
		return( prgname );
	else
		return( vips__prgname );
}

/**
 * VIPS_INIT:
 * @ARGV0: name of application
 *
 * gtk-doc mistakenly tags this macro as deprecated for unknown reasons. It is
 * *NOT* deprecated, please ignore the warning above. 
 *
 * VIPS_INIT() starts up the world of VIPS. You should call this on
 * program startup before using any other VIPS operations. If you do not call
 * VIPS_INIT(), VIPS will call it for you when you use your first VIPS 
 * operation, but it may not be able to get hold of @ARGV0 and VIPS may 
 * therefore be unable to find its data files. It is much better to call 
 * this macro yourself.
 *
 * @ARGV0 is used to help discover message catalogues if libvips has been 
 * relocated. If you don't need a relocatable package, you can just pass `""`
 * and it'll be fine.
 *
 * Additionally, VIPS_INIT() can be run from any thread, but it must not be
 * called from more than one thread at the same time. This is much easier to 
 * guarantee if you call it yourself.
 *
 * VIPS_INIT() is a macro, since it tries to check ABI compatibility
 * between the caller and the library. You can also call vips_init(), the
 * non-macro version, if macros are not available to you.
 *
 * You may call VIPS_INIT() many times and vips_shutdown() many times, but you 
 * must not call VIPS_INIT() after vips_shutdown(). In other words, you cannot
 * stop and restart vips. 
 *
 * Use the environment variable `VIPS_MIN_STACK_SIZE` to set the minimum stack
 * size. For example, `2m` for a minimum of two megabytes of stack. This can
 * be important for systems like musl where the default stack is very small.
 *
 * VIPS_INIT() does approximately the following:
 *
 * + checks that the libvips your program is expecting is 
 *   binary-compatible with the vips library you're running against
 *
 * + sets a minimum stack size, see above
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
 * + if your platform supports atexit(), VIPS_INIT() will ask for
 *   vips_shutdown() to be called on program exit
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
 * See also: vips_shutdown(), vips_add_option_entries(), vips_version(), 
 * vips_guess_prefix(), vips_guess_libdir().
 *
 * Returns: 0 on success, -1 otherwise
 */

/* Load all plugins in a directory ... look for '.<G_MODULE_SUFFIX>' or
 * '.plg' (deprecated) suffix. Error if we had any probs.
 */
static int
vips_load_plugins( const char *fmt, ... )
{
        va_list ap;
        char dir_name[VIPS_PATH_MAX];
        GDir *dir;
	const char *name;
        int result;

	/* Silently succeed if we can't do modules.
	 */
	if( !g_module_supported() )
		return( 0 );

        va_start( ap, fmt );
        (void) vips_vsnprintf( dir_name, VIPS_PATH_MAX - 1, fmt, ap );
        va_end( ap );

#ifdef DEBUG
	printf( "vips_load_plugins: searching \"%s\"\n", dir_name );
#endif /*DEBUG*/

        if( !(dir = g_dir_open( dir_name, 0, NULL )) ) 
		/* Silent success for dir not there.
		 */
                return( 0 );

        result = 0;
        while( (name = g_dir_read_name( dir )) )
                if( vips_ispostfix( name, "." G_MODULE_SUFFIX )
#if ENABLE_DEPRECATED
				|| vips_ispostfix( name, ".plg" ) 
#endif
			) { 
			char path[VIPS_PATH_MAX];
			GModule *module;

			vips_snprintf( path, VIPS_PATH_MAX - 1, 
				"%s" G_DIR_SEPARATOR_S "%s", dir_name, name );

#ifdef DEBUG
			printf( "vips_load_plugins: loading \"%s\"\n", path );
#endif /*DEBUG*/

			module = g_module_open( path, G_MODULE_BIND_LAZY );
			if( !module ) {
				g_warning( _( "unable to load \"%s\" -- %s" ), 
					path, g_module_error() ); 
				result = -1;
			}
                }
        g_dir_close( dir );

	return( result );
}

/* Install this log handler to hide warning messages.
 */
static void
empty_log_handler( const gchar *log_domain, GLogLevelFlags log_level,
	const gchar *message, gpointer user_data )
{       
}

/* Attempt to set a minimum stacksize. This can be important on systems with a
 * very low default, like musl.
 */
static void
set_stacksize( guint64 size )
{
#ifdef HAVE_PTHREAD_DEFAULT_NP
	pthread_attr_t attr;
	size_t cur_stack_size;

	/* Don't allow stacks less than 2mb.
	 */
	size = VIPS_MAX( size, 2 * 1024 * 1024 );

	if( pthread_attr_init( &attr ) ||
		pthread_attr_getstacksize( &attr, &cur_stack_size ) ) {
		g_warning( "set_stacksize: unable to get stack size" );
		return;
	}

	if( cur_stack_size < size ) {
		if( pthread_attr_setstacksize( &attr, size ) ||
			pthread_setattr_default_np( &attr ) ) 
			g_warning( "set_stacksize: unable to set stack size" );
		else 
			g_info( "set stack size to %" G_GUINT64_FORMAT "k", 
				size / (guint64) 1024 );
	}
#endif /*HAVE_PTHREAD_DEFAULT_NP*/
}

static void
vips_verbose( void ) 
{
	const char *old;

	old = g_getenv( "G_MESSAGES_DEBUG" );

	if( !old ) 
		g_setenv( "G_MESSAGES_DEBUG", G_LOG_DOMAIN, TRUE );
	else if( !g_str_equal( old, "all" ) &&
		!g_strrstr( old, G_LOG_DOMAIN ) ) {
		char *new;

		new = g_strconcat( old, " ", G_LOG_DOMAIN, NULL );
		g_setenv( "G_MESSAGES_DEBUG", new, TRUE );

		g_free( new );
	}
}

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
	extern GType write_thread_state_get_type( void );
	extern GType sink_memory_thread_state_get_type( void ); 
	extern GType render_thread_state_get_type( void ); 
	extern GType vips_source_get_type( void ); 
	extern GType vips_source_custom_get_type( void ); 
	extern GType vips_target_get_type( void ); 
	extern GType vips_target_custom_get_type( void ); 
	extern GType vips_g_input_stream_get_type( void ); 

	static gboolean started = FALSE;
	static gboolean done = FALSE;
	const char *vips_min_stack_size;
	const char *prefix;
	const char *libdir;
	char *locale;

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

#ifdef G_OS_WIN32
	/* Windows has a limit of 512 files open at once for the fopen() family
	 * of functions, and 2048 for the _open() family. This raises the limit
	 * of fopen() to the same level as _open().
	 *
	 * It will not go any higher than this, unfortunately.  
	 */
	(void) _setmaxstdio( 2048 );
#endif /*G_OS_WIN32*/

	vips__threadpool_init();
	vips__buffer_init();
	vips__meta_init();

	/* This does an unsynchronised static hash table init on first call --
	 * we have to make sure we do this single-threaded. See: 
	 * https://github.com/openslide/openslide/issues/161
	 */
#if !GLIB_CHECK_VERSION( 2, 48, 1 )
	(void) g_get_language_names(); 
#endif

	if( !vips__global_lock )
		vips__global_lock = vips_g_mutex_new();

	if( !vips__global_timer )
		vips__global_timer = g_timer_new();

	VIPS_SETSTR( vips__argv0, argv0 );
	vips__prgname = g_path_get_basename( argv0 );

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
	locale = g_build_filename( prefix, "share", "locale", NULL );
	bindtextdomain( GETTEXT_PACKAGE, locale );
	g_free( locale );
	bind_textdomain_codeset( GETTEXT_PACKAGE, "UTF-8" );

	if( g_getenv( "VIPS_INFO" )
#if ENABLE_DEPRECATED
		|| g_getenv( "IM_INFO" )
#endif
	)
		vips_verbose();
	if( g_getenv( "VIPS_PROFILE" ) )
		vips_profile_set( TRUE );
	if( g_getenv( "VIPS_LEAK" ) )
		vips_leak_set( TRUE );
	if( g_getenv( "VIPS_TRACE" ) )
		vips_cache_set_trace( TRUE );
	if( g_getenv( "VIPS_PIPE_READ_LIMIT" ) ) 
		vips_pipe_read_limit = 
			g_ascii_strtoll( g_getenv( "VIPS_PIPE_READ_LIMIT" ),
				NULL, 10 );
	vips_pipe_read_limit_set( vips_pipe_read_limit );

	/* Register base vips types.
	 */
	(void) vips_image_get_type();
	(void) vips_region_get_type();
	(void) write_thread_state_get_type();
	(void) sink_memory_thread_state_get_type(); 
	(void) render_thread_state_get_type(); 
	(void) vips_source_get_type(); 
	(void) vips_source_custom_get_type(); 
	(void) vips_target_get_type(); 
	(void) vips_target_custom_get_type(); 
	vips__meta_init_types();
	vips__interpolate_init();

#if ENABLE_DEPRECATED
	im__format_init();
#endif

	/* Start up operator cache.
	 */
	vips__cache_init();

	/* Recomp reordering system.
	 */
	vips__reorder_init();

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
	vips_g_input_stream_get_type(); 

	/* Load any vips8 modules from the vips libdir. Keep going, even if
	 * some modules fail to load. 
	 */
	(void) vips_load_plugins( "%s/vips-modules-%d.%d", 
		libdir, VIPS_MAJOR_VERSION, VIPS_MINOR_VERSION );

#if ENABLE_DEPRECATED
	/* Load any vips8 plugins from the vips libdir.
	 */
	(void) vips_load_plugins( "%s/vips-plugins-%d.%d", 
		libdir, VIPS_MAJOR_VERSION, VIPS_MINOR_VERSION );

	/* Load up any vips7 plugins in the vips libdir. We don't error on 
	 * failure, it's too annoying to have VIPS refuse to start because of 
	 * a broken plugin.
	 */
	if( im_load_plugins( "%s/vips-%d.%d", 
		libdir, VIPS_MAJOR_VERSION, VIPS_MINOR_VERSION ) ) {
		g_warning( "%s", vips_error_buffer() );
		vips_error_clear();
	}

	/* Also load from libdir. This is old and slightly broken behaviour
	 * :-( kept for back compat convenience.
	 */
	if( im_load_plugins( "%s", libdir ) ) {
		g_warning( "%s", vips_error_buffer() );
		vips_error_clear();
	}
#endif

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

#ifdef DEBUG_LEAK
	vips__image_pixels_quark = 
		g_quark_from_static_string( "vips-image-pixels" ); 
#endif /*DEBUG_LEAK*/

	done = TRUE;

	/* If VIPS_WARNING is defined, suppress all warning messages from vips.
	 *
	 * Libraries should not call g_log_set_handler(), it is
	 * supposed to be for the application layer, but this can be awkward to
	 * set up if you are using libvips from something like Ruby. Allow this
	 * env var hack as a workaround. 
	 */
	if( g_getenv( "VIPS_WARNING" )
#if ENABLE_DEPRECATED
		|| g_getenv( "IM_WARNING" )
#endif
	)
		g_log_set_handler( G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, 
			empty_log_handler, NULL );

	/* Set a minimum stacksize, if we can.
	 */
        if( (vips_min_stack_size = g_getenv( "VIPS_MIN_STACK_SIZE" )) )
		(void) set_stacksize( vips__parse_size( vips_min_stack_size ) );

	vips__thread_gate_stop( "init: startup" ); 

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
	if( vips_init( "vips" ) )
		vips_error_clear();
}

static int
vips_leak( void ) 
{
	char txt[1024];
	VipsBuf buf = VIPS_BUF_STATIC( txt );
	int n_leaks;

	n_leaks = 0;

	n_leaks += vips__object_leak();
	n_leaks += vips__type_leak();
	n_leaks += vips_tracked_get_allocs();
	n_leaks += vips_tracked_get_mem();
	n_leaks += vips_tracked_get_files();

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

	if( strlen( vips_error_buffer() ) > 0 ) {
		vips_buf_appendf( &buf, "error buffer: %s", 
			vips_error_buffer() );
		n_leaks += strlen( vips_error_buffer() );
	}

	fprintf( stderr, "%s", vips_buf_all( &buf ) );

	n_leaks += vips__print_renders();

#ifdef DEBUG
	vips_buffer_dump_all();
#endif /*DEBUG*/

	return( n_leaks );
}

/**
 * vips_thread_shutdown: 
 *
 * Free any thread-private data and flush any profiling information.
 *
 * This function needs to be called when a thread that has been using vips
 * exits. It is called for you by vips_shutdown() and for any threads created
 * within the #VipsThreadPool. 
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
	vips__thread_profile_detach();
	vips__buffer_shutdown();
}

/**
 * vips_shutdown:
 *
 * Call this to drop caches and close plugins. Run with "--vips-leak" to do 
 * a leak check too. 
 *
 * You may call VIPS_INIT() many times and vips_shutdown() many times, but you 
 * must not call VIPS_INIT() after vips_shutdown(). In other words, you cannot
 * stop and restart vips. 
 */
void
vips_shutdown( void )
{
#ifdef DEBUG
	printf( "vips_shutdown:\n" );
#endif /*DEBUG*/

	vips_cache_drop_all();

#if ENABLE_DEPRECATED
	im_close_plugins();
#endif

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

	vips__threadpool_shutdown();

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

		if( !done &&
			vips_leak() ) 
			exit( 1 );

		done = TRUE;
	}

	VIPS_FREE( vips__argv0 );
	VIPS_FREE( vips__prgname );
	VIPS_FREEF( vips_g_mutex_free, vips__global_lock );
	VIPS_FREEF( g_timer_destroy, vips__global_timer );
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
vips_lib_info_cb( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	vips_verbose();

	return( TRUE );
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

static gboolean
vips_lib_version_cb( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	printf( "libvips %s\n", VIPS_VERSION_STRING );
	vips_shutdown();
	exit( 0 );
}

static gboolean
vips_lib_config_cb( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	char **split;
	char *config;

	split = g_strsplit( VIPS_CONFIG, ", ", -1 );
	config = g_strjoinv( "\n", split );

	printf( "%s\n", config );
	g_strfreev( split );
	g_free( config );

	vips_shutdown();
	exit( 0 );
}

static gboolean
vips_cache_max_cb( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	vips_cache_set_max( vips__parse_size( value ) );

	return( TRUE ); 
}

static gboolean
vips_cache_max_memory_cb( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	vips_cache_set_max_mem( vips__parse_size( value ) );

	return( TRUE ); 
}

static gboolean
vips_cache_max_files_cb( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	vips_cache_set_max_files( vips__parse_size( value ) );

	return( TRUE ); 
}

static GOptionEntry option_entries[] = {
	{ "vips-info", 0, G_OPTION_FLAG_HIDDEN | G_OPTION_FLAG_NO_ARG, 
		G_OPTION_ARG_CALLBACK, (gpointer) &vips_lib_info_cb,
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
		G_OPTION_ARG_CALLBACK, (gpointer) &vips_cache_max_cb,
		N_( "cache at most N operations" ), "N" },
	{ "vips-cache-max-memory", 0, 0, 
		G_OPTION_ARG_CALLBACK, (gpointer) &vips_cache_max_memory_cb,
		N_( "cache at most N bytes in memory" ), "N" },
	{ "vips-cache-max-files", 0, 0, 
		G_OPTION_ARG_CALLBACK, (gpointer) &vips_cache_max_files_cb,
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
	{ "vips-config", 0, G_OPTION_FLAG_NO_ARG, 
		G_OPTION_ARG_CALLBACK, (gpointer) &vips_lib_config_cb, 
		N_( "print libvips config" ), NULL },
	{ "vips-pipe-read-limit", 0, 0, 
		G_OPTION_ARG_INT64, (gpointer) &vips_pipe_read_limit, 
		N_( "read at most this many bytes from a pipe" ), NULL },
	{ NULL }
};

/**
 * vips_add_option_entries: 
 * @option_group: group to add to
 *
 * Add the standard vips %GOptionEntry to a %GOptionGroup. 
 *
 * See also: g_option_group_new(). 
 */
void
vips_add_option_entries( GOptionGroup *option_group )
{
	g_option_group_add_entries( option_group, option_entries );
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
			memmove( vname + i, vname + i + 2, 
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

#ifdef G_OS_WIN32
{
	char *dir; 

	/* Windows always searches '.' first, so prepend cwd to path.
	 */
	dir = g_get_current_dir();
	vips_snprintf( full_path, VIPS_PATH_MAX, 
		"%s" G_SEARCHPATH_SEPARATOR_S "%s", dir, path );
	g_free( dir ); 
}
#else /*!G_OS_WIN32*/
	vips_strncpy( full_path, path, VIPS_PATH_MAX );
#endif /*G_OS_WIN32*/

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

	/* Try to guess from cwd. Only if this is a relative path, though. 
	 */
	if( argv0 &&
		!g_path_is_absolute( argv0 ) ) {
		char *dir;
		char full_path[VIPS_PATH_MAX];
		char *resolved;

		dir = g_get_current_dir(); 
		vips_snprintf( full_path, VIPS_PATH_MAX, 
			"%s" G_DIR_SEPARATOR_S "%s", dir, argv0 );
		g_free( dir ); 

		if( (resolved = vips_realpath( full_path )) ) {
			prefix = extract_prefix( resolved, name );
			g_free( resolved );

			if( prefix ) { 
#ifdef DEBUG
				printf( "vips_guess_prefix: found \"%s\" "
					"from cwd\n", prefix );
#endif /*DEBUG*/
				return( prefix );
			}
		}
	}

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

	/* Already set?
	 */
        if( (prefix = g_getenv( env_name )) ) {
#ifdef DEBUG
		printf( "vips_guess_prefix: found \"%s\" in environment\n", 
			prefix );
#endif /*DEBUG*/
                return( prefix );
	}

#ifdef G_OS_WIN32
	prefix = vips__windows_prefix();
#else /*!G_OS_WIN32*/
{
        char *basename;

	basename = g_path_get_basename( argv0 );
	prefix = guess_prefix( argv0, basename );
	g_free( basename ); 
}
#endif /*G_OS_WIN32*/

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
 * Get the ABI current, revision and age (as used by libtool) with @flag 
 * values 3, 4, 5. 
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

	case 3:
		return( VIPS_LIBRARY_CURRENT );

	case 4:
		return( VIPS_LIBRARY_REVISION );

	case 5:
		return( VIPS_LIBRARY_AGE );

	default:
		vips_error( "vips_version", "%s", _( "flag not in [0, 5]" ) );
		return( -1 );
	}
}

/**
 * vips_leak_set:
 * @leak: turn leak checking on or off
 *
 * Turn on or off vips leak checking. See also --vips-leak,
 * vips_add_option_entries() and the `VIPS_LEAK` environment variable.
 *
 * You should call this very early in your program. 
 */
void 
vips_leak_set( gboolean leak )
{
	vips__leak = leak; 
}

/* Deprecated.
 */
size_t
vips__get_sizeof_vipsobject( void )
{
	return( sizeof( VipsObject ) ); 
}

