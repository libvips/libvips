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
 * 	  can happen if (for example) im_guess_prefix() fails and tries to
 * 	  i18n an error message (thanks Christian)
 * 8/6/07
 * 	- just warn if plugins fail to load correctly: too annoying to have
 * 	  VIPS refuse to start because of a dodgy plugin
 * 7/11/07
 * 	- progress feedback option
 * 5/8/08
 * 	- load plugins from libdir/vips-x.x
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

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/internal.h>

#ifdef HAVE_LIBOIL
#include <liboil/liboil.h>
#endif /*HAVE_LIBOIL*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Use in various small places where we need a mutex and it's not worth 
 * making a private one.
 */
GMutex *im__global_lock = NULL;

int
im_init_world( const char *argv0 )
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

	/* Need gobject etc.
	 */
	g_type_init();

#ifdef G_THREADS_ENABLED
	if( !g_thread_supported() ) 
		g_thread_init( NULL );
#endif /*G_THREADS_ENABLED*/

	if( !im__global_lock )
		im__global_lock = g_mutex_new();

	prgname = g_path_get_basename( argv0 );
	g_set_prgname( prgname );
	g_free( prgname );

	/* Try to discover our prefix. 
	 */
	if( !(prefix = im_guess_prefix( argv0, "VIPSHOME" )) || 
		!(libdir = im_guess_libdir( argv0, "VIPSHOME" )) ) 
		return( -1 );

	/* Get i18n .mo files from $VIPSHOME/share/locale/.
	 */
	im_snprintf( name, 256,
			/*
		"%s" G_DIR_SEPARATOR_S "share" G_DIR_SEPARATOR_S "locale",
		 	 */
		"%s" G_DIR_SEPARATOR_S "share",
		prefix );
	bindtextdomain( GETTEXT_PACKAGE, name );
	bind_textdomain_codeset( GETTEXT_PACKAGE, "UTF-8" );

	/* Start up converters for builtin types.
	 */
	im__meta_init_types();

	/* Add the base format load/save operations.
	 */
	im__format_init();

	/* Load up any plugins in the vips libdir. We don't error on failure,
	 * it's too annoying to have VIPS refuse to start because of a broken
	 * plugin.
	 */
	if( im_load_plugins( "%s/vips-%d.%d", 
		libdir, IM_MAJOR_VERSION, IM_MINOR_VERSION ) ) {
		im_warn( "im_init_world", "%s", im_errorstring() );
		im_error_clear();
	}

	/* Start up the buffer cache.
	 */
	im__buffer_init();

#ifdef HAVE_LIBOIL
{
#ifdef DEBUG
	GTimer *timer = g_timer_new();
#endif /*DEBUG*/

	oil_init();

#ifdef DEBUG
	/* 0.3 is only about 0.1s on my laptop, but this may take longer in
	 * future.
	 */
	printf( "oil_init: %gs\n", g_timer_elapsed( timer, NULL ) );
	g_timer_destroy( timer );
#endif /*DEBUG*/
}
#endif /*HAVE_LIBOIL*/

	done = TRUE;

	return( 0 );
}

const char *
im__gettext( const char *msgid )
{
	/* Pass in a nonsense name for argv0 ... this init path is only here
	 * for old programs which are missing an im_init_world() call. We need
	 * i18n set up before we can translate.
	 */
	if( im_init_world( "giant_banana" ) )
		im_error_clear();

	return( dgettext( GETTEXT_PACKAGE, msgid ) );
}

const char *
im__ngettext( const char *msgid, const char *plural, unsigned long int n )
{
	if( im_init_world( "giant_banana" ) )
		im_error_clear();

	return( dngettext( GETTEXT_PACKAGE, msgid, plural, n ) );
}

static GOptionEntry option_entries[] = {
	{ "vips-concurrency", 'c', 0, G_OPTION_ARG_INT, &im__concurrency, 
		N_( "evaluate with N concurrent threads" ), "N" },
	{ "vips-tile-width", 'w', 0, G_OPTION_ARG_INT, &im__tile_width, 
		N_( "set tile width to N (DEBUG)" ), "N" },
	{ "vips-tile-height", 'h', 0, G_OPTION_ARG_INT, &im__tile_height, 
		N_( "set tile height to N (DEBUG)" ), "N" },
	{ "vips-thinstrip-height", 't', 0, 
		G_OPTION_ARG_INT, &im__thinstrip_height, 
		N_( "set thinstrip height to N (DEBUG)" ), "N" },
	{ "vips-fatstrip-height", 'f', 0, 
		G_OPTION_ARG_INT, &im__fatstrip_height, 
		N_( "set fatstrip height to N (DEBUG)" ), "N" },
	{ "vips-progress", 'p', 0, G_OPTION_ARG_NONE, &im__progress, 
		N_( "show progress feedback" ), NULL },
	{ NULL }
};

/* The cmd-line options we support.
 */
GOptionGroup *
im_get_option_group( void )
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
