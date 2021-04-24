/* VIPS universal main program.
 *
 * J. Cupitt, 8/4/93.
 * 12/5/06
 * 	- use GOption. g_*_prgname()
 * 16/7/06
 * 	- hmm, was broken for function name as argv1 case
 * 11/7/06
 * 	- add "all" option to -l
 * 14/7/06
 * 	- ignore "--" arguments.
 * 2/9/06
 * 	- do less init ... im_init_world() does more now
 * 18/8/06
 * 	- use IM_EXEEXT
 * 16/10/06
 * 	- add --version
 * 17/10/06
 * 	- add --swig
 * 	- cleanups
 * 	- remove --swig again, sigh
 * 	- add throw() decls to C++ to help SWIG
 * 14/1/07
 * 	- add --list packages
 * 26/2/07
 * 	- add input *VEC arg types to C++ binding
 * 17/8/08
 * 	- add --list formats
 * 29/11/08
 * 	- add --list interpolators
 * 9/2/09
 * 	- and now we just have --list packages/classes/package-name
 * 13/11/09
 * 	- drop _f postfixes, drop many postfixes
 * 24/6/10
 * 	- less chatty error messages
 * 	- oops, don't rename "copy_set" as "copy_"
 * 6/2/12
 * 	- long arg names in decls to help SWIG
 * 	- don't wrap im_remainderconst_vec()
 * 31/12/12
 * 	- parse options in two passes (thanks Haida)
 * 26/11/17
 * 	- remove throw() decls, they are now deprecated everywhere
 * 18/6/20 kleisauke
 * 	- avoid using vips7 symbols
 * 	- remove deprecated vips7 C++ generator
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
#define DEBUG_FATAL
 */

/* Need to disable these sometimes.
#undef DEBUG_FATAL
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>

#include <vips/vips.h>
#include <vips/internal.h>

#if ENABLE_DEPRECATED
#include <vips/vips7compat.h>
#endif

#ifdef G_OS_WIN32
#define strcasecmp(a,b) _stricmp(a,b)
#endif /*G_OS_WIN32*/

static char *main_option_plugin = NULL;
static gboolean main_option_version;

static void *
list_class( GType type, void *user_data )
{
	VipsObjectClass *class = VIPS_OBJECT_CLASS( g_type_class_ref( type ) );
	int depth = vips_type_depth( type );

	int i;

	if( class->deprecated )
		return( NULL );
	if( VIPS_IS_OPERATION_CLASS( class ) &&
		(VIPS_OPERATION_CLASS( class )->flags & 
		 VIPS_OPERATION_DEPRECATED) )
		return( NULL ); 

	for( i = 0; i < depth * 2; i++ )
		printf( " " );
	vips_object_print_summary_class( 
		VIPS_OBJECT_CLASS( g_type_class_ref( type ) ) );

	return( NULL );
}

static void *
test_nickname( GType type, void *data )
{
	const char *nickname = (const char *) data;

	VipsObjectClass *class;

	if( (class = VIPS_OBJECT_CLASS( g_type_class_ref( type ) )) &&
		strcmp( class->nickname, nickname ) == 0 ) 
		return( class ); 

	return( NULL );
}

static gboolean
parse_main_option_list( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	VipsObjectClass *class;

	if( value &&
		(class = (VipsObjectClass *) vips_type_map_all( 
			g_type_from_name( "VipsObject" ), 
			test_nickname, (void *) value )) ) { 
		vips_type_map_all( G_TYPE_FROM_CLASS( class ), 
			list_class, NULL );
	}
	else if( value ) {
		vips_error( g_get_prgname(), 
			_( "'%s' is not the name of a vips class" ), value );
		vips_error_g( error );

		return( FALSE );
	}
	else {
		vips_type_map_all( g_type_from_name( "VipsOperation" ), 
			list_class, NULL );
	}

	exit( 0 );
}

static GOptionEntry main_option[] = {
	{ "list", 'l', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK, 
		(GOptionArgFunc) parse_main_option_list, 
		N_( "list objects" ), 
		N_( "BASE-NAME" ) },
	{ "plugin", 'p', 0, G_OPTION_ARG_FILENAME, &main_option_plugin, 
		N_( "load PLUGIN" ), 
		N_( "PLUGIN" ) },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &main_option_version, 
		N_( "print version" ), NULL },
	{ NULL }
};

#if ENABLE_DEPRECATED
typedef void *(*map_name_fn)( im_function * );

/* Loop over a package.
 */
static void *
map_package( im_package *pack, map_name_fn fn )
{
	int i;
	void *result;

	for( i = 0; i < pack->nfuncs; i++ ) 
		if( (result = fn( pack->table[i] )) )
			return( result );

	return( NULL );
}

/* Apply a function to a vips operation, or map over a package of operations.
 */
static void *
map_name( const char *name, map_name_fn fn )
{
	im_package *pack;
	im_function *func;

	if( !name || strcmp( name, "all" ) == 0 ) 
		/* Do all packages.
		 */
		im_map_packages( (VSListMap2Fn) map_package, fn );
	else if( (pack = im_find_package( name )) )
		/* Do one package.
		 */
		map_package( pack, fn );
	else if( (func = im_find_function( name )) )
		/* Do a single function.
		 */
		fn( func );
	else {
		vips_error( "map_name", 
			_( "no package or function \"%s\"" ), name );
		return( fn );
	}

	return( NULL );
}

static void *
list_package( im_package *pack )
{
	printf( "%-20s - %d operations\n", pack->name, pack->nfuncs );
	
	return( NULL );
}

static void *
list_function( im_function *func )
{
	printf( "%-20s - %s\n", func->name, _( func->desc ) );
	
	return( NULL );
}
#endif

static int
print_list( int argc, char **argv )
{
#if ENABLE_DEPRECATED
	if( !argv[0] || strcmp( argv[0], "packages" ) == 0 ) 
		im_map_packages( (VSListMap2Fn) list_package, NULL );
	else if( strcmp( argv[0], "classes" ) == 0 ) 
#else
	if( !argv[0] || strcmp( argv[0], "classes" ) == 0 )
#endif
		vips_type_map_all( g_type_from_name( "VipsObject" ), 
			list_class, NULL );
	else if( g_type_from_name( argv[0] ) &&
		g_type_is_a( g_type_from_name( argv[0] ), VIPS_TYPE_OBJECT ) ) {
		vips_type_map_all( g_type_from_name( argv[0] ), 
			list_class, NULL );
	}
	else {
#if ENABLE_DEPRECATED
		if( map_name( argv[0], list_function ) )
			vips_error_exit( "unknown package \"%s\"", argv[0] ); 
#else
		vips_error_exit( "unknown operation \"%s\"", argv[0] );
#endif
	}

	return( 0 );
}

#if ENABLE_DEPRECATED
/* Print "ln -s" lines for this package.
 */
static void *
print_links_package( im_package *pack )
{
	int i;

	for( i = 0; i < pack->nfuncs; i++ ) 
		printf( "rm -f %s" IM_EXEEXT "; "
			"ln -s vips" IM_EXEEXT " %s" IM_EXEEXT "\n", 
			pack->table[i]->name, pack->table[i]->name );

	return( NULL );
}

/* Print "ln -s" lines for this package.
 */
static int
print_links( int argc, char **argv )
{
	im_map_packages( (VSListMap2Fn) print_links_package, NULL );

	return( 0 );
}

/* Does a function have any printing output?
 */
static int
has_print( im_function *fn )
{
	int i;

	for( i = 0; i < fn->argc; i++ )
		if( fn->argv[i].print )
			return( -1 );

	return( 0 );
}
#endif

static int
isvips( const char *name )
{
	/* If we're running uninstalled we get the lt- prefix.
	 */
	if( vips_isprefix( "lt-", name ) ) 
		name += 3;

	return( vips_isprefix( "vips", name ) );
}

#if ENABLE_DEPRECATED
/* Print a usage string from an im_function descriptor.
 */
static void
usage( im_function *fn )
{
	int i;
	im_package *pack = im_package_of_function( fn->name );

	/* Don't print the prgname if we're being run as a symlink.
	 */
	fprintf( stderr, "usage: " );
	if( isvips( g_get_prgname() ) ) 
		fprintf( stderr, "%s ", g_get_prgname() );
	fprintf( stderr, "%s ", fn->name ); 

	/* Print args requiring command-line input.
	 */
	for( i = 0; i < fn->argc; i++ )
		if( fn->argv[i].desc->flags & IM_TYPE_ARG )
			fprintf( stderr, "%s ", fn->argv[i].name );

	/* Print types of command line args.
	 */
	fprintf( stderr, "\nwhere:\n" );
	for( i = 0; i < fn->argc; i++ )
		if( fn->argv[i].desc->flags & IM_TYPE_ARG )
			fprintf( stderr, "\t%s is of type \"%s\"\n", 
				fn->argv[i].name, fn->argv[i].desc->type );

	/* Print output print args.
	 */
	if( has_print( fn ) ) {
		fprintf( stderr, "prints:\n" );
		for( i = 0; i < fn->argc; i++ )
			if( fn->argv[i].print ) 
				fprintf( stderr, "\t%s of type \"%s\"\n", 
					fn->argv[i].name, 
					fn->argv[i].desc->type );
	}

	/* Print description of this function, and package it comes from.
	 */
	fprintf( stderr, "%s", _( fn->desc ) );
	if( pack )
		fprintf( stderr, ", from package \"%s\"", pack->name );
	fprintf( stderr, "\n" );

	/* Print any flags this function has.
	 */
	fprintf( stderr, "flags: " );
	if( fn->flags & IM_FN_PIO )
		fprintf( stderr, "(PIO function) " );
	else
		fprintf( stderr, "(WIO function) " );
	if( fn->flags & IM_FN_TRANSFORM )
		fprintf( stderr, "(coordinate transformer) " );
	else
		fprintf( stderr, "(no coordinate transformation) " );
	if( fn->flags & IM_FN_PTOP )
		fprintf( stderr, "(point-to-point operation) " );
	else
		fprintf( stderr, "(area operation) " );
	if( fn->flags & IM_FN_NOCACHE )
		fprintf( stderr, "(nocache operation) " );
	else
		fprintf( stderr, "(result can be cached) " );

	fprintf( stderr, "\n" );
}
#endif

static int
print_help( int argc, char **argv ) 
{
	return( 0 );
}

/* All our built-in actions.
 */

typedef int (*Action)( int argc, char **argv );

typedef struct _ActionEntry {
	char *name;
	char *description;
	GOptionEntry *group;
	Action action;
} ActionEntry;

static GOptionEntry empty_options[] = {
	{ NULL }
};

static ActionEntry actions[] = {
#if ENABLE_DEPRECATED
	{ "list", N_( "list classes|packages|all|package-name|operation-name" ),
#else
	{ "list", N_( "list classes|all|operation-name" ),
#endif
		&empty_options[0], print_list },
#if ENABLE_DEPRECATED
	{ "links", N_( "generate links for vips/bin" ),
		&empty_options[0], print_links },
#endif
	{ "help", N_( "list possible actions" ),
		&empty_options[0], print_help },
};

static void
parse_options( GOptionContext *context, int *argc, char **argv )
{
	char txt[1024];
	VipsBuf buf = VIPS_BUF_STATIC( txt );
	GError *error = NULL;
	int i, j;

#ifdef DEBUG
	printf( "parse_options:\n" );
	for( i = 0; i < *argc; i++ )
		printf( "%d) %s\n", i, argv[i] );
#endif /*DEBUG*/

	vips_buf_appendf( &buf, "%7s - %s\n", 
		"OPER", _( "execute vips operation OPER" ) );
	g_option_context_set_summary( context, vips_buf_all( &buf ) );

#ifdef G_OS_WIN32
	if( !g_option_context_parse_strv( context, &argv, &error ) ) 
#else /*!G_OS_WIN32*/
	if( !g_option_context_parse( context, argc, &argv, &error ) ) 
#endif /*G_OS_WIN32*/
	{
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		vips_error_exit( NULL );
	}

	/* On Windows, argc will not have been updated by
	 * g_option_context_parse_strv().
	 */
	for( *argc = 0; argv[*argc]; (*argc)++ )
		;

	/* Remove any "--" argument. If one of our arguments is a negative
	 * number, the user will need to have added the "--" flag to stop
	 * GOption parsing. But "--" is still passed down to us and we need to
	 * ignore it.
	 */
	for( i = 1; i < *argc; i++ )
		if( strcmp( argv[i], "--" ) == 0 ) {
			for( j = i; j < *argc; j++ )
				argv[j] = argv[j + 1];

			*argc -= 1;
		}
}

static GOptionGroup *
add_operation_group( GOptionContext *context, VipsOperation *user_data )
{
	GOptionGroup *group;

	group = g_option_group_new( "operation", 
		_( "Operation" ), _( "Operation help" ), user_data, NULL );
	g_option_group_set_translation_domain( group, GETTEXT_PACKAGE );
	g_option_context_add_group( context, group );

	return( group );
}

/* VIPS universal main program. 
 */
int
main( int argc, char **argv )
{
	char *action;
	GOptionContext *context;
	GOptionGroup *main_group;
	GOptionGroup *group;
	VipsOperation *operation;
#if ENABLE_DEPRECATED
	im_function *fn;
#endif
	int i, j;
	gboolean handled;

	GError *error = NULL;

	if( VIPS_INIT( argv[0] ) )
		vips_error_exit( NULL );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

	/* On Windows, argv is ascii-only .. use this to get a utf-8 version of
	 * the args.
	 */
#ifdef G_OS_WIN32
	argv = g_win32_get_command_line();
#endif /*G_OS_WIN32*/

#ifdef DEBUG_FATAL
	/* Set masks for debugging ... stop on any problem. 
	 */
	g_log_set_always_fatal(
		G_LOG_FLAG_RECURSION |
		G_LOG_FLAG_FATAL |
		G_LOG_LEVEL_ERROR |
		G_LOG_LEVEL_CRITICAL |
		G_LOG_LEVEL_WARNING );
#endif /*!DEBUG_FATAL*/

	context = g_option_context_new( _( "[ACTION] [OPTIONS] [PARAMETERS] - "
		"VIPS driver program" ) );

	/* Add and parse the outermost options: the ones this program uses.
	 * For example, we need
	 * to be able to spot that in the case of "--plugin ./poop.plg" we
	 * must remove two args.
	 */
	main_group = g_option_group_new( NULL, NULL, NULL, NULL, NULL );
	g_option_group_add_entries( main_group, main_option );
	vips_add_option_entries( main_group ); 
	g_option_group_set_translation_domain( main_group, GETTEXT_PACKAGE );
	g_option_context_set_main_group( context, main_group );

	/* We add more options later, for example as options to vips8
	 * operations. Ignore any unknown options in this first parse.
	 */
	g_option_context_set_ignore_unknown_options( context, TRUE );

	/* "vips" with no arguments does "vips --help".
	 */
	if( argc == 1 ) { 
		char *help;

		help = g_option_context_get_help( context, TRUE, NULL );
		printf( "%s", help );
		g_free( help );

		exit( 0 );
	}

	/* Also disable help output: we want to be able to display full help
	 * in a second pass after all options have been created.
	 */
	g_option_context_set_help_enabled( context, FALSE );

#ifdef G_OS_WIN32
	if( !g_option_context_parse_strv( context, &argv, &error ) ) 
#else /*!G_OS_WIN32*/
	if( !g_option_context_parse( context, &argc, &argv, &error ) ) 
#endif /*G_OS_WIN32*/
	{
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		vips_error_exit( NULL );
	}

	/* On Windows, argc will not have been updated by
	 * g_option_context_parse_strv().
	 */
	for( argc = 0; argv[argc]; argc++ )
		;

	if( main_option_plugin ) {
#if ENABLE_DEPRECATED
		if( !im_load_plugin( main_option_plugin ) )
			vips_error_exit( NULL );
#else /*!ENABLE_DEPRECATED*/
		GModule *module;

		module = g_module_open( main_option_plugin, G_MODULE_BIND_LAZY );
		if( !module ) {
			vips_error_exit( _( "unable to load \"%s\" -- %s" ),
				main_option_plugin, g_module_error() );
		}
#endif
	}

	if( main_option_version ) 
		printf( "vips-%s\n", vips_version_string() );

	/* Reenable help and unknown option detection ready for the second
	 * option parse.
	 */
	g_option_context_set_ignore_unknown_options( context, FALSE );
	g_option_context_set_help_enabled( context, TRUE );

	/* Try to find our action.
	 */
	handled = FALSE;
	action = NULL;

	/* Should we try to run the thing we are named as?
	 */
	if( !isvips( g_get_prgname() ) ) 
		action = argv[0];

	if( !action ) {
		/* Look for the first non-option argument, if any, and make 
		 * that our action. The parse above will have removed most of
		 * them, but --help (for example) could still remain. 
		 */
		for( i = 1; i < argc; i++ )
			if( argv[i][0] != '-' ) {
				action = argv[i];

				/* Remove the action from argv.
				 */
				for( j = i; j < argc; j++ )
					argv[j] = argv[j + 1];
				argc -= 1;

				break;
			}
	}

	/* Could be one of our built-in actions.
	 */
	if( action ) 
		for( i = 0; i < VIPS_NUMBER( actions ); i++ )
			if( strcmp( action, actions[i].name ) == 0 ) {
				group = add_operation_group( context, NULL );
				g_option_group_add_entries( group, 
					actions[i].group );
				parse_options( context, &argc, argv );

				if( actions[i].action( argc - 1, argv + 1 ) ) 
					vips_error_exit( "%s", action );

				handled = TRUE;
				break;
			}

#if ENABLE_DEPRECATED
	/* Could be a vips7 im_function. We need to test for vips7 first,
	 * since we don't want to use the vips7 compat wrappers in vips8
	 * unless we have to. They don't support all args types.
	 */
	if( action && 
		!handled && 
		(fn = im_find_function( action )) ) {
		if( im_run_command( action, argc - 1, argv + 1 ) ) {
			if( argc == 1 ) 
				usage( fn );
			else
				vips_error_exit( NULL );
		}

		handled = TRUE;
	}

	/* im_find_function() set an error msg.
	 */
	if( action &&
		!handled )
		vips_error_clear();
#endif

	/* Could be a vips8 VipsOperation.
	 */
	if( action && 
		!handled && 
		(operation = vips_operation_new( action )) ) {
		group = add_operation_group( context, operation );
		vips_call_options( group, operation );
		parse_options( context, &argc, argv );

		if( vips_call_argv( operation, argc - 1, argv + 1 ) ) {
			if( argc == 1 ) 
				vips_operation_class_print_usage( 
					VIPS_OPERATION_GET_CLASS( operation ) );

			vips_object_unref_outputs( VIPS_OBJECT( operation ) );
			g_object_unref( operation );

			if( argc == 1 )
				/* We don't exit with an error for something
				 * like "vips fitsload" failing, we use it to
				 * decide if an optional component has been
				 * configured. If we've been built without
				 * fits support, fitsload will fail to find
				 * the operation and we'll error with "unknown
				 * action" below.
				 */
				exit( 0 );
			else
				vips_error_exit( NULL );
		}

		vips_object_unref_outputs( VIPS_OBJECT( operation ) );
		g_object_unref( operation );

		handled = TRUE;
	}

	/* vips_operation_new() sets an error msg for unknown operation.
	 */
	if( action &&
		!handled )
		vips_error_clear();

	if( action && 
		!handled ) {
		vips_error_exit( _( "unknown action \"%s\"" ), action );
	}

	/* Still not handled? We may not have called parse_options(), so
	 * --help args may not have been processed.
	 */
	if( !handled )
		parse_options( context, &argc, argv );

	g_option_context_free( context );

#ifdef G_OS_WIN32
	g_strfreev( argv ); 
#endif /*G_OS_WIN32*/

	vips_shutdown();

	return( 0 );
}
