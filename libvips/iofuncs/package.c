/* VIPS package handling.
 *
 * J. Cupitt, 8/4/93.
 *
 * 18/2/04 JC
 *	- now uses g_module_*() instead of dlopen()
 * 9/8/04
 *	- uses glib dir scanning stuff instead of dirent.h
 * 20/5/08
 * 	- note_dependencies() does IMAGEVEC as well as IMAGE
 * 5/8/08
 * 	- silent success in loading plugins if the dir isn't there
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
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif /*HAVE_SYS_PARAM_H*/
#include <string.h>
#include <stdarg.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Standard VIPS packages.
 */
extern im_package im__arithmetic;
extern im_package im__cimg;
extern im_package im__boolean;
extern im_package im__colour;
extern im_package im__conversion;
extern im_package im__convolution;
extern im_package im__deprecated;
extern im_package im__format;
extern im_package im__freq_filt;
extern im_package im__histograms_lut;
extern im_package im__inplace;
extern im_package im__mask;
extern im_package im__morphology;
extern im_package im__mosaicing;
extern im_package im__other;
extern im_package im__relational;
extern im_package im__resample;
extern im_package im__video;

/* im_guess_prefix() args.
 */
static im_arg_desc guess_prefix_args[] = {
	IM_INPUT_STRING( "argv0" ),
	IM_INPUT_STRING( "env_name" ),
	IM_OUTPUT_STRING( "PREFIX" )
};

/* Call im_guess_prefix() via arg vector.
 */
static int
guess_prefix_vec( im_object *argv )
{
	const char *prefix = vips_guess_prefix( argv[0], argv[1] );

	if( !prefix ) {
		argv[2] = NULL;
		return( -1 );
	}

	argv[2] = vips_strdup( NULL, prefix );

	return( 0 );
}

/* Description of im_guess_prefix.
 */ 
static im_function guess_prefix_desc = {
	"im_guess_prefix", 		/* Name */
	"guess install area",		/* Description */
	0,				/* Flags */
	guess_prefix_vec, 		/* Dispatch function */
	VIPS_NUMBER( guess_prefix_args ), /* Size of arg list */
	guess_prefix_args 		/* Arg list */
};

/* im_guess_libdir() args.
 */
static im_arg_desc guess_libdir_args[] = {
	IM_INPUT_STRING( "argv0" ),
	IM_INPUT_STRING( "env_name" ),
	IM_OUTPUT_STRING( "LIBDIR" )
};

/* Call im_guess_libdir() via arg vector.
 */
static int
guess_libdir_vec( im_object *argv )
{
	const char *libdir = vips_guess_libdir( argv[0], argv[1] );

	if( !libdir ) {
		argv[2] = NULL;
		return( -1 );
	}

	argv[2] = vips_strdup( NULL, libdir );

	return( 0 );
}

/* Description of im_guess_libdir.
 */ 
static im_function guess_libdir_desc = {
	"im_guess_libdir", 		/* Name */
	"guess library area",		/* Description */
	0,				/* Flags */
	guess_libdir_vec, 		/* Dispatch function */
	VIPS_NUMBER( guess_libdir_args ),/* Size of arg list */
	guess_libdir_args 		/* Arg list */
};

/* im_header_int() args.
 */
static im_arg_desc header_int_args[] = {
	IM_INPUT_STRING( "field" ),
	IM_INPUT_IMAGE( "image" ),
	IM_OUTPUT_INT( "value" )
};

/* Call im_header_int() via arg vector.
 */
static int
header_int_vec( im_object *argv )
{
	return( im_header_int( (IMAGE *) argv[1], (const char *) argv[0], 
		(int *) argv[2] ) );
}

/* Description of im_header_int().
 */ 
static im_function header_int_desc = {
	"im_header_int", 		/* Name */
	"extract int fields from header",	/* Description */
	0,				/* Flags */
	header_int_vec, 		/* Dispatch function */
	VIPS_NUMBER( header_int_args ),	/* Size of arg list */
	header_int_args 		/* Arg list */
};

/* im_header_get_typeof() args.
 */
static im_arg_desc header_get_typeof_args[] = {
	IM_INPUT_STRING( "field" ),
	IM_INPUT_IMAGE( "image" ),
	IM_OUTPUT_INT( "gtype" )
};

/* Call im_header_get_typeof() via arg vector.
 */
static int
header_get_typeof_vec( im_object *argv )
{
	int *out = (int *) argv[2];

	*out = im_header_get_typeof( (IMAGE *) argv[1], 
		(const char *) argv[0] ); 

	return( 0 );
}

/* Description of im_header_get_typeof().
 */ 
static im_function header_get_typeof_desc = {
	"im_header_get_typeof",		/* Name */
	"return field type",		/* Description */
	0,				/* Flags */
	header_get_typeof_vec, 		/* Dispatch function */
	VIPS_NUMBER( header_get_typeof_args ),/* Size of arg list */
	header_get_typeof_args 		/* Arg list */
};

/* im_header_double() args.
 */
static im_arg_desc header_double_args[] = {
	IM_INPUT_STRING( "field" ),
	IM_INPUT_IMAGE( "image" ),
	IM_OUTPUT_DOUBLE( "value" )
};

/* Call im_header_double() via arg vector.
 */
static int
header_double_vec( im_object *argv )
{
	return( im_header_double( (IMAGE *) argv[1], (const char *) argv[0], 
		(double *) argv[2] ) );
}

/* Description of im_header_double().
 */ 
static im_function header_double_desc = {
	"im_header_double", 		/* Name */
	"extract double fields from header",	/* Description */
	0,				/* Flags */
	header_double_vec, 		/* Dispatch function */
	VIPS_NUMBER( header_double_args ), /* Size of arg list */
	header_double_args 		/* Arg list */
};

/* im_header_string() args.
 */
static im_arg_desc header_string_args[] = {
	IM_INPUT_STRING( "field" ),
	IM_INPUT_IMAGE( "image" ),
	IM_OUTPUT_STRING( "value" )
};

/* Call im_header_string() via arg vector.
 */
static int
header_string_vec( im_object *argv )
{
	char **out = (char **) &argv[2];

	/* Actually, we call im_header_as_string(), so we can do any field and
	 * not just the string-valued ones.
	 */
	if( im_header_as_string( (IMAGE *) argv[1], 
		(const char *) argv[0], out ) )
		return( -1 );

	return( 0 );
}

/* Description of im_header_string().
 */ 
static im_function header_string_desc = {
	"im_header_string", 		/* Name */
	"extract fields from headers as strings",	/* Description */
	0,				/* Flags */
	header_string_vec, 		/* Dispatch function */
	VIPS_NUMBER( header_string_args ),/* Size of arg list */
	header_string_args 		/* Arg list */
};

/* im_history_get() args.
 */
static im_arg_desc history_get_args[] = {
	IM_INPUT_IMAGE( "image" ),
	IM_OUTPUT_STRING( "history" )
};

/* Call im_history_get() via arg vector.
 */
static int
history_get_vec( im_object *argv )
{
	char **out = (char **) &argv[1];
	const char *str;

	if( !(str = im_history_get( (IMAGE *) argv[0] )) ||
		!(*out = vips_strdup( NULL, str )) )
		return( -1 );

	return( 0 );
}

/* Description of im_history_get().
 */ 
static im_function history_get_desc = {
	"im_history_get", 		/* Name */
	"return the image history as a string",	/* Description */
	0,				/* Flags */
	history_get_vec, 		/* Dispatch function */
	VIPS_NUMBER( history_get_args ),/* Size of arg list */
	history_get_args 		/* Arg list */
};

/* im_getext() args.
 */
static im_arg_desc getext_args[] = {
	IM_INPUT_IMAGE( "image" ),
	IM_OUTPUT_STRING( "history" )
};

/* Call im_getext() via arg vector.
 */
static int
getext_vec( im_object *argv )
{
	void **out = (void **) &argv[1];
	int size;

	/* void/char confusion is fine.
	 */
	if( !(*out = im__read_extension_block( (IMAGE *) argv[0], &size )) )
		return( -1 );

	return( 0 );
}

/* Description of im_getext().
 */ 
static im_function getext_desc = {
	"im_getext", 			/* Name */
	"return the image metadata XML as a string",	/* Description */
	0,				/* Flags */
	getext_vec, 			/* Dispatch function */
	VIPS_NUMBER( getext_args ), 	/* Size of arg list */
	getext_args 			/* Arg list */
};

/* im_printdesc() args.
 */
static im_arg_desc printdesc_args[] = {
	IM_INPUT_IMAGE( "image" ),
};

/* Call im_printdesc() via arg vector.
 */
static int
printdesc_vec( im_object *argv )
{
	vips_object_print( VIPS_OBJECT( argv[0] ) );

	return( 0 );
}

/* Description of im_printdesc().
 */ 
static im_function printdesc_desc = {
	"im_printdesc", 		/* Name */
	"print an image header to stdout",	/* Description */
	0,				/* Flags */
	printdesc_vec, 			/* Dispatch function */
	VIPS_NUMBER( printdesc_args ), 	/* Size of arg list */
	printdesc_args 			/* Arg list */
};

/* im_version_string() args.
 */
static im_arg_desc version_string_args[] = {
	IM_OUTPUT_STRING( "version" )
};

/* Call im_version_string() via arg vector.
 */
static int
version_string_vec( im_object *argv )
{
	if( !(argv[0] = vips_strdup( NULL, vips_version_string() )) )
		return( -1 );

	return( 0 );
}

/* Description of im_version_string.
 */ 
static im_function version_string_desc = {
	"im_version_string", 		/* Name */
	"VIPS version string",		/* Description */
	0,				/* Flags */
	version_string_vec, 		/* Dispatch function */
	VIPS_NUMBER( version_string_args ),/* Size of arg list */
	version_string_args 		/* Arg list */
};

/* im_version() args.
 */
static im_arg_desc version_args[] = {
	IM_INPUT_INT( "flag" ),
	IM_OUTPUT_INT( "version" )
};

/* Call im_version() via arg vector.
 */
static int
version_vec( im_object *argv )
{
	int flag = *((int *) argv[0]);
	int *out = ((int *) argv[1]);

	int version = vips_version( flag );

	if( version < 0 )
		return( -1 );

	*out = version;

	return( 0 );
}

/* Description of im_version.
 */ 
static im_function version_desc = {
	"im_version", 			/* Name */
	"VIPS version number",		/* Description */
	0,				/* Flags */
	version_vec, 			/* Dispatch function */
	VIPS_NUMBER( version_args ), 	/* Size of arg list */
	version_args 			/* Arg list */
};

/* im_cache() args.
 */
static im_arg_desc cache_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "tile_width" ),
	IM_INPUT_INT( "tile_height" ),
	IM_INPUT_INT( "max_tiles" )
};

/* Call im_cache() via arg vector.
 */
static int
cache_vec( im_object *argv )
{
	int tile_width = *((int *) argv[2]);
	int tile_height = *((int *) argv[3]);
	int max_tiles = *((int *) argv[4]);

	return( im_cache( argv[0], argv[1], 
		tile_width, tile_height, max_tiles ) );
}

/* Description of im_cache.
 */ 
static im_function cache_desc = {
	"im_cache", 			/* Name */
	"cache results of an operation",/* Description */
	0,				/* Flags */
	cache_vec, 			/* Dispatch function */
	VIPS_NUMBER( cache_args ), 	/* Size of arg list */
	cache_args 			/* Arg list */
};

/* im_binfile() args.
 */
static im_arg_desc binfile_args[] = {
	IM_INPUT_STRING( "filename" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" ),
	IM_INPUT_INT( "bands" ),
	IM_INPUT_INT( "offset" )
};

/* Call im_binfile() via arg vector.
 */
static int
binfile_vec( im_object *argv )
{
	int width = *((int *) argv[2]);
	int height = *((int *) argv[3]);
	int bands = *((int *) argv[4]);
	int offset = *((int *) argv[5]);
	VipsImage *im;

	if( !(im = vips_image_new_from_file_raw( argv[0], 
		width, height, bands, offset )) )
		return( -1 );
	vips_object_local( argv[1], im );

	if( im_copy( im, argv[1] ) )
		return( -1 );

	return( 0 );
}

/* Description of im_binfile.
 */ 
static im_function binfile_desc = {
	"im_binfile", 			/* Name */
	"open a headerless binary file",/* Description */
	0,				/* Flags */
	binfile_vec, 			/* Dispatch function */
	VIPS_NUMBER( binfile_args ), 	/* Size of arg list */
	binfile_args 			/* Arg list */
};

/* Package up iofuncs functions.
 */
static im_function *iofuncs_list[] = {
	&binfile_desc,
	&cache_desc,
	&getext_desc,
	&guess_prefix_desc,
	&guess_libdir_desc,
	&header_get_typeof_desc,
	&header_int_desc,
	&header_double_desc,
	&header_string_desc,
	&history_get_desc,
	&printdesc_desc,
	&version_desc,
	&version_string_desc
};

/* Package of io functions.
 */
static im_package im__iofuncs = {
	"iofuncs",
	VIPS_NUMBER( iofuncs_list ),
	iofuncs_list
};

/* List of built-in VIPS packages.
 */
static im_package *built_in[] = {
	&im__arithmetic,
	&im__boolean,
#ifdef ENABLE_CXX
	&im__cimg,
#endif /*ENABLE_CXX*/
	&im__colour,
	&im__conversion,
	&im__convolution,
	&im__deprecated,
	&im__format,
	&im__freq_filt,
	&im__histograms_lut,
	&im__inplace,
	&im__iofuncs,
	&im__mask,
	&im__morphology,
	&im__mosaicing,
	&im__other,
	&im__relational,
	&im__resample,
	&im__video
};
/* How we represent a loaded plugin.
 */
typedef struct _Plugin {
	GModule *module;		/* As loaded by g_module_open() */
	char *name;			/* Name we loaded */
	im_package *pack;		/* Package table */
} Plugin;

/* List of loaded plugins.
 */
static GSList *plugin_list = NULL;

/* Free a plugin.
 */
static int
plugin_free( Plugin *plug )
{
	char *name = plug->name ? plug->name : "<unknown>";

	if( plug->module ) {
		if( !g_module_close( plug->module ) ) {
			vips_error( "plugin", 
				_( "unable to close plugin \"%s\"" ), name );
			vips_error( "plugin", "%s", g_module_error() );
			return( -1 );
		}

		plug->module = NULL;
	}
	VIPS_FREE( plug->name );
	plug->pack = NULL;
	vips_free( plug );

	plugin_list = g_slist_remove( plugin_list, plug );

	return( 0 );
}

/* Load a plugin.
 */
im_package *
im_load_plugin( const char *name )
{
	Plugin *plug;

	if( !g_module_supported() ) {
		vips_error( "plugin",	
			"%s", _( "plugins not supported on this platform" ) );
		return( NULL );
	}

	/* Build a new plugin.
	 */
	if( !(plug = VIPS_NEW( NULL, Plugin )) ) 
		return( NULL );
	plug->module = NULL;
	plug->name = NULL;
	plug->pack = NULL;
	plugin_list = g_slist_prepend( plugin_list, plug );

	/* Attach name.
	 */
	if( !(plug->name = vips_strdup( NULL, name )) ) {
		plugin_free( plug );
		return( NULL );
	}

	/* Open library.
	 */
	if( !(plug->module = g_module_open( name, 0 )) ) {
		vips_error( "plugin", _( "unable to open plugin \"%s\"" ), name );
		vips_error( "plugin", "%s", g_module_error() );
		plugin_free( plug );

		return( NULL );
	}

	/* Find package.
	 */
	/* Bizarre double-cast stops a bogus gcc 4.1 compiler warning.
	 */
	if( !g_module_symbol( plug->module, 
		"package_table", (gpointer *) ((void *) &plug->pack) ) ) {
		vips_error( "plugin",
			_( "unable to find symbol \"package_table\" "
				"in plugin \"%s\"" ), name );
		vips_error( "plugin", "%s", g_module_error() );
		plugin_free( plug );

		return( NULL );
	}

	/* Sanity check.
	 */
	if( !plug->pack->name || plug->pack->nfuncs < 0 || 
		plug->pack->nfuncs > 10000 ) {
		vips_error( "plugin",
			_( "corrupted package table in plugin \"%s\"" ), name );
		plugin_free( plug );

		return( NULL );
	}

#ifdef DEBUG
	printf( "added package \"%s\" ...\n", plug->pack->name );
#endif /*DEBUG*/

	return( plug->pack );
}

/* Load all plugins in a directory ... look for '.plg' suffix. Error if we had
 * any probs.
 */
int
im_load_plugins( const char *fmt, ... )
{
        va_list ap;
        char dir_name[PATH_MAX];
        GDir *dir;
	const char *name;
        int result;

	/* Silently succeed if we can't do modules.
	 */
	if( !g_module_supported() )
		return( 0 );

        va_start( ap, fmt );
        (void) im_vsnprintf( dir_name, PATH_MAX - 1, fmt, ap );
        va_end( ap );

        if( !(dir = g_dir_open( dir_name, 0, NULL )) ) 
		/* Silent success for dir not there.
		 */
                return( 0 );

        result = 0;
        while( (name = g_dir_read_name( dir )) )
                if( im_ispostfix( name, ".plg" ) ) { 
			char path[PATH_MAX];

			im_snprintf( path, PATH_MAX - 1, 
				"%s" G_DIR_SEPARATOR_S "%s", dir_name, name );
			if( !im_load_plugin( path ) )
				result = -1;
                }
        g_dir_close( dir );

	return( result );
}

/* Close all loaded plugins.
 */
int
im_close_plugins( void )
{
	while( plugin_list )
		if( plugin_free( (Plugin *) plugin_list->data ) )
			return( -1 );

	return( 0 );
}

/* Apply a user-function to a plugin package.
 */
static void *
apply_plugin( Plugin *plug, VSListMap2Fn fn, void *a )
{
	if( !plug->pack )
		return( NULL );
	else
		return( fn( plug->pack, a, NULL ) );
}

/* Map a function over all packages. Map over plugins first, to allow
 * overriding of VIPS functions.
 */
void *
im_map_packages( VSListMap2Fn fn, void *a )
{
	void *r = im_slist_map2( plugin_list, 
		(VSListMap2Fn) apply_plugin, (void *) fn, a );
	int i;

	/* If not there, try main VIPS package list.
	 */
	if( !r )
		for( i = 0; i < VIPS_NUMBER( built_in ); i++ )
			if( (r = fn( built_in[i], a, NULL )) )
				return( r );

	return( r );
}

/* Search a package for a function.
 */
static im_function *
search_package( im_package *pack, const char *name )
{
	int i;

	for( i = 0; i < pack->nfuncs; i++ ) 
		if( strcmp( pack->table[i]->name, name ) == 0 )
			return( pack->table[i] );

	return( NULL );
}

/* Search all packages for a function.
 */
im_function *
im_find_function( const char *name )
{
	im_function *fn = im_map_packages( 
		(VSListMap2Fn) search_package, (void *) name );

	if( !fn ) {
		vips_error( "im_find_function", _( "\"%s\" not found" ), name );
		return( NULL );
	}

	return( fn );
}

/* Test for package is of name.
 */
static im_package *
package_name( im_package *pack, const char *name )
{
	if( strcmp( pack->name, name ) == 0 )
		return( pack );

	return( NULL );
}

/* Find a package.
 */
im_package *
im_find_package( const char *name )
{
	im_package *pack = im_map_packages( 
		(VSListMap2Fn) package_name, (void *) name );

	if( !pack ) {
		vips_error( "im_find_package", _( "\"%s\" not found" ), name );
		return( NULL );
	}

	return( pack );
}

/* Test for package contains a function.
 */
static im_package *
package_function( im_package *pack, const char *name )
{
	if( search_package( pack, name ) )
		return( pack );
	else
		return( NULL );
}

/* Find a function's package by name.
 */
im_package *
im_package_of_function( const char *name )
{
	im_package *pack = im_map_packages( 
		(VSListMap2Fn) package_function, (void *) name );

	if( !pack ) {
		vips_error( "im_package_of_function",
			_( "\"%s\" not found" ), name );
		return( NULL );
	}

	return( pack );
}

/* Free any store we allocated for the argument list.
 */
int
im_free_vargv( im_function *fn, im_object *vargv )
{
	int i;
	int vargc = fn->argc;

	/* Free all elements.
	 */
	for( i = 0; i < vargc; i++ )
		if( vargv[i] ) {
			/* If there is local storage, free it.
			 */
			if( fn->argv[i].desc->size != 0 )
				vips_free( vargv[i] );

			/* NULL out pointer.
			 */
			vargv[i] = NULL;
		}

	return( 0 );
}

/* Allocate any local store the args will need; NULL out all others.
 */
int
im_allocate_vargv( im_function *fn, im_object *vargv )
{
	int i;
	int vargc = fn->argc;

	/* NULL out all pointers.
	 */
	for( i = 0; i < vargc; i++ )
		vargv[i] = NULL;

	/* Allocate any space we will need.
	 */
	for( i = 0; i < vargc; i++ ) {
		int sz = fn->argv[i].desc->size;

		if( sz != 0 )
			if( !(vargv[i] = vips_malloc( NULL, sz )) ) {
				/* Free anything we did allocate.
				 */
				(void) im_free_vargv( fn, vargv );
				return( -1 );
			}

		/* Zero memory.
		 */
		memset( vargv[i], 0, sz );
	}

	return( 0 );
}

/* Destroy the objects in the arg list.
 */
static int
destroy_args( im_function *fn, im_object *vargv )
{
	int i;
	int vargc = fn->argc;

	/* Destroy all elements with destroy functions.
	 */
	for( i = 0; i < vargc; i++ )
		if( vargv[i] ) 
			/* If there's a destroy function for this type,
			 * trigger it.
			 */
			if( fn->argv[i].desc->dest &&
				fn->argv[i].desc->dest( vargv[i] ) )
				return( -1 );

	return( 0 );
}

/* Init an im_object array from a set of command-line arguments.
 */
static int
build_args( im_function *fn, im_object *vargv, int argc, char **argv )
{
	im_arg_desc *arg = fn->argv;
	int vargc = fn->argc;
	char *str;
	int i, j;

	/* Loop, constructing each im_arg.
	 */
	for( i = 0, j = 0; i < vargc; i++ ) {
		/* Find type for this arg.
		 */
		im_type_desc *type = arg[i].desc;

		/* Do we need to use up a command line argument?
		 */
		if( type->flags & IM_TYPE_ARG ) {
			if( !argv[j] ) {
				vips_error( "im_run_command",
					"%s", _( "too few arguments" ) );
				return( -1 );
			}
			str = argv[j++];

			/* Init object.
			 */
			if( type->init && type->init( &vargv[i], str ) )
				return( -1 );
		}
		else {
			/* Init object with no arg.
			 */
			if( type->init && type->init( &vargv[i], "no arg" ) )
				return( -1 );
		}
	}

	/* Have we used up all the command-line args?
	 */
	if( argv[j] ) {
		vips_error( "im_run_command", "%s", _( "too many arguments" ) );
		return( -1 );
	}

	return( 0 );
}

/* Free a region, but return 0 so we can be used as a close callback.
 */
static void
region_local_image_cb( VipsImage *main, VipsRegion *reg )
{
	g_object_unref( reg );
}

/* Make a region on sub, closed by callback on main.
 */
static int
region_local_image( IMAGE *main, IMAGE *sub )
{
	VipsRegion *reg;

	if( !(reg = vips_region_new( sub )) )
		return( -1 );
	g_signal_connect( main, "close", 
		G_CALLBACK( region_local_image_cb ), reg ); 
 
        return( 0 );
}

/* vargv[i] is an output image on a PIO function ... make all input images 
 * depend on it.
 */
static int
note_dependencies( im_function *fn, im_object *vargv, int i )
{
	int j;

	for( j = 0; j < fn->argc; j++ ) {
		im_type_desc *type = fn->argv[j].desc;

		if( !(type->flags & IM_TYPE_OUTPUT) ) {
			if( strcmp( type->type, IM_TYPE_IMAGE ) == 0 ) {
				if( region_local_image( vargv[i], vargv[j] ) )
					return( -1 );
			}
			else if( strcmp( type->type, IM_TYPE_IMAGEVEC ) == 0 ) {
				im_imagevec_object *iv = vargv[j];
				int k;

				for( k = 0; k < iv->n; k++ )
					if( region_local_image( vargv[i], 
						iv->vec[k] ) )
						return( -1 );
			}
		}
	}

	return( 0 );
}

/* Call all defined print functions.
 */
static int
print_args( im_function *fn, im_object *vargv )
{
	int i;
	int vargc = fn->argc;

	/* Print all elements.
	 */
	for( i = 0; i < vargc; i++ )
		if( fn->argv[i].print && vargv[i] ) 
			if( fn->argv[i].print( vargv[i] ) )
				return( -1 );

	return( 0 );
}

/* Add to the hist of all output images.
 */
static int
add_hist( im_function *fn, im_object *vargv, int argc, char **argv )
{
	int i;
	int vargc = fn->argc;

	/* Search for output images.
	 */
	for( i = 0; i < vargc; i++ )
		if( strcmp( fn->argv[i].desc->type, IM_TYPE_IMAGE ) == 0 &&
			(fn->argv[i].desc->flags & IM_TYPE_OUTPUT) )
			if( im_updatehist( vargv[i], fn->name, argc, argv ) )
				return( -1 );

	return( 0 );
}

/* Call a VIPS function.
 */
static int
dispatch_function( im_function *fn, im_object *vargv, int argc, char **argv )
{
	int i;

	/* Init memory from command line arguments.
	 */
	if( build_args( fn, vargv, argc, argv ) ) 
		return( -1 );

	/* If this is a PIO function, we need to make sure that we close
	 * the input images after the output images, since the output image
	 * may include delayed image conversion filters which will not run
	 * until the output is closed.
	 *
	 * Do this by:
	 *	- for each output image
	 *		- for each input image
	 *			- create a region on the input, closed by a
	 *			  close callback on the output image
	 */
	if( fn->flags & IM_FN_PIO )
		for( i = 0; i < fn->argc; i++ ) {
			im_type_desc *type = fn->argv[i].desc;

			if( type->flags & IM_TYPE_OUTPUT &&
				strcmp( type->type, IM_TYPE_IMAGE ) == 0 )
				if( note_dependencies( fn, vargv, i ) )
					return( -1 );
		}

	/* Call function.
	 */
	if( fn->disp( vargv ) ) 
		return( -1 );

	/* Print output.
	 */
	if( print_args( fn, vargv ) ) 
		return( -1 );

	/* Add to history of all output images.
	 */
	if( add_hist( fn, vargv, argc, argv ) )
		return( -1 );

	/* All ok!
	 */
	return( 0 );
}

/* Run a command.
 */
int
im_run_command( char *name, int argc, char **argv )
{
	static im_object object_array[IM_MAX_ARGS];
	im_object *vargv = object_array;
	im_function *fn;

	/* Search packages for a matching function.
	 */
	if( !(fn = im_find_function( name )) )
		return( -1 );

	/* Allocate space for arguments.
	 */
	if( im_allocate_vargv( fn, vargv ) ) 
		return( -1 );

	/* Call it.
	 */ 
	if( dispatch_function( fn, vargv, argc, argv ) ) {
		destroy_args( fn, vargv );
		im_free_vargv( fn, vargv );
		return( -1 );
	}

	/* Clean up and exit.
	 */
	if( destroy_args( fn, vargv ) ) 
		return( -1 );
	im_free_vargv( fn, vargv );

	return( 0 );
}

/**
 * im_version_string:
 *
 * Get the VIPS version as a static string, including a build date and time.
 * Do not free.
 *
 * Returns: a static version string
 */
const char *
im_version_string( void )
{
	return( IM_VERSION_STRING );
}

/**
 * im_version:
 * @flag: which field of the version to get
 *
 * Get the major, minor or micro library version, with @flag values 0, 1 and
 * 2.
 *
 * Returns: library version number
 */
int
im_version( int flag )
{
	switch( flag ) {
	case 0:
		return( IM_MAJOR_VERSION );
	
	case 1:
		return( IM_MINOR_VERSION );
	
	case 2:
		return( IM_MICRO_VERSION );

	default:
		vips_error( "im_version", "%s", _( "flag not 0, 1, 2" ) );
		return( -1 );
	}
}
