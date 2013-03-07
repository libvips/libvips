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

#ifdef OS_WIN32
#define strcasecmp(a,b) _stricmp(a,b)
#endif

static char *main_option_plugin = NULL;
static gboolean *main_option_version;

static GOptionEntry main_option[] = {
	{ "plugin", 'p', 0, G_OPTION_ARG_FILENAME, &main_option_plugin, 
		N_( "load PLUGIN" ), 
		N_( "PLUGIN" ) },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &main_option_version, 
		N_( "print version" ), NULL },
	{ NULL }
};

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
		im_error( "map_name", 
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

static void *
list_class( GType type )
{
	int depth = vips_type_depth( type );
	int i;

	for( i = 0; i < depth * 2; i++ )
		printf( " " );
	vips_object_print_summary_class( 
		VIPS_OBJECT_CLASS( g_type_class_ref( type ) ) );

	return( NULL );
}

static int
print_list( int argc, char **argv )
{
	if( !argv[0] || strcmp( argv[0], "packages" ) == 0 ) 
		im_map_packages( (VSListMap2Fn) list_package, NULL );
	else if( strcmp( argv[0], "classes" ) == 0 ) 
		vips_type_map_all( g_type_from_name( "VipsObject" ), 
			(VipsTypeMapFn) list_class, NULL );
	else if( g_type_from_name( argv[0] ) &&
		g_type_is_a( g_type_from_name( argv[0] ), VIPS_TYPE_OBJECT ) ) {
		vips_type_map_all( g_type_from_name( argv[0] ), 
			(VipsTypeMapFn) list_class, NULL );
	}
	else {
		if( map_name( argv[0], list_function ) )
			error_exit( "unknown package \"%s\"", argv[0] ); 
	}

	return( 0 );
}

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
	if( im_isprefix( "vips", g_get_prgname() ) ) 
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

/* Convert VIPS type name to C++ type name. NULL for type unsupported by C++
 * layer.
 */
static char *
vips2cpp( im_type_desc *ty )
{
	int k;

	/* VIPS types.
	 */
	static char *vtypes[] = {
		IM_TYPE_DOUBLE,
		IM_TYPE_INT,  
		IM_TYPE_COMPLEX,
		IM_TYPE_STRING,
		IM_TYPE_IMAGE,
		IM_TYPE_IMASK,
		IM_TYPE_DMASK,
		IM_TYPE_DISPLAY,
		IM_TYPE_IMAGEVEC,
		IM_TYPE_DOUBLEVEC,
		IM_TYPE_INTVEC,
		IM_TYPE_INTERPOLATE
	};

	/* Corresponding C++ types.
	 */
	static char *ctypes[] = {
		"double",
		"int",
		"std::complex<double>",
		"char*",
		"VImage",
		"VIMask",
		"VDMask",
		"VDisplay",
		"std::vector<VImage>",
		"std::vector<double>",
		"std::vector<int>",
		"char*"
	};

	for( k = 0; k < IM_NUMBER( vtypes ); k++ )
		if( strcmp( ty->type, vtypes[k] ) == 0 ) 
			return( ctypes[k] );

	return( NULL );
}

/* Test a function definition for C++ suitability.
 */
static int
is_cppable( im_function *fn )
{
	int j;

	/* Don't wrap im_remainderconst_vec().
	 *
	 * This has been replaced by the saner name im_remainder_vec(). If we
	 * generate wrappers for both names we get a overloading clash.
	 */
	if( strcmp( fn->name, "im_remainderconst_vec" ) == 0 )
		return( 0 );

	/* Check we know all the types.
	 */
	for( j = 0; j < fn->argc; j++ ) {
		im_type_desc *ty = fn->argv[j].desc;

		if( !vips2cpp( ty ) )
			return( 0 );
	}

	/* We dont wrap output IMAGEVEC/DOUBLEVEC/INTVEC.
	 */
	for( j = 0; j < fn->argc; j++ ) {
		im_type_desc *ty = fn->argv[j].desc;

		if( ty->flags & IM_TYPE_OUTPUT ) 
			if( strcmp( ty->type, IM_TYPE_IMAGEVEC ) == 0 ||
				strcmp( ty->type, IM_TYPE_DOUBLEVEC ) == 0 ||
				strcmp( ty->type, IM_TYPE_INTVEC ) == 0 )
			return( 0 );
	}

	/* Must be at least one image argument (input or output) ... since we 
	 * get inserted in the VImage class. Other funcs get wrapped by hand.
	 */
	for( j = 0; j < fn->argc; j++ ) 
		if( strcmp( fn->argv[j].desc->type, IM_TYPE_IMAGE ) == 0 ) 
			break;
	if( j == fn->argc )
		return( 0 );

	return( -1 );
}

/* Search for the first output arg, and the first IMAGE input arg.
 */
static void
find_ioargs( im_function *fn, int *ia, int *oa )
{
	int j;

	/* Look for first output arg - this will be the result of the
	 * function.
	 */
	*oa = -1;
	for( j = 0; j < fn->argc; j++ ) {
		im_type_desc *ty = fn->argv[j].desc;

		if( ty->flags & IM_TYPE_OUTPUT ) {
			*oa = j;
			break;
		}
	}

	/* Look for first input IMAGE arg. This will become the implicit
	 * "this" arg.
	 */
	*ia = -1;
	for( j = 0; j < fn->argc; j++ ) {
		im_type_desc *ty = fn->argv[j].desc;

		if( !(ty->flags & IM_TYPE_OUTPUT) && 
			strcmp( ty->type, IM_TYPE_IMAGE ) == 0 ) {
				*ia = j;
				break;
			}
	}
}

static gboolean
drop_postfix( char *str, const char *postfix )
{
	if( vips_ispostfix( str, postfix ) ) {
		str[strlen( str ) - strlen( postfix )] = '\0';

		return( TRUE );
	}

	return( FALSE );
}

/* Turn a VIPS name into a C++ name. Eg. im_lintra_vec becomes lin.
 */
static void
c2cpp_name( const char *in, char *out )
{
	static const char *dont_drop[] = {
		"_set",
	};
	static const char *drop[] = {
		"_vec",
		"const",
		"tra",
		"set",
		"_f"
	};

	int i;
	gboolean changed;

	/* Copy, chopping off "im_" prefix.
	 */
	if( vips_isprefix( "im_", in ) )
		strcpy( out, in + 3 );
	else
		strcpy( out, in );

	/* Repeatedly drop postfixes while we can. Stop if we see a dont_drop
	 * postfix.
	 */
	do {
		gboolean found;

		found = FALSE;
		for( i = 0; i < IM_NUMBER( dont_drop ); i++ )
			if( vips_ispostfix( out, dont_drop[i] ) ) {
				found = TRUE;
				break;
			}
		if( found )
			break;

		changed = FALSE;
		for( i = 0; i < IM_NUMBER( drop ); i++ )
			changed |= drop_postfix( out, drop[i] );
	} while( changed );
}

/* Print prototype for a function (ie. will be followed by code). 
 *
 * Eg.:
 *	VImage VImage::lin( double a, double b ) throw( VError )
 */
static void *
print_cppproto( im_function *fn )
{
	int j;
	char name[4096];
	int oa, ia;
	int flg;

	/* If it's not cppable, do nothing.
	 */
	if( !is_cppable( fn ) )
		return( NULL );

	/* Make C++ name.
	 */
	c2cpp_name( fn->name, name );

	/* Find input and output args. 
	 */
	find_ioargs( fn, &ia, &oa );

	/* Print output type.
	 */
	if( oa == -1 )
		printf( "void " );
	else 
		printf( "%s ", vips2cpp( fn->argv[oa].desc ) );

	printf( "VImage::%s(", name );

	/* Print arg list.
	 */
	flg = 0;
	for( j = 0; j < fn->argc; j++ ) {
		im_type_desc *ty = fn->argv[j].desc;

		/* Skip ia and oa.
		 */
		if( j == ia || j == oa )
			continue;

		/* Print arg type.
		 */
		if( flg )
			printf( ", %s", vips2cpp( ty ) );
		else {
			printf( " %s", vips2cpp( ty ) );
			flg = 1;
		}

		/* If it's an putput arg, print a "&" to make a reference
		 * argument.
		 */
		if( ty->flags & IM_TYPE_OUTPUT )
			printf( "&" );

		/* Print arg name.
		 */
		printf( " %s", fn->argv[j].name );
	}

	/* End of arg list!
	 */
	if( flg )
		printf( " " );
	printf( ") throw( VError )\n" );

	return( NULL );
}

/* Print cpp decl for a function. 
 *
 * Eg.
 *	VImage lin( double, double ) throw( VError );
 */
static void *
print_cppdecl( im_function *fn )
{
	int j;
	char name[4096];
	int oa, ia;
	int flg;

	/* If it's not cppable, do nothing.
	 */
	if( !is_cppable( fn ) )
		return( NULL );

	/* Make C++ name.
	 */
	c2cpp_name( fn->name, name );

	/* Find input and output args. 
	 */
	find_ioargs( fn, &ia, &oa );
	if( ia == -1 ) 
		/* No input image, so make it a static in the class
		 * declaration.
		 */
		printf( "static " );

	/* Print output type.
	 */
	if( oa == -1 )
		printf( "void " );
	else 
		printf( "%s ", vips2cpp( fn->argv[oa].desc ) );

	/* Print function name and start arg list.
	 */
	printf( "%s(", name );

	/* Print arg list.
	 */
	flg = 0;
	for( j = 0; j < fn->argc; j++ ) {
		im_type_desc *ty = fn->argv[j].desc;

		/* Skip ia and oa.
		 */
		if( j == ia || j == oa )
			continue;

		/* Print arg type.
		 */
		if( flg )
			printf( ", %s", vips2cpp( ty ) );
		else {
			printf( " %s", vips2cpp( ty ) );
			flg = 1;
		}

		/* If it's an putput arg, print a "&" to make a reference
		 * argument.
		 */
		if( ty->flags & IM_TYPE_OUTPUT )
			printf( "&" );

		/* Print arg name. 
		 *
		 * Prepend the member name to make the arg
		 * unique. This is important for SWIG since it needs to have
		 * unique names for %apply.
		 */
		printf( " %s_%s", name, fn->argv[j].name );
	}

	/* End of arg list!
	 */
	if( flg )
		printf( " " );

	printf( ") throw( VError );\n" );

	return( NULL );
}

static void
print_invec( int j, const char *arg, 
	const char *vips_name, const char *c_name, const char *extract )
{
	printf( "\t((%s*) _vec.data(%d))->n = %s.size();\n",
		vips_name, j, arg );
	printf( "\t((%s*) _vec.data(%d))->vec = new %s[%s.size()];\n",
		vips_name, j, c_name, arg );
	printf( "\tfor( unsigned int i = 0; i < %s.size(); i++ )\n",
		arg );
	printf( "\t\t((%s*) _vec.data(%d))->vec[i] = %s[i]%s;\n",
		vips_name, j, arg, extract );
}

/* Print the definition for a function.
 */
static void *
print_cppdef( im_function *fn )
{
	int j;
	int ia, oa;

	/* If it's not cppable, do nothing.
	 */
	if( !is_cppable( fn ) )
		return( NULL );

	find_ioargs( fn, &ia, &oa );

	printf( "// %s: %s\n", fn->name, _( fn->desc ) );
	print_cppproto( fn );
	printf( "{\n" );

	/* Declare the implicit input image.
	 */
	if( ia != -1 )
		printf( "\tVImage %s = *this;\n", fn->argv[ia].name );

	/* Declare return value, if any.
	 */
	if( oa != -1 )
		printf( "\t%s %s;\n\n", 
			vips2cpp( fn->argv[oa].desc ),
			fn->argv[oa].name );

	/* Declare the arg vector.
	 */
	printf( "\tVargv _vec( \"%s\" );\n\n", fn->name );

	/* Create the input args.
	 */
	for( j = 0; j < fn->argc; j++ ) {
		im_type_desc *ty = fn->argv[j].desc;

		/* Images are special - have to init the vector, even
		 * for output args. Have to translate VImage.
		 */
		if( strcmp( ty->type, IM_TYPE_IMAGE ) == 0 ) {
			printf( "\t_vec.data(%d) = %s.image();\n",
				j, fn->argv[j].name );
			continue;
		}

		/* For output masks, we have to set an input filename. Not
		 * freed, so constant string is OK.
		 */
		if( (ty->flags & IM_TYPE_OUTPUT) && 
			(strcmp( ty->type, IM_TYPE_IMASK ) == 0 ||
			strcmp( ty->type, IM_TYPE_DMASK ) == 0) ) {
			printf( "\t((im_mask_object*) _vec.data(%d))->name = "
				"(char*)\"noname\";\n", j );
			continue;
		}

		/* Skip other output args.
		 */
		if( ty->flags & IM_TYPE_OUTPUT )
			continue;

		if( strcmp( ty->type, IM_TYPE_IMASK ) == 0 )
			/* Mask types are different - have to use
			 * im_mask_object.
			 */
			printf( "\t((im_mask_object*) "
				"_vec.data(%d))->mask = %s.mask().iptr;\n",
				j, fn->argv[j].name );
		else if( strcmp( ty->type, IM_TYPE_DMASK ) == 0 ) 
			printf( "\t((im_mask_object*) "
				"_vec.data(%d))->mask = %s.mask().dptr;\n",
				j, fn->argv[j].name );
		else if( strcmp( ty->type, IM_TYPE_DISPLAY ) == 0 )
			/* Display have to use VDisplay.
			 */
			printf( "\t_vec.data(%d) = %s.disp();\n",
				j, fn->argv[j].name );
		else if( strcmp( ty->type, IM_TYPE_STRING ) == 0 )
			/* Zap input strings directly into _vec.
			 */
			printf( "\t_vec.data(%d) = (im_object) %s;\n",
				j, fn->argv[j].name );
		else if( strcmp( ty->type, IM_TYPE_IMAGEVEC ) == 0 ) 
			print_invec( j, fn->argv[j].name, 
				"im_imagevec_object", "IMAGE *", ".image()" );
		else if( strcmp( ty->type, IM_TYPE_DOUBLEVEC ) == 0 ) 
			print_invec( j, fn->argv[j].name, 
				"im_doublevec_object", "double", "" );
		else if( strcmp( ty->type, IM_TYPE_INTVEC ) == 0 ) 
			print_invec( j, fn->argv[j].name, 
				"im_intvec_object", "int", "" );
		else if( strcmp( ty->type, IM_TYPE_INTERPOLATE ) == 0 ) {
			printf( "\tif( vips__input_interpolate_init( "
				"&_vec.data(%d), %s ) )\n",
				j, fn->argv[j].name );
			printf( "\t\tverror();\n" );
		}
		else
			/* Just use vips2cpp().
			 */
			printf( "\t*((%s*) _vec.data(%d)) = %s;\n",
				vips2cpp( ty ), j, fn->argv[j].name );
	}

	/* Call function.
	 */
	printf( "\t_vec.call();\n" );

	/* Extract output args.
	 */
	for( j = 0; j < fn->argc; j++ ) {
		im_type_desc *ty = fn->argv[j].desc;

		/* Skip input args.
		 */
		if( !(ty->flags & IM_TYPE_OUTPUT) )
			continue;

		/* Skip images (done on input side, really).
		 */
		if( strcmp( ty->type, IM_TYPE_IMAGE ) == 0 )
			continue;

		if( strcmp( ty->type, IM_TYPE_IMASK ) == 0 ||
			strcmp( ty->type, IM_TYPE_DMASK ) == 0 ) 
			/* Mask types are different - have to use
			 * im_mask_object.
			 */
			printf( "\t%s.embed( (DOUBLEMASK *)((im_mask_object*)"
				"_vec.data(%d))->mask );\n",
				fn->argv[j].name, j );
		else if( strcmp( ty->type, IM_TYPE_STRING ) == 0 )
			/* Strings are grabbed out of the vec.
			 */
			printf( "\t%s = (char*) _vec.data(%d);\n",
				fn->argv[j].name, j ); 
		else 
			/* Just use vips2cpp().
			 */
			printf( "\t%s = *((%s*)_vec.data(%d));\n",
				fn->argv[j].name, vips2cpp( ty ), j ); 
	}

	/* Note dependancies if out is an image and this function uses
	 * PIO.
	 */
	if( oa != -1 ) {
		im_type_desc *ty = fn->argv[oa].desc;
		
		if( strcmp( ty->type, IM_TYPE_IMAGE ) == 0 &&
			(fn->flags & IM_FN_PIO) ) {
			/* Loop for all input args again ..
			 */
			for( j = 0; j < fn->argc; j++ ) {
				im_type_desc *ty2 = fn->argv[j].desc;

				/* Skip output args.
				 */
				if( ty2->flags & IM_TYPE_OUTPUT )
					continue;

				/* Input image.
				 */
				if( strcmp( ty2->type, IM_TYPE_IMAGE ) == 0 ) 
					printf( "\t%s._ref->addref( "
						"%s._ref );\n",
						fn->argv[oa].name,
						fn->argv[j].name );
				else if( strcmp( ty2->type, IM_TYPE_IMAGEVEC ) 
					== 0 ) {
					/* The out depends on every image in
					 * the input vector.
					 */
					printf( "\tfor( unsigned int i = 0; "
						"i < %s.size(); i++ )\n",
						fn->argv[j].name );
					printf( "\t\t%s._ref->addref( "
						"%s[i]._ref );\n",
						fn->argv[oa].name,
						fn->argv[j].name );
				}
			}
		}
	}

	/* Return result.
	 */
	if( oa != -1 )
		printf( "\n\treturn( %s );\n", fn->argv[oa].name );

	printf( "}\n\n" );

	return( NULL );
}

/* Print C++ decls for function, package or all.
 */
static int
print_cppdecls( int argc, char **argv )
{
	printf( "// this file automatically generated from\n"
		"// VIPS library %s\n", im_version_string() );

	if( map_name( argv[0], print_cppdecl ) )
		error_exit( NULL );

	return( 0 );
}

/* Print C++ bindings for function, package or all.
 */
static int
print_cppdefs( int argc, char **argv ) 
{
	printf( "// this file automatically generated from\n"
		"// VIPS library %s\n", im_version_string() );

	if( map_name( argv[0], print_cppdef ) )
		error_exit( NULL );

	return( 0 );
}

static void action_list( VipsBuf *buf );

static int
print_help( int argc, char **argv ) 
{
	char txt[1024];
	VipsBuf buf = VIPS_BUF_STATIC( txt );

	action_list( &buf ); 
	printf( "%s", vips_buf_all( &buf ) );

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
	{ "list", N_( "list classes|packages|all|package-name|operation-name" ),
		&empty_options[0], print_list },
	{ "cpph", N_( "generate headers for C++ binding" ),
		&empty_options[0], print_cppdecls },
	{ "cppc", N_( "generate bodies for C++ binding" ),
		&empty_options[0], print_cppdefs },
	{ "links", N_( "generate links for vips/bin" ),
		&empty_options[0], print_links },
	{ "help", N_( "list possible actions" ),
		&empty_options[0], print_help },
};

static void
action_list( VipsBuf *buf )
{
	int i;

	vips_buf_appends( buf, _( "possible actions:\n" ) );
	for( i = 0; i < VIPS_NUMBER( actions ); i++ )
		vips_buf_appendf( buf, "%7s - %s\n", 
			actions[i].name, _( actions[i].description ) ); 
	vips_buf_appendf( buf, "%7s - %s\n", 
		"OP", _( "execute vips operation OP" ) );
}

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

	action_list( &buf ); 
	g_option_context_set_summary( context, vips_buf_all( &buf ) );

	if( !g_option_context_parse( context, argc, &argv, &error ) ) {
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		error_exit( NULL );
	}

	/* Remove any "--" argument. If one of our arguments is a negative
	 * number, the user will need to have added the "--" flag to stop
	 * GOption parsing. But "--" is still passed down to us and we need to
	 * ignore it.
	 */
	for( i = 1; i < *argc - 1; i++ )
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
	im_function *fn;
	int i, j;
	gboolean handled;

	GError *error = NULL;

	if( im_init_world( argv[0] ) )
	        error_exit( NULL );
	textdomain( GETTEXT_PACKAGE );
	setlocale( LC_ALL, "" );

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
	g_option_group_set_translation_domain( main_group, GETTEXT_PACKAGE );
	g_option_context_set_main_group( context, main_group );

	/* Add the libvips options too.
	 */
	g_option_context_add_group( context, im_get_option_group() );

	/* We add more options later, for example as options to vips8
	 * operations. Ignore any unknown options in this first parse.
	 */
	g_option_context_set_ignore_unknown_options( context, TRUE );

	/* Also disable help output: we want to be able to display full help
	 * in a second pass after all options have been created.
	 */
	g_option_context_set_help_enabled( context, FALSE );

	if( !g_option_context_parse( context, &argc, &argv, &error ) ) {
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		error_exit( NULL );
	}

	if( main_option_plugin ) {
		if( !im_load_plugin( main_option_plugin ) )
			error_exit( NULL ); 
	}

	if( main_option_version ) 
		printf( "vips-%s\n", im_version_string() );

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
	if( !im_isprefix( "vips", g_get_prgname() ) ) 
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
					error_exit( "%s", action );

				handled = TRUE;
				break;
			}

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
				error_exit( NULL );
		}

		handled = TRUE;
	}

	/* im_find_function() set an error msg.
	 */
	if( action &&
		!handled )
		im_error_clear();

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

			error_exit( NULL );
		}

		vips_object_unref_outputs( VIPS_OBJECT( operation ) );
		g_object_unref( operation );

		handled = TRUE;
	}

	/* vips_operation_new() sets an error msg for unknown operation.
	 */
	if( action &&
		!handled )
		im_error_clear();

	/* Still not handled? We may not have called parse_options(), so
	 * --help args may not have been processed.
	 */
	if( !handled )
		parse_options( context, &argc, argv );

	if( action && 
		!handled ) {
		print_help( argc, argv );
		error_exit( _( "unknown action \"%s\"" ), action );
	}

	g_option_context_free( context );

	vips_shutdown();

	return( 0 );
}
