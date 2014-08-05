/* base class for all vips operations
 */

/*

    Copyright (C) 1991-2005 The National Gallery

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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include <gobject/gvaluecollector.h>

/**
 * SECTION: operation
 * @short_description: the VIPS operation base object class
 * @stability: Stable
 * @see_also: <link linkend="libvips-object">object</link>
 * @include: vips/vips.h
 *
 * The #VipsOperation class and associated types and macros.
 *
 * #VipsOperation is the base class for all operations in libvips. It builds
 * on #VipsObject to provide the introspection and command-line interface to
 * libvips. 
 *
 * It also maintains a cache of recent operations. You can tune the cache
 * behaviour in various ways, see vips_cache_set_max() and friends. 
 *
 * vips_call(), vips_call_split() and vips_call_split_option_string() are used
 * by vips to implement the C API. They can execute any #VipsOperation,
 * passing in a set of required and optional arguments. Normally you would not
 * use these functions directly: every operation has a tiny wrapper function
 * which provides type-safety for the required arguments. For example,
 * vips_embed() is defined as:
 *
 * |[
 * int
 * vips_embed( VipsImage *in, VipsImage **out, 
 *   int x, int y, int width, int height, ... )
 * {
 *   va_list ap;
 *   int result;
 *
 *   va_start( ap, height );
 *   result = vips_call_split( "embed", ap, in, out, x, y, width, height );
 *   va_end( ap );
 *
 *   return( result );
 * }
 * ]|
 *
 * If you are writing a language binding, you won't need these. Instead, make
 * a new operation with vips_operation_new() (all it does is look up the
 * operation by name with vips_type_find(), then call g_object_new() for you),
 * then use vips_argument_map() and friends to loop over the operation's
 * arguments setting them. Once you have set all arguments, use
 * vips_cache_operation_build() to look up the operation in the cache and
 * either build or dup it. If something goes wrong, you'll need to use
 * vips_object_unref_outputs() and g_object_unref() to free the
 * partially-built object.
 *
 * Use vips_call_argv() to run any vips operation from a command-line style
 * argc/argv array. This is the thing used by the vips main program to
 * implement the vips command-line interface. 
 */

/** 
 * VipsOperationFlags:
 * @VIPS_OPERATION_NONE: no flags
 * @VIPS_OPERATION_SEQUENTIAL: can work sequentially
 * @VIPS_OPERATION_NOCACHE: must not be cached
 * @VIPS_OPERATION_DEPRECATED: a compatibility thing
 *
 * Flags we associate with an operation.
 *
 * @VIPS_OPERATION_SEQUENTIAL means that the operation works like vips_conv():
 * it can happily process images top-to-bottom with only small non-local
 * references.
 *
 * @VIPS_OPERATION_SEQUENTIAL_UNBUFFERED means that the operation works like 
 * vips_copy(): it can happily process images top-to-bottom and makes no 
 * non-local references. 
 *
 * @VIPS_OPERATION_NOCACHE means that the operation must not be cached by
 * vips. 
 *
 * @VIPS_OPERATION_DEPRECATED means this is an old operation kept in vips for
 * compatibility only and should be hidden from users.
 */

/* Abstract base class for operations.
 */

/* Our signals. 
 */
enum {
	SIG_INVALIDATE,		
	SIG_LAST
};

static guint vips_operation_signals[SIG_LAST] = { 0 };

G_DEFINE_ABSTRACT_TYPE( VipsOperation, vips_operation, VIPS_TYPE_OBJECT );

static void
vips_operation_finalize( GObject *gobject )
{
	VipsOperation *operation = VIPS_OPERATION( gobject );

	VIPS_DEBUG_MSG( "vips_operation_finalize: %p\n", gobject );

	if( operation->pixels ) {
		VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gobject );

		vips_info( class->nickname, 
			_( "%d pixels calculated" ), operation->pixels ); 
	}

	G_OBJECT_CLASS( vips_operation_parent_class )->finalize( gobject );
}

static void
vips_operation_dispose( GObject *gobject )
{
	VIPS_DEBUG_MSG( "vips_operation_dispose: %p\n", gobject );

	G_OBJECT_CLASS( vips_operation_parent_class )->dispose( gobject );
}

/* Three basic types of command-line argument. 
 *
 * INPUTS: things like an input image, there is a filename argument on the
 * command-line which is used to construct the operation argument.
 *
 * NOARG_OUTPUT: things like the result of VipsMax, there's no correspondiong
 * command-line argument, we just print the value.
 *
 * OPTIONS: optional arguments.
 *
 * NONE: hide this thing.
 */

typedef enum {
	USAGE_INPUTS,
	USAGE_NOARG_OUTPUT,
	USAGE_OPTIONS,
	USAGE_NONE
} UsageType; 

typedef struct {
	char *message;		/* header message on first print */
	UsageType type; 	/* Type of arg to select */
	gboolean oftype;	/* Show as "of type" */
	int n;			/* Arg number */
} VipsOperationClassUsage;

/* Put an arg into one the categories above.
 */
static UsageType
vips_operation_class_usage_classify( VipsArgumentClass *argument_class )
{
	if( !(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ||
		(argument_class->flags & VIPS_ARGUMENT_DEPRECATED) ) 
		return( USAGE_NONE ); 

	if( !(argument_class->flags & VIPS_ARGUMENT_REQUIRED) )
		return( USAGE_OPTIONS ); 

	if( vips_argument_class_needsstring( argument_class ) )
		return( USAGE_INPUTS ); 

	if( (argument_class->flags & VIPS_ARGUMENT_OUTPUT) &&
		!vips_argument_class_needsstring( argument_class ) )
		return( USAGE_NOARG_OUTPUT ); 

	return( USAGE_NONE ); 
}

static void *
vips_operation_class_usage_arg( VipsObjectClass *object_class, 
	GParamSpec *pspec, VipsArgumentClass *argument_class,
	VipsBuf *buf, VipsOperationClassUsage *usage )
{
	if( usage->type == 
		vips_operation_class_usage_classify( argument_class ) ) { 
		if( usage->message && 
			usage->n == 0 ) 
			vips_buf_appendf( buf, "%s\n", usage->message );

		if( usage->oftype ) 
			vips_buf_appendf( buf, "   %-12s - %s, %s %s\n",
				g_param_spec_get_name( pspec ), 
				g_param_spec_get_blurb( pspec ), 
				(argument_class->flags & VIPS_ARGUMENT_INPUT) ?
					_( "input" ) : _( "output" ),
				g_type_name( 
					G_PARAM_SPEC_VALUE_TYPE( pspec ) ) );
		else {
				if( usage->n > 0 )
					vips_buf_appends( buf, " " );
				vips_buf_appends( buf, 
					g_param_spec_get_name( pspec ) );
		}

		usage->n += 1;
	}

	return( NULL );
}

static void
vips_operation_usage( VipsOperationClass *class, VipsBuf *buf )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );

	VipsOperationClassUsage usage;

	vips_buf_appendf( buf, "%s\n", object_class->description );
	vips_buf_appendf( buf, "usage:\n" ); 

	/* First pass through args: show the required names.
	 */
	vips_buf_appendf( buf, "   %s ", object_class->nickname );
	usage.message = NULL;
	usage.type = USAGE_INPUTS;
	usage.oftype = FALSE;
	usage.n = 0;
	vips_argument_class_map( object_class,
		(VipsArgumentClassMapFn) vips_operation_class_usage_arg, 
			buf, &usage );
	vips_buf_appends( buf, "\n" );

	/* Show required types.
	 */
	usage.message = "where:";
	usage.type = USAGE_INPUTS;
	usage.oftype = TRUE;
	usage.n = 0;
	vips_argument_class_map( object_class,
		(VipsArgumentClassMapFn) vips_operation_class_usage_arg, 
			buf, &usage );

	/* Show outputs with no input arg (eg. output maximum value for
	 * vips_max()).
	 */
	usage.message = "outputs:";
	usage.type = USAGE_NOARG_OUTPUT;
	usage.oftype = TRUE;
	usage.n = 0;
	vips_argument_class_map( object_class,
		(VipsArgumentClassMapFn) vips_operation_class_usage_arg, 
			buf, &usage );

	/* Show optional args.
	 */
	usage.message = "optional arguments:";
	usage.type = USAGE_OPTIONS;
	usage.oftype = TRUE;
	usage.n = 0;
	vips_argument_class_map( object_class,
		(VipsArgumentClassMapFn) vips_operation_class_usage_arg, 
			buf, &usage );

	/* Show flags.
	 */
	if( class->flags ) {
		GFlagsValue *value;
		VipsOperationFlags flags;
		GFlagsClass *flags_class = 
			g_type_class_ref( VIPS_TYPE_OPERATION_FLAGS );

		vips_buf_appendf( buf, "operation flags: " );
		flags = class->flags; 
		while( flags && (value = 
			g_flags_get_first_value( flags_class, flags )) ) {
			vips_buf_appendf( buf, "%s ", value->value_nick );
			flags &= ~value->value;
		}
		vips_buf_appends( buf, "\n" );
	}
}

static void *
vips_operation_call_argument( VipsObject *object, GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsArgument *argument = (VipsArgument *) argument_class;

	printf( "   %s: offset = %d ", 
		g_param_spec_get_name( argument->pspec ),
		argument_class->offset );
	if( argument_class->flags & VIPS_ARGUMENT_REQUIRED )
		printf ("required " );
	if( argument_class->flags & VIPS_ARGUMENT_CONSTRUCT )
		printf ("construct " );
	if( argument_class->flags & VIPS_ARGUMENT_SET_ONCE )
		printf ("set-once " );
	if( argument_instance->assigned )
		printf ("assigned " );
	printf( "\n" );

	return( NULL );
}

static void
vips_operation_dump( VipsObject *object, VipsBuf *buf )
{
	VipsOperation *operation = VIPS_OPERATION( object );
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );

	printf( "%s args:\n", object_class->nickname );
	vips_argument_map( VIPS_OBJECT( operation ),
		vips_operation_call_argument, NULL, NULL );

	VIPS_OBJECT_CLASS( vips_operation_parent_class )->dump( object, buf );
}

static void *
vips_operation_vips_operation_print_summary_arg( VipsObject *object, 
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsBuf *buf = (VipsBuf *) a;

	/* Just assigned required input construct args
	 */
	if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		argument_instance->assigned ) {
		const char *name = g_param_spec_get_name( pspec );
		GType type = G_PARAM_SPEC_VALUE_TYPE( pspec );

		GValue gvalue = { 0, };
		char *str;

		g_value_init( &gvalue, type );
		g_object_get_property( G_OBJECT( object ), name, &gvalue ); 
		str = g_strdup_value_contents( &gvalue );
		vips_buf_appendf( buf, " %s=%s", name, str );
		g_free( str );
		g_value_unset( &gvalue ); 
	}

	return( NULL );
}

static void
vips_operation_summary( VipsObject *object, VipsBuf *buf )
{
	VipsOperation *operation = VIPS_OPERATION( object );
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );

	vips_buf_appendf( buf, "%s", object_class->nickname ); 
	vips_argument_map( VIPS_OBJECT( operation ),
		vips_operation_vips_operation_print_summary_arg, buf, NULL );

	vips_buf_appends( buf, " -" );

	VIPS_OBJECT_CLASS( vips_operation_parent_class )->
		summary( object, buf );
}

static VipsOperationFlags
vips_operation_real_get_flags( VipsOperation *operation ) 
{
	VipsOperationClass *class = VIPS_OPERATION_GET_CLASS( operation );

	return( class->flags );
}

static void
vips_operation_class_init( VipsOperationClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->finalize = vips_operation_finalize;
	gobject_class->dispose = vips_operation_dispose;

	vobject_class->nickname = "operation";
	vobject_class->description = _( "operations" );
	vobject_class->summary = vips_operation_summary;
	vobject_class->dump = vips_operation_dump;

	class->usage = vips_operation_usage;
	class->get_flags = vips_operation_real_get_flags;

	vips_operation_signals[SIG_INVALIDATE] = g_signal_new( "invalidate",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsOperationClass, invalidate ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
}

static void
vips_operation_init( VipsOperation *operation )
{
}

/**
 * vips_operation_get_flags:
 * @operation: operation to fetch flags from
 *
 * Returns the set of flags for this operation.
 *
 * Returns: 0 on success, or -1 on error.
 */
VipsOperationFlags
vips_operation_get_flags( VipsOperation *operation ) 
{
	VipsOperationClass *class = VIPS_OPERATION_GET_CLASS( operation );

	return( class->get_flags( operation ) );
}

/**
 * vips_operation_class_print_usage: (skip)
 * @operation_class: class to print usage for
 *
 * Print a usage message for the operation to stdout.
 */
void
vips_operation_class_print_usage( VipsOperationClass *operation_class )
{
	char str[2048];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	operation_class->usage( operation_class, &buf );
	printf( "%s", vips_buf_all( &buf ) );
}

void
vips_operation_invalidate( VipsOperation *operation )
{
	/*
	printf( "vips_operation_invalidate: %p\n", operation ); 
	vips_object_print_summary( VIPS_OBJECT( operation ) ); 
	 */

	g_signal_emit( operation, vips_operation_signals[SIG_INVALIDATE], 0 );
}

VipsOperation *
vips_operation_new( const char *name )
{
	GType type;
	VipsObject *object;
	VipsOperation *operation;

	vips_check_init();

	if( !(type = vips_type_find( "VipsOperation", name )) ) {
		vips_error( "VipsOperation", 
			_( "class \"%s\" not found" ), name );
		return( NULL );
	}

	if( !(object = g_object_new( type, NULL )) ) {
		vips_error( "VipsOperation", 
			_( "\"%s\" is not an instantiable class" ), name );
		return( NULL );
	}

	operation = VIPS_OPERATION( object );

	VIPS_DEBUG_MSG( "vips_operation_new: %s (%p)\n", name, operation );

	return( operation );
}

/* Some systems do not have va_copy() ... this might work (it does on MSVC),
 * apparently.
 *
 * FIXME ... this should be in configure.in
 */
#ifndef va_copy
#define va_copy(d,s) ((d) = (s))
#endif

static int
vips_operation_set_valist_required( VipsOperation *operation, va_list ap )
{
	VIPS_DEBUG_MSG( "vips_operation_set_valist_required:\n" );

	/* Set required input arguments. Can't use vips_argument_map here 
	 * :-( because passing va_list by reference is not portable. 
	 */
	VIPS_ARGUMENT_FOR_ALL( operation, 
		pspec, argument_class, argument_instance ) {

		g_assert( argument_instance );

		if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) ) {
			VIPS_ARGUMENT_COLLECT_SET( pspec, argument_class, ap );

#ifdef VIPS_DEBUG
			{
				char *str;

				str = g_strdup_value_contents( &value );
				VIPS_DEBUG_MSG( "\t%s = %s\n", 
					g_param_spec_get_name( pspec ), str );
				g_free( str );
			}
#endif /*VIPS_DEBUG */

			g_object_set_property( G_OBJECT( operation ),
				g_param_spec_get_name( pspec ), &value );

			VIPS_ARGUMENT_COLLECT_GET( pspec, argument_class, ap );

#ifdef VIPS_DEBUG
			printf( "\tskipping arg %p for %s\n", 
				arg, g_param_spec_get_name( pspec ) );
#endif /*VIPS_DEBUG */

			VIPS_ARGUMENT_COLLECT_END
		}
	} VIPS_ARGUMENT_FOR_ALL_END

	return( 0 );
}

static int
vips_operation_get_valist_required( VipsOperation *operation, va_list ap )
{
	VIPS_DEBUG_MSG( "vips_operation_get_valist_required:\n" );

	/* Extract output arguments. Can't use vips_argument_map here 
	 * :-( because passing va_list by reference is not portable. 
	 */
	VIPS_ARGUMENT_FOR_ALL( operation, 
		pspec, argument_class, argument_instance ) {
		if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) ) {
			VIPS_ARGUMENT_COLLECT_SET( pspec, argument_class, ap );

			VIPS_ARGUMENT_COLLECT_GET( pspec, argument_class, ap );

			if( !argument_instance->assigned ) 
				continue;

#ifdef VIPS_DEBUG
			printf( "\twriting %s to %p\n", 
				g_param_spec_get_name( pspec ), arg );
#endif /*VIPS_DEBUG */

			/* It'd be nice to be able to test for arg being a
			 * valid gobject pointer, since passing in a valid
			 * pointer, and having us destroy it, is a common
			 * error and a cause of hard-to-find leaks.
			 *
			 * Unfortunately, G_IS_OBJECT() can't be given an
			 * arbitrary pointer for testing -- you're very likely
			 * to get coredumps.
			 */

			g_object_get( G_OBJECT( operation ), 
				g_param_spec_get_name( pspec ), arg, NULL );

			/* If the pspec is an object, that will up the ref
			 * count. We want to hand over the ref, so we have to
			 * knock it down again.
			 */
			if( G_IS_PARAM_SPEC_OBJECT( pspec ) ) {
				GObject *object;

				object = *((GObject **) arg);
				g_object_unref( object ); 
			}

			VIPS_ARGUMENT_COLLECT_END
		}
	} VIPS_ARGUMENT_FOR_ALL_END

	return( 0 );
}

static int
vips_operation_get_valist_optional( VipsOperation *operation, va_list ap )
{
	char *name;

	VIPS_DEBUG_MSG( "vips_operation_get_valist_optional:\n" );

	for( name = va_arg( ap, char * ); name; name = va_arg( ap, char * ) ) { 
		GParamSpec *pspec;
		VipsArgumentClass *argument_class;
		VipsArgumentInstance *argument_instance;

		VIPS_DEBUG_MSG( "\tname = '%s' (%p)\n", name, name );

		if( vips_object_get_argument( VIPS_OBJECT( operation ), name,
			&pspec, &argument_class, &argument_instance ) )
			return( -1 );

		VIPS_ARGUMENT_COLLECT_SET( pspec, argument_class, ap );

		/* We must collect input args as we walk the name/value list,
		 * but we don't do anything with them.
		 */

		VIPS_ARGUMENT_COLLECT_GET( pspec, argument_class, ap );

		/* Here's an output arg.
		 */

#ifdef VIPS_DEBUG
		printf( "\twriting %s to %p\n", 
			g_param_spec_get_name( pspec ), arg );
#endif /*VIPS_DEBUG */

		/* If the dest pointer is NULL, skip the read.
		 */
		if( arg ) {
			g_object_get( G_OBJECT( operation ), 
				g_param_spec_get_name( pspec ), arg, 
				NULL );

			/* If the pspec is an object, that will up 
			 * the ref count. We want to hand over the 
			 * ref, so we have to knock it down again.
			 */
			if( G_IS_PARAM_SPEC_OBJECT( pspec ) ) {
				GObject *object;

				object = *((GObject **) arg);
				g_object_unref( object ); 
			}
		}

		VIPS_ARGUMENT_COLLECT_END
	}

	return( 0 );
}

/* This can change operation to point at an old, cached one.
 */
static int
vips_call_required_optional( VipsOperation **operation,
	va_list required, va_list optional ) 
{
	int result;
	va_list a;
	va_list b;

	/* We need to be able to walk required and optional twice. On x64 gcc,
	 * vips_operation_set_valist_required() etc. will destructively alter
	 * the passed-in va_list. We make a copy and walk that instead.
	 */
	va_copy( a, required );
	va_copy( b, optional );
	result = vips_operation_set_valist_required( *operation, a ) ||
		vips_object_set_valist( VIPS_OBJECT( *operation ), b );
	va_end( a );
	va_end( b );

	if( result )
		return( -1 );

	/* Build from cache.
	 */
	if( vips_cache_operation_buildp( operation ) )
		return( -1 );

	/* Walk args again, writing output.
	 */
	va_copy( a, required );
	va_copy( b, optional );
	result = vips_operation_get_valist_required( *operation, required ) ||
		vips_operation_get_valist_optional( *operation, optional );
	va_end( a );
	va_end( b );

	return( result );
}

static int
vips_call_by_name( const char *operation_name, 
	const char *option_string, va_list required, va_list optional )
{
	VipsOperation *operation;
	int result;

	VIPS_DEBUG_MSG( "vips_call_by_name: starting for %s ...\n", 
		operation_name );

	if( !(operation = vips_operation_new( operation_name )) )
		return( -1 );

	/* Set str options before vargs options, so the user can't override
	 * thnigs we set deliberately.
	 */
	if( option_string &&
		vips_object_set_from_string( VIPS_OBJECT( operation ), 
			option_string ) ) {
		vips_object_unref_outputs( VIPS_OBJECT( operation ) );
		g_object_unref( operation ); 

		return( -1 ); 
	}

	result = vips_call_required_optional( &operation, required, optional );

	/* Build failed: junk args and back out.
	 */
	if( result ) {
		vips_object_unref_outputs( VIPS_OBJECT( operation ) );
		g_object_unref( operation );

		return( -1 );
	}

	/* The operation we have built should now have been reffed by one of 
	 * its arguments or have finished its work. Either way, we can unref.
	 */
	g_object_unref( operation );

	return( result );
}

/**
 * vips_call:
 * @operation_name:
 * @...: required args, then a %NULL-terminated list of argument/value pairs
 *
 * vips_call() calls the named operation, passing in required arguments, and
 * then setting any optional ones from the remainder of the arguments as a set
 * of name/value pairs. 
 *
 * For example, vips_embed() takes six required arguments, @in, @out, @x, @y, 
 * @width, @height; and has two optional arguments, @extend and @background.
 * You can run it with vips_call() like this: 
 *
 * |[
 * VipsImage *in = ...
 * VipsImage *out;
 *
 * if( vips_call( "embed", in, &out, 10, 10, 100, 100,
 * 	"extend", VIPS_EXTEND_COPY,
 * 	NULL ) )
 * 	... error
 * ]|
 *
 * Normally of course you'd just use the vips_embed() wrapper function and get
 * type-safety for the required arguments. 
 *
 * See also: vips_call_split(), vips_call_options().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_call( const char *operation_name, ... )
{
	VipsOperation *operation;
	int result;
	va_list required;
	va_list optional;

	if( !(operation = vips_operation_new( operation_name )) )
		return( -1 );

	/* We have to break the va_list into separate required and optional 
	 * components.
	 *
	 * Note the start, grab the required, then copy and reuse.
	 */
	va_start( required, operation_name );

	va_copy( optional, required );

	VIPS_ARGUMENT_FOR_ALL( operation, 
		pspec, argument_class, argument_instance ) {

		g_assert( argument_instance );

		if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) ) {
			VIPS_ARGUMENT_COLLECT_SET( pspec, argument_class, 
				optional );

			VIPS_ARGUMENT_COLLECT_GET( pspec, argument_class, 
				optional );

			VIPS_ARGUMENT_COLLECT_END
		}
	} VIPS_ARGUMENT_FOR_ALL_END

	/* We just needed this operation for the arg loop.
	 */
	g_object_unref( operation ); 

	result = vips_call_by_name( operation_name, NULL, required, optional ); 

	va_end( required );
	va_end( optional );

	return( result );
}

int
vips_call_split( const char *operation_name, va_list optional, ... ) 
{
	int result;
	va_list required;

	va_start( required, optional );
	result = vips_call_by_name( operation_name, NULL, 
		required, optional );
	va_end( required );

	return( result );
}

int
vips_call_split_option_string( const char *operation_name, 
	const char *option_string, va_list optional, ... ) 
{
	int result;
	va_list required;

	va_start( required, optional );
	result = vips_call_by_name( operation_name, option_string, 
		required, optional );
	va_end( required );

	return( result );
}

static void *
vips_call_find_pspec( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	const char *name = (const char *) a;

	/* One char names we assume are "-x" style abbreviations, longer names
	 * we match the whole string.
	 */
	if( !(argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		!argument_instance->assigned ) 
		if( (strlen( name ) == 1 && 
			g_param_spec_get_name( pspec )[0] == name[0]) ||
			strcmp( g_param_spec_get_name( pspec ), name  ) == 0 ) 
			return( argument_instance );

	return( NULL );
}

/* Keep this stuff around for output args.
 */
typedef struct _VipsCallOptionOutput {
	VipsArgumentInstance *argument_instance;
	char *value;
} VipsCallOptionOutput;

static int
vips_call_option_output( VipsObject *object,
	VipsCallOptionOutput *output )
{
	VipsArgumentInstance *argument_instance = output->argument_instance;
	GParamSpec *pspec = ((VipsArgument *) argument_instance)->pspec;

	int result;

	/* Don't look at the output arg if _build() hasn't run sucessfully, it
	 * probably won't have been set. 
	 */
	result = 0;
	if( object->constructed )
		result = vips_object_get_argument_to_string( object, 
			g_param_spec_get_name( pspec ), output->value );

	return( result ); 
}

static void
vips_call_option_output_free( VipsObject *object, VipsCallOptionOutput *output )
{
	VIPS_FREE( output->value ); 
	g_free( output );
}

static gboolean
vips_call_options_set( const gchar *option_name, const gchar *value, 
	gpointer data, GError **error )
{
	VipsOperation *operation = (VipsOperation *) data;
	const char *name;
	VipsArgumentInstance *argument_instance;
	VipsArgumentClass *argument_class;
	GParamSpec *pspec;

	VIPS_DEBUG_MSG( "vips_call_options_set: %s = %s\n", 
		option_name, value );

	/* Remove any leading "--" from the option name.
	 */
	for( name = option_name; *name == '-'; name++ )
		;

	if( !(argument_instance = (VipsArgumentInstance *) 
		vips_argument_map( 
			VIPS_OBJECT( operation ),
			vips_call_find_pspec, (void *) name, NULL )) ) {
		vips_error( VIPS_OBJECT_GET_CLASS( operation )->nickname, 
			_( "unknown argument '%s'" ), name );
		vips_error_g( error );
		return( FALSE );
	}
	argument_class = argument_instance->argument_class;
	pspec = ((VipsArgument *) argument_instance)->pspec;

	if( (argument_class->flags & VIPS_ARGUMENT_INPUT) ) {
		if( vips_object_set_argument_from_string( 
			VIPS_OBJECT( operation ),
			g_param_spec_get_name( pspec ), value ) ) {
			vips_error_g( error );
			return( FALSE );
		}

#ifdef VIPS_DEBUG
{
		GType type = G_PARAM_SPEC_VALUE_TYPE( pspec );
		GValue gvalue = { 0, };
		char *str;

		g_value_init( &gvalue, type );
		g_object_get_property( G_OBJECT( operation ), 
			g_param_spec_get_name( pspec ), &gvalue ); 
		str = g_strdup_value_contents( &gvalue );
		VIPS_DEBUG_MSG( "\tGValue %s = %s\n", 
			g_param_spec_get_name( pspec ), str );
		g_free( str );
		g_value_unset( &gvalue ); 
}
#endif /*VIPS_DEBUG*/
	}
	else if( (argument_class->flags & VIPS_ARGUMENT_OUTPUT) ) {
		VipsCallOptionOutput *output;

		/* We can't do output now, we have to attach a callback to do
		 * the processing after the operation has run.
		 */
		output = g_new( VipsCallOptionOutput, 1 );
		output->argument_instance = argument_instance;
		output->value = g_strdup( value );
		g_signal_connect( operation, "postbuild",
			G_CALLBACK( vips_call_option_output ),
			output );
		g_signal_connect( operation, "close",
			G_CALLBACK( vips_call_option_output_free ),
			output );
	}

	return( TRUE );
}

static void *
vips_call_options_add( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	GOptionGroup *group = (GOptionGroup *) a;

	if( !(argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		!argument_instance->assigned ) {
		const char *name = g_param_spec_get_name( pspec );
		gboolean needs_string = 
			vips_object_argument_needsstring( object, name );
		GOptionEntry entry[2];

		entry[0].long_name = name;
		entry[0].description = g_param_spec_get_blurb( pspec );

		/* Don't set short names for deprecated args.
		 */
		if( argument_class->flags & VIPS_ARGUMENT_DEPRECATED ) 
			entry[0].short_name = '\0';
		else
			entry[0].short_name = name[0];

		entry[0].flags = 0;
		if( !needs_string ) 
			entry[0].flags |= G_OPTION_FLAG_NO_ARG;
		if( argument_class->flags & VIPS_ARGUMENT_DEPRECATED ) 
			entry[0].flags |= G_OPTION_FLAG_HIDDEN;

		entry[0].arg = G_OPTION_ARG_CALLBACK;
		entry[0].arg_data = (gpointer) vips_call_options_set;
		if( needs_string ) 
			entry[0].arg_description = 
				g_type_name( G_PARAM_SPEC_VALUE_TYPE( pspec ) );
		else
			entry[0].arg_description = NULL;

		entry[1].long_name = NULL;

		VIPS_DEBUG_MSG( "vips_call_options_add: adding %s\n", name );

		g_option_group_add_entries( group, &entry[0] );
	}

	return( NULL );
}

void
vips_call_options( GOptionGroup *group, VipsOperation *operation )
{
	(void) vips_argument_map( VIPS_OBJECT( operation ),
		vips_call_options_add, group, NULL );
}

/* What we track during an argv call.
 */
typedef struct _VipsCall {
	VipsOperation *operation;
	int argc;
	char **argv;
	int i;
} VipsCall;

static const char *
vips_call_get_arg( VipsCall *call, int i )
{
	if( i < 0 || i >= call->argc ) {
		vips_error( VIPS_OBJECT_GET_CLASS( call->operation )->nickname, 
			"%s", _( "too few arguments" ) );
		return( NULL );
	}

	return( call->argv[i] );
}

static void *
vips_call_argv_input( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsCall *call = (VipsCall *) a;

	/* Loop over all required construct args.
	 */
	if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		!(argument_class->flags & VIPS_ARGUMENT_DEPRECATED) ) { 
		const char *name = g_param_spec_get_name( pspec );

		if( (argument_class->flags & VIPS_ARGUMENT_INPUT) ) {
			const char *arg;

			if( !(arg = vips_call_get_arg( call, call->i )) ||
				vips_object_set_argument_from_string( object, 
					name, arg ) ) 
				return( pspec );

			call->i += 1;
		}
		else if( (argument_class->flags & VIPS_ARGUMENT_OUTPUT) ) {
			if( vips_object_argument_needsstring( object, name ) )
				call->i += 1;
		}
	}

	return( NULL );
}

static void *
vips_call_argv_output( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsCall *call = (VipsCall *) a;

	/* Loop over all required construct args.
	 */
	if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		!(argument_class->flags & VIPS_ARGUMENT_DEPRECATED) ) { 
		if( (argument_class->flags & VIPS_ARGUMENT_INPUT) ) 
			call->i += 1;
		else if( (argument_class->flags & VIPS_ARGUMENT_OUTPUT) ) {
			const char *name = g_param_spec_get_name( pspec );
			const char *arg;

			arg = NULL;
			if( vips_object_argument_needsstring( object, name ) ) {
				arg = vips_call_get_arg( call, call->i );
				if( !arg )
					return( pspec );

				call->i += 1;
			}

			if( vips_object_get_argument_to_string( object, 
				name, arg ) ) 
				return( pspec );
		}
	}

	return( NULL );
}

/* Our main command-line entry point. Optional args should have been set by
 * the GOption parser already, see above.
 *
 * We don't create the operation, so we must not unref it. The caller must
 * unref on error too. The caller must also call vips_object_unref_outputs() on
 * all code paths.
 */
int
vips_call_argv( VipsOperation *operation, int argc, char **argv )
{
	VipsCall call;

	g_assert( argc >= 0 );

#ifdef VIPS_DEBUG
	printf( "vips_call_argv: " );
	vips_object_print_name( VIPS_OBJECT( operation ) );
	printf( "\n" );
{
	int i;

	for( i = 0; i < argc; i++ )
		printf( "%d) %s\n", i, argv[i] );
}
#endif /*VIPS_DEBUG*/

	call.operation = operation;
	call.argc = argc;
	call.argv = argv;

	call.i = 0;
	if( vips_argument_map( VIPS_OBJECT( operation ),
		vips_call_argv_input, &call, NULL ) ) 
		return( -1 );

	/* Any unused arguments? We must fail. Consider eg. "vips bandjoin a b
	 * c". This would overwrite b with a and ignore c, potentially
	 * disasterous.
	 */
	if( argc > call.i ) {
		vips_error( VIPS_OBJECT_GET_CLASS( operation )->nickname, 
			"%s", _( "too many arguments" ) );
		return( -1 );
	}

	/* We can't use the operation cache, we need to be able to change the
	 * operation pointer. The cache probably wouldn't help anyway.
	 */
	if( vips_object_build( VIPS_OBJECT( operation ) ) ) 
		return( -1 );

	call.i = 0;
	if( vips_argument_map( VIPS_OBJECT( operation ),
		vips_call_argv_output, &call, NULL ) ) 
		return( -1 );

	return( 0 );
}
