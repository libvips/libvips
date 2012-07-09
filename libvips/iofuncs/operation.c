/* base class for all vips operations
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

/* Abstract base class for operations.
 */

G_DEFINE_ABSTRACT_TYPE( VipsOperation, vips_operation, VIPS_TYPE_OBJECT );

static void
vips_operation_finalize( GObject *gobject )
{
	VIPS_DEBUG_MSG( "vips_operation_finalize: %p\n", gobject );

	G_OBJECT_CLASS( vips_operation_parent_class )->finalize( gobject );
}

static void
vips_operation_dispose( GObject *gobject )
{
	VIPS_DEBUG_MSG( "vips_operation_dispose: %p\n", gobject );

	G_OBJECT_CLASS( vips_operation_parent_class )->dispose( gobject );
}

/* What to show about the argument.
 */
typedef struct {
	char *message;		/* header message on first print */
	gboolean required;	/* show required args or optional */
	gboolean oftype;	/* "is of type" message */
	int n;			/* Arg number */
} VipsOperationClassUsage;

static void *
vips_operation_class_usage_arg( VipsObjectClass *object_class, 
	GParamSpec *pspec, VipsArgumentClass *argument_class,
	VipsBuf *buf, VipsOperationClassUsage *usage )
{
	/* Only show construct args ... others are internal.
	 */
	if( usage->required == 
		((argument_class->flags & VIPS_ARGUMENT_REQUIRED) != 0) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ) {
		if( usage->message && usage->n == 0 ) 
			vips_buf_appendf( buf, "%s\n", usage->message );

		if( usage->oftype ) {
			vips_buf_appendf( buf, "   %-12s - %s, %s %s\n",
				g_param_spec_get_name( pspec ), 
				g_param_spec_get_blurb( pspec ), 
				(argument_class->flags & VIPS_ARGUMENT_INPUT) ?
					_( "input" ) : _( "output" ),
				g_type_name( 
					G_PARAM_SPEC_VALUE_TYPE( pspec ) ) );
		}
		else {
			if( usage->n > 0 )
				vips_buf_appends( buf, " " );
			vips_buf_appends( buf, g_param_spec_get_name( pspec ) );
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

	/* First pass through args: show the required names.
	 */
	vips_buf_appendf( buf, "   %s ", object_class->nickname );
	usage.message = NULL;
	usage.required = TRUE;
	usage.oftype = FALSE;
	usage.n = 0;
	vips_argument_class_map( object_class,
		(VipsArgumentClassMapFn) vips_operation_class_usage_arg, 
			buf, &usage );
	vips_buf_appends( buf, "\n" );

	/* Show required types.
	 */
	usage.message = "where:";
	usage.required = TRUE;
	usage.oftype = TRUE;
	usage.n = 0;
	vips_argument_class_map( object_class,
		(VipsArgumentClassMapFn) vips_operation_class_usage_arg, 
			buf, &usage );

	/* Show optional args.
	 */
	usage.message = "optional arguments:";
	usage.required = FALSE;
	usage.oftype = TRUE;
	usage.n = 0;
	vips_argument_class_map( object_class,
		(VipsArgumentClassMapFn) vips_operation_class_usage_arg, 
			buf, &usage );
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
		(argument_class->flags & VIPS_ARGUMENT_INPUT) && 
		argument_instance->assigned ) {
		const char *name = g_param_spec_get_name( pspec );
		GType type = G_PARAM_SPEC_VALUE_TYPE( pspec );

		GValue gvalue = { 0, };
		char *str;

		g_value_init( &gvalue, type );
		g_object_get_property( G_OBJECT( object ), name, &gvalue ); 
		str = g_strdup_value_contents( &gvalue );
		vips_buf_appendf( buf, " %s", str );
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

	VIPS_OBJECT_CLASS( vips_operation_parent_class )->
		summary( object, buf );
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
}

static void
vips_operation_init( VipsOperation *operation )
{
	/* Init our instance fields.
	 */
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
	printf( "%s", _( "usage:" ) );
	printf( "\n%s", vips_buf_all( &buf ) );
}

VipsOperation *
vips_operation_new( const char *name )
{
	GType type;
	VipsOperation *operation;

	vips_check_init();

	if( !(type = vips_type_find( "VipsOperation", name )) ) {
		vips_error( "VipsOperation", 
			_( "class \"%s\" not found" ), name );
		return( NULL );
	}
	operation = VIPS_OPERATION( g_object_new( type, NULL ) );

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

	name = va_arg( ap, char * );

	while( name ) {
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

		name = va_arg( ap, char * );
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
		vips_object_set_valist( *operation, b );
	va_end( a );
	va_end( b );

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

int
vips_call( const char *operation_name, ... )
{
	VipsOperation *operation;
	int result;
	va_list required;
	va_list optional;

	VIPS_DEBUG_MSG( "vips_call: starting for %s ...\n", operation_name );

	if( !(operation = vips_operation_new( operation_name ) ) )
		return( -1 );

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "where:\n" );
	vips_object_print( VIPS_OBJECT( operation ) );
#endif /*VIPS_DEBUG*/

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

	result = vips_call_required_optional( &operation, required, optional );

	va_end( required );
	va_end( optional );

	/* Failed: junk args and back out.
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

int
vips_call_split( const char *operation_name, va_list optional, ... ) 
{
	VipsOperation *operation;
	int result;
	va_list required;

	VIPS_DEBUG_MSG( "vips_call_split: starting for %s ...\n", 
		operation_name );

	if( !(operation = vips_operation_new( operation_name ) ) )
		return( -1 );

	va_start( required, optional );
	result = vips_call_required_optional( &operation, required, optional );
	va_end( required );

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
	const char *value;
} VipsCallOptionOutput;

static void
vips_call_option_output( VipsObject *object,
	VipsCallOptionOutput *output )
{
	VipsArgumentInstance *argument_instance = output->argument_instance;
	GParamSpec *pspec = ((VipsArgument *) argument_instance)->pspec;

	if( vips_object_get_argument_to_string( object, 
		g_param_spec_get_name( pspec ), output->value ) ) {
		/* FIXME .. Hmm what can we do here? If an arg is image
		 * output, for example, we will lose the error.
		 */
	}

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
		 *
		 * FIXME ... something like posteval or postbuild might be
		 * better for this?
		 */
		output = g_new( VipsCallOptionOutput, 1 );
		output->argument_instance = argument_instance;
		output->value = value;
		g_signal_connect( operation, "preclose",
			G_CALLBACK( vips_call_option_output ),
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
			vips_object_get_argument_needs_string( object, name );
		GOptionEntry entry[2];

		entry[0].long_name = name;
		entry[0].short_name = name[0];
		entry[0].flags = 0;
		if( !needs_string ) 
			entry[0].flags |= G_OPTION_FLAG_NO_ARG;
		entry[0].arg = G_OPTION_ARG_CALLBACK;
		entry[0].arg_data = (gpointer) vips_call_options_set;
		entry[0].description = g_param_spec_get_blurb( pspec );
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
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ) {
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
			if( vips_object_get_argument_needs_string( object,
				name ) )
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
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ) {
		if( (argument_class->flags & VIPS_ARGUMENT_INPUT) ) 
			call->i += 1;
		else if( (argument_class->flags & VIPS_ARGUMENT_OUTPUT) ) {
			const char *name = g_param_spec_get_name( pspec );
			const char *arg;

			arg = NULL;
			if( vips_object_get_argument_needs_string( object,
				name ) ) {
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

/**
 * vips_operation_set_nocache: 
 * @operation: operation to set
 * @nocache: TRUE means don't cache this operation
 *
 * Set this before the end of _build() to stop this operation being cached.
 * Some operations, like sequential read from a TIFF file, for example, cannot
 * be reused.
 */
void 
vips_operation_set_nocache( VipsOperation *operation, gboolean nocache )
{
#ifdef VIPS_DEBUG
	printf( "vips_operation_set_nocache: " );
	vips_object_print_name( VIPS_OBJECT( operation ) );
	printf( " %d\n", nocache );
#endif /*VIPS_DEBUG*/

	operation->nocache = nocache;
}
