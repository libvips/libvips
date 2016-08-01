/* abstract base class for all vips objects
 *
 * Edited from nip's base class, 15/10/08
 */

/*

    Copyright (C) 1991-2003 The National Gallery

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
#define DEBUG
#define VIPS_DEBUG
#define DEBUG_REF
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include <gobject/gvaluecollector.h>

#include "vipsmarshal.h"

/**
 * SECTION: object
 * @short_description: the VIPS base object class
 * @stability: Stable
 * @see_also: <link linkend="VipsOperation">operation</link>
 * @include: vips/vips.h
 *
 * The #VipsObject class and associated types and macros.
 *
 * #VipsObject is the base class for all objects in libvips. It has the
 * following major features:
 *
 * <emphasis>Functional class creation</emphasis> Vips objects have a very 
 * regular lifecycle: initialise, build, use, destroy. They behave rather like
 * function calls and are free of side-effects. 
 *
 * <emphasis>Run-time introspection</emphasis> Vips objects can be fully 
 * introspected at run-time. There is not need for separate source-code 
 * analysis. 
 *
 * <emphasis>Command-line interface</emphasis> Any vips object can be run from
 * the command-line with the `vips` driver program. 
 *
 * ## The #VipsObject lifecycle
 *
 * #VipsObject s have a strictly defined lifecycle, split broadly as construct
 * and then use. In detail, the stages are:
 *
 * 1. g_object_new(). The #VipsObject is created with g_object_new(). Objects
 * in this state are blank slates and need to have their various parameters
 * set.
 *
 * 2. g_object_set(). You loop over the #VipsArgument that the object has
 * defined with vips_argument_map(). Arguments have a set of flags attached to
 * them for required, optional, input, output, type, and so on. You must set
 * all required arguments. 
 *
 * 3. vips_object_build(). Call this to construct the object and get it ready
 * for use. Building an object happens in four stages, see below.
 *
 * 4. g_object_get(). The object has now been built. You can read out any 
 * computed values.  
 *
 * 5. g_object_unref(). When you are done with an object, you can unref it.
 * See the section on reference counting for an explanation of the convention
 * that #VipsObject uses. When the last ref to an object is released, the
 * object is closed. Objects close in three stages, see below.
 *
 * The stages inside vips_object_build() are:
 *
 * 1. Chain up through the object's @build class methods. At each stage,
 * each class does any initial setup and checking, then chains up to its
 * superclass.
 *
 * 2. The innermost @build method inside #VipsObject itself checks that all 
 * input arguments have been set and then returns. 
 *
 * 3. All object @build methods now finish executing, from innermost to
 * outermost. They know all input arguments have been checked and supplied, so
 * now they set all output arguments. 
 *
 * 4. vips_object_build() finishes the process by checking that all output
 * objects have been set, and then triggering the #VipsObject::postbuild
 * signal. #VipsObject::postbuild only runs if the object has constructed
 * successfuly.
 *
 * #VipsOperation has a cache of recent operation objects, see that class for
 * an explanation of vips_cache_operation_build(). 
 *
 * Finally the stages inside close are:
 *
 * 1. #VipsObject::preclose. This is emitted at the start of
 * the #VipsObject dispose. The object is still functioning. 
 *
 * 2. #VipsObject::close. This runs just after all #VipsArgument held by
 * the object have been released.
 *
 * 3. #VipsObject::postclose. This runs right at the end. The object
 * pointer is still valid, but nothing else is. 
 *
 * ## #VipsArgument
 *
 * libvips has a simple mechanism for automating at least some aspects of
 * %GObject properties. You add a set of macros to your _class_init() which
 * describe the arguments, and set the get and set functions to the vips ones.
 *
 * See <link linkend="extending">extending</link> for a complete example. 
 *
 * ## The #VipsObject reference counting convention
 *
 * #VipsObject has a set of conventions to simplify reference counting.
 *
 * 1. All input %GObject have a ref added to them, owned by the object. When a
 * #VipsObject is unreffed, all of these refs to input objects are
 * automatically dropped.
 *
 * 2. All output %GObject hold a ref to the object. When a %GObject which is an
 * output of a #VipsObject is disposed, it must drop this reference.
 * #VipsObject which are outputs of other #VipsObject will do this
 * automatically. 
 *
 * See #VipsOperation for an example of #VipsObject reference counting. 
 *
 */

/** 
 * VipsArgumentFlags:
 * @VIPS_ARGUMENT_NONE: no flags
 * @VIPS_ARGUMENT_REQUIRED: must be set in the constructor
 * @VIPS_ARGUMENT_CONSTRUCT: can only be set in the constructor
 * @VIPS_ARGUMENT_SET_ONCE: can only be set once
 * @VIPS_ARGUMENT_SET_ALWAYS: don't do use-before-set checks
 * @VIPS_ARGUMENT_INPUT: is an input argument (one we depend on)
 * @VIPS_ARGUMENT_OUTPUT: is an output argument (depends on us)
 * @VIPS_ARGUMENT_DEPRECATED: just there for back-compat, hide 
 * @VIPS_ARGUMENT_MODIFY: the input argument will be modified
 *
 * Flags we associate with each object argument.
 *
 * Have separate input & output flags. Both set is an error; neither set is OK.
 *
 * Input gobjects are automatically reffed, output gobjects automatically ref
 * us. We also automatically watch for "destroy" and unlink.
 *
 * @VIPS_ARGUMENT_SET_ALWAYS is handy for arguments which are set from C. For
 * example, VipsImage::width is a property that gives access to the Xsize
 * member of struct _VipsImage. We default its 'assigned' to TRUE
 * since the field is always set directly by C.
 *
 * @VIPS_ARGUMENT_DEPRECATED arguments are not shown in help text, are not
 * looked for if required, are not checked for "have-been-set". You can
 * deprecate a required argument, but you must obviously add a new required
 * argument if you do.
 *
 * Input args with @VIPS_ARGUMENT_MODIFY will be modified by the operation.
 * This is used for things like the in-place drawing operations. 
 */

/* Our signals. 
 */
enum {
	SIG_POSTBUILD,		
	SIG_PRECLOSE,		
	SIG_CLOSE,		
	SIG_POSTCLOSE,		
	SIG_LAST
};

/* Table of all objects, handy for debugging.
 */
static GHashTable *vips__object_all = NULL;
static GMutex *vips__object_all_lock = NULL;

static guint vips_object_signals[SIG_LAST] = { 0 };

int _vips__argument_id = 1;

/* Keep a cache of nickname -> GType lookups.
 */
static GHashTable *vips__object_nickname_table = NULL;

G_DEFINE_ABSTRACT_TYPE( VipsObject, vips_object, G_TYPE_OBJECT );

/* Don't call this directly, see vips_object_build().
 */
static int
vips_object_postbuild( VipsObject *object )
{
	int result;

#ifdef DEBUG
	printf( "vips_object_postbuild: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_signal_emit( object, vips_object_signals[SIG_POSTBUILD], 0, &result );

	return( result ); 
}

void
vips_object_preclose( VipsObject *object )
{
	if( !object->preclose ) {
		object->preclose = TRUE;

#ifdef DEBUG
		printf( "vips_object_preclose: " );
		vips_object_print_name( object );
		printf( "\n" );
#endif /*DEBUG*/

		g_signal_emit( object, vips_object_signals[SIG_PRECLOSE], 0 );
	}
}

static void
vips_object_close( VipsObject *object )
{
	if( !object->close ) {
		object->close = TRUE;

#ifdef DEBUG
		printf( "vips_object_close: " );
		vips_object_print_name( object );
		printf( "\n" );
#endif /*DEBUG*/

		g_signal_emit( object, vips_object_signals[SIG_CLOSE], 0 );
	}
}

static void
vips_object_postclose( VipsObject *object )
{
	if( !object->postclose ) {
		object->postclose = TRUE;

#ifdef DEBUG
		printf( "vips_object_postclose: " );
		vips_object_print_name( object );
		printf( "\n" );
#endif /*DEBUG*/

		g_signal_emit( object, vips_object_signals[SIG_POSTCLOSE], 0 );
	}
}

static void *
vips_object_check_required( VipsObject *object, GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	int *result = (int *) a;
	VipsArgumentFlags *iomask = (VipsArgumentFlags *) b;

	VIPS_DEBUG_MSG( "vips_object_check_required: %s\n", 
		g_param_spec_get_name( pspec ) );
	VIPS_DEBUG_MSG( "\trequired: %d\n", 
		argument_class->flags & VIPS_ARGUMENT_REQUIRED );
	VIPS_DEBUG_MSG( "\tconstruct: %d\n", 
		argument_class->flags & VIPS_ARGUMENT_CONSTRUCT ); 
	VIPS_DEBUG_MSG( "\tinput: %d\n", 
		argument_class->flags & VIPS_ARGUMENT_INPUT ); 
	VIPS_DEBUG_MSG( "\toutput: %d\n", 
		argument_class->flags & VIPS_ARGUMENT_OUTPUT ); 
	VIPS_DEBUG_MSG( "\tassigned: %d\n", 
		argument_instance->assigned );

	if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		!(argument_class->flags & VIPS_ARGUMENT_DEPRECATED) &&
		(argument_class->flags & *iomask) &&
		!argument_instance->assigned ) {
		vips_error( class->nickname, 
			_( "parameter %s not set" ),
			g_param_spec_get_name( pspec ) );
		*result = -1;
	}

	return( NULL );
}

int
vips_object_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );

	/* Input and output args must both be set.
	 */
	VipsArgumentFlags iomask = 
		VIPS_ARGUMENT_INPUT | VIPS_ARGUMENT_OUTPUT;

	int result;

#ifdef DEBUG
	printf( "vips_object_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( object_class->build( object ) )
		return( -1 );

	/* Check all required arguments have been supplied, don't stop on 1st
	 * error.
	 */
	result = 0;
	(void) vips_argument_map( object,
		vips_object_check_required, &result, &iomask );

	/* ... more checks go here.
	 */
	object->constructed = TRUE;

	/* Only postbuild on success.
	 */
	if( !result )
		result = vips_object_postbuild( object );

	return( result );
}

/**
 * vips_object_summary_class: (skip)
 * @klass: class to summarise
 * @buf: write summary here
 *
 * Generate a human-readable summary for a class. 
 */
void
vips_object_summary_class( VipsObjectClass *klass, VipsBuf *buf )
{
	klass->summary_class( klass, buf );
}

/**
 * vips_object_summary: (skip)
 * @object: object to summarise
 * @buf: write summary here
 *
 * Generate a human-readable summary for an object. 
 */
void
vips_object_summary( VipsObject *object, VipsBuf *buf )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	class->summary( object, buf );
}

/**
 * vips_object_dump: (skip)
 * @object: object to dump
 * @buf: write dump here
 *
 * Dump everything that vips knows about an object to a string.
 */
void
vips_object_dump( VipsObject *object, VipsBuf *buf )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	class->dump( object, buf );
}

void
vips_object_print_summary_class( VipsObjectClass *class )
{
	char str[2048];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	vips_object_summary_class( class, &buf );
	printf( "%s\n", vips_buf_all( &buf ) );
}

void
vips_object_print_summary( VipsObject *object )
{
	char str[2048];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	vips_object_summary( object, &buf );
	printf( "%s\n", vips_buf_all( &buf ) );
}

void
vips_object_print_dump( VipsObject *object )
{
	char str[32768];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	vips_object_dump( object, &buf );
	printf( "%s\n", vips_buf_all( &buf ) );
}

void
vips_object_print_name( VipsObject *object )
{
	printf( "%s (%p)", G_OBJECT_TYPE_NAME( object ), object );
}

gboolean
vips_object_sanity( VipsObject *object )
{
	VipsObjectClass *class;
	char str[1000];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	if( !object ) {
		printf( "vips_object_sanity: null object\n" );

		return( FALSE );
	}

	class = VIPS_OBJECT_GET_CLASS( object );
	class->sanity( object, &buf );
	if( !vips_buf_is_empty( &buf ) ) {
		printf( "sanity failure: " );
		vips_object_print_name( object );
		printf( " %s\n", vips_buf_all( &buf ) );

		return( FALSE );
	}

	return( TRUE );
}

/* On a rewind, we dispose the old contents of the object and
 * reconstruct. This is used in things like im_pincheck() where a "w"
 * image has to be rewound and become a "p" image.
 *
 * Override in subclasses if you want to preserve some fields, see image.c.
 */
void
vips_object_rewind( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	class->rewind( object );
}

/* Extra stuff we track for properties to do our argument handling.
 */

static void
vips_argument_instance_detach( VipsArgumentInstance *argument_instance )
{
	VipsObject *object = argument_instance->object;
	VipsArgumentClass *argument_class = argument_instance->argument_class;

	if( argument_instance->close_id ) {
		/* If close_id is set, the argument must be a gobject of some
		 * sort, so we can fetch it.
		 */
		GObject *member = G_STRUCT_MEMBER( GObject *, object,
			argument_class->offset );

		if( g_signal_handler_is_connected( member,
			argument_instance->close_id ) )
			g_signal_handler_disconnect( member,
				argument_instance->close_id );
		argument_instance->close_id = 0;
	}

	if( argument_instance->invalidate_id ) {
		GObject *member = G_STRUCT_MEMBER( GObject *, object,
			argument_class->offset );

		if( g_signal_handler_is_connected( member,
			argument_instance->invalidate_id ) )
			g_signal_handler_disconnect( member,
				argument_instance->invalidate_id );
		argument_instance->invalidate_id = 0;
	}
}

/* Free a VipsArgumentInstance ... VipsArgumentClass can just be g_free()d.
 */
static void
vips_argument_instance_free( VipsArgumentInstance *argument_instance )
{
	vips_argument_instance_detach( argument_instance );
	g_free( argument_instance );
}

VipsArgument *
vips__argument_table_lookup( VipsArgumentTable *table, GParamSpec *pspec )
{
	VipsArgument *argument;

	g_mutex_lock( vips__global_lock );
	argument = (VipsArgument *) g_hash_table_lookup( table, pspec );
	g_mutex_unlock( vips__global_lock );

	return( argument );
}

static void
vips_argument_table_replace( VipsArgumentTable *table, VipsArgument *argument )
{
	g_hash_table_replace( table, argument->pspec, argument );
}

static void
vips_argument_table_destroy( VipsArgumentTable *table )
{
	g_hash_table_destroy( table );
}

/**
 * vips_argument_map: (skip)
 * @object: object whose args should be enumerated
 * @fn: call this function for every argument
 * @a: client data
 * @b: client data
 *
 * Loop over the vips_arguments to an object. Stop when @fn returns non-%NULL
 * and return that value. 
 *
 * Returns: %NULL if @fn returns %NULL for all arguments, otherwise the first
 * non-%NULL value from @fn.
 */
void *
vips_argument_map( VipsObject *object,
	VipsArgumentMapFn fn, void *a, void *b )
{
	/* Make sure we can't go during the loop. This can happen if eg. we
	 * flush an arg that refs us.
	 */
	g_object_ref( object ); 

	VIPS_ARGUMENT_FOR_ALL( object, 
		pspec, argument_class, argument_instance ) { 
		void *result;

		/* argument_instance should not be NULL.
		 */
		g_assert( argument_instance );

		if( (result = fn( object, pspec,
			argument_class, argument_instance, a, b )) ) {
			g_object_unref( object ); 
			return( result );
		}
	} VIPS_ARGUMENT_FOR_ALL_END

	g_object_unref( object ); 

	return( NULL );
}

/**
 * vips_argument_class_map: (skip)
 *
 * And loop over a class. Same as ^^, but with no VipsArgumentInstance.
 */
void *
vips_argument_class_map( VipsObjectClass *object_class,
	VipsArgumentClassMapFn fn, void *a, void *b )
{
	GSList *p; 
 
	for( p = object_class->argument_table_traverse; p; p = p->next ) { 
		VipsArgumentClass *arg_class = 
			(VipsArgumentClass *) p->data; 
		VipsArgument *argument = (VipsArgument *) arg_class; 
		GParamSpec *pspec = argument->pspec; 

		void *result;

		if( (result = 
			fn( object_class, pspec, arg_class, a, b )) )
			return( result );
	}

	return( NULL );
}

/* Does an vipsargument need an argument to write to? For example, an image
 * output needs a filename, a double output just prints.
 */
gboolean
vips_argument_class_needsstring( VipsArgumentClass *argument_class )
{
	GParamSpec *pspec = ((VipsArgument *) argument_class)->pspec;

	GType otype;
	VipsObjectClass *oclass;

	if( G_IS_PARAM_SPEC_BOOLEAN( pspec ) ) 
		/* Bools, input or output, don't need args.
		 */
		return( FALSE );

	if( argument_class->flags & VIPS_ARGUMENT_INPUT ) 
		/* All other inputs need something.
		 */
		return( TRUE );

	/* Just output objects.
	 */

	if( (otype = G_PARAM_SPEC_VALUE_TYPE( pspec )) &&
		g_type_is_a( otype, VIPS_TYPE_OBJECT ) &&
		(oclass = g_type_class_ref( otype )) )
		/* For now, only vipsobject subclasses can ask for args.
		 */
		return( oclass->output_needs_arg );
	else
		return( FALSE );
}

/* Create a VipsArgumentInstance for each installed argument property. Ideally
 * we'd do this during _init() but g_object_class_find_property() does not seem
 * to work then :-( so we have to delay it until first access. See
 * vips__argument_get_instance().
 */
static void
vips_argument_init( VipsObject *object )
{
	if( !object->argument_table ) {
#ifdef DEBUG
		printf( "vips_argument_init: " );
		vips_object_print_name( object );
		printf( "\n" );
#endif /*DEBUG*/

		object->argument_table = g_hash_table_new_full( g_direct_hash,
			g_direct_equal, NULL,
			(GDestroyNotify) vips_argument_instance_free );

		/* Make a VipsArgumentInstance for each installed argument
		 * property. We can't use vips_argument_map() since that does
		 * some sanity checks that won't pass until all arg instance
		 * are built.
		 */
		VIPS_ARGUMENT_FOR_ALL( object, 
			pspec, argument_class, argument_instance ) {
#ifdef DEBUG
			printf( "vips_argument_init: "
				"adding instance argument for %s\n",
				g_param_spec_get_name( pspec ) );
#endif /*DEBUG*/

			/* argument_instance should be NULL since we've not 
			 * set it yet.
			 */
			g_assert( argument_instance == NULL );

			argument_instance = g_new( VipsArgumentInstance, 1 );

			((VipsArgument *) argument_instance)->pspec = pspec;
			argument_instance->argument_class = argument_class;
			argument_instance->object = object;
			/* SET_ALWAYS args default to assigned.
			 */
			argument_instance->assigned = 
				argument_class->flags & 
					VIPS_ARGUMENT_SET_ALWAYS;
			argument_instance->close_id = 0;
			argument_instance->invalidate_id = 0;

			vips_argument_table_replace( object->argument_table, 
				(VipsArgument *) argument_instance );
		} VIPS_ARGUMENT_FOR_ALL_END
	}
}

/**
 * vips__argument_get_instance: (skip)
 *
 * Convenience ... given the VipsArgumentClass, get the VipsArgumentInstance.
 */
VipsArgumentInstance *
vips__argument_get_instance( VipsArgumentClass *argument_class,
	VipsObject *object )
{
	/* Make sure the instance args are built.
	 */
	vips_argument_init( object );

	return( (VipsArgumentInstance *)
		vips__argument_table_lookup( object->argument_table,
			((VipsArgument *) argument_class)->pspec ) );
}

/**
 * vips_object_get_argument: (skip)
 * @object: the object to fetch the args from
 * @name: arg to fetch
 * @pspec: (transfer none): the pspec for this arg
 * @argument_class: (transfer none): the argument_class for this arg
 * @argument_instance: (transfer none): the argument_instance for this arg
 *
 * Look up the three things you need to work with a vips argument.
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_object_get_argument( VipsObject *object, const char *name,
	GParamSpec **pspec,
	VipsArgumentClass **argument_class,
	VipsArgumentInstance **argument_instance )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	if( !(*pspec = g_object_class_find_property( 
		G_OBJECT_CLASS( class ), name )) ) {
		vips_error( class->nickname, 
			_( "no property named `%s'" ), name );
		return( -1 );
	}

	if( !(*argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( class->argument_table, 
		*pspec )) ) {
		vips_error( class->nickname, 
			_( "no vips argument named `%s'" ), name );
		return( -1 );
	}
	if( !(*argument_instance = vips__argument_get_instance( 
		*argument_class, object )) ) {
		vips_error( class->nickname, 
			_( "argument `%s' has no instance" ), name );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_object_argument_isset:
 * @object: the object to fetch the args from
 * @name: arg to fetch
 *
 * Convenience: has an argument been assigned. Useful for bindings.
 *
 * Returns: %TRUE if the argument has been assigned.
 */
gboolean
vips_object_argument_isset( VipsObject *object, const char *name )
{
	GParamSpec *pspec;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;

	if( vips_object_get_argument( object, name,
		&pspec, &argument_class, &argument_instance ) )
		return( FALSE );

	return( argument_instance->assigned );
}

/**
 * vips_object_get_argument_flags:
 * @object: the object to fetch the args from
 * @name: arg to fetch
 *
 * Convenience: get the flags for an argument. Useful for bindings.
 *
 * Returns: The #VipsArgumentFlags for this argument.
 */
VipsArgumentFlags
vips_object_get_argument_flags( VipsObject *object, const char *name )
{
	GParamSpec *pspec;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;

	if( vips_object_get_argument( object, name,
		&pspec, &argument_class, &argument_instance ) )
		return( 0 );

	return( argument_class->flags );
}

/**
 * vips_object_get_argument_priority:
 * @object: the object to fetch the args from
 * @name: arg to fetch
 *
 * Convenience: get the priority for an argument. Useful for bindings.
 *
 * Returns: The priority of this argument.
 */
int
vips_object_get_argument_priority( VipsObject *object, const char *name )
{
	GParamSpec *pspec;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;

	if( vips_object_get_argument( object, name,
		&pspec, &argument_class, &argument_instance ) )
		return( 0 );

	return( argument_class->priority );
}

static void
vips_object_clear_member( VipsArgumentInstance *argument_instance )
{
	VipsObject *object = argument_instance->object;
	VipsArgumentClass *argument_class = argument_instance->argument_class;
	GObject **member = &G_STRUCT_MEMBER( GObject *, object,
		argument_class->offset );

	vips_argument_instance_detach( argument_instance );

	if( *member ) {
		if( argument_class->flags & VIPS_ARGUMENT_INPUT ) {
#ifdef DEBUG_REF
			printf( "vips_object_clear_member: vips object: " );
			vips_object_print_name( object );
			printf( "  no longer refers to gobject %s (%p)\n",
				G_OBJECT_TYPE_NAME( *member ), *member );
			printf( "  count down to %d\n",
				G_OBJECT( *member )->ref_count - 1 );
#endif /*DEBUG_REF*/

			/* We reffed the object.
			 */
			g_object_unref( *member );
		}
		else if( argument_class->flags & VIPS_ARGUMENT_OUTPUT ) {
#ifdef DEBUG_REF
			printf( "vips_object_clear_member: gobject %s (%p)\n",
				G_OBJECT_TYPE_NAME( *member ), *member );
			printf( "  no longer refers to vips object: " );
			vips_object_print_name( object );
			printf( "  count down to %d\n",
				G_OBJECT( object )->ref_count - 1 );
#endif /*DEBUG_REF*/

			g_object_unref( object );
		}

		*member = NULL;
	}
}

/* Free any args which are holding resources.
 */
static void *
vips_object_dispose_argument( VipsObject *object, GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	g_assert( ((VipsArgument *) argument_class)->pspec == pspec );
	g_assert( ((VipsArgument *) argument_instance)->pspec == pspec );

	if( G_IS_PARAM_SPEC_OBJECT( pspec ) ||
		G_IS_PARAM_SPEC_BOXED( pspec ) ) {
#ifdef DEBUG
		printf( "vips_object_dispose_argument: " );
		vips_object_print_name( object );
		printf( ".%s\n", g_param_spec_get_name( pspec ) ); 
#endif /*DEBUG*/

		g_object_set( object, 
			g_param_spec_get_name( pspec ), NULL, 
			NULL );
	}

	return( NULL );
}

/* Free all args on this object which may be holding resources.
 *
 * Note that this is not the same as vips_object_unref_outputs(). That 
 * looks for output objects which may have been created during _build() which
 * hold refs to this object and unrefs them. 
 *
 * This function looks for objects which this object holds refs to and which
 * may be holding sub-resources and zaps them.
 */
static void
vips_argument_dispose_all( VipsObject *object )
{
#ifdef DEBUG
	printf( "vips_argument_dispose_all: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	vips_argument_map( object, vips_object_dispose_argument, NULL, NULL );
}

/* Free any args which are holding memory.
 */
static void *
vips_object_free_argument( VipsObject *object, GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	g_assert( ((VipsArgument *) argument_class)->pspec == pspec );
	g_assert( ((VipsArgument *) argument_instance)->pspec == pspec );

	if( G_IS_PARAM_SPEC_STRING( pspec ) ) {
#ifdef DEBUG
		printf( "vips_object_free_argument: " );
		vips_object_print_name( object );
		printf( ".%s\n", g_param_spec_get_name( pspec ) ); 
#endif /*DEBUG*/

		g_object_set( object, 
			g_param_spec_get_name( pspec ), NULL, 
			NULL );
	}

	return( NULL );
}

/* Free args which hold memory. Things like strings need to be freed right at
 * the end in case anyone is still using them.
 */
static void
vips_argument_free_all( VipsObject *object )
{
#ifdef DEBUG
	printf( "vips_argument_free_all: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	vips_argument_map( object, vips_object_free_argument, NULL, NULL );
}

static void
vips_object_dispose( GObject *gobject )
{
	VipsObject *object = VIPS_OBJECT( gobject );

#ifdef DEBUG
	printf( "vips_object_dispose: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	/* Our subclasses should have already called this. Run it again, just
	 * in case.
	 */
#ifdef DEBUG
	if( !object->preclose ) 
		printf( "vips_object_dispose: pre-close missing!\n" );
#endif /*DEBUG*/
	vips_object_preclose( object );

	/* Clear all our arguments: they may be holding resources we should 
	 * drop.
	 */
	vips_argument_dispose_all( object );

	vips_object_close( object );

	vips_object_postclose( object );

	vips_argument_free_all( object );

	VIPS_FREEF( vips_argument_table_destroy, object->argument_table );

	G_OBJECT_CLASS( vips_object_parent_class )->dispose( gobject );
}

static void
vips_object_finalize( GObject *gobject )
{
	VipsObject *object = VIPS_OBJECT( gobject );

#ifdef DEBUG
	printf( "vips_object_finalize: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	/* I'd like to have post-close in here, but you can't emit signals
	 * from finalize, sadly.
	 */

	g_mutex_lock( vips__object_all_lock );
	g_hash_table_remove( vips__object_all, object );
	g_mutex_unlock( vips__object_all_lock );

	G_OBJECT_CLASS( vips_object_parent_class )->finalize( gobject );
}

static void
vips_object_arg_invalidate( GObject *argument,
	VipsArgumentInstance *argument_instance )
{
	/* Image @argument has signalled "invalidate" ... resignal on our
	 * operation.
	 */
	if( VIPS_IS_OPERATION( argument_instance->object ) )
		vips_operation_invalidate( 
			VIPS_OPERATION( argument_instance->object ) ); 
}

static void
vips_object_arg_close( GObject *argument,
	VipsArgumentInstance *argument_instance )
{
	VipsObject *object = argument_instance->object;
	GParamSpec *pspec = ((VipsArgument *) argument_instance)->pspec;

	/* Argument had reffed us ... now it's being closed, so we NULL out
	 * the pointer to unref.
	 */
	g_object_set( object, 
		g_param_spec_get_name( pspec ), NULL,
		NULL );
}

/* Set a member to an object. Handle the ref counts and signal
 * connect/disconnect.
 */
void
vips__object_set_member( VipsObject *object, GParamSpec *pspec,
	GObject **member, GObject *argument )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( class->argument_table, pspec );
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance( argument_class, object );
	GType otype = G_PARAM_SPEC_VALUE_TYPE( pspec );

	g_assert( argument_instance );

	vips_object_clear_member( argument_instance );

	g_assert( !*member );
	*member = argument;

	if( *member ) {
		if( argument_class->flags & VIPS_ARGUMENT_INPUT ) {
#ifdef DEBUG_REF
			printf( "vips__object_set_member: vips object: " );
			vips_object_print_name( object );
			printf( "  refers to gobject %s (%p)\n",
				G_OBJECT_TYPE_NAME( *member ), *member );
			printf( "  count up to %d\n",
				G_OBJECT( *member )->ref_count );
#endif /*DEBUG_REF*/

			/* Ref the argument.
			 */
			g_object_ref( *member );
		}
		else if( argument_class->flags & VIPS_ARGUMENT_OUTPUT ) {
#ifdef DEBUG_REF
			printf( "vips__object_set_member: gobject %s (%p)\n",
				G_OBJECT_TYPE_NAME( *member ), *member );
			printf( "  refers to vips object: " );
			vips_object_print_name( object );
			printf( "  count up to %d\n",
				G_OBJECT (object)->ref_count );
#endif /*DEBUG_REF*/

			/* The argument reffs us.
			 */
			g_object_ref( object );
		}
	}

	if( *member &&
		g_type_is_a( otype, VIPS_TYPE_IMAGE ) ) { 
		if( argument_class->flags & VIPS_ARGUMENT_INPUT ) {
			g_assert( !argument_instance->invalidate_id );

			argument_instance->invalidate_id =
				g_signal_connect( *member, "invalidate",
					G_CALLBACK( 
						vips_object_arg_invalidate ),
					argument_instance );
		}
		else if( argument_class->flags & VIPS_ARGUMENT_OUTPUT ) {
			g_assert( !argument_instance->close_id );

			argument_instance->close_id =
				g_signal_connect( *member, "close",
					G_CALLBACK( vips_object_arg_close ),
					argument_instance );
		}
	}
}

/* Is a value NULL? We allow multiple sets of NULL so props can be cleared.
 * The pspec gives the value type, for consistency with the way value types
 * are detected in set and get.
 */
gboolean
vips_value_is_null( GParamSpec *pspec, const GValue *value )
{
	if( G_IS_PARAM_SPEC_STRING( pspec ) && 
		!g_value_get_string( value ) )
		return( TRUE );
	if( G_IS_PARAM_SPEC_OBJECT( pspec ) &&
		!g_value_get_object( value ) )
		return( TRUE );
	if( G_IS_PARAM_SPEC_POINTER( pspec ) &&
		!g_value_get_pointer( value ) )
		return( TRUE );
	if( G_IS_PARAM_SPEC_BOXED( pspec ) &&
		!g_value_get_boxed( value ) )
		return( TRUE );

	return( FALSE );
}

/* Also used by subclasses, so not static.
 */
void
vips_object_set_property( GObject *gobject,
	guint property_id, const GValue *value, GParamSpec *pspec )
{
	VipsObject *object = VIPS_OBJECT( gobject );
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gobject );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( class->argument_table, pspec );
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance( argument_class, object );

	g_assert( argument_instance );

#ifdef DEBUG
	printf( "vips_object_set_property: " );
	vips_object_print_name( object );
	printf( ".%s\n", g_param_spec_get_name( pspec ) );

	/* This can crash horribly with some values, have it as a separate
	 * chunk so we can easily comment it out.
	 */
{
	char *str_value;

	str_value = g_strdup_value_contents( value );
	printf( "\t%s\n", str_value );
	g_free( str_value );
}
#endif /*DEBUG*/

	g_assert( ((VipsArgument *) argument_class)->pspec == pspec );
	g_assert( ((VipsArgument *) argument_instance)->pspec == pspec );

	/* If this is a construct-only argument, we can only set before we've
	 * built.
	 */
	if( argument_class->flags & VIPS_ARGUMENT_CONSTRUCT &&
		object->constructed &&
		!vips_value_is_null( pspec, value ) ) {
		g_warning( "%s: %s can't assign '%s' after construct",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_param_spec_get_name( pspec ) );
		return;
	}

	/* If this is a set-once argument, check we've not set it before.
	 */
	if( argument_class->flags & VIPS_ARGUMENT_SET_ONCE &&
		argument_instance->assigned &&
		!vips_value_is_null( pspec, value ) ) {
		g_warning( "%s: %s can only assign '%s' once",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_param_spec_get_name( pspec ) );
		return;
	}

	/* We can't use a switch since some param specs don't have fundamental
	 * types and are hence not compile-time constants, argh.
	 */
	if( G_IS_PARAM_SPEC_STRING( pspec ) ) {
		char **member = &G_STRUCT_MEMBER( char *, object,
			argument_class->offset );

		if( *member )
			g_free( *member );
		*member = g_value_dup_string( value );
	}
	else if( G_IS_PARAM_SPEC_OBJECT( pspec ) ) {
		GObject **member = &G_STRUCT_MEMBER( GObject *, object,
			argument_class->offset );

		vips__object_set_member( object, pspec, member,
			g_value_get_object( value ) );
	}
	else if( G_IS_PARAM_SPEC_INT( pspec ) ) {
		int *member = &G_STRUCT_MEMBER( int, object,
			argument_class->offset );

		*member = g_value_get_int( value );
	}
	else if( G_IS_PARAM_SPEC_UINT64( pspec ) ) {
		guint64 *member = &G_STRUCT_MEMBER( guint64, object,
			argument_class->offset );

		*member = g_value_get_uint64( value );
	}
	else if( G_IS_PARAM_SPEC_BOOLEAN( pspec ) ) {
		gboolean *member = &G_STRUCT_MEMBER( gboolean, object,
			argument_class->offset );

		*member = g_value_get_boolean( value );
	}
	else if( G_IS_PARAM_SPEC_ENUM( pspec ) ) {
		int *member = &G_STRUCT_MEMBER( int, object,
			argument_class->offset );

		*member = g_value_get_enum( value );
	}
	else if( G_IS_PARAM_SPEC_FLAGS( pspec ) ) {
		int *member = &G_STRUCT_MEMBER( int, object,
			argument_class->offset );

		*member = g_value_get_flags( value );
	}
	else if( G_IS_PARAM_SPEC_POINTER( pspec ) ) {
		gpointer *member = &G_STRUCT_MEMBER( gpointer, object,
			argument_class->offset );

		*member = g_value_get_pointer( value );
	}
	else if( G_IS_PARAM_SPEC_DOUBLE( pspec ) ) {
		double *member = &G_STRUCT_MEMBER( double, object,
			argument_class->offset );

		*member = g_value_get_double( value );
	}
	else if( G_IS_PARAM_SPEC_BOXED( pspec ) ) {
		gpointer *member = &G_STRUCT_MEMBER( gpointer, object,
			argument_class->offset );

		if( *member ) {
			g_boxed_free( G_PARAM_SPEC_VALUE_TYPE( pspec ),
				*member );
			*member = NULL;
		}

		/* Copy the boxed into our pointer (will use eg.
		 * vips__object_vector_dup()).
		 */
		*member = g_value_dup_boxed( value );
	}
	else {
		g_warning( "%s: %s.%s unimplemented property type %s",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_param_spec_get_name( pspec ),
			g_type_name( G_PARAM_SPEC_VALUE_TYPE( pspec ) ) );
	}

	/* Note that it's now been set.
	 */
	argument_instance->assigned = TRUE;
}

/* Also used by subclasses, so not static.
 */
void
vips_object_get_property( GObject *gobject,
	guint property_id, GValue *value, GParamSpec *pspec )
{
	VipsObject *object = VIPS_OBJECT( gobject );
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gobject );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( class->argument_table, pspec );
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance( argument_class, object );

	g_assert( ((VipsArgument *) argument_class)->pspec == pspec );

	if( !argument_instance->assigned ) {
		/* Set the value to the default. Things like Ruby
		 * gobject-introspection will walk objects during GC, and we
		 * can find ourselves fetching object values between init and
		 * build.
		 */
		g_param_value_set_default( pspec, value );
		return;
	}

	if( G_IS_PARAM_SPEC_STRING( pspec ) ) {
		char *member = G_STRUCT_MEMBER( char *, object,
			argument_class->offset );

		g_value_set_string( value, member );
	}
	else if( G_IS_PARAM_SPEC_OBJECT( pspec ) ) {
		GObject **member = &G_STRUCT_MEMBER( GObject *, object,
			argument_class->offset );

		g_value_set_object( value, *member );
	}
	else if( G_IS_PARAM_SPEC_INT( pspec ) ) {
		int *member = &G_STRUCT_MEMBER( int, object,
			argument_class->offset );

		g_value_set_int( value, *member );
	}
	else if( G_IS_PARAM_SPEC_UINT64( pspec ) ) {
		guint64 *member = &G_STRUCT_MEMBER( guint64, object,
			argument_class->offset );

		g_value_set_uint64( value, *member );
	}
	else if( G_IS_PARAM_SPEC_BOOLEAN( pspec ) ) {
		gboolean *member = &G_STRUCT_MEMBER( gboolean, object,
			argument_class->offset );

		g_value_set_boolean( value, *member );
	}
	else if( G_IS_PARAM_SPEC_ENUM( pspec ) ) {
		int *member = &G_STRUCT_MEMBER( int, object,
			argument_class->offset );

		g_value_set_enum( value, *member );
	}
	else if( G_IS_PARAM_SPEC_FLAGS( pspec ) ) {
		int *member = &G_STRUCT_MEMBER( int, object,
			argument_class->offset );

		g_value_set_flags( value, *member );
	}
	else if( G_IS_PARAM_SPEC_POINTER( pspec ) ) {
		gpointer *member = &G_STRUCT_MEMBER( gpointer, object,
			argument_class->offset );

		g_value_set_pointer( value, *member );
	}
	else if( G_IS_PARAM_SPEC_DOUBLE( pspec ) ) {
		double *member = &G_STRUCT_MEMBER( double, object,
			argument_class->offset );

		g_value_set_double( value, *member );
	}
	else if( G_IS_PARAM_SPEC_BOXED( pspec ) ) {
		gpointer *member = &G_STRUCT_MEMBER( gpointer, object,
			argument_class->offset );

		/* Copy the boxed into our pointer (will use eg.
		 * vips__object_vector_dup ()).
		 */
		g_value_set_boxed( value, *member );
	}
	else {
		g_warning( "%s: %s.%s unimplemented property type %s",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_param_spec_get_name( pspec ),
			g_type_name( G_PARAM_SPEC_VALUE_TYPE( pspec ) ) );
	}
}

static int
vips_object_real_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );

	/* Only test input args, output ones can be set by our subclasses as
	 * they build. See vips_object_build() above.
	 */
	VipsArgumentFlags iomask = VIPS_ARGUMENT_INPUT;

	int result;

#ifdef DEBUG
	printf( "vips_object_real_build: " ); 
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_assert( !object->constructed );

	/* It'd be nice if this just copied a pointer rather than did a
	 * strdup(). Set these here rather than in object_init, so that the
	 * class gets a chance to set them.
	 */
	g_object_set( object,
		"nickname", object_class->nickname,
		"description", object_class->description, NULL );

	/* Check all required input arguments have been supplied, don't stop 
	 * on 1st error.
	 */
	result = 0;
	(void) vips_argument_map( object,
		vips_object_check_required, &result, &iomask );

	return( result );
}

static int
vips_object_real_postbuild( VipsObject *object )
{
#ifdef DEBUG
	printf( "vips_object_real_postbuild: " ); 
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_assert( object->constructed ); 

	return( 0 ); 
}

static void
vips_object_real_summary_class( VipsObjectClass *class, VipsBuf *buf )
{
	vips_buf_appendf( buf, "%s", G_OBJECT_CLASS_NAME( class ) );
	if( class->nickname )
		vips_buf_appendf( buf, " (%s)", class->nickname );
	if( class->description )
		vips_buf_appendf( buf, ", %s", class->description );
}

static void
vips_object_real_summary( VipsObject *object, VipsBuf *buf )
{
}

static void
vips_object_real_dump( VipsObject *object, VipsBuf *buf )
{
	vips_buf_appendf( buf, " %s (%p) count=%d", 
		G_OBJECT_TYPE_NAME( object ), 
		object, 
		G_OBJECT( object )->ref_count );

	if( object->local_memory )
		vips_buf_appendf( buf, " %zd bytes", object->local_memory ); 
}

static void
vips_object_real_sanity( VipsObject *object, VipsBuf *buf )
{
}

static void
vips_object_real_rewind( VipsObject *object )
{
#ifdef DEBUG
	printf( "vips_object_real_rewind\n" );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_object_run_dispose( G_OBJECT( object ) );

	object->constructed = FALSE;
	object->preclose = FALSE;
	object->close = FALSE;
	object->postclose = FALSE;
}

static VipsObject *
vips_object_real_new_from_string( const char *string )
{
	GType type;

	vips_check_init();

	/* The main arg selects the subclass.
	 */
	if( !(type = vips_type_find( NULL, string )) ) {
		vips_error( "VipsObject", 
			_( "class \"%s\" not found" ), string );
		return( NULL );
	}

	return( VIPS_OBJECT( g_object_new( type, NULL ) ) );
}

static void 
vips_object_real_to_string( VipsObject *object, VipsBuf *buf )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	/* Just "bicubic" or whatever.
	 */
	vips_buf_appends( buf, class->nickname );
}

static void
transform_string_double( const GValue *src_value, GValue *dest_value )
{
	g_value_set_double( dest_value,
		g_ascii_strtod( g_value_get_string( src_value ), NULL ) );
}

static void
vips_object_class_init( VipsObjectClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );

	if( !vips__object_all ) {
		vips__object_all = g_hash_table_new( 
			g_direct_hash, g_direct_equal );
		vips__object_all_lock = vips_g_mutex_new();
	}

	gobject_class->dispose = vips_object_dispose;
	gobject_class->finalize = vips_object_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	class->build = vips_object_real_build;
	class->postbuild = vips_object_real_postbuild;
	class->summary_class = vips_object_real_summary_class;
	class->summary = vips_object_real_summary;
	class->dump = vips_object_real_dump;
	class->sanity = vips_object_real_sanity;
	class->rewind = vips_object_real_rewind;
	class->new_from_string = vips_object_real_new_from_string;
	class->to_string = vips_object_real_to_string;
	class->nickname = "object";
	class->description = _( "base class" );

	/* Table of VipsArgumentClass ... we can just g_free() them.
	 */
	class->argument_table = g_hash_table_new_full(
		g_direct_hash, g_direct_equal, NULL, (GDestroyNotify) g_free );
	class->argument_table_traverse = NULL;

	/* For setting double arguments from the command-line.
	 */
	g_value_register_transform_func( G_TYPE_STRING, G_TYPE_DOUBLE,
		transform_string_double );

	VIPS_ARG_STRING( class, "nickname", 1, 
		_( "Nickname" ),
		_( "Class nickname" ),
		VIPS_ARGUMENT_SET_ONCE,
		G_STRUCT_OFFSET( VipsObject, nickname ), 
		"" );

	VIPS_ARG_STRING( class, "description", 2, 
		_( "Description" ),
		_( "Class description" ),
		VIPS_ARGUMENT_SET_ONCE,
		G_STRUCT_OFFSET( VipsObject, description ), 
		"" );

	/**
	 * VipsObject::postbuild:
	 * @object: the object that has been built
	 *
	 * The ::postbuild signal is emitted once just after successful object
	 * construction. Return non-zero to cause object construction to fail. 
	 */
	vips_object_signals[SIG_POSTBUILD] = g_signal_new( "postbuild",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsObjectClass, postbuild ), 
		NULL, NULL,
		vips_INT__VOID,
		G_TYPE_INT, 0 );

	/**
	 * VipsObject::preclose:
	 * @object: the object that is to close
	 *
	 * The ::preclose signal is emitted once just before object close
	 * starts. The oject is still alive.
	 */
	vips_object_signals[SIG_PRECLOSE] = g_signal_new( "preclose",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsObjectClass, preclose ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );

	/**
	 * VipsObject::close:
	 * @object: the object that is closing
	 *
	 * The ::close signal is emitted once during object close. The object
	 * is dying and may not work. 
	 */
	vips_object_signals[SIG_CLOSE] = g_signal_new( "close",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsObjectClass, close ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );

	/**
	 * VipsObject::postclose:
	 * @object: the object that has closed
	 *
	 * The ::postclose signal is emitted once after object close. The 
	 * object pointer is still valid, but nothing else. 
	 */
	vips_object_signals[SIG_POSTCLOSE] = g_signal_new( "postclose",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsObjectClass, postclose ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );

}

static void
vips_object_init( VipsObject *object )
{
#ifdef DEBUG
	printf( "vips_object_init: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_mutex_lock( vips__object_all_lock );
	g_hash_table_insert( vips__object_all, object, object );
	g_mutex_unlock( vips__object_all_lock );
}

static gint
traverse_sort( gconstpointer a, gconstpointer b )
{
	VipsArgumentClass *class1 = (VipsArgumentClass *) a;
	VipsArgumentClass *class2 = (VipsArgumentClass *) b;

	return( class1->priority - class2->priority );
}

/* Add a vipsargument ... automate some stuff with this.
 */
void
vips_object_class_install_argument( VipsObjectClass *object_class,
	GParamSpec *pspec, VipsArgumentFlags flags, int priority, guint offset )
{
	VipsArgumentClass *argument_class = g_new( VipsArgumentClass, 1 );
	GSList *argument_table_traverse;

#ifdef DEBUG
	printf( "vips_object_class_install_argument: %p %s %s\n", 
		object_class,
		g_type_name( G_TYPE_FROM_CLASS( object_class ) ),
		g_param_spec_get_name( pspec ) );
#endif /*DEBUG*/

	/* object_class->argument* is shared, so we must lock.
	 */
	g_mutex_lock( vips__global_lock );

	/* Must be a new one.
	 */
	g_assert( !g_hash_table_lookup( object_class->argument_table, pspec ) );

	/* Mustn't have INPUT and OUTPUT both set.
	 */
	g_assert( !(
		(flags & VIPS_ARGUMENT_INPUT) &&
		(flags & VIPS_ARGUMENT_OUTPUT)) );

	((VipsArgument *) argument_class)->pspec = pspec;
	argument_class->object_class = object_class;
	argument_class->flags = flags;
	argument_class->priority = priority;
	argument_class->offset = offset;

	vips_argument_table_replace( object_class->argument_table,
		(VipsArgument *) argument_class );

	/* If this is the first argument for a new subclass, we need to clone
	 * the traverse list we inherit.
	 */
	if( object_class->argument_table_traverse_gtype != 
		G_TYPE_FROM_CLASS( object_class ) ) {
#ifdef DEBUG
		printf( "vips_object_class_install_argument: "
			"cloning traverse\n" ); 
#endif /*DEBUG*/

		object_class->argument_table_traverse = 
			g_slist_copy( object_class->argument_table_traverse );
		object_class->argument_table_traverse_gtype = 
			G_TYPE_FROM_CLASS( object_class );
	}

	/* We read argument_table_traverse without a lock (eg. see 
	 * vips_argument_map()), so we must be very careful updating it.
	 */
	argument_table_traverse = 
		g_slist_copy( object_class->argument_table_traverse );

	argument_table_traverse = g_slist_prepend(
		argument_table_traverse, argument_class );
	argument_table_traverse = g_slist_sort(
		argument_table_traverse, traverse_sort );
	VIPS_SWAP( GSList *, 
		argument_table_traverse, 
		object_class->argument_table_traverse ); 

	g_slist_free( argument_table_traverse );  

#ifdef DEBUG
{
	GSList *p;

	printf( "%d items on traverse %p\n", 
		g_slist_length( object_class->argument_table_traverse ),
		&object_class->argument_table_traverse );
	for( p = object_class->argument_table_traverse; p; p = p->next ) {
		VipsArgumentClass *argument_class = 
			(VipsArgumentClass *) p->data;

		printf( "\t%p %s\n", 
			argument_class, 
			g_param_spec_get_name( 
				((VipsArgument *) argument_class)->pspec ) );
	}
}
#endif /*DEBUG*/

	g_mutex_unlock( vips__global_lock );
}

static void
vips_object_no_value( VipsObject *object, const char *name )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	GParamSpec *pspec;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;

	if( vips_object_get_argument( object, name,
		&pspec, &argument_class, &argument_instance ) )
		g_assert_not_reached();

	if( strcmp( name, g_param_spec_get_name( pspec ) ) == 0 )
		vips_error( class->nickname,
			_( "no value supplied for argument '%s'" ), name );
	else
		vips_error( class->nickname,
			_( "no value supplied for argument '%s' ('%s')" ), 
			name,
			g_param_spec_get_name( pspec ) );
}

/* Set a named arg from a string.
 */
int
vips_object_set_argument_from_string( VipsObject *object, 
	const char *name, const char *value )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	GParamSpec *pspec;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;
	VipsObjectClass *oclass;
	GType otype;

	GValue gvalue = { 0 };

	VIPS_DEBUG_MSG( "vips_object_set_argument_from_string: %s = %s\n", 
		name, value );

	if( vips_object_get_argument( object, name,
		&pspec, &argument_class, &argument_instance ) )
		return( -1 );

	otype = G_PARAM_SPEC_VALUE_TYPE( pspec );

	g_assert( argument_class->flags & VIPS_ARGUMENT_INPUT );

	if( g_type_is_a( otype, VIPS_TYPE_IMAGE ) ) { 
		VipsImage *out;
		VipsOperationFlags flags;
		VipsAccess access;

		if( !value ) {
			vips_object_no_value( object, name );
			return( -1 );
		}

		flags = 0;
		if( VIPS_IS_OPERATION( object ) )
			flags = vips_operation_get_flags( 
				VIPS_OPERATION( object ) );

		/* Read the filename. 
		 */
		if( flags & VIPS_OPERATION_SEQUENTIAL_UNBUFFERED ) 
			access = VIPS_ACCESS_SEQUENTIAL_UNBUFFERED;
		else if( flags & VIPS_OPERATION_SEQUENTIAL ) 
			access = VIPS_ACCESS_SEQUENTIAL;
		else
			access = VIPS_ACCESS_RANDOM; 

		if( !(out = vips_image_new_from_file( value, 
			"access", access,
			NULL )) )
			return( -1 );

		g_value_init( &gvalue, VIPS_TYPE_IMAGE );
		g_value_set_object( &gvalue, out );

		/* Setting gvalue will have upped @out's count again,
		 * go back to 1 so that gvalue has the only ref.
		 */
		g_object_unref( out );
	}
	else if( g_type_is_a( otype, VIPS_TYPE_ARRAY_IMAGE ) ) { 
		/* We have to have a special case for this, we can't just rely
		 * on transform_g_string_array_image(), since we need to be
		 * able to set the access hint on the image.
		 */
		VipsArrayImage *array_image;
		VipsOperationFlags flags;
		VipsAccess access;

		if( !value ) {
			vips_object_no_value( object, name );
			return( -1 );
		}

		flags = 0;
		if( VIPS_IS_OPERATION( object ) )
			flags = vips_operation_get_flags( 
				VIPS_OPERATION( object ) );

		if( flags & VIPS_OPERATION_SEQUENTIAL_UNBUFFERED ) 
			access = VIPS_ACCESS_SEQUENTIAL_UNBUFFERED;
		else if( flags & VIPS_OPERATION_SEQUENTIAL ) 
			access = VIPS_ACCESS_SEQUENTIAL;
		else
			access = VIPS_ACCESS_RANDOM; 

		if( !(array_image = 
			vips_array_image_new_from_string( value, access )) )
			return( -1 ); 

		g_value_init( &gvalue, VIPS_TYPE_ARRAY_IMAGE );
		g_value_set_boxed( &gvalue, array_image );

		/* Setting gvalue will have upped @array_image's count again,
		 * go back to 1 so that gvalue has the only ref.
		 */
		vips_area_unref( (VipsArea *) array_image );
	}
	else if( g_type_is_a( otype, VIPS_TYPE_OBJECT ) &&
		(oclass = g_type_class_ref( otype )) ) { 
		VipsObject *new_object;

		if( !value ) {
			vips_object_no_value( object, name );
			return( -1 );
		}

		if( !(new_object = 
			vips_object_new_from_string( oclass, value )) )
			return( -1 );

		/* Not necessarily a VipsOperation subclass so we don't use
		 * the cache. We could have a separate case for this.
		 */
		if( vips_object_build( new_object ) ) {
			g_object_unref( new_object );
			return( -1 );
		}

		g_value_init( &gvalue, G_TYPE_OBJECT );
		g_value_set_object( &gvalue, new_object );

		/* The GValue now has a ref, we can drop ours.
		 */
		g_object_unref( new_object );
	}
	else if( G_IS_PARAM_SPEC_BOOLEAN( pspec ) ) {
		gboolean b;

		b = TRUE;
		if( value &&
			(strcasecmp( value, "false" ) == 0 ||
			strcasecmp( value, "no" ) == 0 ||
			strcmp( value, "0" ) == 0) )
			b = FALSE;

		g_value_init( &gvalue, G_TYPE_BOOLEAN );
		g_value_set_boolean( &gvalue, b );
	}
	else if( G_IS_PARAM_SPEC_INT( pspec ) ) {
		int i;

		if( !value ) {
			vips_object_no_value( object, name );
			return( -1 );
		}

		if( sscanf( value, "%d", &i ) != 1 ) {
			vips_error( class->nickname,
				_( "'%s' is not an integer" ), value );
			return( -1 );
		}

		g_value_init( &gvalue, G_TYPE_INT );
		g_value_set_int( &gvalue, i );
	}
	else if( G_IS_PARAM_SPEC_UINT64( pspec ) ) {
		/* Not allways the same as guint64 :-( argh.
		 */
		long long l;

		if( !value ) {
			vips_object_no_value( object, name );
			return( -1 );
		}

		if( sscanf( value, "%lld", &l ) != 1 ) {
			vips_error( class->nickname,
				_( "'%s' is not an integer" ), value );
			return( -1 );
		}

		g_value_init( &gvalue, G_TYPE_UINT64 );
		g_value_set_uint64( &gvalue, l );
	}
	else if( G_IS_PARAM_SPEC_DOUBLE( pspec ) ) {
		double d;

		if( !value ) {
			vips_object_no_value( object, name );
			return( -1 );
		}

		if( sscanf( value, "%lg", &d ) != 1 ) {
			vips_error( class->nickname,
				_( "'%s' is not a double" ), value );
			return( -1 );
		}

		g_value_init( &gvalue, G_TYPE_DOUBLE );
		g_value_set_double( &gvalue, d );
	}
	else if( G_IS_PARAM_SPEC_ENUM( pspec ) ) {
		int i;

		if( !value ) {
			vips_object_no_value( object, name );
			return( -1 );
		}

		if( (i = vips_enum_from_nick( class->nickname, 
			otype, value )) < 0 ) 
			return( -1 );

		g_value_init( &gvalue, otype );
		g_value_set_enum( &gvalue, i );
	}
	else if( G_IS_PARAM_SPEC_FLAGS( pspec ) ) {
		/* Allow a symbolic name, or an int. 
		 */
		int i;

		if( !value ) {
			vips_object_no_value( object, name );
			return( -1 );
		}

		if( sscanf( value, "%d", &i ) != 1 &&
			(i = vips_flags_from_nick( class->nickname, 
			otype, value )) < 0 ) {
			vips_error( class->nickname,
				_( "'%s' is not an integer" ), value );
			return( -1 );
		}

		g_value_init( &gvalue, otype );
		g_value_set_flags( &gvalue, i );
	}
	else {
		if( !value ) {
			vips_object_no_value( object, name );
			return( -1 );
		}

		g_value_init( &gvalue, G_TYPE_STRING );
		g_value_set_string( &gvalue, value );
	}

	g_object_set_property( G_OBJECT( object ), name, &gvalue );
	g_value_unset( &gvalue );

	return( 0 );
}

/* Does an vipsargument need an argument to write to? For example, an image
 * output needs a filename, a double output just prints.
 */
gboolean
vips_object_argument_needsstring( VipsObject *object, const char *name )
{
	GParamSpec *pspec;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;

#ifdef DEBUG
	printf( "vips_object_argument_needsstring: %s\n", name );
#endif /*DEBUG*/

	if( vips_object_get_argument( object, name,
		&pspec, &argument_class, &argument_instance ) )
		return( -1 );

	return( vips_argument_class_needsstring( argument_class ) ); 
}

static void
vips_object_print_arg( VipsObject *object, GParamSpec *pspec, VipsBuf *buf )
{
	GType type = G_PARAM_SPEC_VALUE_TYPE( pspec );
	const char *name = g_param_spec_get_name( pspec );
	GValue value = { 0, };
	char *str_value;

	g_value_init( &value, type );
	g_object_get_property( G_OBJECT( object ), name, &value );
	str_value = g_strdup_value_contents( &value );
	vips_buf_appends( buf, str_value );
	g_free( str_value );
	g_value_unset( &value );
}

/* Write a named arg to the string. If the arg does not need a string (see
 * above), arg will be NULL.
 */
int
vips_object_get_argument_to_string( VipsObject *object, 
	const char *name, const char *arg )
{
	GParamSpec *pspec;
	GType otype;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;
	VipsObjectClass *oclass;

#ifdef DEBUG
	printf( "vips_object_get_argument_to_string: %s -> %s\n", 
		name, arg );
#endif /*DEBUG*/

	if( vips_object_get_argument( object, name,
		&pspec, &argument_class, &argument_instance ) )
		return( -1 );

	otype = G_PARAM_SPEC_VALUE_TYPE( pspec );

	g_assert( argument_class->flags & VIPS_ARGUMENT_OUTPUT );

	if( g_type_is_a( otype, VIPS_TYPE_IMAGE ) ) { 
		VipsImage *in;
/* Pull out the image and write it.
		 */
		g_object_get( object, name, &in, NULL );
		if( vips_image_write_to_file( in, arg, NULL ) ) {
			g_object_unref( in );
			return( -1 );
		}
		g_object_unref( in );
	}
	else if( g_type_is_a( otype, VIPS_TYPE_OBJECT ) &&
		(oclass = g_type_class_ref( otype )) &&
		oclass->output_to_arg ) {
		VipsObject *value;

		g_object_get( object, name, &value, NULL );
		if( oclass->output_to_arg( value, arg ) ) {
			g_object_unref( value );
			return( -1 );
		}
		g_object_unref( value );
	}
	else {
		char str[1000];
		VipsBuf buf = VIPS_BUF_STATIC( str );

		vips_object_print_arg( object, pspec, &buf );
		printf( "%s\n", vips_buf_all( &buf ) );
	}

	return( 0 );
}

static void *
vips_argument_is_required( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		(argument_class->flags & VIPS_ARGUMENT_INPUT) &&
		!argument_instance->assigned )
		return( pspec );

	return( NULL );
}

/* Find the first unassigned required input arg.
 */
static GParamSpec *
vips_object_find_required( VipsObject *object )
{
	return( (GParamSpec *) vips_argument_map( object,
		vips_argument_is_required, NULL, NULL ) );
}

/**
 * vips_object_new: (skip)
 * @type: object to create
 * @set: set arguments with this
 * @a: client data
 * @b: client data
 *
 * g_object_new() the object, set any arguments with @set, call
 * vips_object_build() and return the complete object.
 *
 * Returns: the new object
 */
VipsObject *
vips_object_new( GType type, VipsObjectSetArguments set, void *a, void *b )
{
	VipsObject *object;

	vips_check_init();

	object = VIPS_OBJECT( g_object_new( type, NULL ) );

	if( set && set( object, a, b ) ) {
		g_object_unref( object );
		return( NULL );
	}

	if( vips_object_build( object ) ) {
		g_object_unref( object );
		return( NULL );
	}

	return( object );
}

/**
 * vips_object_set_valist:
 * @object: object to set arguments on
 * @ap: %NULL-terminated list of argument/value pairs
 *
 * See vips_object_set().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_object_set_valist( VipsObject *object, va_list ap )
{
	char *name;

	VIPS_DEBUG_MSG( "vips_object_set_valist:\n" );

	for( name = va_arg( ap, char * ); name; name = va_arg( ap, char * ) ) {
		GParamSpec *pspec;
		VipsArgumentClass *argument_class;
		VipsArgumentInstance *argument_instance;

		VIPS_DEBUG_MSG( "\tname = '%s' (%p)\n", name, name );

		if( vips_object_get_argument( VIPS_OBJECT( object ), name,
			&pspec, &argument_class, &argument_instance ) )
			return( -1 );

		VIPS_ARGUMENT_COLLECT_SET( pspec, argument_class, ap );

		g_object_set_property( G_OBJECT( object ), name, &value );

		VIPS_ARGUMENT_COLLECT_GET( pspec, argument_class, ap );

		VIPS_ARGUMENT_COLLECT_END
	}

	return( 0 );
}

/**
 * vips_object_set:
 * @object: object to set arguments on
 * @...: %NULL-terminated list of argument/value pairs
 *
 * Set a list of vips object arguments. For example:
 *
 * |[
 * vips_object_set (operation,
 *   "input", in,
 *   "output", &amp;out,
 *   NULL);
 * ]|
 *
 * Input arguments are given in-line, output arguments are given as pointers
 * to where the output value should be written.
 *
 * See also: vips_object_set_valist(), vips_object_set_from_string(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_object_set( VipsObject *object, ... )
{
	va_list ap;
	int result;

	va_start( ap, object );
	result = vips_object_set_valist( object, ap );
	va_end( ap );

	return( result );
}

/* Set object args from a string. @p should be the initial left bracket and
 * there should be no tokens after the matching right bracket. @p is modified. 
 */
static int
vips_object_set_args( VipsObject *object, const char *p )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	VipsToken token;
	char string[VIPS_PATH_MAX];
	char string2[VIPS_PATH_MAX];
	GParamSpec *pspec;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;

	if( !(p = vips__token_need( p, VIPS_TOKEN_LEFT, 
		string, VIPS_PATH_MAX )) )
		return( -1 );

	if( !(p = vips__token_segment( p, &token, string, VIPS_PATH_MAX )) )
		return( -1 );

	for(;;) {
		if( token == VIPS_TOKEN_RIGHT )
			break;
		if( token != VIPS_TOKEN_STRING ) {
			vips_error( class->nickname,
				_( "expected string or ), saw %s" ), 
				vips_enum_nick( VIPS_TYPE_TOKEN, token ) );
			return( -1 );
		}

		/* We have to look for a '=', ']' or a ',' to see if string is
		 * a param name or a value.
		 */
		if( !(p = vips__token_segment( p, &token, 
			string2, VIPS_PATH_MAX )) )
			return( -1 );
		if( token == VIPS_TOKEN_EQUALS ) {
			if( !(p = vips__token_segment_need( p, VIPS_TOKEN_STRING,
				string2, VIPS_PATH_MAX )) )
				return( -1 );
			if( vips_object_set_argument_from_string( object, 
				string, string2 ) )
				return( -1 );

			if( !(p = vips__token_must( p, &token,
				string2, VIPS_PATH_MAX )) )
				return( -1 );
		}
		else if( g_object_class_find_property( 
			G_OBJECT_GET_CLASS( object ), string ) &&
			!vips_object_get_argument( object, string, 
				&pspec, &argument_class, &argument_instance ) &&
			(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
			(argument_class->flags & VIPS_ARGUMENT_INPUT) &&
			G_IS_PARAM_SPEC_BOOLEAN( pspec ) ) {
			/* The string is the name of an optional
			 * input boolean ... set it!
			 */
			if( !argument_instance->assigned )
				g_object_set( object, string, TRUE, NULL );
		}
		else if( (pspec = vips_object_find_required( object )) ) {
			if( vips_object_set_argument_from_string( object, 
				g_param_spec_get_name( pspec ), string ) ) 
				return( -1 );
		}
		else {
			vips_error( class->nickname,
				_( "unable to set '%s'" ), string );
			return( -1 );
		}

		/* Now must be a , or a ). 
		 */
		if( token == VIPS_TOKEN_COMMA ) {
			if( !(p = vips__token_must( p, &token, 
				string, VIPS_PATH_MAX )) )
				return( -1 );
		}
		else if( token != VIPS_TOKEN_RIGHT ) {
			vips_error( class->nickname,
				"%s", _( "not , or ) after parameter" ) );
			return( -1 );
		}
	}

	if( (p = vips__token_get( p, &token, string, VIPS_PATH_MAX )) ) {
		vips_error( class->nickname,
			"%s", _( "extra tokens after ')'" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * vips_object_set_from_string:
 * @object: object to set arguments on
 * @string: arguments as a string
 *
 * Set object arguments from a string. The string can be something like
 * "a=12", or "a = 12, b = 13", or "fred". The string can optionally be
 * enclosed in brackets. 
 *
 * You'd typically use this between creating the object and building it. 
 *
 * See also: vips_object_set(), vips_object_build(),
 * vips_cache_operation_buildp(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_object_set_from_string( VipsObject *object, const char *string )
{
	const char *q;
	VipsToken token;
	char buffer[VIPS_PATH_MAX];
	char str[VIPS_PATH_MAX];

	vips_strncpy( buffer, string, VIPS_PATH_MAX );

	/* Does string start with a bracket? If it doesn't, enclose the whole
	 * thing in [].
	 */
	if( !(q = vips__token_get( buffer, &token, str, VIPS_PATH_MAX )) ||
		token != VIPS_TOKEN_LEFT )
		vips_snprintf( buffer, VIPS_PATH_MAX, "[%s]", string );
	else
		vips_strncpy( buffer, string, VIPS_PATH_MAX );

	return( vips_object_set_args( object, buffer ) ); 
}

VipsObject *
vips_object_new_from_string( VipsObjectClass *object_class, const char *p )
{
	const char *q;
	char str[VIPS_PATH_MAX];
	VipsObject *object;

	g_assert( object_class );
	g_assert( object_class->new_from_string );

	/* Find the start of the optional args on the end of the string, take
	 * everything before that as the principal arg for the constructor.
	 */
	if( (q = vips__find_rightmost_brackets( p )) )
		vips_strncpy( str, p, VIPS_MIN( VIPS_PATH_MAX, q - p + 1 ) );
	else
		vips_strncpy( str, p, VIPS_PATH_MAX );
	if( !(object = object_class->new_from_string( str )) )
		return( NULL );

	/* More tokens there? Set any other args.
	 */
	if( q && 
		vips_object_set_from_string( object, q ) ) {
		g_object_unref( object );
		return( NULL );
	}

	return( object ); 
}

static void *
vips_object_to_string_required( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsBuf *buf = (VipsBuf *) a;
	gboolean *first = (gboolean *) b;

	if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) ) {
		if( *first ) {
			vips_buf_appends( buf, "(" );
			*first = FALSE;
		}
		else {
			vips_buf_appends( buf, "," );
		}

		vips_object_print_arg( object, pspec, buf );
	}

	return( NULL );
}

static void *
vips_object_to_string_optional( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsBuf *buf = (VipsBuf *) a;
	gboolean *first = (gboolean *) b;

	if( !(argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		argument_instance->assigned ) {
		if( *first ) {
			vips_buf_appends( buf, "(" );
			*first = FALSE;
		}
		else {
			vips_buf_appends( buf, "," );
		}

		vips_buf_appends( buf, g_param_spec_get_name( pspec ) );
		vips_buf_appends( buf, "=" );
		vips_object_print_arg( object, pspec, buf );
	}

	return( NULL );
}

/**
 * vips_object_to_string: 
 * @object: object to stringify
 * @buf: write string here
 *
 * The inverse of vips_object_new_from_string(): turn @object into eg.
 * "VipsInterpolateSnohalo1(blur=.333333)".
 */
void
vips_object_to_string( VipsObject *object, VipsBuf *buf )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );

	gboolean first;

	g_assert( object_class->to_string );

	/* Nicknames are not guaranteed to be unique, so use the full type
	 * name.
	 */
	object_class->to_string( object, buf );
	first = TRUE;
	(void) vips_argument_map( object,
		vips_object_to_string_required, buf, &first );
	(void) vips_argument_map( object,
		vips_object_to_string_optional, buf, &first );
	if( !first )
		vips_buf_appends( buf, ")" );
}

typedef struct {
	VipsSListMap2Fn fn;
	void *a;
	void *b;
	void *result;
} VipsObjectMapArgs;

static void
vips_object_map_sub( VipsObject *key, VipsObject *value, 
	VipsObjectMapArgs *args )
{
	if( !args->result )
		args->result = args->fn( key, args->a, args->b );
}

/**
 * vips_object_map: (skip)
 * @fn: function to call for all objects
 * @a: client data
 * @b: client data
 *
 * Call a function for all alive objects.
 * Stop when @fn returns non-%NULL and return that value. 
 *
 * Returns: %NULL if @fn returns %NULL for all arguments, otherwise the first
 * non-%NULL value from @fn.
 */
void *
vips_object_map( VipsSListMap2Fn fn, void *a, void *b )
{
	VipsObjectMapArgs args;

	args.fn = fn;
	args.a = a;
	args.b = b;
	args.result = NULL;

	/* We must test vips__object_all before we lock because the lock is
	 * only created when the first object is created.
	 */
	if( vips__object_all ) {
		g_mutex_lock( vips__object_all_lock );
		g_hash_table_foreach( vips__object_all, 
			(GHFunc) vips_object_map_sub, &args );
		g_mutex_unlock( vips__object_all_lock );
	}

	return( args.result );
}

/**
 * vips_type_map: (skip)
 * @base: base type
 * @fn: call this function for every type
 * @a: client data
 * @b: client data
 *
 * Map over a type's children. Stop when @fn returns non-%NULL
 * and return that value. 
 *
 * Returns: %NULL if @fn returns %NULL for all arguments, otherwise the first
 * non-%NULL value from @fn.
 */
void *
vips_type_map( GType base, VipsTypeMap2Fn fn, void *a, void *b )
{
	GType *child;
	guint n_children;
	unsigned int i;
	void *result;

	child = g_type_children( base, &n_children );
	result = NULL;
	for( i = 0; i < n_children && !result; i++ )
		result = fn( child[i], a, b );
	g_free( child );

	return( result );
}

/**
 * vips_type_map_all: (skip)
 * @base: base type
 * @fn: call this function for every type
 * @a: client data
 *
 * Map over a type's children, direct and indirect. Stop when @fn returns 
 * non-%NULL and return that value. 
 *
 * Returns: %NULL if @fn returns %NULL for all arguments, otherwise the first
 * non-%NULL value from @fn.
 */
void *
vips_type_map_all( GType base, VipsTypeMapFn fn, void *a )
{
	void *result;

	if( !(result = fn( base, a )) )
		result = vips_type_map( base, 
			(VipsTypeMap2Fn) vips_type_map_all, fn, a );

	return( result );
}

/**
 * vips_class_map_all: (skip) 
 * @type: base type
 * @fn: call this function for every type
 * @a: client data
 *
 * Loop over all the subclasses of @type. Non-abstract classes only.
 * Stop when @fn returns 
 * non-%NULL and return that value. 
 *
 * Returns: %NULL if @fn returns %NULL for all arguments, otherwise the first
 * non-%NULL value from @fn.
 */
void *
vips_class_map_all( GType type, VipsClassMapFn fn, void *a )
{
	void *result;

	/* Avoid abstract classes. Use type_map_all for them.
	 */
	if( !G_TYPE_IS_ABSTRACT( type ) ) {
		/* We never unref this ref, but we never unload classes
		 * anyway, so so what.
		 */
		if( (result = fn( 
			VIPS_OBJECT_CLASS( g_type_class_ref( type ) ), a )) )
			return( result );
	}

	if( (result = vips_type_map( type, 
		(VipsTypeMap2Fn) vips_class_map_all, fn, a )) )
		return( result );

	return( NULL );
}

/* How deeply nested is a class ... used to indent class lists.
 */
int
vips_type_depth( GType type )
{
	int depth;

	depth = 0;
	while( type != VIPS_TYPE_OBJECT && 
		(type = g_type_parent( type )) )
		depth += 1;

	return( depth );
}

static void *
test_name( VipsObjectClass *class, const char *nickname )
{
	if( strcasecmp( class->nickname, nickname ) == 0 )
		return( class );

	/* Check the class name too, why not.
	 */
	if( strcasecmp( G_OBJECT_CLASS_NAME( class ), nickname ) == 0 )
		return( class );

	return( NULL );
}

/**
 * vips_class_find: 
 * @basename: name of base class
 * @nickname: search for a class with this nickname
 *
 * Search below @basename, return the first class whose name or @nickname
 * matches.
 *
 * See also: vips_type_find()
 *
 * Returns: (transfer none): the found class.
 */
const VipsObjectClass *
vips_class_find( const char *basename, const char *nickname )
{
	const char *classname = basename ? basename : "VipsObject";

	VipsObjectClass *class;
	GType base;

	if( !(base = g_type_from_name( classname )) )
		return( NULL );
	class = vips_class_map_all( base, 
		(VipsClassMapFn) test_name, (void *) nickname );

	return( class );
}

/* What we store for each nickname. We can't just store the type with
 * GINT_TO_POINTER() since GType is 64 bits on some platforms.
 */
typedef struct _NicknameGType {
	const char *nickname;
	GType type;
	gboolean duplicate;
} NicknameGType;

static void *
vips_class_add_hash( VipsObjectClass *class, GHashTable *table )
{
	GType type = G_OBJECT_CLASS_TYPE( class );
	NicknameGType *hit;

	hit = (NicknameGType *) 
		g_hash_table_lookup( table, (void *) class->nickname );

	/* If this is not a unique name, mark as a duplicate. In this case
	 * we'll need to fall back to a search.
	 */
	if( hit ) 
		hit->duplicate = TRUE;
	else {
		hit = g_new( NicknameGType, 1 );
		hit->nickname = class->nickname;
		hit->type = type;
		hit->duplicate = FALSE;
		g_hash_table_insert( table, (void *) hit->nickname, hit );
	}

	return( NULL ); 
}

static void *
vips_class_build_hash( void )
{
	GHashTable *table;
	GType base;

	table = g_hash_table_new( g_str_hash, g_str_equal );

	if( !(base = g_type_from_name( "VipsObject" )) )
		return( NULL );
	vips_class_map_all( base, 
		(VipsClassMapFn) vips_class_add_hash, (void *) table );

	return( table ); 
}

/**
 * vips_type_find:
 * @basename: name of base class
 * @nickname: search for a class with this nickname
 *
 * Search below @basename, return the %GType of the class whose name or 
 * @nickname matches, or 0 for not found. 
 * If @basename is NULL, the whole of #VipsObject is searched.
 *
 * This function uses a cache, so it should be quick. 
 *
 * See also: vips_class_find()
 *
 * Returns: the %GType of the class, or 0 if the class is not found.
 */
GType
vips_type_find( const char *basename, const char *nickname )
{
	static GOnce once = G_ONCE_INIT;

	const char *classname = basename ? basename : "VipsObject";

	NicknameGType *hit;
	GType base;
	GType type;

	vips__object_nickname_table = (GHashTable *) g_once( &once, 
		(GThreadFunc) vips_class_build_hash, NULL ); 

	hit = (NicknameGType *) 
		g_hash_table_lookup( vips__object_nickname_table, 
			(void *) nickname );

	/* We must only search below basename ... check that the cache hit is
	 * in the right part of the tree.
	 */
	if( !(base = g_type_from_name( classname )) )
		return( 0 );
	if( hit &&
		!hit->duplicate &&
		g_type_is_a( hit->type, base ) ) 
		type = hit->type;
	else {
		const VipsObjectClass *class;

		if( !(class = vips_class_find( basename, nickname )) )
			return( 0 );

		type = G_OBJECT_CLASS_TYPE( class );
	}

	return( type );
}

/**
 * vips_nickname_find:
 * @type: #GType to search for
 *
 * Return the VIPS nickname for a %GType. Handy for language bindings. 
 *
 * Returns: (transfer none): the class nickname. 
 */
const char *
vips_nickname_find( GType type )
{
	gpointer p;
	VipsObjectClass *class;

	if( type &&
		(p = g_type_class_ref( type )) &&
		VIPS_IS_OBJECT_CLASS( p ) &&
		(class = VIPS_OBJECT_CLASS( p )) )
		return( class->nickname );

	return( NULL );
}

/* The vips_object_local() macro uses this as its callback.
 */
void
vips_object_local_cb( VipsObject *vobject, GObject *gobject )
{
	VIPS_FREEF( g_object_unref, gobject );
}

typedef struct {
	VipsObject **array;
	int n;
} VipsObjectLocal;

static void
vips_object_local_array_cb( GObject *parent, VipsObjectLocal *local )
{
	int i;

	for( i = 0; i < local->n; i++ )
		VIPS_FREEF( g_object_unref, local->array[i] );

	VIPS_FREEF( g_free, local->array );
	VIPS_FREEF( g_free, local );
}

/** 
 * vips_object_local_array: (skip)
 * @parent: objects unref when this object unrefs
 * @n: array size
 *
 * Make an array of NULL VipsObject pointers. When @parent closes, every
 * non-NULL pointer in the array will be unreffed and the array will be
 * freed. Handy for creating a set of temporary images for a function.
 *
 * The array is NULL-terminated, ie. contains an extra NULL element at the
 * end. 
 *
 * Example:
 *
 * |[
 * VipsObject **t;
 *
 * t = vips_object_local_array( a, 5 );
 * if( 
 *   vips_add( a, b, &amp;t[0], NULL ) ||
 *   vips_invert( t[0], &amp;t[1], NULL ) ||
 *   vips_add( t[1], t[0], &amp;t[2], NULL ) ||
 *   vips_costra( t[2], out, NULL ) )
 *   return( -1 );
 * ]|
 *
 * See also: vips_object_local().
 *
 * Returns: an array of NULL pointers of length @n
 */
VipsObject **
vips_object_local_array( VipsObject *parent, int n )
{
	VipsObjectLocal *local;

	local = g_new( VipsObjectLocal, 1 );
	local->n = n;
	/* Make the array 1 too long so we can be sure there's a NULL 
	 * terminator.
	 */
	local->array = g_new0( VipsObject *, n + 1 );

	g_signal_connect( parent, "close", 
		G_CALLBACK( vips_object_local_array_cb ), local );

	return( local->array );
}

void 
vips_object_set_static( VipsObject *object, gboolean static_object )
{
	object->static_object = static_object;
}

static void *
vips_object_n_static_cb( VipsObject *object, int *n )
{
	if( object->static_object )
		*n += 1;

	return( NULL );
}

static int
vips_object_n_static( void )
{
	int n;

	n = 0;
	vips_object_map( 
		(VipsSListMap2Fn) vips_object_n_static_cb, &n, NULL );

	return( n );
}

static void *
vips_object_print_all_cb( VipsObject *object, int *n )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	char str[32768];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	fprintf( stderr, "%d) %s (%p)", 
		*n, G_OBJECT_TYPE_NAME( object ), object );
	if( object->local_memory )
		fprintf( stderr, " %zd bytes", object->local_memory ); 
	fprintf( stderr, ", count=%d", G_OBJECT( object )->ref_count ); 
	fprintf( stderr, "\n" ); 

	vips_object_summary_class( class, &buf );
	vips_buf_appends( &buf, ", " );
	vips_object_summary( object, &buf ); 
	fprintf( stderr, "%s\n", vips_buf_all( &buf ) );

	*n += 1;

	return( NULL );
}

void
vips_object_print_all( void )
{
	if( vips__object_all &&
		g_hash_table_size( vips__object_all ) > 
			vips_object_n_static() ) {
		int n;

		fprintf( stderr, "%d objects alive:\n", 
			g_hash_table_size( vips__object_all ) ); 

		n = 0;
		vips_object_map( 
			(VipsSListMap2Fn) vips_object_print_all_cb, &n, NULL );
	}

	vips__type_leak();
}

static void *
vips_object_sanity_all_cb( VipsObject *object )
{
	(void) vips_object_sanity( object );

	return( NULL );
}

void
vips_object_sanity_all( void )
{
	vips_object_map( 
		(VipsSListMap2Fn) vips_object_sanity_all_cb, NULL, NULL );
}

static void *
vips_object_unref_outputs_sub( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	if( (argument_class->flags & VIPS_ARGUMENT_OUTPUT) &&
		G_IS_PARAM_SPEC_OBJECT( pspec ) &&
		argument_instance->assigned ) {
		GObject *value;

		g_object_get( object, 
			g_param_spec_get_name( pspec ), &value, NULL );

		/* Doing the get refs the object, so unref the get, then unref
		 * again since this an an output object of the operation.
		 */
		g_object_unref( value );
		g_object_unref( value );
	}

	return( NULL );
}

/**
 * vips_object_unref_outputs:
 * @object: object to drop output refs from
 *
 * Unref all assigned output objects. Useful for language bindings. 
 *
 * After an object is built, all output args are owned by the caller. If
 * something goes wrong before then, we have to unref the outputs that have
 * been made so far. This function can also be useful for callers when
 * they've finished processing outputs themselves.
 *
 * See also: vips_cache_operation_build().
 */
void
vips_object_unref_outputs( VipsObject *object )
{
	(void) vips_argument_map( object,
		vips_object_unref_outputs_sub, NULL, NULL );
}

/**
 * vips_object_get_description:
 * @object: object to fetch description from
 *
 * Fetch the object description. Useful for language bindings. 
 *
 * @object.description is only avaliable after _build(), which can be too
 * late. This function fetches from the instance, if possible, but falls back
 * to the class description if we are too early. 
 * 
 * Returns: the object description
 */
const char *
vips_object_get_description( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	if( object->description ) 
		return( object->description ) ;
	else
		return( class->description ) ;
}
