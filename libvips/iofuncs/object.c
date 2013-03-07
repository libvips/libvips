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

/* Our signals. 
 */
enum {
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

G_DEFINE_ABSTRACT_TYPE( VipsObject, vips_object, G_TYPE_OBJECT );

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

	return( result );
}

/**
 * vips_object_summary_class: (skip)
 *
 */
void
vips_object_summary_class( VipsObjectClass *class, VipsBuf *buf )
{
	class->summary_class( class, buf );
}

/**
 * vips_object_summary: (skip)
 *
 */
void
vips_object_summary( VipsObject *object, VipsBuf *buf )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	class->summary( object, buf );
}

/**
 * vips_object_dump: (skip)
 *
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

/* Free a VipsArgumentInstance ... VipsArgumentClass can just be g_free()d.
 */
static void
vips_argument_instance_free( VipsArgumentInstance *argument_instance )
{
	if( argument_instance->close_id ) {
		g_signal_handler_disconnect( argument_instance->object,
			argument_instance->close_id );
		argument_instance->close_id = 0;
	}
	g_free( argument_instance );
}

VipsArgument *
vips__argument_table_lookup( VipsArgumentTable *table, GParamSpec *pspec )
{
	return( g_hash_table_lookup( table, pspec ) );
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
	if( argument_class &&
		!(*argument_instance = vips__argument_get_instance( 
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
 * Returns: The #VipsArgmentFlags for this argument.
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
vips_object_clear_member( VipsObject *object, GParamSpec *pspec, 
	GObject **member )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( class->argument_table, pspec );
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance( argument_class, object );

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

			/* The object reffed us. Stop listening link to the
			 * object's "close" signal. We can come here from
			 * object being closed, in which case the handler
			 * will already have been disconnected for us.
			 */
			if( g_signal_handler_is_connected( object,
				argument_instance->close_id ) )
				g_signal_handler_disconnect( object,
					argument_instance->close_id );
			argument_instance->close_id = 0;

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

	g_assert( argument_instance );

	vips_object_clear_member( object, pspec, member );

	g_assert( !*member );
	*member = argument;

	if( *member ) {
		if( argument_class->flags & VIPS_ARGUMENT_INPUT ) {
#ifdef DEBUG_REF
			printf( "vips_object_set_member: vips object: " );
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
			printf( "vips_object_set_member: gobject %s (%p)\n",
				G_OBJECT_TYPE_NAME( *member ), *member );
			printf( "  refers to vips object: " );
			vips_object_print_name( object );
			printf( "  count up to %d\n",
				G_OBJECT (object)->ref_count );
#endif /*DEBUG_REF*/

			/* The argument reffs us.
			 */
			g_object_ref( object );

			/* FIXME ... could use a NULLing weakref
			 */
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

	if( !argument_class ) {
		G_OBJECT_WARN_INVALID_PROPERTY_ID( gobject,
			property_id, pspec );
		return;
	}

#ifdef DEBUG
	printf( "vips_object_set_property: " );
	vips_object_print_name( object );
	printf( ".%s\n", g_param_spec_get_name( pspec ) );

	/* This can crash horribly with some values, have it as a separate
	 * chunk so we can easily commenmt it out.
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

	if( !argument_class ) {
		G_OBJECT_WARN_INVALID_PROPERTY_ID( gobject,
			property_id, pspec );
		return;
	}

	g_assert( ((VipsArgument *) argument_class)->pspec == pspec );

	if( !argument_instance->assigned ) {
		g_warning( "%s: %s.%s attempt to read unset %s property",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_param_spec_get_name( pspec ),
			g_type_name( G_PARAM_SPEC_VALUE_TYPE( pspec ) ) );
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
	vips_buf_appendf( buf, " %s (%p)", 
		G_OBJECT_TYPE_NAME( object ), object );
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

	vips_object_signals[SIG_PRECLOSE] = g_signal_new( "preclose",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsObjectClass, preclose ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
	vips_object_signals[SIG_CLOSE] = g_signal_new( "close",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_RUN_LAST,
		G_STRUCT_OFFSET( VipsObjectClass, close ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
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

#ifdef DEBUG
	printf( "vips_object_class_install_argument: %p %s %s\n", 
		object_class,
		g_type_name( G_TYPE_FROM_CLASS( object_class ) ),
		g_param_spec_get_name( pspec ) );
#endif /*DEBUG*/

	/* Must be a new one.
	 */
	g_assert( !vips__argument_table_lookup( object_class->argument_table,
		pspec ) );

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

	object_class->argument_table_traverse = g_slist_prepend(
		object_class->argument_table_traverse, argument_class );
	object_class->argument_table_traverse = g_slist_sort(
		object_class->argument_table_traverse, traverse_sort );

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
}

/* Make a bad-enum error. A common and fiddly case.
 */
static void
vips_enum_error( VipsObjectClass *class, GType otype, const char *value )
{
	GEnumClass *genum = G_ENUM_CLASS( g_type_class_ref( otype ) );
	int i;
	char str[1000];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	/* -1 since we always have a "last" member.
	 */
	for( i = 0; i < genum->n_values - 1; i++ ) {
		if( i > 0 )
			vips_buf_appends( &buf, ", " );
		vips_buf_appends( &buf, genum->values[i].value_nick );
	}

	vips_error( class->nickname, _( "enum '%s' has no member '%s', " 
		"should be one of: %s" ),
		g_type_name( otype ), value, vips_buf_all( &buf ) );
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

		flags = 0;
		if( VIPS_IS_OPERATION( object ) )
			flags = vips_operation_get_flags( 
				VIPS_OPERATION( object ) );

		/* Read the filename. vips_foreign_load_options()
		 * handles embedded options.
		 */
		if( flags & VIPS_OPERATION_SEQUENTIAL ) {
			if( vips_foreign_load_options( value, &out, 
				"sequential", TRUE,
				NULL ) )
				return( -1 );
		}
		else {
			if( vips_foreign_load_options( value, &out, 
				NULL ) )
				return( -1 );
		}

		g_value_init( &gvalue, VIPS_TYPE_IMAGE );
		g_value_set_object( &gvalue, out );

		/* Setting gvalue will have upped @out's count again,
		 * go back to 1 so that gvalue has the only ref.
		 */
		g_object_unref( out );
	}
	else if( g_type_is_a( otype, VIPS_TYPE_OBJECT ) &&
		(oclass = g_type_class_ref( otype )) ) { 
		VipsObject *new_object;

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

		if( sscanf( value, "%Ld", &l ) != 1 ) {
			vips_error( class->nickname,
				_( "'%s' is not an integer" ), value );
			return( -1 );
		}

		g_value_init( &gvalue, G_TYPE_UINT64 );
		g_value_set_uint64( &gvalue, l );
	}
	else if( G_IS_PARAM_SPEC_DOUBLE( pspec ) ) {
		double d;

		if( sscanf( value, "%lg", &d ) != 1 ) {
			vips_error( class->nickname,
				_( "'%s' is not a double" ), value );
			return( -1 );
		}

		g_value_init( &gvalue, G_TYPE_DOUBLE );
		g_value_set_double( &gvalue, d );
	}
	else if( G_IS_PARAM_SPEC_ENUM( pspec ) ) {
		GEnumValue *enum_value;

		if( !(enum_value = g_enum_get_value_by_name( 
			g_type_class_ref( otype ), value )) ) {
			if( !(enum_value = g_enum_get_value_by_nick( 
				g_type_class_ref( otype ), value )) ) {
				vips_enum_error( class, otype, value ); 
				return( -1 );
			}
		}

		g_value_init( &gvalue, otype );
		g_value_set_enum( &gvalue, enum_value->value );
	}
	else if( G_IS_PARAM_SPEC_FLAGS( pspec ) ) {
		/* Hard to set from a symbolic name. Just take an int.
		 */
		int i;

		if( sscanf( value, "%d", &i ) != 1 ) {
			vips_error( class->nickname,
				_( "'%s' is not an integer" ), value );
			return( -1 );
		}

		g_value_init( &gvalue, otype );
		g_value_set_flags( &gvalue, i );
	}
	else {
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
	GType otype;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;
	VipsObjectClass *oclass;

#ifdef DEBUG
	printf( "vips_object_argument_needsstring: %s\n", name );
#endif /*DEBUG*/

	if( vips_object_get_argument( object, name,
		&pspec, &argument_class, &argument_instance ) )
		return( -1 );

	if( G_IS_PARAM_SPEC_BOOLEAN( pspec ) ) 
		/* Bools, input or output, don't need args.
		 */
		return( FALSE );
	else if( argument_class->flags & VIPS_ARGUMENT_INPUT ) 
		/* All other inputs need something.
		 */
		return( TRUE );
	if( (otype = G_PARAM_SPEC_VALUE_TYPE( pspec )) &&
		g_type_is_a( otype, VIPS_TYPE_OBJECT ) &&
		(oclass = g_type_class_ref( otype )) )
		/* For now, only vipsobject subclasses can ask for args.
		 */
		return( oclass->output_needs_arg );
	else
		return( FALSE );
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
		 * vips_foreign_save_options() handles embedded options.
		 */
		g_object_get( object, name, &in, NULL );
		if( vips_foreign_save_options( in, arg, NULL ) ) {
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

	name = va_arg( ap, char * );

	while( name ) {
		GParamSpec *pspec;
		VipsArgumentClass *argument_class;
		VipsArgumentInstance *argument_instance;

		VIPS_DEBUG_MSG( "\tname = '%s' (%p)\n", name, name );

		if( vips_object_get_argument( VIPS_OBJECT( object ), name,
			&pspec, &argument_class, &argument_instance ) )
			return( -1 );

		VIPS_ARGUMENT_COLLECT_SET( pspec, argument_class, ap );

		g_object_set_property( G_OBJECT( object ), 
			name, &value );

		VIPS_ARGUMENT_COLLECT_GET( pspec, argument_class, ap );

		VIPS_ARGUMENT_COLLECT_END

		name = va_arg( ap, char * );
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
 *   "output", &out,
 *   NULL);
 * ]|
 *
 * Input arguments are given in-line, output arguments are given as pointers
 * to where the output value should be written.
 *
 * See also: vips_object_set_valist().
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
 * there should be no tokens after the matching right bracket.
 */
static int
vips_object_set_args( VipsObject *object, const char *p )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	VipsToken token;
	char string[PATH_MAX];
	char string2[PATH_MAX];
	GParamSpec *pspec;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;

	if( !(p = vips__token_need( p, VIPS_TOKEN_LEFT, string, PATH_MAX )) )
		return( -1 );

	do {
		if( !(p = vips__token_need( p, VIPS_TOKEN_STRING,
			string, PATH_MAX )) )
			return( -1 );

		/* We have to look for a '=', ')' or a ',' to see if string is
		 * a param name or a value.
		 */
		if( !(p = vips__token_must( p, &token, string2, PATH_MAX )) )
			return( -1 );
		if( token == VIPS_TOKEN_EQUALS ) {
			if( !(p = vips__token_need( p, VIPS_TOKEN_STRING,
				string2, PATH_MAX )) )
				return( -1 );
			if( vips_object_set_argument_from_string( object, 
				string, string2 ) )
				return( -1 );
			if( !(p = vips__token_must( p, &token,
				string2, PATH_MAX )) )
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
		if( token != VIPS_TOKEN_RIGHT && token != VIPS_TOKEN_COMMA ) {
			vips_error( class->nickname,
				"%s", _( "not , or ) after parameter" ) );
			return( -1 );
		}
	} while( token != VIPS_TOKEN_RIGHT );

	if( (p = vips__token_get( p, &token, string, PATH_MAX )) ) {
		vips_error( class->nickname,
			"%s", _( "extra tokens after ')'" ) );
		return( -1 );
	}

	return( 0 );
}

VipsObject *
vips_object_new_from_string( VipsObjectClass *object_class, const char *p )
{
	const char *q;
	char str[PATH_MAX];
	VipsObject *object;

	g_assert( object_class );
	g_assert( object_class->new_from_string );

	/* Find the start of the optional args on the end of the string, take
	 * everything before that as the principal arg for the constructor.
	 */
	if( (q = vips__find_rightmost_brackets( p )) )
		vips_strncpy( str, p, VIPS_MIN( PATH_MAX, q - p + 1 ) );
	else
		vips_strncpy( str, p, PATH_MAX );
	if( !(object = object_class->new_from_string( str )) )
		return( NULL );

	/* More tokens there? Set any other args.
	 */
	if( q && 
		vips_object_set_args( object, q ) ) {
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
 * vips_object_to_string: (skip)
 * @object: object to stringify
 * @buf: write string here
 *
 * The inverse of vips_object_new_from_string(): turn an object into eg.
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
 *
 * Loop over all the subclasses of a base type. Non-abstract classes only.
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
	while( type != VIPS_TYPE_OBJECT && (type = g_type_parent( type )) )
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
 * vips_class_find: (skip)
 * @basename: name of base class
 * @nickname: search for a class with this nickname
 *
 * Search below basename, return the first class whose name or nickname
 * matches.
 *
 * Returns: the found class.
 */
VipsObjectClass *
vips_class_find( const char *basename, const char *nickname )
{
	const char *classname = basename ? basename : "VipsObject";

	VipsObjectClass *class;
	GType base;

	if( !(base = g_type_from_name( classname )) || 
		!(class = vips_class_map_all( base, 
			(VipsClassMapFn) test_name, (void *) nickname )) ) 
		return( NULL );

	return( class );
}

GType
vips_type_find( const char *basename, const char *nickname )
{
	VipsObjectClass *class;

	if( !(class = vips_class_find( basename, nickname )) )
		return( 0 );

	return( G_OBJECT_CLASS_TYPE( class ) );
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
 * non-NULL pointer in the array will be unreffed and the arraqy will be
 * freed.
 * Handy for creating a 
 * set of temporary images for a function.
 *
 * Example:
 *
 * |[
 * VipsObject **t;
 *
 * t = vips_object_local_array( a, 5 );
 * if( 
 *   vips_add( a, b, &t[0], NULL ) ||
 *   vips_invert( t[0], &t[1], NULL ) ||
 *   vips_add( t[1], t[0], &t[2], NULL ) ||
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

	fprintf( stderr, "%d) %s (%p)\n", 
		*n, G_OBJECT_TYPE_NAME( object ), object );

	vips_object_summary_class( class, &buf );
	vips_buf_appends( &buf, " " );
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

/* Unref all assigned output objects.
 *
 * After an object is built, all output args are owned by the caller. If
 * something goes wrong before then, we have to unref the outputs that have
 * been made so far. And this function can also be useful for callers when
 * they've finished processing outputs themselves.
 */
void
vips_object_unref_outputs( VipsObject *object )
{
	(void) vips_argument_map( object,
		vips_object_unref_outputs_sub, NULL, NULL );
}
