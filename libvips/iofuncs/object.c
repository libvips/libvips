/* abstract base class for all vips objects
 *
 * Edited from nip's base class, 15/10/08
 */

/*

    Copyright (C) 1991-2003 The National Gallery

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
#define DEBUG
#define VIPS_DEBUG
#define DEBUG_REF
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Properties.
 */
enum {
	PROP_NICKNAME = 1,/* Class properties as object props */
	PROP_DESCRIPTION,
	PROP_LAST
};

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

G_DEFINE_ABSTRACT_TYPE( VipsObject, vips_object, G_TYPE_OBJECT );

void
vips_object_preclose( VipsObject *object )
{
	if( !object->preclose ) {
		object->preclose = TRUE;

#ifdef DEBUG
		printf( "vips_object_preclose: " );
		vips_object_print( object );
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
		vips_object_print( object );
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
		vips_object_print( object );
#endif /*DEBUG*/

		g_signal_emit( object, vips_object_signals[SIG_POSTCLOSE], 0 );
	}
}

int
vips_object_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );

#ifdef DEBUG
	printf( "vips_object_build: " );
	vips_object_print( object );
#endif /*DEBUG*/

	return( object_class->build( object ) );
}

void
vips_object_print_class( VipsObjectClass *class )
{
	char str[1000];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	class->print_class( class, &buf );
	printf( "%s\n", vips_buf_all( &buf ) );
}

void
vips_object_print( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	char str[1000];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	vips_object_print_class( class );
	class->print( object, &buf );
	printf( "%s\n", vips_buf_all( &buf ) );
}

gboolean
vips_object_sanity( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	char str[1000];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	class->sanity( object, &buf );
	if( !vips_buf_is_empty( &buf ) ) {
		printf( "sanity failure: " );
		vips_object_print( object );
		printf( "%s\n", vips_buf_all( &buf ) );
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
	if( argument_instance->destroy_id ) {
		g_signal_handler_disconnect( argument_instance->object,
			argument_instance->destroy_id );
		argument_instance->destroy_id = 0;
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

/* Loop over the vips_arguments to an object.
 */
void *
vips_argument_map( VipsObject *object,
	VipsArgumentMapFn fn, void *a, void *b )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	GSList *p;

	for( p = class->argument_table_traverse; p; p = p->next ) {
		VipsArgumentClass *argument_class =
			(VipsArgumentClass *) p->data;
		VipsArgument *argument = (VipsArgument *) argument_class;
		GParamSpec *pspec = argument->pspec;
		VipsArgumentInstance *argument_instance =
			vips__argument_get_instance( argument_class, object );

		/* We have many props on the arg table ... filter out the ones
		 * for this class.
		 */
		if( g_object_class_find_property( G_OBJECT_CLASS( class ),
			pspec->name ) == pspec ) {
			void *result;

			if( (result = fn( object, pspec,
				argument_class, argument_instance, a, b )) )
				return( result );
		}
	}

	return( NULL );
}

static void *
vips_argument_init2( VipsObject *object, GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsArgument *argument;

#ifdef DEBUG
	printf( "vips_argument_init_sub: adding instance argument for %s\n",
		pspec->name );
#endif /*DEBUG*/

	/* argument_instance should be NULL since we've not set it yet.
	 */
	g_assert( argument_instance == NULL );

	argument_instance = g_new( VipsArgumentInstance, 1 );
	argument = (VipsArgument *) argument_instance;

	argument->pspec = ((VipsArgument *) argument_class)->pspec;
	argument_instance->object = object;
	argument_instance->assigned = FALSE;
	argument_instance->destroy_id = 0;

	vips_argument_table_replace( object->argument_table, argument );

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
		object->argument_table = g_hash_table_new_full( g_direct_hash,
			g_direct_equal, NULL,
			(GDestroyNotify) vips_argument_instance_free );

		/* Make a VipsArgumentInstance for each installed argument
		 * property.
		 */
		vips_argument_map( object, vips_argument_init2, NULL, NULL );
	}
}

/* Convenience ... given the VipsArgumentClass, get the VipsArgumentInstance.
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

static void
vips_object_clear_object( VipsObject *object, GParamSpec *pspec )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( class->argument_table, pspec );
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance( argument_class, object );
	GObject **member = &G_STRUCT_MEMBER( GObject *, object,
		argument_class->offset );

	if( *member ) {
		if( argument_class->flags & VIPS_ARGUMENT_INPUT ) {
#ifdef DEBUG_REF
			printf( "vips_object_clear_object: vips object: " );
			vips_object_print( object );
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
			printf( "vips_object_clear_object: gobject %s (%p)\n",
				G_OBJECT_TYPE_NAME( *member ), *member );
			printf( "  no longer refers to vips object: " );
			vips_object_print( object );
			printf( "  count down to %d\n",
				G_OBJECT( object )->ref_count - 1 );
#endif /*DEBUG_REF*/

			/* The object reffed us. Stop listening link to the
			 * object's "destroy" signal. We can come here from
			 * object being destroyed, in which case the handler
			 * will already have been disconnected for us.
			 */
			if( g_signal_handler_is_connected( object,
				argument_instance->destroy_id ) )
				g_signal_handler_disconnect( object,
					argument_instance->destroy_id );
			argument_instance->destroy_id = 0;
			*member = NULL;

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
#ifdef DEBUG
	printf( "vips_object_dispose_argument: " );
	vips_object_print( object );
	printf( ".%s\n", pspec->name );
#endif /*DEBUG*/

	g_assert( ((VipsArgument *) argument_class)->pspec == pspec );
	g_assert( ((VipsArgument *) argument_instance)->pspec == pspec );

	if( G_IS_PARAM_SPEC_STRING( pspec ) ) {
		char **member = &G_STRUCT_MEMBER( char *, object,
			argument_class->offset );

		VIPS_FREE( *member );
	}
	else if( G_IS_PARAM_SPEC_OBJECT( pspec ) )
		vips_object_clear_object( object, pspec );
	else if( G_IS_PARAM_SPEC_BOXED( pspec ) ) {
		gpointer *member = &G_STRUCT_MEMBER( gpointer, object,
			argument_class->offset );

		if( *member ) {
			g_boxed_free( G_PARAM_SPEC_VALUE_TYPE( pspec ),
				*member );
			*member = NULL;
		}
	}

	return( NULL );
}

static void
vips_object_dispose( GObject *gobject )
{
	VipsObject *object = VIPS_OBJECT( gobject );

#ifdef DEBUG
	printf( "vips_object_dispose: " );
	vips_object_print( object );
#endif /*DEBUG*/

	/* Our subclasses should have already called this. Run it again, just
	 * in case.
	 */
	if( !object->preclose ) {
#ifdef VIPS_DEBUG
		printf( "vips_object_dispose: no vips_object_preclose()\n" );
		vips_object_print( VIPS_OBJECT( gobject ) );
#endif /*VIPS_DEBUG*/

		vips_object_preclose( object );
	}

	/* Clear all our arguments: they may be holding refs we should drop.
	 */
	vips_argument_map( object, vips_object_dispose_argument, NULL, NULL );
	VIPS_FREEF( vips_argument_table_destroy, object->argument_table );

	G_OBJECT_CLASS( vips_object_parent_class )->dispose( gobject );
}

static void
vips_object_finalize( GObject *gobject )
{
	VipsObject *object = VIPS_OBJECT( gobject );

#ifdef DEBUG
	printf( "vips_object_finalize: " );
	vips_object_print( object );
#endif /*DEBUG*/

	vips_object_close( object );

	g_mutex_lock( vips__object_all_lock );
	g_hash_table_remove( vips__object_all, object );
	g_mutex_unlock( vips__object_all_lock );

	G_OBJECT_CLASS( vips_object_parent_class )->finalize( gobject );

	vips_object_postclose( object );
}

static void
vips_object_arg_destroy( GObject *argument,
	VipsArgumentInstance *argument_instance )
{
	VipsObject *object = argument_instance->object;
	GParamSpec *pspec = ((VipsArgument *) argument_instance)->pspec;

	/* Argument had reffed us ... now it's being destroyed, so we unref.
	 */
	vips_object_clear_object( object, pspec );
}

static void
vips_object_set_object( VipsObject *object, GParamSpec *pspec,
	GObject *argument )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( class->argument_table, pspec );
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance( argument_class, object );
	GObject **member = &G_STRUCT_MEMBER( GObject *, object,
		argument_class->offset );

	g_assert( !*member );

	*member = argument;

	if( *member ) {
		if( argument_class->flags & VIPS_ARGUMENT_INPUT ) {
#ifdef DEBUG_REF
			printf( "vips_object_set_object: vips object: " );
			vips_object_print( object );
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
			printf( "vips_object_set_object: gobject %s (%p)\n",
				G_OBJECT_TYPE_NAME( *member ), *member );
			printf( "  refers to vips object: " );
			vips_object_print( object );
			printf( "  count up to %d\n",
				G_OBJECT (object)->ref_count );
#endif /*DEBUG_REF*/

			/* The argument reffs us.
			 */
			g_object_ref( object );
			argument_instance->destroy_id =
				g_signal_connect( *member, "destroy",
					G_CALLBACK( vips_object_arg_destroy ),
					argument_instance );
		}
	}
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

	if( !argument_class ) {
		G_OBJECT_WARN_INVALID_PROPERTY_ID( gobject,
			property_id, pspec );
		return;
	}

#ifdef DEBUG
{
	char *str_value;

	str_value = g_strdup_value_contents( value );
	printf( "vips_object_set_property: " );
	vips_object_print( object );
	printf( ".%s = %s\n", g_param_spec_get_name( pspec ), str_value );
	g_free( str_value );
}
#endif /*DEBUG*/

	g_assert( ((VipsArgument *) argument_class)->pspec == pspec );
	g_assert( ((VipsArgument *) argument_instance)->pspec == pspec );

	/* If this is a construct-only argument, we can only set before we've
	 * built.
	 */
	if( argument_class->flags & VIPS_ARGUMENT_CONSTRUCT &&
		object->constructed ) {
		g_warning( "%s: %s can't assign '%s' after construct",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_param_spec_get_name( pspec ) );
		return;
	}

	/* If this is a set-once argument, check we've not set it before.
	 */
	if( argument_class->flags & VIPS_ARGUMENT_SET_ONCE &&
		argument_instance->assigned ) {
		g_warning( "%s: %s can only assign '%s' once",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_param_spec_get_name( pspec ) );
		return;
	}

	if( G_IS_PARAM_SPEC_STRING( pspec ) ) {
		char **member = &G_STRUCT_MEMBER( char *, object,
			argument_class->offset );

		VIPS_SETSTR( *member, g_value_get_string( value ) );
	}
	else if( G_IS_PARAM_SPEC_OBJECT( pspec ) ) {
		/* Remove any old object.
		 */
		vips_object_clear_object( object, pspec );

		/* Install the new object.
		 */
		vips_object_set_object( object, pspec,
			g_value_get_object( value ) );
	}
	else if( G_IS_PARAM_SPEC_INT( pspec ) ) {
		int *member = &G_STRUCT_MEMBER( int, object,
			argument_class->offset );

		*member = g_value_get_int( value );
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
		 * vips__object_vector_dup ()).
		 */
		*member = g_value_dup_boxed( value );
	}
	else {
		g_warning( "%s: %s unimplemented property type %s",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
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

	if( !argument_class ) {
		G_OBJECT_WARN_INVALID_PROPERTY_ID( gobject,
			property_id, pspec );
		return;
	}

	g_assert( ((VipsArgument *) argument_class)->pspec == pspec );

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
		g_warning( "%s: %s unimplemented property type %s",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_type_name( G_PARAM_SPEC_VALUE_TYPE( pspec ) ) );
	}
}

static void *
vips_object_check_required( VipsObject *object, GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	int *result = (int *) a;

	if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		!argument_instance->assigned ) {
		vips_error( "check_required",
			_( "required construct param %s to %s not set" ),
			g_param_spec_get_name( pspec ),
			G_OBJECT_TYPE_NAME( object ) );
		*result = -1;
	}

	return( NULL );
}

static int
vips_object_real_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );

	int result;

	g_assert( !object->constructed );

	/* Check all required arguments have been supplied, don't stop on 1st
	 * error.
	 */
	result = 0;
	(void) vips_argument_map( object,
		vips_object_check_required, &result, NULL );

	/* ... more checks go here.
	 */
	object->constructed = TRUE;

	/* It'd be nice if this just copied a pointer rather than did a
	 * strdup(). Set these here rather than in object_init, so that the
	 * class gets a chance to set them.
	 */
	g_object_set( object,
		"nickname", object_class->nickname,
		"description", object_class->description, NULL );

	return( result );
}

static void
vips_object_real_print_class( VipsObjectClass *class, VipsBuf *buf )
{
	vips_buf_appendf( buf, "%s", G_OBJECT_CLASS_NAME( class ) );
	if( class->nickname )
		vips_buf_appendf( buf, " (%s)", class->nickname );
	if( class->description )
		vips_buf_appendf( buf, ", %s", class->description );
}

static void
vips_object_real_print( VipsObject *object, VipsBuf *buf )
{
	vips_buf_appendf( buf, " (%p)", object );
}

static void
vips_object_real_sanity( VipsObject *object, VipsBuf *buf )
{
}

static void
vips_object_real_rewind( VipsObject *object )
{
#ifdef DEBUG
	printf( "vips_object_rewind\n" );
	vips_object_print( object );
#endif /*DEBUG*/

	g_object_run_dispose( G_OBJECT( object ) );

	object->constructed = FALSE;
	object->preclose = FALSE;
	object->close = FALSE;
	object->postclose = FALSE;
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

	GParamSpec *pspec;

	if( !vips__object_all ) {
		vips__object_all = g_hash_table_new( 
			g_direct_hash, g_direct_equal );
		vips__object_all_lock = g_mutex_new();
	}

	gobject_class->dispose = vips_object_dispose;
	gobject_class->finalize = vips_object_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	class->build = vips_object_real_build;
	class->print_class = vips_object_real_print_class;
	class->print = vips_object_real_print;
	class->sanity = vips_object_real_sanity;
	class->rewind = vips_object_real_rewind;
	class->nickname = "object";
	class->description = _( "VIPS base class" );

	/* Table of VipsArgumentClass ... we can just g_free() them.
	 */
	class->argument_table = g_hash_table_new_full(
		g_direct_hash, g_direct_equal, NULL, (GDestroyNotify) g_free );
	class->argument_table_traverse = NULL;

	/* For setting double arguments from the command-line.
	 */
	g_value_register_transform_func( G_TYPE_STRING, G_TYPE_DOUBLE,
		transform_string_double );

	/* Create properties.
	 */
	pspec = g_param_spec_string( "nickname",
		_( "Nickname" ),
		_( "Class nickname" ),
		"",
		(GParamFlags) G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class,
		PROP_NICKNAME, pspec );
	vips_object_class_install_argument( class, pspec,
		VIPS_ARGUMENT_SET_ONCE,
		G_STRUCT_OFFSET( VipsObject, nickname ) );

	pspec = g_param_spec_string( "description",
		_( "Description" ),
		_( "Class description" ),
		"",
		(GParamFlags) G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class,
		PROP_DESCRIPTION, pspec );
	vips_object_class_install_argument( class, pspec,
		VIPS_ARGUMENT_SET_ONCE,
		G_STRUCT_OFFSET( VipsObject, description ) );

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
	vips_object_print( object );
#endif /*DEBUG*/

	g_mutex_lock( vips__object_all_lock );
	g_hash_table_insert( vips__object_all, object, object );
	g_mutex_unlock( vips__object_all_lock );
}

/* Add a vipsargument ... automate some stuff with this.
 */
void
vips_object_class_install_argument( VipsObjectClass *object_class,
	GParamSpec *pspec, VipsArgumentFlags flags, guint offset )
{
	VipsArgumentClass *argument_class = g_new( VipsArgumentClass, 1 );

#ifdef DEBUG
	printf( "vips_object_class_install_argument: %s\n", pspec->name );
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
	argument_class->offset = offset;

	vips_argument_table_replace( object_class->argument_table,
		(VipsArgument *) argument_class );
	object_class->argument_table_traverse = g_slist_append(
		object_class->argument_table_traverse, argument_class );
}

/* Set a named arg from a string.
 */
static int
vips_object_set_arg( VipsObject *object, const char *name, const char *value )
{
	GValue gvalue = { 0 };

	g_value_init( &gvalue, G_TYPE_STRING );
	g_value_set_string( &gvalue, value );
	g_object_set_property( G_OBJECT( object ), name, &gvalue );
	g_value_unset( &gvalue );

	return( 0 );
}

static void *
vips_object_set_required_test( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	if( (argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		!argument_instance->assigned )
		return( pspec );

	return( NULL );
}

/* Set the first unassigned required arg to the string.
 */
static int
vips_object_set_required( VipsObject *object, const char *value )
{
	GParamSpec *pspec;

	if( !(pspec = vips_argument_map( object,
		vips_object_set_required_test, NULL, NULL )) ) {
		vips_error( "vips_object_set_required",
			_( "no unset required arguments for %s" ), value );
		return( -1 );
	}

	if( vips_object_set_arg( object, pspec->name, value ) )
		return( -1 );

	return( 0 );
}

/* Set object args from a string. We've seen the '(', we need to check for the
 * closing ')' and make sure there's no extra stuff.
 */
static int
vips_object_set_args( VipsObject *object, const char *p )
{
	VipsToken token;
	char string[PATH_MAX];
	char string2[PATH_MAX];

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
			if( vips_object_set_arg( object, string, string2 ) )
				return( -1 );
			if( !(p = vips__token_must( p, &token,
				string2, PATH_MAX )) )
				return( -1 );
		}
		else {
			if( vips_object_set_required( object, string ) )
				return( -1 );
		}

		/* Now must be a , or a ).
		 */
		if( token != VIPS_TOKEN_RIGHT && token != VIPS_TOKEN_COMMA ) {
			vips_error( "set_args", "%s",
				_( "not , or ) after parameter" ) );
			return( -1 );
		}
	} while( token != VIPS_TOKEN_RIGHT );

	if( (p = vips__token_get( p, &token, string, PATH_MAX )) ) {
		vips_error( "set_args", "%s",
			_( "extra tokens after ')'" ) );
		return( -1 );
	}

	return( 0 );
}

VipsObject *
vips_object_new( GType type, VipsObjectSetArguments set, void *a, void *b )
{
	VipsObject *object;

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

static void *
vips_object_new_from_string_set( VipsObject *object, void *a, void *b )
{
	const char *p = (const char *) a;
	VipsToken token;
	char string[PATH_MAX];

	if( (p = vips__token_get( p, &token, string, PATH_MAX )) ) {
		if( token == VIPS_TOKEN_LEFT &&
			vips_object_set_args( object, p ) ) {
			vips_error( "object_new", "%s",
				_( "bad object arguments" ) );
			return( object );
		}
	}

	return( NULL );
}

VipsObject *
vips_object_new_from_string( const char *basename, const char *p )
{
	char string[PATH_MAX];
	GType type;

	if( !(p = vips__token_need( p, VIPS_TOKEN_STRING, string, PATH_MAX )) ||
		!(type = vips_type_find( basename, string )) )
		return( NULL );

	return( vips_object_new( type,
		vips_object_new_from_string_set, (void *) p, NULL ) );
}

static void
vips_object_print_arg( VipsObject *object, GParamSpec *pspec, VipsBuf *buf )
{
	GType type = G_PARAM_SPEC_VALUE_TYPE( pspec );
	const char *name = g_param_spec_get_name( pspec );
	GValue value = { 0 };
	char *str_value;

	g_value_init( &value, type );
	g_object_get_property( G_OBJECT( object ), name, &value );
	str_value = g_strdup_value_contents( &value );
	vips_buf_appends( buf, str_value );
	g_free( str_value );
	g_value_unset( &value );

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

/* The inverse of vips_object_new_from_string(): turn an object into eg.
 * "VipsInterpolateSnohalo1(blur=.333333)".
 */
void
vips_object_to_string( VipsObject *object, VipsBuf *buf )
{
	gboolean first;

	/* Nicknames are not guaranteed to be unique, so use the full type
	 * name.
	 */
	vips_buf_appends( buf, G_OBJECT_TYPE_NAME( object ) );
	first = TRUE;
	(void) vips_argument_map( object,
		vips_object_to_string_required, buf, &first );
	(void) vips_argument_map( object,
		vips_object_to_string_optional, buf, &first );
	if( !first )
		vips_buf_appends( buf, ")" );
}

typedef struct {
	VSListMap2Fn fn;
	void *a;
	void *b;
	void *result;
} VipsObjectMapArgs;

static void
vips_object_map_sub( VipsObject *object, VipsObjectMapArgs *args )
{
	if( !args->result )
		args->result = args->fn( object, args->a, args->b );
}

void *
vips_object_map( VSListMap2Fn fn, void *a, void *b )
{
	VipsObjectMapArgs args;

	args.fn = fn;
	args.a = a;
	args.b = b;
	args.result = NULL;
	g_mutex_lock( vips__object_all_lock );
	if( vips__object_all )
		g_hash_table_foreach( vips__object_all, 
			(GHFunc) vips_object_map_sub, &args );
	g_mutex_unlock( vips__object_all_lock );

	return( args.result );
}

void
vips_object_local_cb( VipsObject *vobject, GObject *gobject )
{
	g_object_unref( gobject );
}

int
vips_object_unref( VipsObject *obj )
{
	g_object_unref( obj );

	return( 0 );
}

static void *
vips_object_print_all_cb( VipsObject *object )
{
	vips_object_print( object );

	return( NULL );
}

void
vips_object_print_all( void )
{
	vips_object_map( (VSListMap2Fn) vips_object_print_all_cb, NULL, NULL );
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
	vips_object_map( (VSListMap2Fn) vips_object_sanity_all_cb, NULL, NULL );
}
