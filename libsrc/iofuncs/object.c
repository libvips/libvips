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

/* Our signals. 
 */
enum {
	SIG_CHANGED,	/* VipsObject has changed somehow */
	SIG_LAST
};

static guint vips_object_signals[SIG_LAST] = { 0 };

G_DEFINE_ABSTRACT_TYPE( VipsObject, vips_object, G_TYPE_OBJECT );

void *
vips_object_changed( VipsObject *object )
{
	g_return_val_if_fail( object != NULL, NULL );
	g_return_val_if_fail( VIPS_IS_OBJECT( object ), NULL );

#ifdef DEBUG
	printf( "vips_object_changed: " );
	vips_object_print( object );
#endif /*DEBUG*/

	g_signal_emit( G_OBJECT( object ), 
		vips_object_signals[SIG_CHANGED], 0 );

	return( NULL );
}

void
vips_object_print_class( VipsObjectClass *class )
{
	im_buf_t buf;
	char str[1000];

	im_buf_init_static( &buf, str, 1000 );
	class->print_class( class, &buf );
	printf( "%s\n", im_buf_all( &buf ) );
}

void
vips_object_print( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	im_buf_t buf;
	char str[1000];

	vips_object_print_class( class );
	im_buf_init_static( &buf, str, 1000 );
	class->print( object, &buf );
	printf( "\n%s (%p)\n", im_buf_all( &buf ), object );
}

/* Extra stuff we track for properties to do our argument handling.
 */

/* Free a VipsArgumentInstance ... VipsArgumentClass can just be g_free()d.
 */
static void
vips_argument_instance_free (VipsArgumentInstance *argument_instance)
{
	if (argument_instance->destroy_id) {
		g_signal_handler_disconnect (argument_instance->object,
			argument_instance->destroy_id);
		argument_instance->destroy_id = 0;
	}
	g_free (argument_instance);
}

VipsArgument *
vips__argument_table_lookup (VipsArgumentTable *table, 
	GParamSpec *pspec)
{
	return (g_hash_table_lookup (table, pspec));
}

static void
vips_argument_table_replace (VipsArgumentTable *table, VipsArgument *argument)
{
	g_hash_table_replace (table, argument->pspec, argument);
}

static void
vips_argument_table_destroy (VipsArgumentTable *table)
{
	g_hash_table_destroy (table);
}

static void *
vips_argument_init_sub (VipsObject *object, GParamSpec *pspec,
	VipsArgumentClass *argument_class, 
	VipsArgumentInstance *argument_instance)
{
	VipsArgument *argument;

#ifdef DEBUG
	printf ("vips_argument_init_sub: adding instance argument for %s\n",
		pspec->name);
#endif /*DEBUG*/

	/* argument_instance should be NULL since we've not set it yet.
	 */
	g_assert (argument_instance == NULL);

	argument_instance = g_new (VipsArgumentInstance, 1);
	argument = (VipsArgument *) argument_instance;

	argument->pspec = ((VipsArgument *) argument_class)->pspec;
	argument_instance->object = object;
	argument_instance->assigned = FALSE;
	argument_instance->destroy_id = 0;

	vips_argument_table_replace (object->argument_table, argument);

	return (NULL);
}

/* Create a VipsArgumentInstance for each installed argument property. Ideally
 * we'd do this during _init() but g_object_class_find_property() does not seem
 * to work then :-( so we have to delay it until first access.
 */
static void
vips_argument_init (VipsObject *object)
{
	if( !object->argument_table ) {
		object->argument_table = g_hash_table_new_full (g_direct_hash, 
			g_direct_equal, NULL, 
			(GDestroyNotify) vips_argument_instance_free);

		/* Make a VipsArgumentInstance for each installed argument 
		 * property.
		 */
		vips__argument_map (object,
			(VipsArgumentMapFn) vips_argument_init_sub, NULL, NULL);
	}
}

/* Convenience ... given the VipsArgumentClass, get the VipsArgumentInstance.
 */
VipsArgumentInstance *
vips__argument_get_instance (VipsArgumentClass *argument_class, 
	VipsObject *object) 
{
	/* Make sure the instance args are built.
	 */
	vips_argument_init (object);

	return ((VipsArgumentInstance *) 
		vips__argument_table_lookup (object->argument_table,
			((VipsArgument *) argument_class)->pspec));
}

/* Loop over the vips_arguments to an object.
 *
 * Note: this code copy-pasted into vips_operation_call_valist(), keep in sync.
 */
void *
vips__argument_map (VipsObject *object, VipsArgumentMapFn fn, void *a, void *b)
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS (object);
	GSList *p;

	for (p = object_class->argument_table_traverse; p; p = p->next) {
		VipsArgumentClass *argument_class = 
			(VipsArgumentClass *) p->data;
		VipsArgument *argument = 
			(VipsArgument *) argument_class;
		GParamSpec *pspec = argument->pspec;
		VipsArgumentInstance *argument_instance =
			vips__argument_get_instance (argument_class, object);

		/* We have many props on the arg table ... filter out the ones
		 * for this class.
		 */
		if (g_object_class_find_property (G_OBJECT_CLASS (object_class),
			pspec->name) == pspec) {
			void *result;

			if ((result = fn (object, pspec, 
				argument_class, argument_instance, a, b)))
				return (result);
		}
	}

	return (NULL);
}

static void
vips_object_clear_object (VipsObject *object, GParamSpec *pspec)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS (object);
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup (class->argument_table, pspec);
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance (argument_class, object);
	GObject **member = &G_STRUCT_MEMBER (GObject *, object, 
		argument_class->offset);

	if (*member) {
		if (argument_class->flags & VIPS_ARGUMENT_INPUT) {
#ifdef DEBUG_REF
			printf ("vips_object_clear_object: vips object: ");
			vips_object_print (object);
			printf ("  no longer refers to gobject %s (%p)\n", 
				G_OBJECT_TYPE_NAME (*member), *member);
			printf ("  count down to %d\n", 
				G_OBJECT (*member)->ref_count - 1);
#endif /*DEBUG_REF*/

			/* We reffed the object.
			 */
			g_object_unref (*member);
		}
		else if (argument_class->flags & VIPS_ARGUMENT_OUTPUT) {
#ifdef DEBUG_REF
			printf ("vips_object_clear_object: gobject %s (%p)\n",
				G_OBJECT_TYPE_NAME (*member), *member);
			printf ("  no longer refers to vips object: "); 
			vips_object_print (object);
			printf ("  count down to %d\n", 
				G_OBJECT (object)->ref_count - 1);
#endif /*DEBUG_REF*/

			/* The object reffed us. Stop listening link to the
			 * object's "destroy" signal. We can come here from
			 * object being destroyed, in which case the handler
			 * will already have been disconnected for us. 
			 */
			if( g_signal_handler_is_connected (object,
				argument_instance->destroy_id))
				g_signal_handler_disconnect (object,
					argument_instance->destroy_id);
			argument_instance->destroy_id = 0;
			*member = NULL;

			g_object_unref (object);
		}

		*member = NULL;
	}
}

/* Free any args which are holding resources.
 */
static void *
vips_object_dispose_argument (VipsObject *object, GParamSpec *pspec, 
	VipsArgumentClass *argument_class, 
	VipsArgumentInstance *argument_instance,
	void *a, void *b)
{
#ifdef DEBUG
	printf ("vips_object_dispose_argument: %s.%s\n", 
		object->name, pspec->name);
#endif /*DEBUG*/

	g_assert (((VipsArgument *) argument_class)->pspec == pspec);
	g_assert (((VipsArgument *) argument_instance)->pspec == pspec);

	if (G_IS_PARAM_SPEC_STRING (pspec)) {
		char **member = &G_STRUCT_MEMBER (char *, object, 
			argument_class->offset);

		IM_FREE (*member); 
	}
	else if (G_IS_PARAM_SPEC_OBJECT (pspec)) 
		vips_object_clear_object (object, pspec);
	else if (G_IS_PARAM_SPEC_BOXED (pspec)) {
		gpointer *member = &G_STRUCT_MEMBER (gpointer, object, 
			argument_class->offset);

		if (*member) {
			g_boxed_free (G_PARAM_SPEC_VALUE_TYPE (pspec), *member);
			*member = NULL;
		}
	}

	return (NULL);
}

static void
vips_object_dispose( GObject *gobject )
{
	VipsObject *object = VIPS_OBJECT( gobject );

#ifdef DEBUG
	printf( "vips_object_dispose: " );
	vips_object_print( object );
#endif /*DEBUG*/

	/* Clear all our arguments: they may be holding refs we should drop.
	 */
	vips__argument_map (object, 
		vips_object_dispose_argument, NULL, NULL);

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

	IM_FREEF (vips_argument_table_destroy, object->argument_table);
	IM_FREE( object->name );

	G_OBJECT_CLASS( vips_object_parent_class )->finalize( gobject );
}

static void
vips_object_arg_destroy (GObject *argument, 
	VipsArgumentInstance *argument_instance)
{
	VipsObject *object = argument_instance->object;
	GParamSpec *pspec = ((VipsArgument *) argument_instance)->pspec;

	/* Argument had reffed us ... now it's being destroyed, so we unref.
	 */
	vips_object_clear_object (object, pspec);
} 

static void
vips_object_set_object (VipsObject *object, GParamSpec *pspec, 
	GObject *argument)
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS (object);
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup (class->argument_table, pspec);
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance (argument_class, object);
	GObject **member = &G_STRUCT_MEMBER (GObject *, object, 
		argument_class->offset);

	g_assert (!*member);

	*member = argument;

	if (*member) {
		if (argument_class->flags & VIPS_ARGUMENT_INPUT) {
#ifdef DEBUG_REF
			printf ("vips_object_set_object: vips object: ");
			vips_object_print (object);
			printf ("  refers to gobject %s (%p)\n", 
				G_OBJECT_TYPE_NAME (*member), *member);
			printf ("  count up to %d\n", 
				G_OBJECT (*member)->ref_count);
#endif /*DEBUG_REF*/

			/* Ref the argument.
			 */
			g_object_ref (*member);
		}
		else if (argument_class->flags & VIPS_ARGUMENT_OUTPUT) {
#ifdef DEBUG_REF
			printf ("vips_object_set_object: gobject %s (%p)\n",
				G_OBJECT_TYPE_NAME (*member), *member);
			printf ("  refers to vips object: "); 
			vips_object_print (object);
			printf ("  count up to %d\n", 
				G_OBJECT (object)->ref_count);
#endif /*DEBUG_REF*/

			/* The argument reffs us.
			 */
			g_object_ref (object);
			argument_instance->destroy_id =
				g_signal_connect (*member, "destroy",
					G_CALLBACK (vips_object_arg_destroy),
					argument_instance);
		}
	}
}

static void
vips_object_set_property (GObject *gobject, 
	guint property_id, const GValue *value, GParamSpec *pspec)
{
	VipsObject *object = VIPS_OBJECT (gobject);
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS (gobject);
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup (class->argument_table, pspec);
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance (argument_class, object);

	if (!argument_class) {
		G_OBJECT_WARN_INVALID_PROPERTY_ID (gobject, 
			property_id, pspec);
		return;
	}

#ifdef DEBUG
{
	char *str_value;

	str_value = g_strdup_value_contents (value);
	printf ("vips_object_set_property: %s.%s = %s\n", 
		object->name, pspec->name, str_value);
	g_free (str_value);
}
#endif /*DEBUG*/

	g_assert (((VipsArgument *) argument_class)->pspec == pspec);
	g_assert (((VipsArgument *) argument_instance)->pspec == pspec);

	/* If this is a construct-only argument, we can only set before we've
	 * built.

	 	FIXME ... how do we spot end of construct? put this back

	if (argument_class->flags & VIPS_ARGUMENT_CONSTRUCT && 
		object->done_build) {
		g_warning ("%s: can't assign '%s' after construct", G_STRLOC,
			((VipsArgument *)argument_class)->pspec->name);
		return;
	}
	 */

	/* If this is a set-once argument, check we've not set it before.
	 */
	if (argument_class->flags & VIPS_ARGUMENT_SET_ONCE &&
		argument_instance->assigned) {
		g_warning ("%s: can only assign '%s' once", G_STRLOC,
			((VipsArgument *)argument_class)->pspec->name);
		return;
	}

	if (G_IS_PARAM_SPEC_STRING (pspec)) {
		char **member = &G_STRUCT_MEMBER (char *, object, 
			argument_class->offset);

		IM_SETSTR (*member, g_value_get_string (value));
	}
	else if (G_IS_PARAM_SPEC_OBJECT (pspec)) {
		/* Remove any old object.
		 */
		vips_object_clear_object (object, pspec);

		/* Install the new object.
		 */
		vips_object_set_object (object, pspec, 
			g_value_get_object (value));
	}
	else if (G_IS_PARAM_SPEC_INT (pspec)) {
		int *member = &G_STRUCT_MEMBER (int, object, 
			argument_class->offset);

		*member = g_value_get_int (value);
	}
	else if (G_IS_PARAM_SPEC_BOOLEAN (pspec)) {
		gboolean *member = &G_STRUCT_MEMBER (gboolean, object, 
			argument_class->offset);

		*member = g_value_get_boolean (value);
	}
	else if (G_IS_PARAM_SPEC_ENUM (pspec)) {
		int *member = &G_STRUCT_MEMBER (int, object, 
			argument_class->offset);

		*member = g_value_get_enum (value);
	}
	else if (G_IS_PARAM_SPEC_POINTER (pspec)) {
		gpointer *member = &G_STRUCT_MEMBER (gpointer, object, 
			argument_class->offset);

		*member = g_value_get_pointer (value);
	}
	else if (G_IS_PARAM_SPEC_BOXED (pspec)) {
		gpointer *member = &G_STRUCT_MEMBER (gpointer, object, 
			argument_class->offset);

		if (*member) {
			g_boxed_free (G_PARAM_SPEC_VALUE_TYPE (pspec), *member);
			*member = NULL;
		}

		/* Copy the boxed into our pointer (will use eg.
		 * vips__object_vector_dup ()).
		 */
		*member = g_value_dup_boxed (value);
	}
	else {
		g_warning ("%s: '%s' has unimplemented type", G_STRLOC,
			((VipsArgument *)argument_class)->pspec->name);
	}

	/* Note that it's now been set. 
	 */
	argument_instance->assigned = TRUE;
}

static void
vips_object_get_property (GObject *gobject, 
	guint property_id, GValue *value, GParamSpec *pspec)
{
	VipsObject *object = VIPS_OBJECT (gobject);
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS (gobject);
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup (class->argument_table, pspec);

	if (!argument_class) {
		G_OBJECT_WARN_INVALID_PROPERTY_ID (gobject, 
			property_id, pspec);
		return;
	}

	g_assert (((VipsArgument *) argument_class)->pspec == pspec);

	if (G_IS_PARAM_SPEC_STRING (pspec)) {
		char *member = G_STRUCT_MEMBER (char *, object, 
			argument_class->offset);

		g_value_set_string (value, member);
	}
	else if (G_IS_PARAM_SPEC_OBJECT (pspec)) {
		GObject **member = &G_STRUCT_MEMBER (GObject *, object, 
			argument_class->offset);

		g_value_set_object (value, *member);
	}
	else if (G_IS_PARAM_SPEC_INT (pspec)) {
		int *member = &G_STRUCT_MEMBER (int, object, 
			argument_class->offset);

		g_value_set_int (value, *member);
	}
	else if (G_IS_PARAM_SPEC_BOOLEAN (pspec)) {
		gboolean *member = &G_STRUCT_MEMBER (gboolean, object, 
			argument_class->offset);

		g_value_set_boolean (value, *member);
	}
	else if (G_IS_PARAM_SPEC_ENUM (pspec)) {
		int *member = &G_STRUCT_MEMBER (int, object, 
			argument_class->offset);

		g_value_set_enum (value, *member);
	}
	else if (G_IS_PARAM_SPEC_POINTER (pspec)) {
		gpointer *member = &G_STRUCT_MEMBER (gpointer, object, 
			argument_class->offset);

		g_value_set_pointer (value, *member);
	}
	else if (G_IS_PARAM_SPEC_BOXED (pspec)) {
		gpointer *member = &G_STRUCT_MEMBER (gpointer, object, 
			argument_class->offset);

		/* Copy the boxed into our pointer (will use eg.
		 * vips__object_vector_dup ()).
		 */
		g_value_set_boxed (value, *member);
	}
	else {
		g_warning ("%s: unimplemented property type", G_STRLOC);
	}
}

static void
vips_object_real_changed( VipsObject *object )
{
#ifdef DEBUG
	VipsObject *object = VIPS_OBJECT( gobject );

	printf( "vips_object_real_changed: " );
	vips_object_print( object );
#endif /*DEBUG*/
}

static void
vips_object_real_print_class( VipsObjectClass *class, im_buf_t *buf )
{
	im_buf_appendf( buf, "%s", G_OBJECT_CLASS_NAME( class ) );
	if( class->nickname )
		im_buf_appendf( buf, " (%s)", class->nickname );
	if( class->description )
		im_buf_appendf( buf, ", %s", class->description );
}

static void
vips_object_real_print( VipsObject *object, im_buf_t *buf )
{
	if( object->name )
		im_buf_appendf( buf, "\"%s\"", object->name );
}

static void
vips_object_class_init( VipsObjectClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );

	gobject_class->dispose = vips_object_dispose;
	gobject_class->finalize = vips_object_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	class->changed = vips_object_real_changed;
	class->print_class = vips_object_real_print_class;
	class->print = vips_object_real_print;
	class->nickname = "object";
	class->description = _( "VIPS base class" );

	vips_object_signals[SIG_CHANGED] = g_signal_new( "changed",
		G_OBJECT_CLASS_TYPE( gobject_class ),
		G_SIGNAL_RUN_FIRST,
		G_STRUCT_OFFSET( VipsObjectClass, changed ),
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
}

void
vips_object_set_name( VipsObject *object, const char *name )
{
	IM_SETSTR( object->name, name );
	vips_object_changed( object );
}

/* Add a vipsargument ... automate some stuff with this.
 */
void
vips_object_class_install_argument (VipsObjectClass *object_class, 
	GParamSpec *pspec, VipsArgumentFlags flags, guint offset)
{
	VipsArgumentClass *argument_class = g_new (VipsArgumentClass, 1);

	/* Must be a new one.
	 */
	g_assert (!vips__argument_table_lookup (object_class->argument_table,
		pspec));

	/* Mustn't have INPUT and OUTPUT both set.
	 */
	g_assert ((flags & (VIPS_ARGUMENT_INPUT | VIPS_ARGUMENT_OUTPUT)) != 
		(VIPS_ARGUMENT_INPUT | VIPS_ARGUMENT_OUTPUT));

	((VipsArgument *) argument_class)->pspec = pspec;
	argument_class->object_class = object_class;
	argument_class->flags = flags;
	argument_class->offset = offset;

	vips_argument_table_replace (object_class->argument_table,
		(VipsArgument *) argument_class);
	object_class->argument_table_traverse = g_slist_append (
		object_class->argument_table_traverse, argument_class);
}

/* Has a property been set?
 */
gboolean 
vips_object_argument_assigned (VipsObject *object, const char *property_name)
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS (object);
	GParamSpec *pspec;
	VipsArgumentClass *argument_class;
	VipsArgumentInstance *argument_instance;

	if (!(pspec = g_object_class_find_property (
		G_OBJECT_CLASS (object_class), property_name))) {
		g_warning ("property %s not found", property_name);
		return (FALSE);
	}
	if (!(argument_class = (VipsArgumentClass *) 
		vips__argument_table_lookup (object_class->argument_table, 
			pspec))) {
		g_warning ("vips argument for property %s not found", 
			property_name);
		return (FALSE);
	}
	if (!(argument_instance = vips__argument_get_instance (
		argument_class, object))) {
		g_warning ("properties for vips argument %s not found", 
			property_name);
		return (FALSE);
	}

	return (argument_instance->assigned);
}

