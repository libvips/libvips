/* wrap a vips7 operation as a vips8 class
 * 
 * 12/7/11
 * 	- quick hack
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

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>
#include <vips/vector.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define VIPS7_PREFIX "Vips7_"

static GHashTable *vips7_types = NULL;

typedef struct _Vips7 {
	VipsOperation parent_object;

	/* vips7 dispatch spine we build.
	 */
	im_object *vargv;

	/* Set if we get an error during construct.
	 */
	gboolean error;

} Vips7;

typedef struct _Vips7Class { 
	VipsOperationClass  parent_class;

	/* Look this up from the class name.
	 */
	im_function *fn;

	/* Set if we can't wrap this im_function for some reason.
	 */
	gboolean not_supported;

} Vips7Class;

typedef enum {
	VIPS7_NONE = -1,
	VIPS7_DOUBLE = 0,
	VIPS7_INT,
	VIPS7_COMPLEX,
	VIPS7_STRING,
	VIPS7_IMAGE,
	VIPS7_DOUBLEVEC,
	VIPS7_DMASK,
	VIPS7_IMASK,
	VIPS7_IMAGEVEC,
	VIPS7_INTVEC,
	VIPS7_GVALUE,
	VIPS7_INTERPOLATE
} Vips7Type;

static char *vips7_supported[] = {
	IM_TYPE_DOUBLE,
	IM_TYPE_INT,
	IM_TYPE_COMPLEX,
	IM_TYPE_STRING,
	IM_TYPE_IMAGE,
	IM_TYPE_DOUBLEVEC,
	IM_TYPE_DMASK,
	IM_TYPE_IMASK,
	IM_TYPE_IMAGEVEC,
	IM_TYPE_INTVEC,
	IM_TYPE_GVALUE,
	IM_TYPE_INTERPOLATE
};

/* Turn a vips7 type name to an enum.
 */
static Vips7Type
vips7_lookup_type( im_arg_type type )
{
	int i;

	for( i = 0; i < IM_NUMBER( vips7_supported ); i++ )
		if( strcmp( type, vips7_supported[i] ) == 0 )
			return( (Vips7Type) i );

	return( VIPS7_NONE );
}

static void
vips7_dispose( GObject *gobject )
{
	Vips7 *vips7 = VIPS7( gobject );

#ifdef DEBUG
	printf( "vips7_dispose: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	G_OBJECT_CLASS( parent_class )->dispose( gobject );
}

/* Junk stuff we may have attached to vargv.
 */
static void
vips7_vargv_free( im_function *fn, im_object *vargv )
{
	int i;

	for( i = 0; i < fn->argc; i++ ) {
		im_arg_desc *arg = &fn->argv[i];
		im_type_desc *type = arg->desc;
		im_arg_type vt = type->type;

		switch( vips7_lookup_type( vt ) ) {
		case CALL_NONE:         /* IM_TYPE_DISPLAY */
		case CALL_DOUBLE:
		case CALL_INT:
		case CALL_COMPLEX:
		case CALL_GVALUE:
		case CALL_INTERPOLATE:
		case CALL_IMAGE:
			/* Do nothing.
			 */
			break;

		case CALL_STRING:
			VIPS_FREE( obj );
			break;

		case CALL_IMAGEVEC:
			VIPS_FREE( ((im_imagevec_object *) obj)->vec );
			break;

		case CALL_DOUBLEVEC:
			VIPS_FREE( ((im_doublevec_object *) obj)->vec );
			break;

		case CALL_INTVEC:
			VIPS_FREE( ((im_intvec_object *) obj)->vec );
			break;

		case CALL_DMASK:
			VIPS_FREE( ((im_mask_object *) obj)->name );
			VIPS_FREEF( im_free_dmask,
				((im_mask_object *) obj)->mask );
			break;

		case CALL_IMASK:
			VIPS_FREE( ((im_mask_object *) obj)->name );
			VIPS_FREEF( im_free_imask,
				((im_mask_object *) obj)->mask );
			break;

		default:
			g_assert( FALSE );
		}
	}
}

static void
vips7_finalize( GObject *gobject )
{
	Vips7 *vips7 = VIPS7( gobject );
	Vips7Class *class = VIPS7_GET_CLASS( vips7 );

#ifdef DEBUG
	printf( "vips7_finalize: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( vips7->vargv ) {
		vips7_vargv_free( class->fn, vips7->vargv )
		im_free_vargv( class->fn, vips7->vargv );
		VIPS_FREE( vips7->vargv );
	}

	G_OBJECT_CLASS( parent_class )->finalize( gobject );
}

static void
vips7_object_set_property( GObject *gobject,
	guint property_id, const GValue *value, GParamSpec *pspec )
{
	VipsObject *object = VIPS_OBJECT( gobject );
	VipsObjectClass *oclass = VIPS_OBJECT_GET_CLASS( gobject );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( oclass->argument_table, pspec );
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance( argument_class, object );

	Vips7 *vips7 = VIPS7( gobject );
	Vips7Class *class = VIPS7_GET_CLASS( vips7 );
	int i = argument_class->offset;
	im_arg_desc *arg = &class->fn->argv[i];
	im_type_desc *type = arg->desc;
	im_arg_type vt = type->type;

	g_assert( argument_instance );

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
	vips_object_print_name( object );
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

	switch( vips7_lookup_type( vt ) ) {
	case VIPS7_DOUBLE:
		*((double*)vi->vargv[i]) = g_value_get_double( value );
		break;

	case VIPS7_INT:
		*((int*)vi->vargv[i]) = g_value_get_int( value );
		break;

	case VIPS7_STRING:
		VIPS_SETSTR( vi->vargv[i], g_value_get_string( value ) );
		break;

	case VIPS7_GVALUE:
		vi->vargv[i] = value;
		break;

	case VIPS7_IMAGE:
	case VIPS7_INTERPOLATE:
		vi->vargv[i] = g_value_get_object( value );
		break;

	default:
		vips7->error = TRUE;
		break;
	}

	/* Note that it's now been set.
	 */
	argument_instance->assigned = TRUE;
}

static void
vips7_object_get_property( GObject *gobject,
	guint property_id, GValue *value, GParamSpec *pspec )
{
	VipsObject *object = VIPS_OBJECT( gobject );
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gobject );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( class->argument_table, pspec );

	Vips7 *vips7 = VIPS7( gobject );
	Vips7Class *class = VIPS7_GET_CLASS( vips7 );
	int i = argument_class->offset;
	im_arg_desc *arg = &class->fn->argv[i];
	im_type_desc *type = arg->desc;
	im_arg_type vt = type->type;

	if( !argument_class ) {
		G_OBJECT_WARN_INVALID_PROPERTY_ID( gobject,
			property_id, pspec );
		return;
	}

	g_assert( ((VipsArgument *) argument_class)->pspec == pspec );

	if( !argument_instance->assigned ) {
		g_warning( "%s: %s attempt to read unset property %s",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_type_name( G_PARAM_SPEC_VALUE_TYPE( pspec ) ) );
		return;
	}

	switch( vips7_lookup_type( vt ) ) {
	case VIPS7_DOUBLE:
		g_value_set_double( value, *((double*)vi->vargv[i]) ); 
		break;

	case VIPS7_INT:
		g_value_set_int( value, *((int*)vi->vargv[i]) ); 
		break;

	case VIPS7_STRING:
		g_value_set_string( value, vi->vargv[i] );
		break;

	case VIPS7_IMAGE:
	case VIPS7_INTERPOLATE:
	case VIPS7_GVALUE:
		g_value_set_object( value, vi->vargv[i] ); 
		break;

	default:
		g_warning( "%s: %s unimplemented property type %s",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_type_name( G_PARAM_SPEC_VALUE_TYPE( pspec ) ) );
		break;
	}
}

static int
vips7_build( VipsObject *object )
{
	Vips7 *vips7 = VIPS_VIPS7( object );
	Vips7Class *class = VIPS7_GET_CLASS( vips7 );
	im_function *fn = class->fn;

	if( vips7->error ) {
		vips_error( "vips7", 
			_( "error constructing vips7 operation %s" ), 
			class->nickname );
		return( -1 );
	}

	if( class->not_supported ) {
		vips_error( "vips7", _( "unable to call vips7 operation "
			"%s from vips8" ), class->nickname );
		return( -1 );
	}

	if( VIPS_OBJECT_CLASS( parent_class )->build( object ) )
		return( -1 );

	if( fn->disp( vips7->vargv ) )
		return( -1 );

	return( 0 );
}

static void
vips7_class_init( VipsVips7Class *class )
{
	/* The name of the vips operation we wrap is hidden in our class name.
	 */
	const char *name = G_OBJECT_CLASS_NAME( class ) + 
		strlen( VIPS7_PREFIX );

	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *oclass = VIPS_OPERATION_CLASS( class );

	im_function *fn = im_find_function( name );

	int i;

	g_assert( fn );

	gobject_class->dispose = vips7_dispose;
	gobject_class->finalize = vips7_finalize;
	gobject_class->set_property = vips7_object_set_property;
	gobject_class->get_property = vips7_object_get_property;

	object_class->build = vips7_build;
	object_class->nickname = name;
	object_class->description = fn->desc;

	class->fn = fn;

	for( i = 0; i < fn->argc; i++ ) {
		im_arg_desc *arg = &fn->argv[i];
		im_type_desc *type = arg->desc;
		im_arg_type vt = type->type;

		GParamSpec *pspec;

		switch( vips7_lookup_type( vt ) ) {
		case VIPS7_DOUBLEVEC:
		case VIPS7_DMASK:
		case VIPS7_IMASK:
		case VIPS7_IMAGEVEC:
		case VIPS7_INTVEC:
		case VIPS7_GVALUE:
		case VIPS7_INTERPOLATE:
		case VIPS7_DOUBLE:
		case VIPS7_INT:
		case VIPS7_COMPLEX:
		case VIPS7_STRING:
		case VIPS7_NONE:
			/* Can't wrap this function. class_init can't fail, so
			 * set a flag to block _build().
			 */
			class->not_supported = TRUE;
			break;

		case VIPS7_IMAGE:
			pspec = g_param_spec_object( arg->name, 
				arg->name, 
				arg->name,
				VIPS_TYPE_IMAGE,
				G_PARAM_READWRITE );
			g_object_class_install_property( gobject_class, 
				i, pspec );
			vips_object_class_install_argument( vobject_class, 
				pspec,
				(type->flags & IM_TYPE_OUTPUT) ?
					VIPS_ARGUMENT_REQUIRED_OUTPUT : 
					VIPS_ARGUMENT_REQUIRED_INPUT,
				i );
			break;

		default:
			g_assert( 0 );
		}
	}
}

static void
vips7_arg_close( GObject *argument,
	VipsArgumentInstance *argument_instance )
{
	VipsObject *object = argument_instance->object;
	GParamSpec *pspec = ((VipsArgument *) argument_instance)->pspec;

	g_object_unref( object );
}

/* Init an output slot in vargv.
 */
static void *
vips7_build_output( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	Vips7 *vips7 = VIPS7( object );  
	Vips7Class *class = VIPS7_GET_CLASS( vips7 );
	int i = argument_class->offset;
	im_arg_desc *arg = &class->fn->argv[i];
	im_type_desc *type = arg->desc;
	im_arg_type vt = type->type;

	/* We want required, construct-time, unassigned output args.
	 */
	if( !(argument_class->flags & VIPS_ARGUMENT_REQUIRED) ||
		!(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ||
		argument_instance->assigned ||
		!(argument_class->flags & VIPS_ARGUMENT_OUTPUT) )
		return( NULL ); 

	/* Provide output objects for the operation to write to.
	 */
	switch( vips7_lookup_type( vt ) ) {
	case VIPS7_DOUBLE:
	case VIPS7_INT:
	case VIPS7_COMPLEX:
	case VIPS7_STRING:
		break;

	case VIPS7_IMAGE:
		/* Output objects ref this operation.
		 */
		vips7->vargv[i] = vips_image_new(); 
		g_object_ref( vips7 );

		/* vipsobject will handle close_id disconnect for us.
		 */
		argument_instance->close_id =
			g_signal_connect( *member, "close",
				G_CALLBACK( vips7_arg_close ),
				argument_instance );
		break;

	case VIPS7_DMASK:
	case VIPS7_IMASK:
	{
		im_mask_object *mo = vips7->vargv[i];

		mo->mask = NULL;
		mo->name = im_strdup( NULL, "" );

		break;
	}

	case VIPS7_GVALUE:
	{
		GValue *value = vips7->vargv[i];

		memset( value, 0, sizeof( GValue ) );

		break;
	}

	case VIPS7_DOUBLEVEC:
	case VIPS7_INTVEC:
	{
		/* intvec is also int + pointer.
		 */
		im_doublevec_object *dv = vips7->vargv[i];

		dv->n = 0;
		dv->vec = NULL;

		break;
	}

	default:
		vips7->error = TRUE;
		break;
	}

	return( NULL );
}

static void
vips7_init( VipsVips7 *vips7 )
{
	Vips7Class *class = VIPS7_GET_CLASS( vips7 );
	im_function *fn = class->fn;

        if( !(vips7->vargv = IM_ARRAY( NULL, fn->argc + 1, im_object )) ||
		im_allocate_vargv( vi->fn, vi->vargv ) ) {
		vips7->error = TRUE;
		return;
	}

	/* Init all the output args.
	 */
	(void) vips_argument_map( VIPS_OBJECT( vips7 ),
		vips_call_char_option, 
		(void *) name, (void *) value );
}

static GType
vips7_get_type( im_function *fn )
{
	static const GTypeInfo info = {
		sizeof( VipsVips7Class ),
		NULL,           /* base_init */
		NULL,           /* base_finalize */
		(GClassInitFunc) vips_vips7_class_init,
		NULL,           /* class_finalize */
		NULL,           /* class_data */
		sizeof( VipsVips7 ),
		32,             /* n_preallocs */
		(GInstanceInitFunc) vips_vips7_init,
	};

	char name[256];
	GType type;

	if( !vips7_types )
		vips7_types = g_hash_table_new( g_direct_hash, g_direct_equal );

	if( (type = g_hash_table_lookup( vips7_types, fn )) )
		return( type );

	im_snprintf( name, 256, VIPS7_PREFIX "%s", fn->name );
	type = g_type_register_static( VIPS_OPERATION, name, &info, 0 );
	g_hash_table_insert( vips7_types, fn, type );

	return( type );
}



/* Walk the whole of the vips7 operation table building classes.
 */
void
vips__init_vips7_classes( void )
{
}
