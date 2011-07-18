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
 
   	TODO:

	- works for iamges, but not tested for much else
	- masks would be hard, vips8 won't really have these
	- keep for testing, mostly ... iofuncs/init.c has a commeted-out
	  call to init this thing

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

#define VIPS_WRAP7_PREFIX "VipsWrap7_"

static GHashTable *vips_wrap7_subclass_types = NULL;

/* VipsWrap7 is an abstract type ... subclass for each operation we wrap with 
 * no extra members.
 */

typedef struct _VipsWrap7 {
	VipsOperation parent_object;

	/* vips7 dispatch spine we build.
	 */
	im_object *vargv;

	/* Set if we get an error during construct.
	 */
	gboolean error;

} VipsWrap7;

typedef struct _VipsWrap7Class { 
	VipsOperationClass  parent_class;

	/* Look this up from the class name.
	 */
	im_function *fn;

	/* Set if we can't wrap this im_function for some reason.
	 */
	gboolean not_supported;

} VipsWrap7Class;

#define VIPS_TYPE_WRAP7 (vips_wrap7_get_type())
#define VIPS_WRAP7( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), VIPS_TYPE_WRAP7, VipsWrap7 ))
#define VIPS_WRAP7_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), VIPS_TYPE_WRAP7, VipsWrap7Class))
#define VIPS_IS_WRAP7( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_WRAP7 ))
#define VIPS_IS_WRAP7_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_WRAP7 ))
#define VIPS_WRAP7_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), VIPS_TYPE_WRAP7, VipsWrap7Class ))

typedef enum {
	VIPS_WRAP7_NONE = -1,
	VIPS_WRAP7_DOUBLE = 0,
	VIPS_WRAP7_INT,
	VIPS_WRAP7_COMPLEX,
	VIPS_WRAP7_STRING,
	VIPS_WRAP7_IMAGE,
	VIPS_WRAP7_DOUBLEVEC,
	VIPS_WRAP7_DMASK,
	VIPS_WRAP7_IMASK,
	VIPS_WRAP7_IMAGEVEC,
	VIPS_WRAP7_INTVEC,
	VIPS_WRAP7_GVALUE,
	VIPS_WRAP7_INTERPOLATE
} VipsWrap7Type;

static char *vips_wrap7_supported[] = {
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
static VipsWrap7Type
vips_wrap7_lookup_type( im_arg_type type )
{
	int i;

	for( i = 0; i < VIPS_NUMBER( vips_wrap7_supported ); i++ )
		if( strcmp( type, vips_wrap7_supported[i] ) == 0 )
			return( (VipsWrap7Type) i );

	return( VIPS_WRAP7_NONE );
}

G_DEFINE_ABSTRACT_TYPE( VipsWrap7, vips_wrap7, VIPS_TYPE_OPERATION );

/* Drop any refs vargv may hold.
 */
static void
vips_wrap7_vargv_dispose( im_function *fn, im_object *vargv )
{
	int i;

	for( i = 0; i < fn->argc; i++ ) {
		im_arg_desc *arg = &fn->argv[i];
		im_type_desc *type = arg->desc;
		im_arg_type vt = type->type;

		switch( vips_wrap7_lookup_type( vt ) ) {
		case VIPS_WRAP7_NONE:         /* IM_TYPE_DISPLAY */
		case VIPS_WRAP7_DOUBLE:
		case VIPS_WRAP7_INT:
		case VIPS_WRAP7_COMPLEX:
		case VIPS_WRAP7_DOUBLEVEC:
		case VIPS_WRAP7_INTVEC:
		case VIPS_WRAP7_DMASK:
		case VIPS_WRAP7_IMASK:
			/* Do nothing.
			 */
			break;

		case VIPS_WRAP7_INTERPOLATE:
		case VIPS_WRAP7_IMAGE:
			if( vargv[i] ) 
				VIPS_UNREF( vargv[i] );
			break;

		case VIPS_WRAP7_IMAGEVEC:
{
			im_imagevec_object *iv = vargv[i]; 
			int j; 

			for( j = 0; j < iv->n; j++ )
				if( iv->vec[j] ) 
					VIPS_UNREF( iv->vec[j] );
}
			break;

		case VIPS_WRAP7_GVALUE:
			g_value_unset( vargv[i] );
			break;

		default:
			g_assert( FALSE );
		}
	}
}

static void
vips_wrap7_dispose( GObject *gobject )
{
	VipsWrap7 *wrap7 = VIPS_WRAP7( gobject );
	VipsWrap7Class *class = VIPS_WRAP7_GET_CLASS( wrap7 );

#ifdef DEBUG
	printf( "vips_wrap7_dispose: " );
	vips_object_print_name( VIPS_OBJECT( wrap7 ) );
	printf( "\n" );
#endif /*DEBUG*/

	vips_wrap7_vargv_dispose( class->fn, wrap7->vargv );

	G_OBJECT_CLASS( vips_wrap7_parent_class )->dispose( gobject );
}

/* Junk stuff we may have attached to vargv.
 */
static void
vips_wrap7_vargv_finalize( im_function *fn, im_object *vargv )
{
	int i;

	for( i = 0; i < fn->argc; i++ ) {
		im_arg_desc *arg = &fn->argv[i];
		im_type_desc *type = arg->desc;
		im_arg_type vt = type->type;

		switch( vips_wrap7_lookup_type( vt ) ) {
		case VIPS_WRAP7_NONE:         /* IM_TYPE_DISPLAY */
		case VIPS_WRAP7_DOUBLE:
		case VIPS_WRAP7_INT:
		case VIPS_WRAP7_COMPLEX:
		case VIPS_WRAP7_GVALUE:
		case VIPS_WRAP7_INTERPOLATE:
		case VIPS_WRAP7_IMAGE:
			/* Do nothing.
			 */
			break;

		case VIPS_WRAP7_STRING:
			VIPS_FREE( vargv[i] );
			break;

		case VIPS_WRAP7_IMAGEVEC:
			VIPS_FREE( ((im_imagevec_object *) vargv[i])->vec );
			break;

		case VIPS_WRAP7_DOUBLEVEC:
			VIPS_FREE( ((im_doublevec_object *) vargv[i])->vec );
			break;

		case VIPS_WRAP7_INTVEC:
			VIPS_FREE( ((im_intvec_object *) vargv[i])->vec );
			break;

		case VIPS_WRAP7_DMASK:
			VIPS_FREE( ((im_mask_object *) vargv[i])->name );
			VIPS_FREEF( im_free_dmask,
				((im_mask_object *) vargv[i])->mask );
			break;

		case VIPS_WRAP7_IMASK:
			VIPS_FREE( ((im_mask_object *) vargv[i])->name );
			VIPS_FREEF( im_free_imask,
				((im_mask_object *) vargv[i])->mask );
			break;

		default:
			g_assert( FALSE );
		}
	}
}

static void
vips_wrap7_finalize( GObject *gobject )
{
	VipsWrap7 *wrap7 = VIPS_WRAP7( gobject );
	VipsWrap7Class *class = VIPS_WRAP7_GET_CLASS( wrap7 );

#ifdef DEBUG
	printf( "vips_wrap7_finalize: " );
	vips_object_print_name( VIPS_OBJECT( wrap7 ) );
	printf( "\n" );
#endif /*DEBUG*/

	if( wrap7->vargv ) {
		vips_wrap7_vargv_finalize( class->fn, wrap7->vargv );
		im_free_vargv( class->fn, wrap7->vargv );
		VIPS_FREE( wrap7->vargv );
	}

	G_OBJECT_CLASS( vips_wrap7_parent_class )->finalize( gobject );
}

/* Like the one in object.c, but write to vargv instead. Use offset to record
 * the index in vargv we set.
 */
static void
vips_wrap7_object_set_property( GObject *gobject,
	guint property_id, const GValue *value, GParamSpec *pspec )
{
	VipsObject *object = VIPS_OBJECT( gobject );
	VipsObjectClass *oclass = VIPS_OBJECT_GET_CLASS( gobject );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( oclass->argument_table, pspec );
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance( argument_class, object );

	VipsWrap7 *wrap7 = VIPS_WRAP7( gobject );
	VipsWrap7Class *class = VIPS_WRAP7_GET_CLASS( wrap7 );
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
		object->constructed &&
		!vips_pspec_value_is_null( pspec, value ) ) {
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
		!vips_pspec_value_is_null( pspec, value ) ) {
		g_warning( "%s: %s can only assign '%s' once",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_param_spec_get_name( pspec ) );
		return;
	}

	switch( vips_wrap7_lookup_type( vt ) ) {
	case VIPS_WRAP7_DOUBLE:
		*((double*)wrap7->vargv[i]) = g_value_get_double( value );
		break;

	case VIPS_WRAP7_INT:
		*((int*)wrap7->vargv[i]) = g_value_get_int( value );
		break;

	case VIPS_WRAP7_STRING:
		VIPS_SETSTR( wrap7->vargv[i], g_value_get_string( value ) );
		break;

	case VIPS_WRAP7_GVALUE:
		g_value_init( wrap7->vargv[i], G_VALUE_TYPE( value ) );
		g_value_copy( value, wrap7->vargv[i] );
		break;

	case VIPS_WRAP7_IMAGE:
	case VIPS_WRAP7_INTERPOLATE:
		vips__object_set_member( object, pspec,
			(GObject **) &wrap7->vargv[i], 
			g_value_get_object( value ) );
		break;

	default:
		wrap7->error = TRUE;
		break;
	}

	/* Note that it's now been set.
	 */
	argument_instance->assigned = TRUE;
}

static void
vips_wrap7_object_get_property( GObject *gobject,
	guint property_id, GValue *value, GParamSpec *pspec )
{
	VipsObject *object = VIPS_OBJECT( gobject );
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( gobject );
	VipsArgumentClass *argument_class = (VipsArgumentClass *)
		vips__argument_table_lookup( class->argument_table, pspec );
	VipsArgumentInstance *argument_instance =
		vips__argument_get_instance( argument_class, object );

	VipsWrap7 *wrap7 = VIPS_WRAP7( gobject );
	VipsWrap7Class *wclass = VIPS_WRAP7_GET_CLASS( wrap7 );
	int i = argument_class->offset;
	im_arg_desc *arg = &wclass->fn->argv[i];
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

	switch( vips_wrap7_lookup_type( vt ) ) {
	case VIPS_WRAP7_DOUBLE:
		g_value_set_double( value, *((double*)wrap7->vargv[i]) ); 
		break;

	case VIPS_WRAP7_INT:
		g_value_set_int( value, *((int*)wrap7->vargv[i]) ); 
		break;

	case VIPS_WRAP7_STRING:
		g_value_set_string( value, wrap7->vargv[i] );
		break;

	case VIPS_WRAP7_IMAGE:
	case VIPS_WRAP7_INTERPOLATE:
	case VIPS_WRAP7_GVALUE:
		g_value_set_object( value, wrap7->vargv[i] ); 
		break;

	default:
		g_warning( "%s: %s unimplemented property type %s",
			G_STRLOC,
			G_OBJECT_TYPE_NAME( gobject ),
			g_type_name( G_PARAM_SPEC_VALUE_TYPE( pspec ) ) );
		break;
	}
}

/* Init an output slot in vargv.
 */
static void *
vips_wrap7_build_output( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsWrap7 *wrap7 = VIPS_WRAP7( object );  
	VipsWrap7Class *class = VIPS_WRAP7_GET_CLASS( wrap7 );
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
	switch( vips_wrap7_lookup_type( vt ) ) {
	case VIPS_WRAP7_DOUBLE:
	case VIPS_WRAP7_INT:
	case VIPS_WRAP7_COMPLEX:
	case VIPS_WRAP7_STRING:
		break;

	case VIPS_WRAP7_IMAGE:
		g_object_set( object, arg->name, vips_image_new(), NULL ); 
		break;

	case VIPS_WRAP7_DMASK:
	case VIPS_WRAP7_IMASK:
		break;

	case VIPS_WRAP7_GVALUE:
	{
		GValue *value = wrap7->vargv[i];

		memset( value, 0, sizeof( GValue ) );

		break;
	}

	case VIPS_WRAP7_DOUBLEVEC:
	case VIPS_WRAP7_INTVEC:
	default:
		wrap7->error = TRUE;
		break;
	}

	return( NULL );
}

static int
vips_wrap7_build( VipsObject *object )
{
	VipsWrap7 *wrap7 = VIPS_WRAP7( object );
	VipsWrap7Class *class = VIPS_WRAP7_GET_CLASS( wrap7 );
	VipsObjectClass *oclass = VIPS_OBJECT_CLASS( class );

	if( wrap7->error ) {
		vips_error( "wrap7", 
			_( "error constructing vips7 operation %s" ), 
			oclass->nickname );
		return( -1 );
	}

	if( class->not_supported ) {
		vips_error( "wrap7", _( "unable to call vips7 operation "
			"%s from vips8" ), oclass->nickname );
		return( -1 );
	}

#ifdef DEBUG
	printf( "vips_wrap7_build: " );
	vips_object_print_name( VIPS_OBJECT( wrap7 ) );
	printf( " building output\n" );
#endif /*DEBUG*/

	/* Init all the output args.
	 */
	(void) vips_argument_map( VIPS_OBJECT( wrap7 ),
		vips_wrap7_build_output, 
		NULL, NULL ); 

	if( VIPS_OBJECT_CLASS( vips_wrap7_parent_class )->build( object ) )
		return( -1 );

	if( class->fn->disp( wrap7->vargv ) )
		return( -1 );

	return( 0 );
}

static void
vips_wrap7_print_class( VipsObjectClass *oclass, VipsBuf *buf )
{
	VipsWrap7Class *class = VIPS_WRAP7_CLASS( oclass );
	im_function *fn = class->fn;

	if( fn )
		vips_buf_appendf( buf, "%s ", fn->name );
	else
		vips_buf_appendf( buf, "%s ", G_OBJECT_CLASS_NAME( class ) );

	if( oclass->nickname )
		vips_buf_appendf( buf, "(%s), ", oclass->nickname );
	if( oclass->description )
		vips_buf_appendf( buf, "%s", oclass->description );

	if( fn )
		vips_buf_appendf( buf, ", from package \"%s\"", 
			im_package_of_function( fn->name )->name );
}

static void
vips_wrap7_print( VipsObject *object, VipsBuf *buf )
{
	VipsWrap7Class *class = VIPS_WRAP7_GET_CLASS( object );
	im_function *fn = class->fn;
	im_package *pack = im_package_of_function( fn->name );

	VIPS_OBJECT_CLASS( vips_wrap7_parent_class )->print( object, buf );

	if( pack )
		vips_buf_appendf( buf, "from package \"%s\"", pack->name );
	vips_buf_appendf( buf, "\n" );

	/* Print any flags this function has.
	 */
	vips_buf_appendf( buf, "flags: " );
	if( fn->flags & IM_FN_PIO )
		vips_buf_appendf( buf, "(PIO function) " );
	else
		vips_buf_appendf( buf, "(WIO function) " );
	if( fn->flags & IM_FN_TRANSFORM )
		vips_buf_appendf( buf, "(coordinate transformer) " );
	else
		vips_buf_appendf( buf, "(no coordinate transformation) " );
	if( fn->flags & IM_FN_PTOP )
		vips_buf_appendf( buf, "(point-to-point operation) " );
	else
		vips_buf_appendf( buf, "(area operation) " );
	if( fn->flags & IM_FN_NOCACHE )
		vips_buf_appendf( buf, "(nocache operation) " );
	else
		vips_buf_appendf( buf, "(result can be cached) " );

	vips_buf_appendf( buf, "\n" );
}

static void
vips_wrap7_class_init( VipsWrap7Class *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *vobject_class = (VipsObjectClass *) class;

	gobject_class->dispose = vips_wrap7_dispose;
	gobject_class->finalize = vips_wrap7_finalize;

	vobject_class->nickname = "wrap7";
	vobject_class->description = _( "vips7 operations as vips8 classes" );
	vobject_class->build = vips_wrap7_build;
	vobject_class->print_class = vips_wrap7_print_class;
	vobject_class->print = vips_wrap7_print;
}

static void
vips_wrap7_init( VipsWrap7 *wrap7 )
{
}

/* Build a subclass of vips7 for every vips7 operation.
 */

static void
vips_wrap7_subclass_class_init( VipsWrap7Class *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *vobject_class = (VipsObjectClass *) class;

	/* The name of the vips operation we wrap is hidden in our class name.
	 */
	const char *name = G_OBJECT_CLASS_NAME( class ) + 
		strlen( VIPS_WRAP7_PREFIX );
	im_function *fn = im_find_function( name );

	int i;

	g_assert( !class->fn );
	g_assert( fn );

	gobject_class->set_property = vips_wrap7_object_set_property;
	gobject_class->get_property = vips_wrap7_object_get_property;

	vobject_class->nickname = im_strdup( NULL, name );
	vobject_class->description = fn->desc;

	class->fn = fn;

	for( i = fn->argc - 1; i >= 0; i-- ) {
		im_arg_desc *arg = &fn->argv[i];
		im_type_desc *type = arg->desc;
		im_arg_type vt = type->type;

		GParamSpec *pspec;

		switch( vips_wrap7_lookup_type( vt ) ) {
		case VIPS_WRAP7_DOUBLEVEC:
		case VIPS_WRAP7_DMASK:
		case VIPS_WRAP7_IMASK:
		case VIPS_WRAP7_IMAGEVEC:
		case VIPS_WRAP7_INTVEC:
		case VIPS_WRAP7_GVALUE:
		case VIPS_WRAP7_INTERPOLATE:
		case VIPS_WRAP7_DOUBLE:
		case VIPS_WRAP7_INT:
		case VIPS_WRAP7_COMPLEX:
		case VIPS_WRAP7_STRING:
		case VIPS_WRAP7_NONE:
			/* Can't wrap this function. class_init can't fail, so
			 * set a flag to block _build().
			 */
			class->not_supported = TRUE;
			break;

		case VIPS_WRAP7_IMAGE:
			pspec = g_param_spec_object( arg->name, 
				arg->name, 
				arg->name,
				VIPS_TYPE_IMAGE,
				G_PARAM_READWRITE );
			g_object_class_install_property( gobject_class, 
				i + 1, pspec );
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
vips_wrap7_subclass_init( VipsWrap7 *wrap7 )
{
	VipsWrap7Class *class = VIPS_WRAP7_GET_CLASS( wrap7 );
	im_function *fn = class->fn;

        if( !(wrap7->vargv = IM_ARRAY( NULL, fn->argc + 1, im_object )) ||
		im_allocate_vargv( fn, wrap7->vargv ) ) {
		wrap7->error = TRUE;
		return;
	}
}

static GType
vips_wrap7_subclass_get_type( im_function *fn )
{
	static const GTypeInfo info = {
		sizeof( VipsWrap7Class ),
		NULL,           /* base_init */
		NULL,           /* base_finalize */
		(GClassInitFunc) vips_wrap7_subclass_class_init,
		NULL,           /* class_finalize */
		NULL,           /* class_data */
		sizeof( VipsWrap7 ),
		32,             /* n_preallocs */
		(GInstanceInitFunc) vips_wrap7_subclass_init,
	};

	char name[256];
	GType type;

	if( !vips_wrap7_subclass_types )
		vips_wrap7_subclass_types = 
			g_hash_table_new( g_direct_hash, g_direct_equal );

	if( (type = (GType) 
		g_hash_table_lookup( vips_wrap7_subclass_types, fn )) )
		return( type );

	im_snprintf( name, 256, VIPS_WRAP7_PREFIX "%s", fn->name );
	type = g_type_register_static( VIPS_TYPE_WRAP7, name, &info, 0 );
	g_hash_table_insert( vips_wrap7_subclass_types, fn, (gpointer) type );

	return( type );
}

static void *
vips_wrap7_build_package( im_package *package )
{
	int i;

	for( i = 0; i < package->nfuncs; i++ ) 
		(void) vips_wrap7_subclass_get_type( package->table[i] ); 

	return( NULL );
}

/* Walk the whole of the vips7 operation table building classes. 
 */
void
vips__init_wrap7_classes( void )
{
	(void) im_map_packages( (VSListMap2Fn) vips_wrap7_build_package, NULL );
}
