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
#define DEBUG
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

#include <gobject/gvaluecollector.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Abstract base class for operations.
 */

G_DEFINE_ABSTRACT_TYPE( VipsOperation, vips_operation, VIPS_TYPE_OBJECT );

/* What to show about the argument.
 */
typedef struct {
	gboolean required;	/* show required args or optional */
	gboolean oftype;	/* "is of type" message */
	int n;			/* Arg number */
} VipsOperationPrint;

static void *
vips_operation_print_arg( VipsObject *object, GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	VipsBuf *buf, VipsOperationPrint *print )
{
	/* Only show unassigned args ... assigned args are internal.
	 */

	if( print->required == 
		((argument_class->flags & VIPS_ARGUMENT_REQUIRED) != 0) &&
		!argument_instance->assigned ) {
		if( print->oftype ) 
			vips_buf_appendf( buf, "   %s :: %s\n",
				pspec->name,
				g_type_name( pspec->value_type ) );
		else {
			if( print->n > 0 )
				vips_buf_appends( buf, ", " );
			vips_buf_appends( buf, pspec->name );
		}

		print->n += 1;
	}

	return( NULL );
}

static void
vips_operation_print( VipsObject *object, VipsBuf *buf )
{
	VipsOperation *operation = VIPS_OPERATION( object );
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );
	VipsOperationPrint print;

	/* First pass through args: show the required names.
	 */
	vips_buf_appendf( buf, "VipsOperation.%s (", object_class->nickname );
	print.required = TRUE;
	print.oftype = FALSE;
	print.n = 0;
	vips_argument_map( VIPS_OBJECT( operation ),
		(VipsArgumentMapFn) vips_operation_print_arg, buf, &print );
	vips_buf_appends( buf, ")\n" );

	/* Show required types.
	 */
	vips_buf_appends( buf, "where:\n" );
	print.required = TRUE;
	print.oftype = TRUE;
	print.n = 0;
	vips_argument_map( VIPS_OBJECT( operation ),
		(VipsArgumentMapFn) vips_operation_print_arg, buf, &print );

	/* Show optional args.
	 */
	vips_buf_appends( buf, "optional arguments:\n" );
	print.required = FALSE;
	print.oftype = TRUE;
	print.n = 0;
	vips_argument_map( VIPS_OBJECT( operation ),
		(VipsArgumentMapFn) vips_operation_print_arg, buf, &print );
}

static int
vips_operation_build( VipsObject *object )
{
	if( VIPS_OBJECT_CLASS( vips_operation_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_operation_class_init( VipsOperationClass *class )
{
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	vobject_class->print = vips_operation_print;
	vobject_class->build = vips_operation_build;
}

static void
vips_operation_init( VipsOperation *operation )
{
	/* Init our instance fields.
	 */
}

#ifdef DEBUG
static void *
vips_operation_call_argument( VipsObject *object, GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance )
{
	VipsArgument *argument = (VipsArgument *) argument_class;

	printf( "   %s: offset=%d ", 
		argument->pspec->name, argument_class->offset );
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
#endif /*DEBUG*/

int
vips_operation_call_valist( VipsOperation *operation, va_list ap )
{
	VipsObject *object = VIPS_OBJECT( operation );
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	GSList *p;
	char *first_property_name;

	/* First extract required arguments. Can't use vips_argument_map here 
	 * :-( because passing va_list by reference is not portable. So we
	 * have to copy-paste the vips_argument_map() loop. Keep in sync with
	 * that.
	 */

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

			/* End of stuff copy-pasted from vips_argument_map().
			 */
			if( argument_class->flags & VIPS_ARGUMENT_REQUIRED &&
				!argument_instance->assigned ) {
				GValue value = { 0 };
				char *msg = NULL;

				g_value_init( &value, 
					G_PARAM_SPEC_VALUE_TYPE( pspec ) );
				G_VALUE_COLLECT( &value, ap, 0, &msg );
				if( msg ) {
					vips_error( class->description,
						"%s", _( msg ) ); 
					g_value_unset( &value );
					g_free( msg );
					return( -1 );
				}

				g_object_set_property( G_OBJECT( operation ),
					pspec->name, &value );
				g_value_unset( &value );
			}
		}
	}

	/* Now set optional args. 
	 */
	first_property_name = va_arg( ap, char * );
	g_object_set_valist( G_OBJECT( operation ), first_property_name, ap );

	if( vips_object_build( VIPS_OBJECT( operation ) ) )
		return( -1 );

	return( 0 );
}

VipsOperation *
vips_operation_new( const char *name )
{
	GType type;

	if( !(type = vips_type_find( "VipsOperation", name )) )
		return( NULL );

	return( VIPS_OPERATION( vips_object_new( type, NULL, NULL, NULL ) ) );
}

int
vips_call( const char *operation_name, ... ) 
{
	va_list ap;
	VipsOperation *operation;
	int result;

#ifdef DEBUG
	printf( "vips_call: starting for %s ...\n", operation_name );
#endif /*DEBUG*/

	if( !(operation = vips_operation_new( operation_name ) ) )
		return( -1 );

	va_start( ap, operation_name );
	result = vips_operation_call_valist( operation, ap );
	va_end( ap );

	/* The operation we have built should now be reffed by one of it's
	 * arguments ... or have finished it's work.
	 */
	g_object_unref( operation );

	return( -1 );
}
