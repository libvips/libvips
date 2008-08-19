/* Define built-in VIPS types.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Keep types in a GHashTable, indexed by name + type_param.
 */
static GHashTable *im_type_table = NULL;

/* Keep operations in a GHashTable, indexed by name.
 */
static GHashTable *im_operation_table = NULL;

static unsigned int
im_type_hash( im_type_t *type )
{
	return( g_str_hash( type->name ) | 
		GPOINTER_TO_UINT( type->type_param ) );
}

static gboolean
im_type_equal( im_type_t *type1, im_type_t *type2 )
{
	return( type1->type_param == type2->type_param && 
		g_str_equal( type1->name, type2->name ) );
}

im_type_t *
im_type_register( const char *name, 
	im_type_t *type_param, size_t size )
{
	im_type_t *type;

	if( im_type_lookup( name, type_param ) ) {
		im_error( "im_type_register", 
			_( "type name already registered" ) ); 
		return( NULL );
	}

	if( !(type = IM_NEW( NULL, im_type_t )) )
		return( NULL );
	type->name = name;
	type->type_param = type_param;
	type->size = size;

	if( !im_type_table ) 
		im_type_table = g_hash_table_new( 
			(GHashFunc) im_type_hash, 
			(GEqualFunc) im_type_equal );
	g_hash_table_insert( im_type_table, type, type );

	return( type );
}

typedef struct {
	void *a;
	void *b;
	VSListMap2Fn fn;
	void *result;
} Pair;

static gboolean
im_hash_table_predicate( const char *key, im_type_t *type, Pair *pair )
{
	return( (pair->result == pair->fn( type, pair->a, pair->b )) );
}

void *
im_hash_table_map( GHashTable *hash, VSListMap2Fn fn, void *a, void *b )
{
	Pair pair;

	pair.a = a;
	pair.b = b;
	pair.fn = fn;
	pair.result = NULL;

	g_hash_table_find( hash, (GHRFunc) im_hash_table_predicate, &pair ); 

	return( pair.result );
}

void *
im_type_map( VSListMap2Fn fn, void *a, void *b )
{
	return( im_hash_table_map( im_type_table, fn, a, b ) );
}

im_type_t *
im_type_lookup( const char *name, im_type_t *type_param )
{
	im_type_t type;

	type.name = name;
	type.type_param = type_param;

	return( (im_type_t *) g_hash_table_lookup( im_type_table, &type ) );
}

/* Register the base VIPS types.
 */
void
im__type_init( void )
{
	im_type_register( IM_TYPE_NAME_DOUBLE, NULL, sizeof( double ) ); 
	im_type_register( IM_TYPE_NAME_INT, NULL, sizeof( int ) );
	im_type_register( IM_TYPE_NAME_COMPLEX, NULL, 2 * sizeof( double ) ); 
	im_type_register( IM_TYPE_NAME_STRING, NULL, 0 ); 
	im_type_register( IM_TYPE_NAME_IMASK, NULL, sizeof( im_value_mask_t ) );
	im_type_register( IM_TYPE_NAME_DMASK, NULL, sizeof( im_value_mask_t ) );
	im_type_register( IM_TYPE_NAME_IMAGE, NULL, 0 ); 
	im_type_register( IM_TYPE_NAME_DISPLAY, NULL, 0 ); 
	im_type_register( IM_TYPE_NAME_GVALUE, NULL, sizeof( GValue ) ); 
	im_type_register( IM_TYPE_NAME_ARRAY, 
		NULL, sizeof( im_value_array_t ) ); 
}

/* Allocate an im_value_t.
 */
static im_value_t *
im_value_new( im_type_t *type )
{
	im_value_t *value;

	if( type->size ) {
		if( !(value = im_malloc( NULL, type->size )) )
			return( NULL );
		memset( value, 0, type->size );
	}
	else
		value = NULL;

	return( value );
}

/* Free an im_value_t.
 */
static void
im_value_free( im_value_t *value, im_type_t *type )
{
	if( type->size ) 
		IM_FREE( value );
}

/* Convenience functions to build and free various values.
 */
void
im_value_imask_free( im_value_mask_t *value )
{
	IM_FREE( value->name );
	IM_FREEF( im_free_imask, value->mask );
}

void
im_value_dmask_free( im_value_mask_t *value )
{
	IM_FREE( value->name );
	IM_FREEF( im_free_dmask, value->mask );
}

void
im_value_gvalue_free( GValue *value )
{
	g_value_unset( value );
}

void
im_value_array_free( im_value_array_t *value, im_type_t *type )
{
	int i;

	for( i = 0; i < value->n; i++ )
		im_value_free( value->array[i], type->type_param );
}

gboolean
im_value_mask_output_init( im_value_mask_t *value, const char *name )
{
	if( !(value->name = im_strdup( NULL, name )) )
		return( FALSE );

	return( TRUE );
}

gboolean
im_value_imask_input_init( im_value_mask_t *value, const char *name )
{
	INTMASK *mask;

	if( !(mask = im_read_imask( name )) )
		return( FALSE );
	value->mask = (void *) mask;
	if( !(value->name = im_strdup( NULL, name )) ) {
		im_value_imask_free( value );
		return( FALSE );
	}

	return( TRUE );
}

/* Create arguments.
 */
im_argument_t *
im_argument_new( const char *name, im_type_t *type, gboolean input )
{
	im_argument_t *argument;

	if( !(argument = IM_NEW( NULL, im_argument_t )) )
		return( NULL );
	argument->name = name;
	argument->type = type;
	argument->input = input;

	return( argument );
}

void
im_argument_free( im_argument_t *argument )
{
	im_free( argument );
}

/* Register/iterate/lookup operations.
 */
void
im_operation_unregister( im_operation_t *operation )
{
	int i;

	g_hash_table_remove( im_operation_table, operation->name );
	for( i = 0; i < operation->argc; i++ )
		IM_FREEF( im_argument_free, operation->argv[i] );
	IM_FREE( operation );
}

im_operation_t *
im_operation_register( const char *name, const char *desc,
	im_operation_flags flags, im_operation_dispatch_fn disp, int argc )
{
	im_operation_t *operation;

	if( im_operation_lookup( name ) ) {
		im_error( "im_operation_register", 
			_( "operation name already registered" ) ); 
		return( NULL );
	}

	if( !(operation = IM_NEW( NULL, im_operation_t )) )
		return( NULL );
	operation->name = name;
	operation->desc = desc;
	operation->flags = flags;
	operation->disp = disp;
	operation->argc = argc;
	operation->argv = NULL;

	if( !(operation->argv = IM_ARRAY( NULL, argc, im_argument_t * )) ) {
		im_operation_unregister( operation );
		return( NULL );
	}
	memset( operation->argv, 0, argc * sizeof( im_argument_t * ) );

	if( !im_operation_table ) 
		im_operation_table = g_hash_table_new( 
			g_str_hash, g_str_equal );
	g_hash_table_insert( im_operation_table, (char *) name, operation );

	return( operation );
}

void *
im_operation_map( VSListMap2Fn fn, void *a, void *b )
{
	return( im_hash_table_map( im_operation_table, fn, a, b ) );
}

im_operation_t *
im_operation_lookup( const char *name )
{
	return( (im_operation_t *) 
		g_hash_table_lookup( im_operation_table, name ) );
}

static int
add_vec( im_value_t **argv )
{
	return( im_add( argv[0], argv[1], argv[2] ) );
}

/* Make a sample operation.
 */
void
im__operation_init( void )
{
	im_operation_t *operation;

	operation = im_operation_register( "im_add", _( "add two images" ),
		IM_FN_PIO | IM_FN_PTOP,
		add_vec, 	
		3 ); 
	operation->argv[0] = im_argument_new( "in1", 
		im_type_lookup( IM_TYPE_NAME_IMAGE, NULL ), TRUE );
	operation->argv[1] = im_argument_new( "in2", 
		im_type_lookup( IM_TYPE_NAME_IMAGE, NULL ), TRUE );
	operation->argv[2] = im_argument_new( "out", 
		im_type_lookup( IM_TYPE_NAME_IMAGE, NULL ), TRUE );
}
