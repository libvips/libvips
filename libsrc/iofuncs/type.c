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
	im_type_t *type_param, size_t size, 
	im_value_init_fn init, im_value_free_fn free )
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
	type->init = init;
	type->free = free;

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
im_type_map_predicate( const char *key, im_type_t *type, Pair *pair )
{
	return( (pair->result == pair->fn( type, pair->a, pair->b )) );
}

void *
im_type_map( VSListMap2Fn fn, void *a, void *b )
{
	Pair pair;

	pair.a = a;
	pair.b = b;
	pair.fn = fn;
	pair.result = NULL;

	g_hash_table_find( im_type_table, 
		(GHRFunc) im_type_map_predicate, &pair ); 

	return( pair.result );
}

im_type_t *
im_type_lookup( const char *name, im_type_t *type_param )
{
	im_type_t type;

	type.name = name;
	type.type_param = type_param;

	return( (im_type_t *) g_hash_table_lookup( im_type_table, &type ) );
}

/* Allocate an im_value_t.
 */
static im_value_t *
im_value_new( im_value_t **value, im_type_t *type )
{
	if( type->size ) {
		if( !(*value = im_malloc( NULL, type->size )) )
			return( NULL );
		memset( *value, 0, type->size );
	}
	else
		*value = NULL;

	if( type->init )
		if( type->init( value, type ) );

	return( *value );
}

/* Free an im_value_t.
 */
static void
im_value_free( im_value_t **value, im_type_t *type )
{
	if( type->free && *value )
		type->free( *value, type );
	if( type->size ) 
		IM_FREE( *value );
}

/* Free a mask object.
 */
static void
im_value_imask_free( im_value_mask_t *value, im_type_t *type )
{
	IM_FREE( value->name );
	IM_FREEF( im_free_imask, value->mask );
}

static void
im_value_dmask_free( im_value_mask_t *value, im_type_t *type )
{
	IM_FREE( value->name );
	IM_FREEF( im_free_dmask, value->mask );
}

static void
im_value_gvalue_free( GValue *value, im_type_t *type )
{
	g_value_unset( value );
}

static void
im_value_array_free( im_value_array_t *value, im_type_t *type )
{
	int i;

	for( i = 0; i < value->n; i++ )
		im_value_free( value->array[i], type->type_param );
}

/* Register the base VIPS types.
 */
void
im__type_init( void )
{
	im_type_register( IM_TYPE_NAME_DOUBLE, NULL, sizeof( double ), 
		NULL, NULL );
	im_type_register( IM_TYPE_NAME_INT, NULL, sizeof( int ), 
		NULL, NULL );
	im_type_register( IM_TYPE_NAME_COMPLEX, NULL, 2 * sizeof( double ), 
		NULL, NULL );
	im_type_register( IM_TYPE_NAME_STRING, NULL, 0, 
		NULL, (im_value_free_fn) im_free );
	im_type_register( IM_TYPE_NAME_IMASK, NULL, sizeof( im_value_mask_t ), 
		NULL, (im_value_free_fn) im_value_imask_free );
	im_type_register( IM_TYPE_NAME_DMASK, NULL, sizeof( im_value_mask_t ), 
		NULL, (im_value_free_fn) im_value_dmask_free );
	im_type_register( IM_TYPE_NAME_IMAGE, NULL, 0, 
		NULL, NULL );
	im_type_register( IM_TYPE_NAME_DISPLAY, NULL, 0, 
		NULL, NULL );
	im_type_register( IM_TYPE_NAME_GVALUE, NULL, sizeof( GValue ), 
		NULL, (im_value_free_fn) im_value_gvalue_free );
	im_type_register( IM_TYPE_NAME_ARRAY, NULL, sizeof( im_value_array_t ), 
		NULL, (im_value_free_fn) im_value_array_free );
}
