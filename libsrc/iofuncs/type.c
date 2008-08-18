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

/* Keep types in a GHashTable, indexed by name.
 */
static GHashTable *im_type_table = NULL;

im_type_t *
im_type_register( const char *name, size_t size,
	im_type_init_fn init, im_type_free_fn free )
{
	im_type_t *type;

	if( !(type = IM_NEW( NULL, im_type_t )) )
		return( NULL );

	type->name = name;
	type->size = size;
	type->init = init;
	type->free = free;

	if( !im_type_table ) 
		im_type_table = g_hash_table_new( g_str_hash, g_str_equal ); 
	g_hash_table_insert( im_type_table, (char *) name, type );

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
im_type_lookup( const char *name )
{
	return( (im_type_t *) g_hash_table_lookup( im_type_table, name ) );
}

/* Free a mask object.
 */
static void
im_object_imask_free( im_object_mask_t *mask )
{
	IM_FREE( mask->name );
	IM_FREEF( im_free_imask, mask->mask );
}

static void
im_object_dmask_free( im_object_mask_t *mask )
{
	IM_FREE( mask->name );
	IM_FREEF( im_free_dmask, mask->mask );
}

static void
gvalue_free( im_object obj )
{
	GValue *value = obj;

	g_value_unset( value );
}

/* Register the base VIPS types.
 */
void
im__type_init( void )
{
	im_type_register( IM_TYPE_NAME_DOUBLE, 
		sizeof( double ), NULL, NULL );
	im_type_register( IM_TYPE_NAME_INT, 
		sizeof( int ), NULL, NULL );
	im_type_register( IM_TYPE_NAME_COMPLEX, 
		2 * sizeof( double ), NULL, NULL );
	im_type_register( IM_TYPE_NAME_STRING, 
		0, NULL, (im_type_free_fn) im_free );
	im_type_register( IM_TYPE_NAME_IMASK, 
		sizeof( im_object_mask_t ), 
		NULL, (im_type_free_fn) im_object_imask_free );
	im_type_register( IM_TYPE_NAME_DMASK, 
		sizeof( im_object_mask_t ), 
		NULL, (im_type_free_fn) im_object_dmask_free );
	im_type_register( IM_TYPE_NAME_IMAGE, 
		0, NULL, NULL );
	im_type_register( IM_TYPE_NAME_DISPLAY, 
		0, NULL, NULL );
	im_type_register( IM_TYPE_NAME_GVALUE, 
		0, NULL, gvalue_free );
	im_type_register( IM_TYPE_NAME_ARRAY, 
		0, NULL, NULL );
}

