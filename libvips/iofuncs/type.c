/* array type 
 *
 * Unlike GArray, this has fixed length, tracks a GType for elements, and has
 * a per-element free function.
 *
 * 27/10/11
 * 	- from header.c
 * 16/7/13
 * 	- leakcheck VipsArea
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define VIPS_DEBUG
#define DEBUG
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

/**
 * SECTION: type
 * @short_description: basic types
 * @stability: Stable
 * @see_also: <link linkend="libvips-header">header</link>
 * @include: vips/vips.h
 *
 * A selection of %GType defintions used by VIPS. 
 */

/* A very simple boxed type for testing. Just an int.
 *
 * You can manipulate this thing from Python (for example) with:
 *
 * from gi.repository import Vips
 * a = Vips.Thing.new(12)
 * print a.i
 * b = a
 * del a
 * print b.i
 * del b
 */

/**
 * vips_thing_new:
 * @n:
 *
 * Returns: (transfer full): a new #VipsThing.
 */
VipsThing *
vips_thing_new( int i )
{
	VipsThing *thing;

	thing = g_new( VipsThing, 1 );
	thing->i = i;

	printf( "vips_thing_new: %d %p\n", i, thing );

	return( thing );
}

static VipsThing *
vips_thing_copy( VipsThing *thing )
{
	VipsThing *thing2;

	thing2 = vips_thing_new( thing->i );

	printf( "vips_thing_copy: %d %p = %p\n", thing->i, thing2, thing );

	return( thing2 );
}

static void
vips_thing_free( VipsThing *thing )
{
	printf( "vips_thing_free: %d %p\n", thing->i, thing );

	g_free( thing );
}

/*
 * glib-2.26+ only 
 
G_DEFINE_BOXED_TYPE( VipsThing, vips_thing,
	(GBoxedCopyFunc) vips_thing_copy, 
	(GBoxedFreeFunc) vips_thing_free );

 */

GType
vips_thing_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "VipsThing",
			(GBoxedCopyFunc) vips_thing_copy, 
			(GBoxedFreeFunc) vips_thing_free );
	}

	return( type );
}

static GSList *vips_area_all = NULL;

VipsArea *
vips_area_copy( VipsArea *area )
{
	g_mutex_lock( area->lock );

	g_assert( area->count > 0 );

	area->count += 1;

#ifdef DEBUG
	printf( "vips_area_copy: %p count = %d\n", area, area->count );
#endif /*DEBUG*/

	g_mutex_unlock( area->lock );

	return( area );
}

void
vips_area_unref( VipsArea *area )
{
	g_mutex_lock( area->lock );

	g_assert( area->count > 0 );

	area->count -= 1;

#ifdef DEBUG
	printf( "vips_area_unref: %p count = %d\n", area, area->count );
#endif /*DEBUG*/

	if( vips__leak ) {
		g_mutex_lock( vips__global_lock );
		g_assert( g_slist_find( vips_area_all, area ) ); 
		g_mutex_unlock( vips__global_lock );
	}

	if( area->count == 0 ) {
		if( area->free_fn && area->data ) {
			area->free_fn( area->data, area );
			area->data = NULL;
			area->free_fn = NULL;
		}

		g_mutex_unlock( area->lock );

		VIPS_FREEF( vips_g_mutex_free, area->lock );

		g_free( area );

		if( vips__leak ) {
			g_mutex_lock( vips__global_lock );
			vips_area_all = g_slist_remove( vips_area_all, area ); 
			g_mutex_unlock( vips__global_lock );
		}

#ifdef DEBUG
		g_mutex_lock( vips__global_lock );
		printf( "vips_area_unref: free .. total = %d\n", 
			g_slist_length( vips_area_all ) );
		g_mutex_unlock( vips__global_lock );
#endif /*DEBUG*/
	}
	else
		g_mutex_unlock( area->lock );
}

/**
 * vips_area_new: 
 * @free_fn: (scope async): @data will be freed with this function
 * @data: data will be freed with this function
 *
 * A VipsArea wraps a chunk of memory. It adds reference counting and a free
 * function. It also keeps a count and a %GType, so the area can be an array.
 *
 * This type is used for things like passing an array of double or an array of
 * #VipsObject pointers to operations, and for reference-counted immutable
 * strings. 
 *
 * Inital count == 1, so _unref() after attaching somewhere.
 *
 * See also: vips_area_unref().
 *
 * Returns: (transfer full): the new #VipsArea.
 */
VipsArea *
vips_area_new( VipsCallbackFn free_fn, void *data )
{
	VipsArea *area;

	area = g_new( VipsArea, 1 );
	area->count = 1;
	area->lock = vips_g_mutex_new();
	area->length = 0;
	area->data = data;
	area->free_fn = free_fn;
	area->type = 0;
	area->sizeof_type = 0;

	if( vips__leak ) {
		g_mutex_lock( vips__global_lock );
		vips_area_all = g_slist_prepend( vips_area_all, area ); 
		g_mutex_unlock( vips__global_lock );
	}

#ifdef DEBUG
	g_mutex_lock( vips__global_lock );
	printf( "vips_area_new: %p count = %d (%d in total)\n", 
		area, area->count, 
		g_slist_length( vips_area_all ) );
	g_mutex_unlock( vips__global_lock );
#endif /*DEBUG*/

	return( area );
}

void
vips__type_leak( void )
{
	if( vips_area_all ) {
		GSList *p; 

		printf( "VipsArea leaks:\n" ); 
		for( p = vips_area_all; p; p = p->next ) {
			VipsArea *area = (VipsArea *) p->data;

			printf( "\t%p count = %d\n", area, area->count );
		}
		printf( "%d in total\n", g_slist_length( vips_area_all ) );
	}
}

/**
 * vips_area_new_array: 
 * @type: %GType of elements to store
 * @sizeof_type: sizeof() an element in the array
 * @n: number of elements in the array
 *
 * An area which holds an array of elements of some %GType. To set values for
 * the elements, get the pointer and write.
 *
 * See also: vips_area_unref().
 *
 * Returns: (transfer full): the new #VipsArea.
 */
VipsArea *
vips_area_new_array( GType type, size_t sizeof_type, int n )
{
	VipsArea *area;
	void *array;

	array = g_malloc( n * sizeof_type );
	area = vips_area_new( (VipsCallbackFn) g_free, array );
	area->n = n;
	area->length = n * sizeof_type;
	area->type = type;
	area->sizeof_type = sizeof_type;

	return( area );
}

static void
vips_area_free_array_object( GObject **array, VipsArea *area )
{
	int i;

	for( i = 0; i < area->n; i++ ) 
		VIPS_FREEF( g_object_unref, array[i] );
	VIPS_FREE( array ); 

	area->n = 0;
}

/**
 * vips_area_new_array_object:
 * @n: number of elements in the array
 *
 * An area which holds an array of %GObjects. See vips_area_new_array(). When
 * the area is freed, each %GObject will be unreffed.
 *
 * See also: vips_area_unref().
 *
 * Returns: (transfer full): the new #VipsArea.
 */
VipsArea *
vips_area_new_array_object( int n )
{
	GObject **array;
	VipsArea *area;

	array = g_new0( GObject *, n );
	area = vips_area_new( (VipsCallbackFn) vips_area_free_array_object, 
		array );
	area->n = n;
	area->length = n * sizeof( GObject * );
	area->type = G_TYPE_OBJECT;
	area->sizeof_type = sizeof( GObject * );

	return( area );
}

/**
 * vips_area_get_data:
 * @area: #VipsArea to fetch from
 * @length: (allow-none): optionally return length in bytes here
 * @n: (allow-none): optionally return number of elements here
 * @type: (allow-none): optionally return element type here
 * @sizeof_type: (allow-none): optionally return sizeof() element type here
 *
 * Return the data pointer plus optionally the length in bytes of an area, 
 * the number of elements, the %GType of each element and the sizeof() each
 * element.
 *
 * Returns: (transfer none): The pointer held by @area.
 */
void *
vips_area_get_data( VipsArea *area, 
	size_t *length, int *n, GType *type, size_t *sizeof_type )
{
	if( length )
		*length = area->length;
	if( n )
		*n = area->n;
	if( type )
		*type = area->type;
	if( sizeof_type )
		*sizeof_type = area->sizeof_type;

	return( area->data );
}

/* Transform an area to a G_TYPE_STRING.
 */
static void
transform_area_g_string( const GValue *src_value, GValue *dest_value )
{
	VipsArea *area;
	char buf[256];

	area = g_value_get_boxed( src_value );
	vips_snprintf( buf, 256, "VIPS_TYPE_AREA, count = %d, data = %p",
		area->count, area->data );
	g_value_set_string( dest_value, buf );
}

GType
vips_area_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "VipsArea",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( type, G_TYPE_STRING,
			transform_area_g_string );
	}

	return( type );
}

/* Transform funcs for builtin types to SAVE_STRING.
 */
static void
transform_int_save_string( const GValue *src_value, GValue *dest_value )
{
	vips_value_set_save_stringf( dest_value, 
		"%d", g_value_get_int( src_value ) );
}

static void
transform_save_string_int( const GValue *src_value, GValue *dest_value )
{
	g_value_set_int( dest_value, 
		atoi( vips_value_get_save_string( src_value ) ) );
}

static void
transform_double_save_string( const GValue *src_value, GValue *dest_value )
{
	char buf[G_ASCII_DTOSTR_BUF_SIZE];

	/* Need to be locale independent.
	 */
	g_ascii_dtostr( buf, G_ASCII_DTOSTR_BUF_SIZE, 
		g_value_get_double( src_value ) );
	vips_value_set_save_string( dest_value, buf );
}

static void
transform_save_string_double( const GValue *src_value, GValue *dest_value )
{
	g_value_set_double( dest_value, 
		g_ascii_strtod( vips_value_get_save_string( src_value ), 
			NULL ) );
}

/* Save meta fields to the header. We have a new string type for header fields
 * to save to XML and define transform functions to go from our meta types to
 * this string type.
 */
GType
vips_save_string_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "VipsSaveString",
			(GBoxedCopyFunc) g_strdup, 
			(GBoxedFreeFunc) g_free );
	}

	return( type );
}

/* Transform a refstring to a G_TYPE_STRING and back.
 */
static void
transform_ref_string_g_string( const GValue *src_value, GValue *dest_value )
{
	g_value_set_string( dest_value, 
		vips_value_get_ref_string( src_value, NULL ) );
}

static void
transform_g_string_ref_string( const GValue *src_value, GValue *dest_value )
{
	vips_value_set_ref_string( dest_value, 
		g_value_get_string( src_value ) );
}

/* To a save string.
 */
static void
transform_ref_string_save_string( const GValue *src_value, GValue *dest_value )
{
	vips_value_set_save_stringf( dest_value, 
		"%s", vips_value_get_ref_string( src_value, NULL ) );
}

static void
transform_save_string_ref_string( const GValue *src_value, GValue *dest_value )
{
	vips_value_set_ref_string( dest_value, 
		vips_value_get_save_string( src_value ) );
}

GType
vips_ref_string_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "VipsRefString",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( type, G_TYPE_STRING,
			transform_ref_string_g_string );
		g_value_register_transform_func( G_TYPE_STRING, type,
			transform_g_string_ref_string );
		g_value_register_transform_func( type, VIPS_TYPE_SAVE_STRING,
			transform_ref_string_save_string );
		g_value_register_transform_func( VIPS_TYPE_SAVE_STRING, type,
			transform_save_string_ref_string );
	}

	return( type );
}

/**
 * vips_blob_new: 
 * @free_fn: (scope async): (allow-none): @data will be freed with this function
 * @data: (array length=size) (element-type guint8) (transfer full): data to store
 * @size: number of bytes in @data
 *
 * Like vips_area_new(), but track a length as well. The returned #VipsBlob
 * takes ownership of @data and will free it with @free_fn. Pass NULL for
 * @free_fn to not transfer ownership.
 *
 * An area of mem with a free func and a length (some sort of binary object,
 * like an ICC profile).
 * 
 * See also: vips_area_unref().
 *
 * Returns: (transfer full): the new #VipsBlob.
 */
VipsBlob *
vips_blob_new( VipsCallbackFn free_fn, void *data, size_t size )
{
	VipsArea *area;

	area = vips_area_new( free_fn, data );
	area->length = size;

	return( (VipsBlob *) area );
}

/**
 * vips_blob_get: 
 * @blob: #VipsBlob to fetch from
 * @size: return number of bytes of data
 *
 * Get the data from a #VipsBlob. 
 * 
 * See also: vips_blob_new().
 *
 * Returns: (array length=size) (element-type guint8) (transfer none): the data
 */
void *
vips_blob_get( VipsBlob *blob, size_t *size )
{
	return( vips_area_get_data( VIPS_AREA( blob ), 
		size, NULL, NULL, NULL ) ); 
}

/* Transform a blob to a G_TYPE_STRING.
 */
static void
transform_blob_g_string( const GValue *src_value, GValue *dest_value )
{
	void *blob;
	size_t blob_length;
	char buf[256];

	blob = vips_value_get_blob( src_value, &blob_length );
	vips_snprintf( buf, 256, "VIPS_TYPE_BLOB, data = %p, length = %zd",
		blob, blob_length );
	g_value_set_string( dest_value, buf );
} 

/* Transform a blob to a save string and back.
 */
static void
transform_blob_save_string( const GValue *src_value, GValue *dest_value )
{
	void *blob;
	size_t blob_length;
	char *b64;

	blob = vips_value_get_blob( src_value, &blob_length );
	if( (b64 = vips__b64_encode( blob, blob_length )) ) {
		vips_value_set_save_string( dest_value, b64 );
		vips_free( b64 );
	}
}

static void
transform_save_string_blob( const GValue *src_value, GValue *dest_value )
{
	const char *b64;
	void *blob;
	size_t blob_length;

	b64 = vips_value_get_save_string( src_value );
	if( (blob = vips__b64_decode( b64, &blob_length )) )
		vips_value_set_blob( dest_value, 
			(VipsCallbackFn) vips_free, blob, blob_length );
}

GType
vips_blob_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "VipsBlob",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( type, G_TYPE_STRING,
			transform_blob_g_string );
		g_value_register_transform_func( type, VIPS_TYPE_SAVE_STRING,
			transform_blob_save_string );
		g_value_register_transform_func( VIPS_TYPE_SAVE_STRING, type,
			transform_save_string_blob );
	}

	return( type );
}

/**
 * vips_array_int_new:
 * @array: (array length=n): array of int
 * @n: number of ints
 *
 * Allocate a new array of ints and copy @array into it. Free with
 * vips_area_unref().
 *
 * See also: #VipsArea.
 *
 * Returns: (transfer full): A new #VipsArrayInt.
 */
VipsArrayInt *
vips_array_int_new( const int *array, int n )
{
	VipsArea *area;
	int *array_copy;

	area = vips_area_new_array( G_TYPE_INT, sizeof( int ), n );
	array_copy = vips_area_get_data( area, NULL, NULL, NULL, NULL );
	memcpy( array_copy, array, n * sizeof( int ) );

	return( (VipsArrayInt *) area );
}

/**
 * vips_array_int_newv:
 * @n: number of ints
 * @...: list of int arguments
 *
 * Allocate a new array of @n ints and copy @... into it. Free with
 * vips_area_unref().
 *
 * See also: vips_array_int_new()
 *
 * Returns: (transfer full): A new #VipsArrayInt.
 */
VipsArrayInt *
vips_array_int_newv( int n, ... )
{
	va_list ap;
	VipsArea *area;
	int *array;
	int i;

	area = vips_area_new_array( G_TYPE_INT, sizeof( int ), n );
	array = vips_area_get_data( area, NULL, NULL, NULL, NULL );

	va_start( ap, n );
	for( i = 0; i < n; i++ )
		array[i] = va_arg( ap, int ); 
	va_end( ap );

	return( (VipsArrayInt *) area );
}

/**
 * vips_array_int_get:
 * @array: the #VipsArrayInt to fetch from
 * @n: length of array
 *
 * Fetch an int array from a #VipsArrayInt. Useful for language bindings. 
 *
 * Returns: (array length=n): (transfer none): array of int
 */
int *
vips_array_int_get( VipsArrayInt *array, int *n )
{
	VipsArea *area = VIPS_AREA( array );

	g_assert( area->type == G_TYPE_INT ); 

	if( n )
		*n = area->n;

	return( (int *) VIPS_ARRAY_ADDR( array, 0 ) ); 
}

static void
transform_array_int_g_string( const GValue *src_value, GValue *dest_value )
{
	int n;
	int *array;

	char txt[1024];
	VipsBuf buf = VIPS_BUF_STATIC( txt );
	int i;

	if( (array = vips_value_get_array_int( src_value, &n )) ) 
		for( i = 0; i < n; i++ ) 
			/* Use space as a separator since ',' may be a 
			 * decimal point in this locale.
			 */
			vips_buf_appendf( &buf, "%d ", array[i] );

	g_value_set_string( dest_value, vips_buf_all( &buf ) );
}

/* It'd be great to be able to write a generic string->array function, but
 * it doesn't seem possible.
 */
static void
transform_g_string_array_int( const GValue *src_value, GValue *dest_value )
{
	char *str;
	int n;
	char *p, *q;
	int i;
	int *array;

	/* Walk the string to get the number of elements. 
	 * We need a copy of the string, since we insert \0 during
	 * scan.
	 *
	 * We can't allow ',' as a separator, since some locales use it as a
	 * decimal point.
	 */
	str = g_value_dup_string( src_value );

	n = 0;
	for( p = str; (q = vips_break_token( p, "\t; " )); p = q ) 
		n += 1;

	g_free( str );

	vips_value_set_array( dest_value, n, G_TYPE_INT, sizeof( int ) );
	array = (int *) vips_value_get_array( dest_value, NULL, NULL, NULL );

	str = g_value_dup_string( src_value );

	i = 0;
	for( p = str; (q = vips_break_token( p, "\t; " )); p = q ) {
		if( sscanf( p, "%d", &array[i] ) != 1 ) { 
			/* Set array to length zero to indicate an error.
			 */
			vips_error( "vipstype", 
				_( "unable to convert \"%s\" to int" ), p );
			vips_value_set_array( dest_value, 
				0, G_TYPE_INT, sizeof( int ) );
			g_free( str );
			return;
		}

		i += 1;
	}

	g_free( str );
}

GType
vips_array_int_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "VipsArrayInt",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( type, G_TYPE_STRING,
			transform_array_int_g_string );
		g_value_register_transform_func( G_TYPE_STRING, type,
			transform_g_string_array_int );
	}

	return( type );
}

/**
 * vips_array_double_new:
 * @array: (array length=n): array of double
 * @n: number of doubles
 *
 * Allocate a new array of doubles and copy @array into it. Free with
 * vips_area_unref().
 *
 * See also: #VipsArea.
 *
 * Returns: (transfer full): A new #VipsArrayDouble.
 */
VipsArrayDouble *
vips_array_double_new( const double *array, int n )
{
	VipsArea *area;
	double *array_copy;

	area = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n );
	array_copy = vips_area_get_data( area, NULL, NULL, NULL, NULL );
	memcpy( array_copy, array, n * sizeof( double ) );

	return( (VipsArrayDouble *) area );
}

/**
 * vips_array_double_newv:
 * @n: number of doubles
 * @...: list of double arguments
 *
 * Allocate a new array of @n doubles and copy @... into it. Free with
 * vips_area_unref().
 *
 * See also: vips_array_double_new()
 *
 * Returns: (transfer full): A new #VipsArrayDouble.
 */
VipsArrayDouble *
vips_array_double_newv( int n, ... )
{
	va_list ap;
	VipsArea *area;
	double *array;
	int i;

	area = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n );
	array = vips_area_get_data( area, NULL, NULL, NULL, NULL );

	va_start( ap, n );
	for( i = 0; i < n; i++ )
		array[i] = va_arg( ap, double ); 
	va_end( ap );

	return( (VipsArrayDouble *) area );
}

/**
 * vips_array_double_get:
 * @array: the #VipsArrayDouble to fetch from
 * @n: length of array
 *
 * Fetch a double array from a #VipsArrayDouble. Useful for language bindings. 
 *
 * Returns: (array length=n): (transfer none): array of double
 */
double *
vips_array_double_get( VipsArrayDouble *array, int *n )
{
	VipsArea *area = VIPS_AREA( array );

	g_assert( area->type == G_TYPE_DOUBLE ); 

	if( n )
		*n = area->n;

	return( VIPS_ARRAY_ADDR( array, 0 ) ); 
}

static void
transform_array_double_g_string( const GValue *src_value, GValue *dest_value )
{
	int n;
	double *array;

	char txt[1024];
	VipsBuf buf = VIPS_BUF_STATIC( txt );
	int i;

	if( (array = vips_value_get_array_double( src_value, &n )) ) 
		for( i = 0; i < n; i++ ) 
			/* Use space as a separator since ',' may be a decimal 
			 * point in this locale.
			 */
			vips_buf_appendf( &buf, "%g ", array[i] );

	g_value_set_string( dest_value, vips_buf_all( &buf ) );
}

/* It'd be great to be able to write a generic string->array function, but
 * it doesn't seem possible.
 */
static void
transform_g_string_array_double( const GValue *src_value, GValue *dest_value )
{
	char *str;
	int n;
	char *p, *q;
	int i;
	double *array;

	/* Walk the string to get the number of elements. 
	 * We need a copy of the string since we insert \0 during
	 * scan.
	 *
	 * We can't allow ',' as a separator since some locales use it as a
	 * decimal point.
	 */
	str = g_value_dup_string( src_value );

	n = 0;
	for( p = str; (q = vips_break_token( p, "\t; " )); p = q ) 
		n += 1;

	g_free( str );

	vips_value_set_array( dest_value, n, G_TYPE_DOUBLE, sizeof( double ) );
	array = (double *) vips_value_get_array( dest_value, NULL, NULL, NULL );

	str = g_value_dup_string( src_value );

	i = 0;
	for( p = str; (q = vips_break_token( p, "\t; " )); p = q ) {
		if( sscanf( p, "%lf", &array[i] ) != 1 ) { 
			/* Set array to length zero to indicate an error.
			 */
			vips_error( "vipstype", 
				_( "unable to convert \"%s\" to float" ), p );
			vips_value_set_array( dest_value, 
				0, G_TYPE_DOUBLE, sizeof( double ) );
			g_free( str );
			return;
		}

		i += 1;
	}

	g_free( str );
}

GType
vips_array_double_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "VipsArrayDouble",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( type, G_TYPE_STRING,
			transform_array_double_g_string );
		g_value_register_transform_func( G_TYPE_STRING, type,
			transform_g_string_array_double );
	}

	return( type );
}

static void
transform_g_string_array_image( const GValue *src_value, GValue *dest_value )
{
	char *str;
	int n;
	char *p, *q;
	int i;
	GObject **array;

	/* We need a copy of the string, since we insert \0 during
	 * scan.
	 */
	str = g_value_dup_string( src_value );

	n = 0;
	for( p = str; (q = vips_break_token( p, " " )); p = q ) 
		n += 1;

	g_free( str );

	vips_value_set_array_object( dest_value, n );
	array = vips_value_get_array_object( dest_value, NULL );

	str = g_value_dup_string( src_value );

	for( i = 0, p = str; (q = vips_break_token( p, " " )); i++, p = q )
		if( !(array[i] = G_OBJECT( vips_image_new_from_file( p, 
			NULL ) )) ) {
			/* Set the dest to length zero to indicate error.
			 */
			vips_value_set_array_object( dest_value, 0 );
			g_free( str );
			return;
		}

	g_free( str );
}

/**
 * vips_array_image_new:
 * @array: (array length=n): array of #VipsImage
 * @n: number of images
 *
 * Allocate a new array of images and copy @array into it. Free with
 * vips_area_unref().
 *
 * See also: #VipsArea.
 *
 * Returns: (transfer full): A new #VipsArrayImage.
 */
VipsArrayImage *
vips_array_image_new( const VipsImage **array, int n )
{
	VipsArea *area;
	VipsImage *array_copy;

	area = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n );
	array_copy = vips_area_get_data( area, NULL, NULL, NULL, NULL );
	memcpy( array_copy, array, n * sizeof( double ) );

	return( (VipsArrayImage *) area );
}

/**
 * vips_array_image_get:
 * @array: the #VipsArrayImage to fetch from
 * @n: length of array
 *
 * Fetch an image array from a #VipsArrayImage. Useful for language bindings. 
 *
 * Returns: (array length=n): (transfer none): array of #VipsImage
 */
VipsImage **
vips_array_image_get( VipsArrayImage *array, int *n )
{
	VipsArea *area = VIPS_AREA( array );

	g_assert( area->type == VIPS_TYPE_IMAGE ); 

	if( n )
		*n = area->n;

	return( (VipsImage **) VIPS_ARRAY_ADDR( array, 0 ) ); 
}

GType
vips_array_image_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		type = g_boxed_type_register_static( "VipsArrayImage",
			(GBoxedCopyFunc) vips_area_copy, 
			(GBoxedFreeFunc) vips_area_unref );
		g_value_register_transform_func( G_TYPE_STRING, type,
			transform_g_string_array_image );
	}

	return( type );
}

/**
 * vips_value_set_area:
 * @value: (out): set this value
 * @free_fn: (scope async): data will be freed with this function
 * @data: set @value to track this pointer
 *
 * Set value to be a ref-counted area of memory with a free function.
 */
void
vips_value_set_area( GValue *value, VipsCallbackFn free_fn, void *data )
{
	VipsArea *area;

	area = vips_area_new( free_fn, data );
	g_value_init( value, VIPS_TYPE_AREA );
	g_value_set_boxed( value, area );
	vips_area_unref( area );
}

/**
 * vips_value_get_area:
 * @value: get from this value
 * @length: (allow-none): optionally return length here
 *
 * Get the pointer from an area. Don't touch count (area is static).
 *
 * Returns: (transfer none): The pointer held by @value. 
 */
void *
vips_value_get_area( const GValue *value, size_t *length )
{
	VipsArea *area;

	area = g_value_get_boxed( value );

	return( vips_area_get_data( area, length, NULL, NULL, NULL ) ); 
}

/** 
 * vips_value_get_save_string:
 * @value: GValue to get from
 *
 * Get the C string held internally by the GValue.
 *
 * Returns: (transfer none): The C string held by @value. 
 */
const char *
vips_value_get_save_string( const GValue *value )
{
	return( (char *) g_value_get_boxed( value ) );
}

/** 
 * vips_value_set_save_string:
 * @value: (out): GValue to set
 * @str: C string to copy into the GValue
 *
 * Copies the C string into @value.
 */
void
vips_value_set_save_string( GValue *value, const char *str )
{
	g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_SAVE_STRING );

	g_value_set_boxed( value, str );
}

/** 
 * vips_value_set_save_stringf:
 * @value: (out): GValue to set
 * @fmt: printf()-style format string
 * @Varargs: arguments to printf()-formatted @fmt
 *
 * Generates a string and copies it into @value.
 */
void
vips_value_set_save_stringf( GValue *value, const char *fmt, ... )
{
	va_list ap;
	char *str;

	g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_SAVE_STRING );

	va_start( ap, fmt );
	str = g_strdup_vprintf( fmt, ap );
	va_end( ap );
	vips_value_set_save_string( value, str );
	g_free( str );
}

/** 
 * vips_value_get_ref_string:
 * @value: %GValue to get from
 * @length: (allow-none): return length here, optionally
 *
 * Get the C string held internally by the %GValue.
 *
 * Returns: (transfer none): The C string held by @value. 
 */
const char *
vips_value_get_ref_string( const GValue *value, size_t *length )
{
	return( vips_value_get_area( value, length ) );
}

/** 
 * vips_value_set_ref_string:
 * @value: (out): %GValue to set
 * @str: C string to copy into the GValue
 *
 * Copies the C string @str into @value. 
 *
 * vips_ref_string are immutable C strings that are copied between images by
 * copying reference-counted pointers, making the much more efficient than
 * regular %GValue strings.
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_value_set_ref_string( GValue *value, const char *str )
{
	VipsArea *area;
	char *str_copy;

	g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_REF_STRING );

	str_copy = g_strdup( str );
	area = vips_area_new( (VipsCallbackFn) vips_free, str_copy );

	/* Handy place to cache this.
	 */
	area->length = strlen( str );

	g_value_set_boxed( value, area );
	vips_area_unref( area );

	return( 0 );
}

/** 
 * vips_value_set_blob:
 * @value: (out): GValue to set
 * @free_fn: (scope async): free function for @data
 * @data: pointer to area of memory
 * @length: length of memory area
 *
 * Sets @value to hold a @data. When @value is freed, @data will be
 * freed with @free_fn. @value also holds a note of the length of the memory
 * area.
 *
 * blobs are things like ICC profiles or EXIF data. They are relocatable, and
 * are saved to VIPS files for you coded as base64 inside the XML. They are
 * copied by copying reference-counted pointers.
 *
 * See also: vips_value_get_blob()
 */
void
vips_value_set_blob( GValue *value, 
	VipsCallbackFn free_fn, void *data, size_t length ) 
{
	VipsBlob *blob;

	g_assert( G_VALUE_TYPE( value ) == VIPS_TYPE_BLOB );

	blob = vips_blob_new( free_fn, data, length );
	g_value_set_boxed( value, blob );
	vips_area_unref( VIPS_AREA( blob ) );
}

/** 
 * vips_value_get_blob:
 * @value: GValue to set
 * @length: (allow-none): optionally return length of memory area
 *
 * Returns the data pointer from a blob. Optionally returns the length too.
 *
 * blobs are things like ICC profiles or EXIF data. They are relocatable, and
 * are saved to VIPS files for you coded as base64 inside the XML. They are
 * copied by copying reference-counted pointers.
 *
 * See also: vips_value_set_blob()
 *
 * Returns: (transfer none): The pointer held by @value.
 */
void *
vips_value_get_blob( const GValue *value, size_t *length )
{
	return( vips_value_get_area( value, length ) );
}

/**
 * vips_value_set_array: 
 * @value: (out): %GValue to set
 * @n: number of elements 
 * @type: the type of each element 
 * @sizeof_type: the sizeof each element 
 *
 * Set @value to be an array of things. 
 *
 * This allocates memory but does not 
 * initialise the contents: get the pointer and write instead.
 */
void
vips_value_set_array( GValue *value, int n, GType type, size_t sizeof_type )
{
	VipsArea *area;

	area = vips_area_new_array( type, sizeof_type, n );
	g_value_set_boxed( value, area );
	vips_area_unref( area );
}

/** 
 * vips_value_get_array:
 * @value: %GValue to get from
 * @n: (allow-none): return the number of elements here, optionally
 * @type: (allow-none): return the type of each element here, optionally
 * @sizeof_type: (allow-none): return the sizeof each element here, optionally
 *
 * Return the pointer to the array held by @value.
 * Optionally return the other properties of the array in @n, @type,
 * @sizeof_type.
 *
 * See also: vips_value_set_array().
 *
 * Returns: (transfer none): The array address.
 */
void *
vips_value_get_array( const GValue *value, 
	int *n, GType *type, size_t *sizeof_type )
{
	VipsArea *area;

	/* Can't check value type, because we may get called from
	 * vips_*_get_type().
	 */

	if( !(area = g_value_get_boxed( value )) )
		return( NULL ); 
	if( n )
		*n = area->n;
	if( type )
		*type = area->type;
	if( sizeof_type )
		*sizeof_type = area->sizeof_type;

	return( area->data );
}

/** 
 * vips_value_get_array_int:
 * @value: %GValue to get from
 * @n: (allow-none): return the number of elements here, optionally
 *
 * Return the start of the array of ints held by @value.
 * optionally return the number of elements in @n.
 *
 * See also: vips_array_int_set().
 *
 * Returns: (transfer none): The array address.
 */
int *
vips_value_get_array_int( const GValue *value, int *n )
{
	return( vips_value_get_array( value, n, NULL, NULL ) );
}

/** 
 * vips_value_set_array_int:
 * @value: (out): %GValue to get from
 * @array: (array length=n): array of ints
 * @n: the number of elements 
 *
 * Set @value to hold a copy of @array. Pass in the array length in @n. 
 *
 * See also: vips_array_int_get().
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_value_set_array_int( GValue *value, const int *array, int n )
{
	int *array_copy;

	g_value_init( value, VIPS_TYPE_ARRAY_INT );
	vips_value_set_array( value, n, G_TYPE_INT, sizeof( int ) );
	array_copy = vips_value_get_array_int( value, NULL );
	memcpy( array_copy, array, n * sizeof( int ) );

	return( 0 );
}

/** 
 * vips_value_get_array_double:
 * @value: %GValue to get from
 * @n: (allow-none): return the number of elements here, optionally
 *
 * Return the start of the array of doubles held by @value.
 * optionally return the number of elements in @n.
 *
 * See also: vips_array_double_set().
 *
 * Returns: (transfer none): The array address.
 */
double *
vips_value_get_array_double( const GValue *value, int *n )
{
	return( vips_value_get_array( value, n, NULL, NULL ) );
}

/** 
 * vips_value_set_array_double:
 * @value: (out): %GValue to get from
 * @array: (array length=n): array of doubles
 * @n: the number of elements 
 *
 * Set @value to hold a copy of @array. Pass in the array length in @n. 
 *
 * See also: vips_array_double_get().
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_value_set_array_double( GValue *value, const double *array, int n )
{
	double *array_copy;

	g_value_init( value, VIPS_TYPE_ARRAY_DOUBLE );
	vips_value_set_array( value, n, G_TYPE_DOUBLE, sizeof( double ) );
	array_copy = vips_value_get_array_double( value, NULL );
	memcpy( array_copy, array, n * sizeof( double ) );

	return( 0 );
}

/** 
 * vips_value_get_array_image:
 * @value: %GValue to get from
 * @n: (allow-none): return the number of elements here, optionally
 *
 * Return the start of the array of images held by @value.
 * optionally return the number of elements in @n.
 *
 * See also: vips_value_set_array_image().
 *
 * Returns: (transfer none): The array address.
 */
VipsImage **
vips_value_get_array_image( const GValue *value, int *n )
{
	return( vips_value_get_array( value, n, NULL, NULL ) );
}

/** 
 * vips_value_set_array_image:
 * @value: (out): %GValue to get from
 * @array: (array length=n): array of images
 * @n: the number of elements 
 *
 * Set @value to hold a copy of @array. Pass in the array length in @n. 
 *
 * See also: vips_array_image_get().
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_value_set_array_image( GValue *value, VipsImage **array, int n )
{
	VipsImage **array_copy;

	g_value_init( value, VIPS_TYPE_ARRAY_IMAGE );
	vips_value_set_array( value, n, VIPS_TYPE_ARRAY_IMAGE, 
		sizeof( VipsImage * ) );
	array_copy = vips_value_get_array_image( value, NULL );
	memcpy( array_copy, array, n * sizeof( VipsImage * ) );

	return( 0 );
}

/** 
 * vips_value_get_array_object: (skip)
 * @value: %GValue to get from
 * @n: (allow-none): return the number of elements here, optionally
 *
 * Return the start of the array of %GObject held by @value.
 * optionally return the number of elements in @n.
 *
 * See also: vips_array_object_set().
 *
 * Returns: (transfer none): The array address.
 */
GObject **
vips_value_get_array_object( const GValue *value, int *n )
{
	return( vips_value_get_array( value, n, NULL, NULL ) );
}

/** 
 * vips_array_object_set:
 * @value: (out): %GValue to set
 * @n: the number of elements 
 *
 * Set @value to hold an array of %GObject. Pass in the array length in @n. 
 *
 * See also: vips_array_object_get().
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
vips_value_set_array_object( GValue *value, int n )
{
	VipsArea *area;

	if( !(area = vips_area_new_array_object( n )) )
		return( -1 );
	g_value_set_boxed( value, area );
	vips_area_unref( area );

	return( 0 );
}

/* Make the types we need for basic functioning. Called from vips_init().
 */
void
vips__meta_init_types( void )
{
	(void) vips_thing_get_type();
	(void) vips_save_string_get_type();
	(void) vips_area_get_type();
	(void) vips_ref_string_get_type();
	(void) vips_blob_get_type();
	(void) vips_array_int_get_type();
	(void) vips_array_double_get_type();
	(void) vips_array_image_get_type();

	/* Register transform functions to go from built-in saveable types to 
	 * a save string. Transform functions for our own types are set 
	 * during type creation. 
	 */
	g_value_register_transform_func( G_TYPE_INT, VIPS_TYPE_SAVE_STRING,
		transform_int_save_string );
	g_value_register_transform_func( VIPS_TYPE_SAVE_STRING, G_TYPE_INT,
		transform_save_string_int );
	g_value_register_transform_func( G_TYPE_DOUBLE, VIPS_TYPE_SAVE_STRING,
		transform_double_save_string );
	g_value_register_transform_func( VIPS_TYPE_SAVE_STRING, G_TYPE_DOUBLE,
		transform_save_string_double );
}
