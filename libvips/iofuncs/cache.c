/* cache vips operations
 *
 * 20/6/12
 * 	- try to make it compile on centos5
 * 7/7/12
 * 	- add a lock so we can run operations from many threads
 * 28/11/19 [MaxKellermann]
 * 	- make invalidate advisory rather than immediate
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

   TODO

	what about delayed writes ... do we ever write in close? we shouldn't,
	should do in evalend or written or somesuch

	use g_param_values_cmp() instead of value_equal()?

 */

/*
#define VIPS_DEBUG
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <ctype.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

/* Set by GOption from the command line, eg. "12m".
 */
gboolean vips__cache_dump = FALSE;
gboolean vips__cache_trace = FALSE;

/* Max number of cached operations. 
 *
 * It was 10,000, but this was too high for batch-style applications with
 * little reuse. 
 */
static int vips_cache_max = 100;

/* How many tracked open files we allow before we start dropping cache.
 */
static int vips_cache_max_files = 100;

/* How much RAM we spend on caches before we start dropping cached operations
 * ... default 100mb.
 *
 * It was 1gb, but that's a lot of memory for things like vipsthumbnail where
 * there will be (almost) no reuse. Default low and let apps raise it if it'd
 * be useful.
 */
static size_t vips_cache_max_mem = 100 * 1024 * 1024;

/* Hold a ref to all "recent" operations.
 */
static GHashTable *vips_cache_table = NULL;

/* A 'time' counter: increment on all cache ops. Use this to detect LRU.
 */
static int vips_cache_time = 0;

/* Protect cache access with this.
 */
static GMutex *vips_cache_lock = NULL;

/* Old versions of glib are missing these. When we abandon centos 5, switch to
 * g_int64_hash() and g_double_hash().
 */
#define INT64_HASH(X) (g_direct_hash(X))
#define DOUBLE_HASH(X) (g_direct_hash(X))

/* A cache entry.
 */
typedef struct _VipsOperationCacheEntry {
	VipsOperation *operation;

	/* When we added this operation to cache .. used to find LRU for
	 * flush.
	 */
	int time;

	/* We listen for "invalidate" from the operation. Track the id here so
	 * we can disconnect when we drop an operation.
	 */
	gulong invalidate_id;

	/* Set if someone thinks this cache entry should be dropped.
	 */
	gboolean invalid;

} VipsOperationCacheEntry;

/* Pass in the pspec so we can get the generic type. For example, a 
 * held in a GParamSpec allowing OBJECT, but the value could be of type
 * VipsImage. generics are much faster to compare.
 */
static unsigned int
vips_value_hash( GParamSpec *pspec, GValue *value )
{
	GType generic = G_PARAM_SPEC_TYPE( pspec );

	/* Not compile-time constants, so we have to use a set of if()s. Could
	 * make a table at run time I guess.
	 */

	if( generic == G_TYPE_PARAM_BOOLEAN )
		return( (unsigned int) g_value_get_boolean( value ) );
	else if( generic == G_TYPE_PARAM_CHAR )
		return( (unsigned int) g_value_get_schar( value ) );
	else if( generic == G_TYPE_PARAM_UCHAR )
		return( (unsigned int) g_value_get_uchar( value ) );
	else if( generic == G_TYPE_PARAM_INT )
		return( (unsigned int) g_value_get_int( value ) );
	else if( generic == G_TYPE_PARAM_UINT )
		return( (unsigned int) g_value_get_uint( value ) );
	else if( generic == G_TYPE_PARAM_LONG )
		return( (unsigned int) g_value_get_long( value ) );
	else if( generic == G_TYPE_PARAM_ULONG )
		return( (unsigned int) g_value_get_ulong( value ) );
	else if( generic == G_TYPE_PARAM_ENUM )
		return( (unsigned int) g_value_get_enum( value ) );
	else if( generic == G_TYPE_PARAM_FLAGS )
		return( (unsigned int) g_value_get_flags( value ) );
	else if( generic == G_TYPE_PARAM_UINT64 ) {
		guint64 i = g_value_get_uint64( value );

		return( INT64_HASH( (gint64 *) &i ) );
	}
	else if( generic == G_TYPE_PARAM_INT64 ) {
		gint64 i = g_value_get_int64( value );

		return( INT64_HASH( &i ) );
	}
	else if( generic == G_TYPE_PARAM_FLOAT ) {
		float f = g_value_get_float( value );

		return( g_direct_hash( (void *) &f ) );
	}
	else if( generic == G_TYPE_PARAM_DOUBLE ) {
		double d = g_value_get_double( value );

		return( DOUBLE_HASH( &d ) );
	}
	else if( generic == G_TYPE_PARAM_STRING ) {
		const char *s = g_value_get_string( value );

		return( s ? g_str_hash( s ) : 0 );
	}
	else if( generic == G_TYPE_PARAM_BOXED ) {
		void *p = g_value_get_boxed( value );

		return( p ? g_direct_hash( p ) : 0 );
	}
	else if( generic == G_TYPE_PARAM_POINTER ) {
		void *p = g_value_get_pointer( value );

		return( p ? g_direct_hash( p ) : 0 );
	}
	else if( generic == G_TYPE_PARAM_OBJECT ) {
		void *p = g_value_get_object( value );

		return( p ? g_direct_hash( p ) : 0 );
	}
	else {
		/* Fallback: convert to a string and hash that. 
		 * This is very slow, print a warning if we use it 
		 * so we can add another case.
		 */
		char *s;
		unsigned int hash;

		s = g_strdup_value_contents( value ); 
		hash = g_str_hash( s );

		printf( "vips_value_hash: no case for %s\n", s );
		printf( "\ttype %d, %s\n", 
			(int) G_VALUE_TYPE( value ),
			g_type_name( G_VALUE_TYPE( value ) ) );
		printf( "\tgeneric %d, %s\n", 
			(int) G_VALUE_TYPE( generic ),
			g_type_name( generic ) );

		g_free( s );

		return( hash );
	}
}

/* Pass in the pspec so we can get the generic type. For example, a 
 * value could be held in a GParamSpec allowing OBJECT, but the value 
 * could be of type VipsImage. generics are much faster to compare.
 */
static gboolean 
vips_value_equal( GParamSpec *pspec, GValue *v1, GValue *v2 )
{
	GType generic = G_PARAM_SPEC_TYPE( pspec );
	GType t1 = G_VALUE_TYPE( v1 );
	GType t2 = G_VALUE_TYPE( v2 );

	if( t1 != t2 )
		return( FALSE );

	/* Not compile-time constants, so we have to use a set of if()s. Could
	 * make a table at run time I guess.
	 */

	if( generic == G_TYPE_PARAM_BOOLEAN ) 
		return( g_value_get_boolean( v1 ) == 
			g_value_get_boolean( v2 ) );
	else if( generic == G_TYPE_PARAM_CHAR ) 
		return( g_value_get_schar( v1 ) ==
			g_value_get_schar( v2 ) );
	if( generic == G_TYPE_PARAM_UCHAR ) 
		return( g_value_get_uchar( v1 ) ==
			g_value_get_uchar( v2 ) );
	if( generic == G_TYPE_PARAM_INT ) 
		return( g_value_get_int( v1 ) ==
			g_value_get_int( v2 ) );
	if( generic == G_TYPE_PARAM_UINT ) 
		return( g_value_get_uint( v1 ) ==
			g_value_get_uint( v2 ) );
	if( generic == G_TYPE_PARAM_LONG ) 
		return( g_value_get_long( v1 ) ==
			g_value_get_long( v2 ) );
	if( generic == G_TYPE_PARAM_ULONG ) 
		return( g_value_get_ulong( v1 ) ==
			g_value_get_ulong( v2 ) );
	if( generic == G_TYPE_PARAM_ENUM ) 
		return( g_value_get_enum( v1 ) ==
			g_value_get_enum( v2 ) );
	if( generic == G_TYPE_PARAM_FLAGS ) 
		return( g_value_get_flags( v1 ) ==
			g_value_get_flags( v2 ) );
	if( generic == G_TYPE_PARAM_UINT64 ) 
		return( g_value_get_uint64( v1 ) ==
			g_value_get_uint64( v2 ) );
	if( generic == G_TYPE_PARAM_INT64 ) 
		return( g_value_get_int64( v1 ) ==
			g_value_get_int64( v2 ) );
	if( generic == G_TYPE_PARAM_FLOAT ) 
		return( g_value_get_float( v1 ) ==
			g_value_get_float( v2 ) );
	if( generic == G_TYPE_PARAM_DOUBLE ) 
		return( g_value_get_double( v1 ) ==
			g_value_get_double( v2 ) );
	if( generic == G_TYPE_PARAM_STRING ) {
		const char *s1 = g_value_get_string( v1 );
		const char *s2 = g_value_get_string( v2 );

		if( s1 == s2 )
			return( TRUE );
		else
			return( s1 && s2 && strcmp( s1, s2 ) == 0 );
	}
	if( generic == G_TYPE_PARAM_BOXED ) 
		return( g_value_get_boxed( v1 ) ==
			g_value_get_boxed( v2 ) );
	if( generic == G_TYPE_PARAM_POINTER ) 
		return( g_value_get_pointer( v1 ) ==
			g_value_get_pointer( v2 ) );
	if( generic == G_TYPE_PARAM_OBJECT ) 
		return( g_value_get_object( v1 ) ==
			g_value_get_object( v2 ) );
	else {
		/* Fallback: convert to a string and compare that. 
		 * This is very slow, print a warning if we use it 
		 * so we can add another case.
		 */
		char *s1;
		char *s2;
		gboolean equal;

		s1 = g_strdup_value_contents( v1 ); 
		s2 = g_strdup_value_contents( v2 ); 
		equal = strcmp( s1, s2 ) == 0;

		printf( "vips_value_equal: no case for %s, %s\n", 
			s1, s2 );
		printf( "\tt1 %d, %s\n", (int) t1, g_type_name( t1 ) );
		printf( "\tt2 %d, %s\n", (int) t2, g_type_name( t2 ) );
		printf( "\tgeneric %d, %s\n", 
			(int) G_VALUE_TYPE( generic ),
			g_type_name( generic ) );

		g_free( s1 );
		g_free( s2 );

		return( equal );
	}
}

static void *
vips_object_hash_arg( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	unsigned int *hash = (unsigned int *) a;

	if( (argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		(argument_class->flags & VIPS_ARGUMENT_INPUT) &&
		argument_instance->assigned ) {
		const char *name = g_param_spec_get_name( pspec );
		GType type = G_PARAM_SPEC_VALUE_TYPE( pspec );
		GValue value = { 0, };

		g_value_init( &value, type );
		g_object_get_property( G_OBJECT( object ), name, &value ); 
		*hash = (*hash << 1) ^ vips_value_hash( pspec, &value );
		g_value_unset( &value );
	}

	return( NULL );
}

/* Find a hash from the input arguments to a VipsOperstion.
 */
static unsigned int
vips_operation_hash( VipsOperation *operation )
{
	if( !operation->found_hash ) {
		guint hash;

		/* Include the operation type in the hash.
		 */
		hash = (guint) G_OBJECT_TYPE( operation );
		(void) vips_argument_map( VIPS_OBJECT( operation ),
			vips_object_hash_arg, &hash, NULL );

		/* Make sure we can't have a zero hash value.
		 */
		hash |= 1;

		operation->hash = hash;
		operation->found_hash = TRUE;
	}

	return( operation->hash );
}

static void *
vips_object_equal_arg( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	VipsObject *other = (VipsObject *) a;

	const char *name = g_param_spec_get_name( pspec );
	GType type = G_PARAM_SPEC_VALUE_TYPE( pspec );
	GValue v1 = { 0, };
	GValue v2 = { 0, };

	gboolean equal;

	/* Only test assigned input constructor args.
	 */
	if( !(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ||
		!(argument_class->flags & VIPS_ARGUMENT_INPUT) ||
		!argument_instance->assigned ) 
		return( NULL );

	/* If this is an optional arg, we need to check that this was
	 * assigned on @other as well.
	 */
	if( !(argument_class->flags & VIPS_ARGUMENT_REQUIRED) &&
		!vips_object_argument_isset( other, name ) )
		/* Optional and was not set on other ... we've found a
		 * difference!
		 */
		return( object ); 

	g_value_init( &v1, type );
	g_value_init( &v2, type );
	g_object_get_property( G_OBJECT( object ), name, &v1 ); 
	g_object_get_property( G_OBJECT( other ), name, &v2 ); 
	equal = vips_value_equal( pspec, &v1, &v2 );
	g_value_unset( &v1 );
	g_value_unset( &v2 );

	/* Stop (return non-NULL) if we've found a difference.
	 */
	return( !equal ? object : NULL ); 
}

/* Are two objects equal, ie. have the same inputs.
 */
static gboolean 
vips_operation_equal( VipsOperation *a, VipsOperation *b )
{
	if( a == b ) 
		return( TRUE );

	if( G_OBJECT_TYPE( a ) == G_OBJECT_TYPE( b ) &&
		vips_operation_hash( a ) == vips_operation_hash( b ) &&
		!vips_argument_map( VIPS_OBJECT( a ), 
			vips_object_equal_arg, b, NULL ) )
		return( TRUE );

	return( FALSE );
}

void *
vips__cache_once_init( void *data )
{
	vips_cache_lock = vips_g_mutex_new();

	vips_cache_table = g_hash_table_new( 
		(GHashFunc) vips_operation_hash, 
		(GEqualFunc) vips_operation_equal );

	return( NULL ); 
}

void
vips__cache_init( void )
{
	static GOnce once = G_ONCE_INIT;

	VIPS_ONCE( &once, vips__cache_once_init, NULL );
}

static void *
vips_cache_print_fn( void *value, void *a, void *b )
{
	VipsOperationCacheEntry *entry = value;

	char str[32768];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	vips_object_to_string( VIPS_OBJECT( entry->operation ), &buf );

	printf( "%p - %s\n", value, vips_buf_all( &buf ) );

	return( NULL );
}

static void
vips_cache_print_nolock( void )
{
	if( vips_cache_table ) {
		printf( "Operation cache:\n" );
		vips_hash_table_map( vips_cache_table,
			vips_cache_print_fn, NULL, NULL );
	}
}

/**
 * vips_cache_print:
 *
 * Print the whole operation cache to stdout. Handy for debugging.
 */
void
vips_cache_print( void )
{
	g_mutex_lock( vips_cache_lock );

	vips_cache_print_nolock();

	g_mutex_unlock( vips_cache_lock );
}

static void *
vips_object_unref_arg( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	if( (argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		(argument_class->flags & VIPS_ARGUMENT_OUTPUT) &&
		argument_instance->assigned &&
		G_IS_PARAM_SPEC_OBJECT( pspec ) ) {
		GObject *value;

		/* This will up the ref count for us.
		 */
		g_object_get( G_OBJECT( object ), 
			g_param_spec_get_name( pspec ), &value, NULL );

		/* Drop the ref we just got, then drop the ref we make when we
		 * added to the cache.
		 */
		g_object_unref( value );
		g_object_unref( value );
	}

	return( NULL );
}

static void
vips_cache_unref( VipsOperation *operation )
{
#ifdef DEBUG
	printf( "vips_cache_unref: " );
	vips_object_print_summary( VIPS_OBJECT( operation ) );
#endif /*DEBUG*/

	(void) vips_argument_map( VIPS_OBJECT( operation ),
		vips_object_unref_arg, NULL, NULL );
	g_object_unref( operation );
}

/* Remove an operation from the cache.
 */
static void
vips_cache_remove( VipsOperation *operation )
{
	VipsOperationCacheEntry *entry = (VipsOperationCacheEntry *)
		g_hash_table_lookup( vips_cache_table, operation );

#ifdef DEBUG
	printf( "vips_cache_remove: " );
	vips_object_print_summary( VIPS_OBJECT( operation ) );
#endif /*DEBUG*/

	g_assert( entry ); 

	if( entry->invalidate_id ) { 
		g_signal_handler_disconnect( operation, entry->invalidate_id );
		entry->invalidate_id = 0;
	}

	g_hash_table_remove( vips_cache_table, operation );
	vips_cache_unref( operation );

	g_free( entry );
}

static void *
vips_object_ref_arg( VipsObject *object,
	GParamSpec *pspec,
	VipsArgumentClass *argument_class,
	VipsArgumentInstance *argument_instance,
	void *a, void *b )
{
	if( (argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) &&
		(argument_class->flags & VIPS_ARGUMENT_OUTPUT) &&
		argument_instance->assigned &&
		G_IS_PARAM_SPEC_OBJECT( pspec ) ) {
		GObject *value;

		/* This will up the ref count for us.
		 */
		g_object_get( G_OBJECT( object ), 
			g_param_spec_get_name( pspec ), &value, NULL );
	}

	return( NULL );
}

static void
vips_operation_touch( VipsOperation *operation )
{
	VipsOperationCacheEntry *entry = (VipsOperationCacheEntry *)
		g_hash_table_lookup( vips_cache_table, operation );

	vips_cache_time += 1;

	/* Don't up the time for invalid items -- we want them to fall out of
	 * cache.
	 */
	if( !entry->invalid ) 
		entry->time = vips_cache_time;
}

/* Ref an operation for the cache. The operation itself, plus all the output 
 * objects it makes. 
 */
static void
vips_cache_ref( VipsOperation *operation )
{
#ifdef DEBUG
	printf( "vips_cache_ref: " );
	vips_object_print_summary( VIPS_OBJECT( operation ) );
#endif /*DEBUG*/

	g_object_ref( operation );
	(void) vips_argument_map( VIPS_OBJECT( operation ),
		vips_object_ref_arg, NULL, NULL );
	vips_operation_touch( operation );
}

static void
vips_cache_invalidate_cb( VipsOperation *operation, 
	VipsOperationCacheEntry *entry )
{
#ifdef DEBUG
	printf( "vips_cache_invalidate_cb: " );
	vips_object_print_summary( VIPS_OBJECT( operation ) );
#endif /*DEBUG*/

	entry->invalid = TRUE;
}

static void
vips_cache_insert( VipsOperation *operation )
{
	VipsOperationCacheEntry *entry = g_new( VipsOperationCacheEntry, 1 );

#ifdef VIPS_DEBUG
	printf( "vips_cache_insert: adding to cache" );
	vips_object_print_dump( VIPS_OBJECT( operation ) );
#endif /*VIPS_DEBUG*/

	entry->operation = operation;
	entry->time = 0;
	entry->invalidate_id = 0;
	entry->invalid = FALSE;

	g_hash_table_insert( vips_cache_table, operation, entry );
	vips_cache_ref( operation );

	/* If the operation signals "invalidate", we must tag this cache entry
	 * for removal.
	 */
	entry->invalidate_id = g_signal_connect( operation, "invalidate", 
		G_CALLBACK( vips_cache_invalidate_cb ), entry ); 
}

static void *
vips_cache_get_first_fn( void *value, void *a, void *b )
{
	return( value );
}

/* Return the first item.
 */
static VipsOperation *
vips_cache_get_first( void )
{
	VipsOperationCacheEntry *entry;

	if( vips_cache_table &&
		(entry = vips_hash_table_map( vips_cache_table, 
			vips_cache_get_first_fn, NULL, NULL )) )
		return( VIPS_OPERATION( entry->operation ) );

	return( NULL ); 
}

/**
 * vips_cache_drop_all:
 *
 * Drop the whole operation cache, handy for leak tracking. Also called
 * automatically on vips_shutdown().
 */
void
vips_cache_drop_all( void )
{
#ifdef VIPS_DEBUG
	printf( "vips_cache_drop_all:\n" );
#endif /*VIPS_DEBUG*/

	g_mutex_lock( vips_cache_lock );

	if( vips_cache_table ) {
		VipsOperation *operation;

		if( vips__cache_dump )
			vips_cache_print_nolock();

		/* We can't modify the hash in the callback from
		 * g_hash_table_foreach() and friends. Repeatedly drop the
		 * first item instead.
		 */
		while( (operation = vips_cache_get_first()) ) 
			vips_cache_remove( operation );

		VIPS_FREEF( g_hash_table_unref, vips_cache_table );
	}

	g_mutex_unlock( vips_cache_lock );
}

static void
vips_cache_get_lru_cb( VipsOperation *key, VipsOperationCacheEntry *value, 
	VipsOperationCacheEntry **best )
{
	if( !*best ||
		(*best)->time > value->time )
		*best = value;
}

/* Get the least-recently-used cache item. 
 *
 * TODO ... will this be too expensive? probably not
 */
static VipsOperation *
vips_cache_get_lru( void )
{
	VipsOperationCacheEntry *entry;

	entry = NULL;
	g_hash_table_foreach( vips_cache_table,
		(GHFunc) vips_cache_get_lru_cb, &entry );

	if( entry )
		return( entry->operation );

	return( NULL ); 
}

/* Is the cache full? Drop until it's not.
 */
static void
vips_cache_trim( void )
{
	VipsOperation *operation;

	g_mutex_lock( vips_cache_lock );

	while( vips_cache_table &&
		(g_hash_table_size( vips_cache_table ) > vips_cache_max ||
		vips_tracked_get_files() > vips_cache_max_files ||
		vips_tracked_get_mem() > vips_cache_max_mem) &&
		(operation = vips_cache_get_lru()) ) {
#ifdef DEBUG
		printf( "vips_cache_trim: trimming " );
		vips_object_print_summary( VIPS_OBJECT( operation ) );
#endif /*DEBUG*/

		vips_cache_remove( operation );
	}

	g_mutex_unlock( vips_cache_lock );
}

/**
 * vips_cache_operation_lookup:
 * @operation: (transfer none): pointer to operation to lookup
 *
 * Look up an unbuilt @operation in the cache. If we get a hit, ref and 
 * return the old operation. If there's no hit, return NULL.
 *
 * Returns: (transfer full): the cache hit, if any.
 */
VipsOperation *
vips_cache_operation_lookup( VipsOperation *operation )
{
	VipsOperationCacheEntry *hit;
	VipsOperation *result;

	g_assert( VIPS_IS_OPERATION( operation ) );
	g_assert( !VIPS_OBJECT( operation )->constructed ); 

#ifdef VIPS_DEBUG
	printf( "vips_cache_operation_lookup: " );
	vips_object_print_dump( VIPS_OBJECT( operation ) );
#endif /*VIPS_DEBUG*/

	g_mutex_lock( vips_cache_lock );

	result = NULL;

	if( (hit = g_hash_table_lookup( vips_cache_table, operation )) ) {
		if( hit->invalid ||
                        (VIPS_OPERATION_GET_CLASS( hit->operation )->flags &
                                VIPS_OPERATION_BLOCKED) ) {
			/* Has been tagged for removal, or has been blocked.
			 */
			vips_cache_remove( hit->operation );
			hit = NULL;
		}
		else {
			if( vips__cache_trace ) {
				printf( "vips cache*: " );
				vips_object_print_summary( 
					VIPS_OBJECT( operation ) );
			}

			result = hit->operation;
			vips_cache_ref( result );
		}
	}

	g_mutex_unlock( vips_cache_lock );

#ifdef VIPS_DEBUG
	printf( "vips_cache_operation_lookup: result = %p\n", result );
#endif /*VIPS_DEBUG*/

	return( result );
}

/**
 * vips_cache_operation_add:
 * @operation: (transfer none): pointer to operation to add
 *
 * Add a built operation to the cache. The cache will ref the operation. 
 */
void
vips_cache_operation_add( VipsOperation *operation )
{
	g_assert( VIPS_OBJECT( operation )->constructed ); 

	g_mutex_lock( vips_cache_lock );

#ifdef VIPS_DEBUG
	printf( "vips_cache_operation_add: adding " );
	vips_object_print_dump( VIPS_OBJECT( operation ) );
#endif /*VIPS_DEBUG*/

	/* If two threads call the same operation at the same time, 
	 * we can get multiple adds. Let the first one win. See
	 * https://github.com/libvips/libvips/pull/181
	 */
	if( !g_hash_table_lookup( vips_cache_table, operation ) ) {
		VipsOperationFlags flags = 
			vips_operation_get_flags( operation );
		gboolean nocache = flags & VIPS_OPERATION_NOCACHE;

		/* Has to be after _build() so we can see output args.
		 */
		if( vips__cache_trace ) {
			if( nocache )
				printf( "vips cache : " );
			else
				printf( "vips cache+: " );
			vips_object_print_summary( VIPS_OBJECT( operation ) );
		}

		if( !nocache ) 
			vips_cache_insert( operation );
	}

	g_mutex_unlock( vips_cache_lock );

	vips_cache_trim();
}

/**
 * vips_cache_operation_buildp: (skip)
 * @operation: pointer to operation to lookup
 *
 * Look up @operation in the cache. If we get a hit, unref @operation, ref the
 * old one and return that through the argument pointer. 
 *
 * If we miss, build and add @operation.
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_cache_operation_buildp( VipsOperation **operation )
{
	VipsOperation *hit;

	g_assert( VIPS_IS_OPERATION( *operation ) );

#ifdef VIPS_DEBUG
	printf( "vips_cache_operation_buildp: " );
	vips_object_print_dump( VIPS_OBJECT( *operation ) );
#endif /*VIPS_DEBUG*/

	if( (hit = vips_cache_operation_lookup( *operation )) ) {
#ifdef VIPS_DEBUG
		printf( "vips_cache_operation_buildp: cache hit %p\n", hit );
#endif /*VIPS_DEBUG*/

		g_object_unref( *operation );
		*operation = hit;
	}
	else {
#ifdef VIPS_DEBUG
		printf( "vips_cache_operation_buildp: cache miss, building\n" );
#endif /*VIPS_DEBUG*/

		if( vips_object_build( VIPS_OBJECT( *operation ) ) ) 
			return( -1 );

		vips_cache_operation_add( *operation ); 
	}

	return( 0 );
}

/**
 * vips_cache_operation_build:
 * @operation: (transfer none): operation to lookup
 *
 * A binding-friendly version of vips_cache_operation_buildp().
 *
 * After calling this, @operation has the same ref count as when it went in,
 * and the result must be freed with vips_object_unref_outputs() and
 * g_object_unref().
 *
 * Returns: (transfer full): The built operation.
 */
VipsOperation *
vips_cache_operation_build( VipsOperation *operation )
{
	VipsOperation *orig_operation = operation;

	/* Stop it being unreffed for us on hit.
	 */
	g_object_ref( orig_operation );

	if( vips_cache_operation_buildp( &operation ) ) {
		g_object_unref( orig_operation );

		return( NULL );
	}

	return( operation );
}

/**
 * vips_cache_set_max:
 * @max: maximum number of operation to cache
 *
 * Set the maximum number of operations we keep in cache. 
 */
void
vips_cache_set_max( int max )
{
	vips_cache_max = max;
	vips_cache_trim();
}

/**
 * vips_cache_set_max_mem:
 * @max_mem: maximum amount of tracked memory we use 
 *
 * Set the maximum amount of tracked memory we allow before we start dropping
 * cached operations. See vips_tracked_get_mem().
 *
 * libvips only tracks memory it allocates, it can't track memory allocated by
 * external libraries. If you use an operation like vips_magickload(), most of
 * the memory it uses won't be included. 
 *
 * See also: vips_tracked_get_mem(). 
 */
void
vips_cache_set_max_mem( size_t max_mem )
{
	vips_cache_max_mem = max_mem;
	vips_cache_trim();
}

/**
 * vips_cache_get_max:
 *
 * Get the maximum number of operations we keep in cache. 
 *
 * Returns: the maximum number of operations we keep in cache
 */
int
vips_cache_get_max( void )
{
	return( vips_cache_max );
}

/**
 * vips_cache_get_size:
 *
 * Get the current number of operations in cache. 
 *
 * Returns: get the current number of operations in cache.
 */
int
vips_cache_get_size( void )
{
	guint size;

	g_mutex_lock( vips_cache_lock );

	size = 0;
	if( vips_cache_table )
		size = g_hash_table_size( vips_cache_table );

	g_mutex_unlock( vips_cache_lock );

	return( size );
}

/**
 * vips_cache_get_max_mem:
 *
 * Get the maximum amount of tracked memory we allow before we start dropping
 * cached operations. See vips_tracked_get_mem().
 *
 * See also: vips_tracked_get_mem(). 
 *
 * Returns: the maximum amount of tracked memory we allow
 */
size_t
vips_cache_get_max_mem( void )
{
	return( vips_cache_max_mem );
}

/**
 * vips_cache_get_max_files:
 *
 * Get the maximum number of tracked files we allow before we start dropping
 * cached operations. See vips_tracked_get_files().
 *
 * libvips only tracks file descriptors it allocates, it can't track ones 
 * allocated by external libraries. If you use an operation like 
 * vips_magickload(), most of the descriptors it uses won't be included. 
 *
 * See also: vips_tracked_get_files(). 
 *
 * Returns: the maximum number of tracked files we allow
 */
int
vips_cache_get_max_files( void )
{
	return( vips_cache_max_files );
}

/**
 * vips_cache_set_max_files:
 * @max_files: max open files we allow
 *
 * Set the maximum number of tracked files we allow before we start dropping
 * cached operations. See vips_tracked_get_files().
 *
 * See also: vips_tracked_get_files(). 
 */
void
vips_cache_set_max_files( int max_files )
{
	vips_cache_max_files = max_files;
	vips_cache_trim();
}

/**
 * vips_cache_set_dump:
 * @dump: if %TRUE, dump the operation cache on exit
 *
 * Handy for debugging. Print the operation cache to stdout just before exit.
 *
 * See also: vips_cache_set_trace(). 
 */
void
vips_cache_set_dump( gboolean dump )
{
	vips__cache_dump = dump;
}

/**
 * vips_cache_set_trace:
 * @trace: if %TRUE, trace the operation cache 
 *
 * Handy for debugging. Print operation cache actions to stdout as we run.
 *
 * You can set the environment variable `VIPS_TRACE` to turn this option on, or
 * use the command-line flag `--vips-cache-trace`.
 *
 * See also: vips_cache_set_dump(). 
 */
void
vips_cache_set_trace( gboolean trace )
{
	vips__cache_trace = trace;
}
