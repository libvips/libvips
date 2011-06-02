/* manage pools of objects for unreffing
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
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/*

  Here's how to handle ref counts when calling vips operations:

	VipsImage *
	thing( VipsImage *in1, VipsImage *in2 )
	{
		VipsImage *t;
		VipsImage *out;

		if( vips_add( in1, in2, &t, NULL ) )
			return( NULL );
		if( vips_add( in1, t, &out, NULL ) ) {
			g_object_unref( t );
			return( NULL );
		}
		g_object_unref( t );

		return( out );
	}

  The first vips_add() call returns (via the reference argument) a new 
  VipsImage in variable t. The second vips_add() uses this as an input and 
  takes the ref count up to two. After calling the second vips_add() we have 
  to drop t to avoid leaks. We also have to drop t if the second vips_add() 
  fails.

  VipsPool provides a nicer way to track the objects that you create and free 
  them safely. The above function would become:

  	VipsImage *
	thing( VipsPool *pool, VipsImage *in1, VipsImage *in2 )
	{
		VipsPoolContext *context = vips_pool_context_new( pool );

		VipsImage *out;

		if( vips_add( in1, in2, VIPS_VAR_IMAGE_REF( 1 ), NULL ) ||
			vips_add( in1, VIPS_VAR_IMAGE( 1 ), &out, NULL ) )
			return( NULL );

		return( out );
	}

  vips_pool_context_new() creates a new context to hold a set of temporary 
  objects. You can get a reference to a temporary image object with the 
  macro VIPS_VAR_IMAGE_REF(), and get the object with VIPS_VAR_IMAGE(). 
  Temporary objects are numbered from zero.

  Our caller will (eventually) call g_object_unref() on the pool and this 
  will in turn unref all objects in the pool.

 */

G_DEFINE_TYPE( VipsPool, vips_pool, VIPS_TYPE_POOL );

static void
vips_pool_dispose( GObject *gobject )
{
	VipsPool *pool = VIPS_POOL( gobject );

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "vips_pool_dispose: " );
	vips_object_print( VIPS_OBJECT( gobject ) );
#endif /*VIPS_DEBUG*/

	VIPS_FREEF( g_hash_table_unref, pool->contexts );

	G_OBJECT_CLASS( vips_pool_parent_class )->dispose( gobject );
}

static void
vips_pool_context_print( VipsPoolContext *context, VipsBuf *buf )
{
	vips_buf_appendf( buf, "VipsPoolContext %p, %d objects\n", 
		context, context->len );
}

static void
vips_pool_print( VipsObject *object, VipsBuf *buf )
{
	VipsPool *pool = VIPS_POOL( object );

	if( pool->contexts ) {
		int size = g_hash_table_size( pool->contexts );

		vips_buf_appendf( buf, "%d contexts\n", size ); 
		if( size > 0 )  
			g_hash_table_foreach( pool->contexts, 
				(GHFunc) vips_pool_context_print, buf );
	}

	VIPS_OBJECT_CLASS( vips_pool_parent_class )->print( object, buf );
}

static void
vips_pool_class_init( VipsPoolClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->dispose = vips_pool_dispose;

	vobject_class->print = vips_pool_print;
}

static void
vips_pool_init( VipsPool *pool )
{
	pool->contexts = g_hash_table_new_full( g_direct_hash, g_direct_equal, 
		NULL, (GDestroyNotify) g_ptr_array_unref );
}

VipsPool *
vips_pool_new( const char *name )
{
	VipsPool *pool;

	pool = VIPS_POOL( g_object_new( VIPS_TYPE_POOL, NULL ) );

	g_object_set( pool, "name", name, NULL );

	if( vips_object_build( VIPS_OBJECT( pool ) ) ) {
		VIPS_UNREF( pool );
		return( NULL );
	}

	return( pool );
}

VipsPoolContext *
vips_pool_context_new( VipsPool *pool )
{
	VipsPoolContext *context;

	context = g_ptr_array_new_with_free_func( g_object_unref );
	g_hash_table_insert( pool->contexts, context, context );

	return( context );
}

GObject **
vips_pool_context_object( VipsPoolContext *context, int n )
{
	g_assert( n >= 0 );

	if( n >= context->len )
		g_ptr_array_set_size( context, n + 10 );

	return( (GObject **) &g_ptr_array_index( context, n ) );
}

