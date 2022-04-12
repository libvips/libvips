/* vips_configure(): set/clear various libvips settings
 *
 * 11/04/22
 * 	- from configure.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsConfigure {
	VipsOperation parent_instance;

	/* Block all untrusted operations.
	 */
	gboolean untrusted_block;

	/* Block a specific operation.
	 */
	char *operation_block;

	/* Unblock a specific operation.
	 */
	char *operation_unblock;

	/* Enable leak reporting.
	 */
	gboolean leak;

	/* Enable profiling
	 */
	gboolean profile;

	/* Threadpool size.
	 */
	int concurrency;

	/* Max size of pipe.
	 */
	gint64 pipe_read_limit;

	/* Trace libvips operation cache actions.
	 */
	gboolean cache_trace;

	/* Number of recent operations to cache.
	 */
	int cache_max;

	/* Maximum memory to use for operation caching.
	 */
	gint64 cache_max_mem;

	/* Maximum number of open files we allow in the cache.
	 */
	int cache_max_files;

} VipsConfigure;

typedef VipsOperationClass VipsConfigureClass;

G_DEFINE_TYPE( VipsConfigure, vips_configure, VIPS_TYPE_OPERATION );

static int
vips_configure_build( VipsObject *object )
{
	VipsConfigure *configure = (VipsConfigure *) object;

	if( VIPS_OBJECT_CLASS( vips_configure_parent_class )->build( object ) )
		return( -1 );

	if( vips_object_argument_isset( object, "untrusted_block" ) ) 
		vips_block_untrusted_set( configure->untrusted_block );

	if( vips_object_argument_isset( object, "operation_block" ) ) 
		vips_operation_block_set( configure->operation_block, TRUE );
	if( vips_object_argument_isset( object, "operation_unblock" ) ) 
		vips_operation_block_set( configure->operation_block, FALSE );

	return( 0 );
}

static void
vips_configure_class_init( VipsConfigureClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "configure";
	vobject_class->description = _( "set various library options" );
	vobject_class->build = vips_configure_build;

	/* Commands can have side-effects, so don't cache them. 
	 */
	operation_class->flags = VIPS_OPERATION_NOCACHE;

	VIPS_ARG_BOOL( class, "untrusted_block", 2, 
		_( "Block untrusted" ), 
		_( "Block all untrusted operations from running" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConfigure, untrusted_block ),
		FALSE );

	VIPS_ARG_STRING( class, "operation_block", 3, 
		_( "Block operation" ), 
		_( "Block an operation (and any subclasses) from running" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConfigure, operation_block ),
		NULL );

	VIPS_ARG_STRING( class, "operation_unblock", 4, 
		_( "Unblock operation" ), 
		_( "Unblock an operation (and any subclasses) from running" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConfigure, operation_unblock ),
		NULL );

	VIPS_ARG_INT( class, "concurrency", 5, 
		_( "Concurrency" ), 
		_( "Set threadpool size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConfigure, concurrency ),
		0, 0, 1024 );

	VIPS_ARG_UINT64( class, "pipe_read_limit", 6, 
		_( "Pipe read limit" ), 
		_( "Maxiumum number of bytes to buffer for pipe read" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConfigure, pipe_read_limit ),
		0, 1024L * 1024L * 1024L, 1024L * 1024L * 1024L * 1024L ); 

	VIPS_ARG_INT( class, "cache_max", 7, 
		_( "Cache max size" ), 
		_( "Maxium number of operations to cache" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConfigure, cache_max ),
		0, 100, 100000 );

	VIPS_ARG_UINT64( class, "cache_max_mem", 8, 
		_( "Cache max memory size" ), 
		_( "Maxium amount of memory for the operation cache" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConfigure, cache_max ),
		0, 100 * 1024L * 1024L, 1024L * 1024L * 1024L * 1024L ); 

	VIPS_ARG_INT( class, "cache_max_files", 9, 
		_( "Cache max open files" ), 
		_( "Maxium number of open files in operation cache" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsConfigure, cache_max_files ),
		0, 100, 100000 );

}

static void
vips_configure_init( VipsConfigure *configure )
{
	configure->concurrency = -1;
	configure->pipe_read_limit = -1;
}

/**
 * vips_configure:
 * @name: not used
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @untrusted_block: %gboolean, Block all untrusted operations from running
 * * @operation_block : %gchararray, Block an operation from running
 * * @operation_unblock : %gchararray, Unblock an operation from running
 *
 * vips_configure() can be used to set a number of libvips configure
 * options.
 *
 * If @untrusted_block is set, all libvips operations which have been tagged
 * as unsafe for untrusted input will be blocked. All subclasses of these
 * operations are also blocked. See vips_block_untrusted_set().
 *
 * If @operation_block is set, the named libvips operation is blocked. All 
 * subclasses of this operation are also blocked. See
 * vips_operation_block_set().
 *
 * If @operation_unblock is set, the named libvips operation is unblocked. All 
 * subclasses of this operation are also unblocked. See
 * vips_operation_block_set().
 *
 * Returns: 0 on success, -1 on failure. 
 */
int
vips_configure( const char *name, ... )
{
	va_list ap;
	int result;

	va_start( ap, name );
	result = vips_call_split( "configure", ap, name );
	va_end( ap );

	return( result );
}
