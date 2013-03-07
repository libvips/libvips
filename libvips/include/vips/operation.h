/* base class for all vips operations
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_OPERATION_H
#define VIPS_OPERATION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vips.h>

/** 
 * VipsOperationFlags:
 * @VIPS_OPERATION_NONE: no flags
 * @VIPS_OPERATION_SEQUENTIAL: can work sequentially
 * @VIPS_OPERATION_NOCACHE: must not be cached
 *
 * Flags we associate with an operation.
 *
 * @VIPS_OPERATION_SEQUENTIAL means that the operation works like vips_copy:
 * it can happily process images top-to-bottom with only small non-local
 * references.
 *
 * @VIPS_OPERATION_NOCACHE means that the operation must not be cached by
 * vips. 
 */
typedef enum /*< flags >*/ {
	VIPS_OPERATION_NONE = 0,
	VIPS_OPERATION_SEQUENTIAL = 1,
	VIPS_OPERATION_NOCACHE = 2
} VipsOperationFlags;

#define VIPS_TYPE_OPERATION (vips_operation_get_type())
#define VIPS_OPERATION( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_OPERATION, VipsOperation ))
#define VIPS_OPERATION_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_OPERATION, VipsOperationClass ))
#define VIPS_IS_OPERATION( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_OPERATION ))
#define VIPS_IS_OPERATION_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_OPERATION ))
#define VIPS_OPERATION_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_OPERATION, VipsOperationClass ))

typedef gboolean (*VipsOperationBuildFn)( VipsObject * );

typedef struct _VipsOperation {
	VipsObject parent_instance;

	/* When we added this operation to cache .. used to find LRU for
	 * flush.
	 */
	int time;

	/* Keep the hash here.
	 */
	guint hash;
	gboolean found_hash;

} VipsOperation;

typedef struct _VipsOperationClass {
	VipsObjectClass parent_class;

	/* Print the usage message.
	 */
	void (*usage)( struct _VipsOperationClass *, VipsBuf * );

	/* Return a set of operation flags. 
	 */
	VipsOperationFlags (*get_flags)( VipsOperation * ); 
	VipsOperationFlags flags;
} VipsOperationClass;

GType vips_operation_get_type( void );

VipsOperationFlags vips_operation_get_flags( VipsOperation *operation );
void vips_operation_class_print_usage( VipsOperationClass *operation_class );

int vips_operation_call_valist( VipsOperation *operation, va_list ap );
VipsOperation *vips_operation_new( const char *name ); 
int vips_call( const char *operation_name, ... )
	__attribute__((sentinel));
int vips_call_split( const char *operation_name, va_list optional, ... );

void vips_call_options( GOptionGroup *group, VipsOperation *operation );
int vips_call_argv( VipsOperation *operation, int argc, char **argv );

void vips_cache_drop_all( void );
int vips_cache_operation_buildp( VipsOperation **operation );
VipsOperation *vips_cache_operation_build( VipsOperation *operation );
void vips_cache_print( void );
void vips_cache_set_max( int max );
void vips_cache_set_max_mem( size_t max_mem );
int vips_cache_get_max( void );
int vips_cache_get_size( void );
size_t vips_cache_get_max_mem( void );
int vips_cache_get_max_files( void );
void vips_cache_set_max_files( int max_files );
void vips_cache_set_dump( gboolean dump );
void vips_cache_set_trace( gboolean trace );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_OPERATION_H*/
