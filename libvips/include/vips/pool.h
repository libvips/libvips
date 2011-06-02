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

#ifndef VIPS_POOL_H
#define VIPS_POOL_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* A pool context ... just an array of GObject pointers.
 */
typedef GPtrArray VipsPoolContext;

/* A VipsPool is really just a hash table, but we make it a VipsObject so we
 * can put pools into other pools.
 */

#define VIPS_TYPE_POOL (vips_pool_get_type())
#define VIPS_POOL( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), VIPS_TYPE_POOL, VipsPool ))
#define VIPS_POOL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), VIPS_TYPE_POOL, VipsPoolClass))
#define VIPS_IS_POOL( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_POOL ))
#define VIPS_IS_POOL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_POOL ))
#define VIPS_POOL_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), VIPS_TYPE_POOL, VipsPoolClass ))

typedef struct _VipsPool {
	VipsObject parent_object;
	
	/* A table of all the contexts we've seen.
	 */
	GHashTable *contexts;
} VipsPool;

typedef struct _VipsPoolClass {
	VipsObjectClass parent_class;
} VipsPoolClass;

GType vips_pool_get_type( void );

VipsPool *vips_pool_new( const char *name );
VipsPoolContext *vips_pool_context_new( VipsPool *pool );
GObject **vips_pool_context_object( VipsPoolContext *context, int n );

/* Save some typing.
 */
#define VIPS_VAR_IMAGE_REF( N ) \
	((VipsImage **) vips_pool_context_object( context, (N) ))
#define VIPS_VAR_IMAGE( N ) \
	(*((VipsImage **) vips_pool_context_object( context, (N) )))

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_POOL_H*/


