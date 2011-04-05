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

#ifndef VIPS_OPERATION_H
#define VIPS_OPERATION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

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

} VipsOperation;

typedef struct _VipsOperationClass {
	VipsObjectClass parent_class;

} VipsOperationClass;

GType vips_operation_get_type( void );

int vips_operation_call_valist( VipsOperation *operation, va_list ap );
VipsOperation *vips_operation_new( const char *name ); 
int vips_call( const char *operation_name, ... );
int vips_call_split( const char *operation_name, va_list optional, ... );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_OPERATION_H*/
