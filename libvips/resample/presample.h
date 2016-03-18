/* base class for all resample operations
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

#ifndef VIPS_PRESAMPLE_H
#define VIPS_PRESAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_RESAMPLE (vips_resample_get_type())
#define VIPS_RESAMPLE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_RESAMPLE, VipsResample ))
#define VIPS_RESAMPLE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_RESAMPLE, VipsResampleClass))
#define VIPS_IS_RESAMPLE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_RESAMPLE ))
#define VIPS_IS_RESAMPLE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_RESAMPLE ))
#define VIPS_RESAMPLE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_RESAMPLE, VipsResampleClass ))

typedef struct _VipsResample {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

} VipsResample;

typedef struct _VipsResampleClass {
	VipsOperationClass parent_class;

} VipsResampleClass;

GType vips_resample_get_type( void );

/* The max size of the vector we use.
 */
#define MAX_POINT (50)

int vips_reduce_get_points( VipsKernel kernel, double shrink );
void vips_reduce_make_mask( VipsKernel kernel, double shrink, 
	double x, double *c );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PRESAMPLE_H*/


