/* base class for all correlation operations
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

#ifndef VIPS_PCORRELATION_H
#define VIPS_PCORRELATION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vector.h>

#define VIPS_TYPE_CORRELATION (vips_correlation_get_type())
#define VIPS_CORRELATION( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_CORRELATION, VipsCorrelation ))
#define VIPS_CORRELATION_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_CORRELATION, VipsCorrelationClass))
#define VIPS_IS_CORRELATION( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_CORRELATION ))
#define VIPS_IS_CORRELATION_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_CORRELATION ))
#define VIPS_CORRELATION_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_CORRELATION, VipsCorrelationClass ))

typedef struct {
	VipsOperation parent_instance;

	/* Params.
	 */
	VipsImage *in;
	VipsImage *ref;
	VipsImage *out;

	/* The two input images, upcast to the smallest common format. ref is
	 * a memory buffer.
	 */
	VipsImage *in_ready;
	VipsImage *ref_ready;

} VipsCorrelation;

typedef struct {
	VipsOperationClass parent_class;

	/* For each upcast input format, what output format. 
	 */
	const VipsBandFormat *format_table;

	/* Run just before generate. The subclass can fill in some stuff.
	 */
	int (*pre_generate)( VipsCorrelation * );  

	void (*correlation)( VipsCorrelation *, 
		VipsRegion *in, VipsRegion *out ); 

} VipsCorrelationClass;

GType vips_correlation_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PCORRELATION_H*/


