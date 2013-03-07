/* base class for all conversion operations
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

/* We don't want to get confused with the conversion.h in include, put an
 * extra _ in there.
 */

#ifndef VIPS__CONVERSION_H
#define VIPS__CONVERSION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vector.h>

#define VIPS_TYPE_CONVERSION (vips_conversion_get_type())
#define VIPS_CONVERSION( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_CONVERSION, VipsConversion ))
#define VIPS_CONVERSION_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_CONVERSION, VipsConversionClass))
#define VIPS_IS_CONVERSION( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_CONVERSION ))
#define VIPS_IS_CONVERSION_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_CONVERSION ))
#define VIPS_CONVERSION_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_CONVERSION, VipsConversionClass ))

typedef struct _VipsConversion {
	VipsOperation parent_instance;

	/* All have an output image.
	 */
	VipsImage *out;

} VipsConversion;

typedef struct _VipsConversionClass {
	VipsOperationClass parent_class;

} VipsConversionClass;

GType vips_conversion_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS__CONVERSION_H*/


