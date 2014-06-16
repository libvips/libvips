/* base class for various operations on bands
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

#ifndef VIPS__BANDARY_H
#define VIPS__BANDARY_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include "pconversion.h"

#define VIPS_TYPE_BANDARY (vips_bandary_get_type())
#define VIPS_BANDARY( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_BANDARY, VipsBandary ))
#define VIPS_BANDARY_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_BANDARY, VipsBandaryClass))
#define VIPS_IS_BANDARY( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_BANDARY ))
#define VIPS_IS_BANDARY_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_BANDARY ))
#define VIPS_BANDARY_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_BANDARY, VipsBandaryClass ))

struct _VipsBandary;
typedef void (*VipsBandaryProcessFn)( struct _VipsBandary *bandary, 
	VipsPel *out, VipsPel **in, int width );

typedef struct _VipsBandary {
	VipsConversion parent_instance;

	/* Array of input arguments, set these from a subclass.
	 */
	VipsImage **in;
	int n;

	/* The number of output bands. For example, VipsBandjoin sets the sum
	 * of the bands in the input images.
	 */
	int out_bands;

	/* The input images, ready for the operation.
	 */
	VipsImage **ready;

} VipsBandary;

typedef struct _VipsBandaryClass {
	VipsConversionClass parent_class;

	/* The buffer processor.
	 */
	VipsBandaryProcessFn process_line;

	/* For each input format, what output format. Leave NULL for output
	 * format == input format. 
	 */
	const VipsBandFormat *format_table;

} VipsBandaryClass;

GType vips_bandary_get_type( void );

int vips_bandary_copy( VipsBandary *bandary );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS__BANDARY_H*/

