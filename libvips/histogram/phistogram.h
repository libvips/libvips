/* base class for all histogram operations
 *
 * many hists in, one hist out, a buffer processing function in the class
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

#ifndef VIPS_PHISTOGRAM_H
#define VIPS_PHISTOGRAM_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vector.h>

#define VIPS_TYPE_HISTOGRAM (vips_histogram_get_type())
#define VIPS_HISTOGRAM( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_HISTOGRAM, VipsHistogram ))
#define VIPS_HISTOGRAM_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_HISTOGRAM, VipsHistogramClass))
#define VIPS_IS_HISTOGRAM( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_HISTOGRAM ))
#define VIPS_IS_HISTOGRAM_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_HISTOGRAM ))
#define VIPS_HISTOGRAM_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_HISTOGRAM, VipsHistogramClass ))

typedef struct _VipsHistogram VipsHistogram;

typedef void (*VipsHistogramProcessFn)( VipsHistogram *histogram, 
	VipsPel *out, VipsPel **in, int width );

struct _VipsHistogram {
	VipsOperation parent_instance;

	VipsImage *out;

	/* NULL-terminated array of input images. 
	 */
	VipsImage **in;
	int n;

	/* ... and transformed ready for processing.
	 */
	VipsImage **ready; 
};

typedef struct _VipsHistogramClass {
	VipsOperationClass parent_class;

	/* For each input format, what output format. 
	 */
	const VipsBandFormat *format_table;

	VipsHistogramProcessFn process;

} VipsHistogramClass;

GType vips_histogram_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PHISTOGRAM_H*/


