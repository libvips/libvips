/* base class for all hist_buffer operations
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

#ifndef VIPS_PHIST_BUFFER_H
#define VIPS_PHIST_BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vector.h>

#define VIPS_TYPE_HIST_BUFFER (vips_hist_buffer_get_type())
#define VIPS_HIST_BUFFER( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_HIST_BUFFER, VipsHistBuffer ))
#define VIPS_HIST_BUFFER_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_HIST_BUFFER, VipsHistBufferClass))
#define VIPS_IS_HIST_BUFFER( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_HIST_BUFFER ))
#define VIPS_IS_HIST_BUFFER_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_HIST_BUFFER ))
#define VIPS_HIST_BUFFER_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_HIST_BUFFER, VipsHistBufferClass ))

struct _VipsHistBuffer;
typedef void (*VipsHistBufferProcessFn)( struct _VipsHistBuffer *hist_buffer, 
	VipsPel *out, VipsPel *in, int width );

typedef struct _VipsHistBuffer {
	VipsHistogram parent_instance;

} VipsHistBuffer;

typedef struct _VipsHistBufferClass {
	VipsHistogramClass parent_class;

	/* For each input format, what output format. 
	 */
	const VipsBandFormat *format_table;

	VipsHistBufferProcessFn process;
} VipsHistBufferClass;

GType vips_hist_buffer_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PHIST_BUFFER_H*/


