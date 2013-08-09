/* base class for all stats operations
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

#ifndef VIPS_STATISTIC_H
#define VIPS_STATISTIC_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vector.h>

#define VIPS_TYPE_STATISTIC (vips_statistic_get_type())
#define VIPS_STATISTIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_STATISTIC, VipsStatistic ))
#define VIPS_STATISTIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_STATISTIC, VipsStatisticClass))
#define VIPS_IS_STATISTIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_STATISTIC ))
#define VIPS_IS_STATISTIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_STATISTIC ))
#define VIPS_STATISTIC_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_STATISTIC, VipsStatisticClass ))

typedef struct _VipsStatistic VipsStatistic;
typedef struct _VipsStatisticClass VipsStatisticClass;

typedef void *(*VipsStatisticStartFn)( VipsStatistic *statistic ); 
typedef int (*VipsStatisticScanFn)( VipsStatistic *statistic, 
	void *seq, int x, int y, void *p, int n );  
typedef int (*VipsStatisticStopFn)( VipsStatistic *statistic, void *seq );

struct _VipsStatistic {
	VipsOperation parent_instance;

	/* All have an input image.
	 */
	VipsImage *in;

	/* The input image cast and ready for processing. 
	 */
	VipsImage *ready;

	/* Set this to stop computation early.
	 */
	gboolean stop;

	/* Client data for the subclass.
	 */
	void *a; 
	void *b;
};

struct _VipsStatisticClass {
	VipsOperationClass parent_class;

	/* Start/scan/stop, for vips_sink.
	 */
	VipsStatisticStartFn start; 
	VipsStatisticScanFn scan; 
	VipsStatisticStopFn stop;

	/* For each input format, what output format. If NULL, no casting.
	 */
	const VipsBandFormat *format_table;
};

GType vips_statistic_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_STATISTIC_H*/
