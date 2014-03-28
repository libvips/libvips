/* hough transform
 *
 * 7/3/14
 * 	- from hist_find.c
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

#ifndef VIPS_HOUGH_H
#define VIPS_HOUGH_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_HOUGH (vips_hough_get_type())
#define VIPS_HOUGH( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_HOUGH, VipsHough ))
#define VIPS_HOUGH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_HOUGH, VipsHoughClass))
#define VIPS_IS_HOUGH( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_HOUGH ))
#define VIPS_IS_HOUGH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_HOUGH ))
#define VIPS_HOUGH_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_HOUGH, VipsHoughClass ))

typedef struct _VipsHough VipsHough;
typedef struct _VipsHoughClass VipsHoughClass;

typedef int (*VipsHoughInitAccumulator)( VipsHough *hough, 
	VipsImage *accumulator );  
typedef void (*VipsHoughVote)( VipsHough *hough, 
	VipsImage *accumulator, int x, int y ); 

struct _VipsHough {
	VipsStatistic parent_instance;

	/* Size of parameter space. All have at least two dimensions, some
	 * subclasses add a third. 
	 */
	int width;
	int height;

	/* Sum the thread accumulators to here.
	 */
	VipsImage *out; 

};

struct _VipsHoughClass {
	VipsStatisticClass parent_class;

	/* Init an accumulator image.
	 */
	VipsHoughInitAccumulator init_accumulator;

	/* Vote function for this parameter space. 
	 */
	VipsHoughVote vote; 

};

GType vips_hough_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_HOUGH_H*/
