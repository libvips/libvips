/* Various interpolators.
 *
 * J.Cupitt, 15/10/08
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_VINTERPOLATE_H
#define IM_VINTERPOLATE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define TYPE_VINTERPOLATE (vinterpolate_get_type())
#define VINTERPOLATE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), TYPE_VINTERPOLATE, VInterpolate ))
#define VINTERPOLATE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	TYPE_VINTERPOLATE, VInterpolateClass))
#define IS_VINTERPOLATE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), TYPE_VINTERPOLATE ))
#define IS_VINTERPOLATE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), TYPE_VINTERPOLATE ))
#define VINTERPOLATE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	TYPE_VINTERPOLATE, VInterpolateClass ))

typedef struct _VInterpolate {
	VObject parent;

} VInterpolate;

typedef struct _VInterpolateClass {
	VObjectClass parent_class;

	/* Write to pixel out(x,y), interpolating from in(x,y). The caller has
	 * to set the regions up.
	 */
	void (*interpolate)( VInterpolate *, REGION *out, REGION *in,
		int out_x, int out_y, double in_x, double in_y );

	/* This interpolator needs a window of pixels this big.
	 */
	int window;

} VInterpolateClass;

#define TYPE_VINTERPOLATE_YAFR (vinterpolate_yafr_get_type())
#define VINTERPOLATE_YAFR( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), TYPE_VINTERPOLATE_YAFR, VInterpolateYafr ))
#define VINTERPOLATE_YAFR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	TYPE_VINTERPOLATE_YAFR, VInterpolateYafrClass))
#define IS_VINTERPOLATE_YAFR( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), TYPE_VINTERPOLATE_YAFR ))
#define IS_VINTERPOLATE_YAFR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), TYPE_VINTERPOLATE_YAFR ))
#define VINTERPOLATE_YAFR_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	TYPE_VINTERPOLATE_YAFR, VInterpolateYafrClass ))

typedef struct _VInterpolateYafr {
	VObject parent;

} VInterpolateYafr;

typedef struct _VInterpolateYafrClass {
	VObjectClass parent_class;

} VInterpolateYafrClass;

VInterpolate *vinterpolate_bilinear_new( void );

VInterpolateYafr *vinterpolate_yafr_new( void );
void vinterpolate_yafr_set_thing( VInterpolateYafr *, double thing );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_VINTERPOLATE_H*/

