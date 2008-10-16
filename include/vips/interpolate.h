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

#ifndef VIPS_INTERPOLATE_H
#define VIPS_INTERPOLATE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_INTERPOLATE (vips_interpolate_get_type())
#define VIPS_INTERPOLATE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE, VipsInterpolate ))
#define VIPS_INTERPOLATE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE, VipsInterpolateClass))
#define VIPS_IS_INTERPOLATE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE ))
#define VIPS_IS_INTERPOLATE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE ))
#define VIPS_INTERPOLATE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE, VipsInterpolateClass ))

typedef struct _VipsInterpolate {
	VipsObject parent_object;

} VipsInterpolate;

typedef struct _VipsInterpolateClass {
	VipsObjectClass parent_class;

	/* Write to pixel out(x,y), interpolating from in(x,y). The caller has
	 * to set the regions up.
	 */
	void (*interpolate)( VipsInterpolate *, REGION *out, REGION *in,
		int out_x, int out_y, double in_x, double in_y );

	/* This interpolator needs a window of pixels this big.
	 */
	int window;

} VipsInterpolateClass;

VipsInterpolate *vips_interpolate_bilinear_new( void );

/* Convenience: return a static bilinear, so no need to free it.
 */
VipsInterpolate *vips_interpolate_bilinear();

#define VIPS_TYPE_INTERPOLATE_YAFR (vips_interpolate_yafr_get_type())
#define VIPS_INTERPOLATE_YAFR( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_YAFR, VipsInterpolateYafr ))
#define VIPS_INTERPOLATE_YAFR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_YAFR, VipsInterpolateYafrClass))
#define VIPS_IS_INTERPOLATE_YAFR( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_YAFR ))
#define VIPS_IS_INTERPOLATE_YAFR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_YAFR ))
#define VIPS_INTERPOLATE_YAFR_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_YAFR, VipsInterpolateYafrClass ))

typedef struct _VipsInterpolateYafr {
	VipsObject parent_object;

} VipsInterpolateYafr;

typedef struct _VipsInterpolateYafrClass {
	VipsObjectClass parent_class;

} VipsInterpolateYafrClass;

VipsInterpolateYafr *vips_interpolate_yafr_new( void );
void vips_interpolate_yafr_set_thing( VipsInterpolateYafr *, double thing );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_INTERPOLATE_H*/

