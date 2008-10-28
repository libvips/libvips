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

/* An interpolation function. This is a class method, but we have a lookup
 * function for it to speed up dispatch.
 */
typedef void (*VipsInterpolateMethod)( VipsInterpolate *, 
	REGION *out, REGION *in,
	int out_x, int out_y, double in_x, double in_y );

typedef struct _VipsInterpolateClass {
	VipsObjectClass parent_class;

	/* Write to pixel out(x,y), interpolating from in(x,y). The caller has
	 * to set the regions up.
	 */
	VipsInterpolateMethod  interpolate;

	/* This interpolator needs a window this many pixels across and down.
	 */
	int (*get_window_size)( VipsInterpolate * );

	/* Or just set this if you want  constant.
	 */
	int window_size;
} VipsInterpolateClass;

GType vips_interpolate_get_type( void );
void vips_interpolate( VipsInterpolate *interpolate, REGION *out, REGION *in,
        int out_x, int out_y, double in_x, double in_y );
VipsInterpolateMethod vips_interpolate_get_method( VipsInterpolate * );
int vips_interpolate_get_window_size( VipsInterpolate *interpolate );

/* Nearest class starts.
 */

#define VIPS_TYPE_INTERPOLATE_NEAREST (vips_interpolate_nearest_get_type())
#define VIPS_INTERPOLATE_NEAREST( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_NEAREST, VipsInterpolateNearest ))
#define VIPS_INTERPOLATE_NEAREST_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_NEAREST, VipsInterpolateNearestClass))
#define VIPS_IS_INTERPOLATE_NEAREST( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_NEAREST ))
#define VIPS_IS_INTERPOLATE_NEAREST_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_NEAREST ))
#define VIPS_INTERPOLATE_NEAREST_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_NEAREST, VipsInterpolateNearestClass ))

typedef struct _VipsInterpolateNearest {
	VipsInterpolate parent_object;

} VipsInterpolateNearest;

typedef struct _VipsInterpolateNearestClass {
	VipsInterpolateClass parent_class;

} VipsInterpolateNearestClass;

VipsInterpolate *vips_interpolate_nearest_new( void );
GType vips_interpolate_nearest_get_type( void );

/* Convenience: return a static fast nearest, so no need to free it.
 */
VipsInterpolate *vips_interpolate_nearest_static( void );

/* Bilinear class starts.
 */

/* How many bits of precision we keep for transformations, ie. how many
 * pre-computed matricies we have.
 */
#define VIPS_TRANSFORM_SHIFT (5)
#define VIPS_TRANSFORM_SCALE (1 << VIPS_TRANSFORM_SHIFT)

/* How many bits of precision we keep for interpolation, ie. where the decimal
 * is in the fixed-point tables.
 */
#define VIPS_INTERPOLATE_SHIFT (13)
#define VIPS_INTERPOLATE_SCALE (1 << VIPS_INTERPOLATE_SHIFT)

#define VIPS_TYPE_INTERPOLATE_BILINEAR (vips_interpolate_bilinear_get_type())
#define VIPS_INTERPOLATE_BILINEAR( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_BILINEAR, VipsInterpolateBilinear ))
#define VIPS_INTERPOLATE_BILINEAR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_BILINEAR, VipsInterpolateBilinearClass))
#define VIPS_IS_INTERPOLATE_BILINEAR( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_BILINEAR ))
#define VIPS_IS_INTERPOLATE_BILINEAR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_BILINEAR ))
#define VIPS_INTERPOLATE_BILINEAR_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_BILINEAR, VipsInterpolateBilinearClass ))

typedef struct _VipsInterpolateBilinear {
	VipsInterpolate parent_object;

} VipsInterpolateBilinear;

typedef struct _VipsInterpolateBilinearClass {
	VipsInterpolateClass parent_class;

	/* Precalculated interpolation matricies. int (used for pel sizes up 
	 * to short), and double (for all others). We go to scale + 1, so
	 * we can round-to-nearest safely.
 	 */
	int matrixi[VIPS_TRANSFORM_SCALE + 1][VIPS_TRANSFORM_SCALE + 1][4];
	double matrixd[VIPS_TRANSFORM_SCALE + 1][VIPS_TRANSFORM_SCALE + 1][4];
} VipsInterpolateBilinearClass;

GType vips_interpolate_bilinear_get_type( void );
VipsInterpolate *vips_interpolate_bilinear_new( void );

/* Convenience: return a static fast bilinear, so no need to free it.
 */
VipsInterpolate *vips_interpolate_bilinear_static( void );

/* Slow bilinear class starts.
 */

#define VIPS_TYPE_INTERPOLATE_BILINEAR_SLOW \
	(vips_interpolate_bilinear_slow_get_type())
#define VIPS_INTERPOLATE_BILINEAR_SLOW( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_BILINEAR_SLOW, VipsInterpolateBilinearSlow ))
#define VIPS_INTERPOLATE_BILINEAR_SLOW_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_BILINEAR_SLOW, \
	VipsInterpolateBilinearSlowClass))
#define VIPS_IS_INTERPOLATE_BILINEAR_SLOW( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), \
	VIPS_TYPE_INTERPOLATE_BILINEAR_SLOW ))
#define VIPS_IS_INTERPOLATE_BILINEAR_SLOW_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), \
	VIPS_TYPE_INTERPOLATE_BILINEAR_SLOW ))
#define VIPS_INTERPOLATE_BILINEAR_SLOW_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_BILINEAR_SLOW, VipsInterpolateBilinearSlowClass ))

typedef struct _VipsInterpolateBilinearSlow {
	VipsInterpolate parent_object;

} VipsInterpolateBilinearSlow;

typedef struct _VipsInterpolateBilinearSlowClass {
	VipsInterpolateClass parent_class;

} VipsInterpolateBilinearSlowClass;

GType vips_interpolate_bilinear_slow_get_type( void );
VipsInterpolate *vips_interpolate_bilinear_slow_new( void );

/* Convenience: return a static fast bilinear_slow, so no need to free it.
 */
VipsInterpolate *vips_interpolate_bilinear_slow_static( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_INTERPOLATE_H*/

