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
	int matrix_int[VIPS_TRANSFORM_SCALE + 1][2];
	double matrix_double[VIPS_TRANSFORM_SCALE + 1][2];
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

/* Yafr class starts.
 */

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
	VipsInterpolate parent_object;

	/* "sharpening" is a continuous method parameter which is
	 * proportional to the amount of "diagonal straightening" which the
	 * nonlinear correction part of the method may add to the underlying
	 * linear scheme. You may also think of it as a sharpening
	 * parameter: higher values correspond to more sharpening, and
	 * negative values lead to strange looking effects.
	 *
	 * The default value is sharpening = 29/32 when the scheme being
	 * "straightened" is Catmull-Rom---as is the case here. This value
	 * fixes key pixel values near the diagonal boundary between two
	 * monochrome regions (the diagonal boundary pixel values being set
	 * to the halfway colour).
	 *
	 * If resampling seems to add unwanted texture artifacts, push
	 * sharpening toward 0. It is not generally not recommended to set
	 * sharpening to a value larger than 4.
	 *
	 * Sharpening is halved because the .5 which has to do with the
	 * relative coordinates of the evaluation points (which has to do
	 * with .5*rite_width etc) is folded into the constant to save
	 * flops. Consequently, the largest recommended value of
	 * sharpening_over_two is 2=4/2.
	 *
	 * In order to simplify interfacing with users, the parameter which
	 * should be set by the user is normalized so that user_sharpening =
	 * 1 when sharpening is equal to the recommended value. Consistently
	 * with the above discussion, values of user_sharpening between 0
	 * and about 3.625 give good results.
	 */
	double sharpening;
} VipsInterpolateYafr;

typedef struct _VipsInterpolateYafrClass {
	VipsInterpolateClass parent_class;

} VipsInterpolateYafrClass;

GType vips_interpolate_yafr_get_type( void );
VipsInterpolate *vips_interpolate_yafr_new( void );
void vips_interpolate_yafr_set_sharpening( VipsInterpolateYafr *, 
	double sharpening );

/* Convenience: return a static default yafr, so no need to free it.
 */
VipsInterpolate *vips_interpolate_yafr_static( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_INTERPOLATE_H*/

