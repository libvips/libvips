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
 * function for it to speed up dispatch. Write to the memory at "out",
 * interpolate the value at position (x, y) in "in".
 */
typedef void (*VipsInterpolateMethod)( VipsInterpolate *, 
	PEL *out, REGION *in, double x, double y );

typedef struct _VipsInterpolateClass {
	VipsObjectClass parent_class;

	/* Write to pixel out(x,y), interpolating from in(x,y). The caller has
	 * to set the regions up.
	 */
	VipsInterpolateMethod interpolate;

	/* This interpolator needs a window this many pixels across and down.
	 */
	int (*get_window_size)( VipsInterpolate * );

	/* Or just set this if you want  constant.
	 */
	int window_size;
} VipsInterpolateClass;

GType vips_interpolate_get_type( void );
void vips_interpolate( VipsInterpolate *interpolate, 
	PEL *out, REGION *in, double x, double y );
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
 * is in the fixed-point tables. For 16-bit pixels, we need 16 bits for the
 * data, 4 bits to add 16 values together, another bit for the sign and some
 * other stuff, so say 24 total. That leaves 8 bits for the fractional part.
 */
#define VIPS_INTERPOLATE_SHIFT (8)
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
	 * to short), and float (for all others). We go to scale + 1, so
	 * we can round-to-nearest safely. Don't bother with double, since
	 * this is an approximation anyway.
 	 */
	int matrixi[VIPS_TRANSFORM_SCALE + 1][VIPS_TRANSFORM_SCALE + 1][4];
	float matrixd[VIPS_TRANSFORM_SCALE + 1][VIPS_TRANSFORM_SCALE + 1][4];
} VipsInterpolateBilinearClass;

GType vips_interpolate_bilinear_get_type( void );
VipsInterpolate *vips_interpolate_bilinear_new( void );

/* Convenience: return a static bilinear, so no need to free it.
 */
VipsInterpolate *vips_interpolate_bilinear_static( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_INTERPOLATE_H*/

