/* Bicubic (catmull-rom) interpolator.
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

#ifndef VIPS_BICUBIC_H
#define VIPS_BICUBIC_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_INTERPOLATE_BICUBIC \
	(vips_interpolate_bicubic_get_type())
#define VIPS_INTERPOLATE_BICUBIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_BICUBIC, VipsInterpolateBicubic ))
#define VIPS_INTERPOLATE_BICUBIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_BICUBIC, VipsInterpolateBicubicClass))
#define VIPS_IS_INTERPOLATE_BICUBIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_BICUBIC ))
#define VIPS_IS_INTERPOLATE_BICUBIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_BICUBIC ))
#define VIPS_INTERPOLATE_BICUBIC_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_BICUBIC, VipsInterpolateBicubicClass ))

typedef struct _VipsInterpolateBicubic {
	VipsInterpolate parent_object;

} VipsInterpolateBicubic;

typedef struct _VipsInterpolateBicubicClass {
	VipsInterpolateClass parent_class;

	/* Precalculated interpolation matricies. int (used for pel sizes up 
	 * to short), and double (for all others). We go to scale + 1, so
	 * we can round-to-nearest safely.
	 */

	/* We could keep a large set of 2d 4x4 matricies, but this actually
	 * works out slower, since for many resizes the thing will no longer
	 * fit in L1.
	 */
	int matrixi[VIPS_TRANSFORM_SCALE + 1][4];
	double matrixf[VIPS_TRANSFORM_SCALE + 1][4];
} VipsInterpolateBicubicClass;

GType vips_interpolate_bicubic_get_type( void );
VipsInterpolate *vips_interpolate_bicubic_new( void );

/* Convenience: return a static default bicubic, so no need to free it.
 */
VipsInterpolate *vips_interpolate_bicubic_static( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_BICUBIC_H*/

