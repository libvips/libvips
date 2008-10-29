/* YAFRNOHALO interpolator.
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

#ifndef VIPS_YAFRNOHALO_H
#define VIPS_YAFRNOHALO_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_INTERPOLATE_YAFRNOHALO (vips_interpolate_yafrnohalo_get_type())
#define VIPS_INTERPOLATE_YAFRNOHALO( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_YAFRNOHALO, VipsInterpolateYafrnohalo ))
#define VIPS_INTERPOLATE_YAFRNOHALO_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_YAFRNOHALO, VipsInterpolateYafrnohaloClass))
#define VIPS_IS_INTERPOLATE_YAFRNOHALO( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_YAFRNOHALO ))
#define VIPS_IS_INTERPOLATE_YAFRNOHALO_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_YAFRNOHALO ))
#define VIPS_INTERPOLATE_YAFRNOHALO_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_YAFRNOHALO, VipsInterpolateYafrnohaloClass ))

typedef struct _VipsInterpolateYafrnohalo {
	VipsInterpolate parent_object;

	/* "sharpening" is a continuous method parameter which is
	 * proportional to the amount of "diagonal straightening" which the
	 * nonlinear correction part of the method may add to the underlying
	 * linear scheme. You may also think of it as a sharpening
	 * parameter: higher values correspond to more sharpening, and
	 * negative values lead to strange looking effects.
	 *
	 * The default value is sharpening = 4/3 when the scheme being
	 * "straightened" is bilinear---as is the case here. This value
	 * fixes key pixel values near the diagonal boundary between two
	 * monochrome regions (the diagonal boundary pixel values being set
	 * to the halfway colour).
	 *
	 * If resampling seems to add unwanted texture artifacts, push
	 * sharpening toward 0. It is not generally not recommended to set
	 * sharpening to a value larger than 2.
	 *
	 * In order to simplify interfacing with users, the parameter which
	 * should be set by the user is normalized so that user_sharpening =
	 * 1 when sharpening is equal to the recommended value. Consistently
	 * with the above discussion, values of user_sharpening between 0
	 * and about 1.5 give good results.
	 */
	double sharpening;
} VipsInterpolateYafrnohalo;

typedef struct _VipsInterpolateYafrnohaloClass {
	VipsInterpolateClass parent_class;

} VipsInterpolateYafrnohaloClass;

GType vips_interpolate_yafrnohalo_get_type( void );
VipsInterpolate *vips_interpolate_yafrnohalo_new( void );
void vips_interpolate_yafrnohalo_set_sharpening( VipsInterpolateYafrnohalo *, 
	double sharpening );

/* Convenience: return a static default yafrnohalo, so no need to free it.
 */
VipsInterpolate *vips_interpolate_yafrnohalo_static( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_YAFRNOHALO_H*/

