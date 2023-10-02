/* base class for all morphology operations
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

#ifndef VIPS_PMORPHOLOGY_H
#define VIPS_PMORPHOLOGY_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_MORPHOLOGY (vips_morphology_get_type())
#define VIPS_MORPHOLOGY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		VIPS_TYPE_MORPHOLOGY, VipsMorphology))
#define VIPS_MORPHOLOGY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		VIPS_TYPE_MORPHOLOGY, VipsMorphologyClass))
#define VIPS_IS_MORPHOLOGY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), VIPS_TYPE_MORPHOLOGY))
#define VIPS_IS_MORPHOLOGY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), VIPS_TYPE_MORPHOLOGY))
#define VIPS_MORPHOLOGY_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
		VIPS_TYPE_MORPHOLOGY, VipsMorphologyClass))

typedef struct _VipsMorphology VipsMorphology;

struct _VipsMorphology {
	VipsOperation parent_instance;

	VipsImage *in;
};

typedef struct _VipsMorphologyClass {
	VipsOperationClass parent_class;

} VipsMorphologyClass;

GType vips_morphology_get_type(void);

void vips_dilate_uchar_hwy(VipsRegion *out_region, VipsRegion *ir, VipsRect *r,
	int sz, int nn128, int *restrict offsets, guint8 *restrict coeff);

void vips_erode_uchar_hwy(VipsRegion *out_region, VipsRegion *ir, VipsRect *r,
	int sz, int nn128, int *restrict offsets, guint8 *restrict coeff);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PMORPHOLOGY_H*/
