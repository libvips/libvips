/* base class for mask generators
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

#ifndef VIPS_PMASK_H
#define VIPS_PMASK_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* vips7compat.h defines VIPS_MASK(), an old compat macro.
 */
#ifdef VIPS_MASK
#undef VIPS_MASK
#endif /*VIPS_MASK*/

#define VIPS_TYPE_MASK (vips_mask_get_type())
#define VIPS_MASK( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_MASK, VipsMask ))
#define VIPS_MASK_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_MASK, VipsMaskClass))
#define VIPS_IS_MASK( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_MASK ))
#define VIPS_IS_MASK_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_MASK ))
#define VIPS_MASK_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_MASK, VipsMaskClass ))

typedef struct _VipsMask {
	VipsPoint parent_instance;

	gboolean optical;
	gboolean reject;
	gboolean nodc;

} VipsMask;

typedef struct _VipsMaskClass {
	VipsPointClass parent_class;

	double (*point)( VipsMask *, double, double ); 

} VipsMaskClass;

GType vips_mask_get_type( void );

#define VIPS_TYPE_MASK_IDEAL (vips_mask_ideal_get_type())
#define VIPS_MASK_IDEAL( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_MASK_IDEAL, VipsMaskIdeal ))
#define VIPS_MASK_IDEAL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_MASK_IDEAL, VipsMaskIdealClass))
#define VIPS_IS_MASK_IDEAL( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_MASK_IDEAL ))
#define VIPS_IS_MASK_IDEAL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_MASK_IDEAL ))
#define VIPS_MASK_IDEAL_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_MASK_IDEAL, VipsMaskIdealClass ))

typedef struct _VipsMaskIdeal {
	VipsMask parent_instance;

	double frequency_cutoff;

} VipsMaskIdeal;

typedef VipsMaskClass VipsMaskIdealClass;

GType vips_mask_ideal_get_type( void );

#define VIPS_TYPE_MASK_BUTTERWORTH (vips_mask_butterworth_get_type())
#define VIPS_MASK_BUTTERWORTH( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_MASK_BUTTERWORTH, VipsMaskButterworth ))
#define VIPS_MASK_BUTTERWORTH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_MASK_BUTTERWORTH, VipsMaskButterworthClass))
#define VIPS_IS_MASK_BUTTERWORTH( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_MASK_BUTTERWORTH ))
#define VIPS_IS_MASK_BUTTERWORTH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_MASK_BUTTERWORTH ))
#define VIPS_MASK_BUTTERWORTH_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_MASK_BUTTERWORTH, VipsMaskButterworthClass ))

typedef struct _VipsMaskButterworth {
	VipsMask parent_instance;

	double order;
	double frequency_cutoff;
	double amplitude_cutoff;

} VipsMaskButterworth;

typedef VipsMaskClass VipsMaskButterworthClass;

GType vips_mask_butterworth_get_type( void );

#define VIPS_TYPE_MASK_GAUSSIAN (vips_mask_gaussian_get_type())
#define VIPS_MASK_GAUSSIAN( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_MASK_GAUSSIAN, VipsMaskGaussian ))
#define VIPS_MASK_GAUSSIAN_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_MASK_GAUSSIAN, VipsMaskGaussianClass))
#define VIPS_IS_MASK_GAUSSIAN( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_MASK_GAUSSIAN ))
#define VIPS_IS_MASK_GAUSSIAN_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_MASK_GAUSSIAN ))
#define VIPS_MASK_GAUSSIAN_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_MASK_GAUSSIAN, VipsMaskGaussianClass ))

typedef struct _VipsMaskGaussian {
	VipsMask parent_instance;

	double frequency_cutoff;
	double amplitude_cutoff;

} VipsMaskGaussian;

typedef VipsMaskClass VipsMaskGaussianClass;

GType vips_mask_gaussian_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PMASK_H*/
