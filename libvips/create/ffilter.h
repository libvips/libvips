/* base class for ffilter generators
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

#ifndef VIPS_FFILTER_H
#define VIPS_FFILTER_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_FFILTER (vips_ffilter_get_type())
#define VIPS_FFILTER( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_FFILTER, VipsFfilter ))
#define VIPS_FFILTER_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_FFILTER, VipsFfilterClass))
#define VIPS_IS_FFILTER( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FFILTER ))
#define VIPS_IS_FFILTER_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FFILTER ))
#define VIPS_FFILTER_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_FFILTER, VipsFfilterClass ))

typedef struct _VipsFfilter {
	VipsPoint parent_instance;

	gboolean optical;
	gboolean reject;
	gboolean nodc;

} VipsFfilter;

typedef struct _VipsFfilterClass {
	VipsPointClass parent_class;

	double (*point)( VipsFfilter *, double, double ); 

} VipsFfilterClass;

GType vips_ffilter_get_type( void );

#define VIPS_TYPE_FFILTER_IDEAL (vips_ffilter_ideal_get_type())
#define VIPS_FFILTER_IDEAL( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_FFILTER_IDEAL, VipsFfilterIdeal ))
#define VIPS_FFILTER_IDEAL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_FFILTER_IDEAL, VipsFfilterIdealClass))
#define VIPS_IS_FFILTER_IDEAL( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FFILTER_IDEAL ))
#define VIPS_IS_FFILTER_IDEAL_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FFILTER_IDEAL ))
#define VIPS_FFILTER_IDEAL_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_FFILTER_IDEAL, VipsFfilterIdealClass ))

typedef struct _VipsFfilterIdeal {
	VipsFfilter parent_instance;

	double frequency_cutoff;

} VipsFfilterIdeal;

typedef VipsFfilterClass VipsFfilterIdealClass;

GType vips_ffilter_ideal_get_type( void );

#define VIPS_TYPE_FFILTER_BUTTERWORTH (vips_ffilter_butterworth_get_type())
#define VIPS_FFILTER_BUTTERWORTH( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_FFILTER_BUTTERWORTH, VipsFfilterButterworth ))
#define VIPS_FFILTER_BUTTERWORTH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_FFILTER_BUTTERWORTH, VipsFfilterButterworthClass))
#define VIPS_IS_FFILTER_BUTTERWORTH( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FFILTER_BUTTERWORTH ))
#define VIPS_IS_FFILTER_BUTTERWORTH_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FFILTER_BUTTERWORTH ))
#define VIPS_FFILTER_BUTTERWORTH_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_FFILTER_BUTTERWORTH, VipsFfilterButterworthClass ))

typedef struct _VipsFfilterButterworth {
	VipsFfilter parent_instance;

	double order;
	double frequency_cutoff;
	double amplitude_cutoff;

} VipsFfilterButterworth;

typedef VipsFfilterClass VipsFfilterButterworthClass;

GType vips_ffilter_butterworth_get_type( void );

#define VIPS_TYPE_FFILTER_GAUSSIAN (vips_ffilter_gaussian_get_type())
#define VIPS_FFILTER_GAUSSIAN( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_FFILTER_GAUSSIAN, VipsFfilterGaussian ))
#define VIPS_FFILTER_GAUSSIAN_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_FFILTER_GAUSSIAN, VipsFfilterGaussianClass))
#define VIPS_IS_FFILTER_GAUSSIAN( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FFILTER_GAUSSIAN ))
#define VIPS_IS_FFILTER_GAUSSIAN_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FFILTER_GAUSSIAN ))
#define VIPS_FFILTER_GAUSSIAN_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_FFILTER_GAUSSIAN, VipsFfilterGaussianClass ))

typedef struct _VipsFfilterGaussian {
	VipsFfilter parent_instance;

	double frequency_cutoff;
	double amplitude_cutoff;

} VipsFfilterGaussian;

typedef VipsFfilterClass VipsFfilterGaussianClass;

GType vips_ffilter_gaussian_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_FFILTER_H*/
