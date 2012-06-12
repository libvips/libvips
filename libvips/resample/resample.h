/* base class for all resample operations
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/* We don't want to get confused with the resample.h in include, put an
 * extra _ in there.
 */

#ifndef VIPS__RESAMPLE_H
#define VIPS__RESAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_RESAMPLE (vips_resample_get_type())
#define VIPS_RESAMPLE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_RESAMPLE, VipsResample ))
#define VIPS_RESAMPLE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_RESAMPLE, VipsResampleClass))
#define VIPS_IS_RESAMPLE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_RESAMPLE ))
#define VIPS_IS_RESAMPLE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_RESAMPLE ))
#define VIPS_RESAMPLE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_RESAMPLE, VipsResampleClass ))

typedef struct _VipsResample {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

} VipsResample;

typedef struct _VipsResampleClass {
	VipsOperationClass parent_class;

} VipsResampleClass;

GType vips_resample_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS__RESAMPLE_H*/


