/* base class for all freqfilt operations
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

#ifndef VIPS_PFREQFILT_H
#define VIPS_PFREQFILT_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vector.h>

#define VIPS_TYPE_FREQFILT (vips_freqfilt_get_type())
#define VIPS_FREQFILT( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_FREQFILT, VipsFreqfilt ))
#define VIPS_FREQFILT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_FREQFILT, VipsFreqfiltClass))
#define VIPS_IS_FREQFILT( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_FREQFILT ))
#define VIPS_IS_FREQFILT_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_FREQFILT ))
#define VIPS_FREQFILT_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_FREQFILT, VipsFreqfiltClass ))

typedef struct _VipsFreqfilt {
	VipsOperation parent_instance;

	/* All have an output image.
	 */
	VipsImage *out;

} VipsFreqfilt;

typedef struct _VipsFreqfiltClass {
	VipsOperationClass parent_class;

} VipsFreqfiltClass;

GType vips_freqfilt_get_type( void );

typedef int (*VipsFftProcessFn)( VipsObject *, VipsImage *, VipsImage ** );

int vips__fftproc( VipsObject *context, 
	VipsImage *in, VipsImage **out, VipsFftProcessFn fn );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PFREQFILT_H*/


