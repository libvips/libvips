/* base class for all nary arithmetic operations
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

#ifndef VIPS_NARY_H
#define VIPS_NARY_H

#include <vips/vips.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include "parithmetic.h"

#define VIPS_TYPE_NARY (vips_nary_get_type())
#define VIPS_NARY( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), VIPS_TYPE_NARY, VipsNary ))
#define VIPS_NARY_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), VIPS_TYPE_NARY, VipsNaryClass))
#define VIPS_IS_NARY( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_NARY ))
#define VIPS_IS_NARY_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_NARY ))
#define VIPS_NARY_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), VIPS_TYPE_NARY, VipsNaryClass ))

typedef struct _VipsNary {
	VipsArithmetic parent_instance;

	/* The input images.
	 */
	VipsArea *in;

} VipsNary;

typedef VipsArithmeticClass VipsNaryClass;

GType vips_nary_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_NARY_H*/


