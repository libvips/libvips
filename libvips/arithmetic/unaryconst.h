/* base class for all unaryconst arithmetic operations
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

#ifndef VIPS_UNARY_CONST_H
#define VIPS_UNARY_CONST_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include "unary.h"

#define VIPS_TYPE_UNARY_CONST (vips_unary_const_get_type())
#define VIPS_UNARY_CONST( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_UNARY_CONST, VipsUnaryConst ))
#define VIPS_UNARY_CONST_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_UNARY_CONST, VipsUnaryConstClass))
#define VIPS_IS_UNARY_CONST( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_UNARY_CONST ))
#define VIPS_IS_UNARY_CONST_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_UNARY_CONST ))
#define VIPS_UNARY_CONST_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_UNARY_CONST, VipsUnaryConstClass ))

typedef struct _VipsUnaryConst {
	VipsUnary parent_instance;

	/* Our constants.
	 */
	VipsArea *c;

	/* The format the constant should be cast to. Subclasses set this
	 * ready for unaryconst's build method.
	 */
	VipsBandFmt const_format;

	/* Our constant expanded to match arith->ready in size and
	 * const_format in type.
	 */
	int n;
	VipsPel *c_ready;

} VipsUnaryConst;

typedef struct _VipsUnaryConstClass {
	VipsUnaryClass parent_class;

} VipsUnaryConstClass;

GType vips_unary_const_get_type( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_UNARY_CONST_H*/


