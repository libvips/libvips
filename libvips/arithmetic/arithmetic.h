/* base class for all arithmetic operations
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

#ifndef VIPS_ARITHMETIC_H
#define VIPS_ARITHMETIC_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vector.h>

#define VIPS_TYPE_ARITHMETIC (vips_arithmetic_get_type())
#define VIPS_ARITHMETIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_ARITHMETIC, VipsArithmetic ))
#define VIPS_ARITHMETIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_ARITHMETIC, VipsArithmeticClass))
#define VIPS_IS_ARITHMETIC( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_ARITHMETIC ))
#define VIPS_IS_ARITHMETIC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_ARITHMETIC ))
#define VIPS_ARITHMETIC_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_ARITHMETIC, VipsArithmeticClass ))

typedef struct _VipsArithmetic {
	VipsOperation parent_instance;

	/* All have an output image.
	 */
	VipsImage *output;

} VipsArithmetic;

typedef struct _VipsArithmeticClass {
	VipsOperationClass parent_class;

	/* For each input format, what output format. Used for arithmetic
	 * too, since we cast inputs to match.
	 */
	VipsBandFormat *format_table;

	/* A vector program for each input type.
	 */
	VipsVector *vectors[VIPS_FORMAT_LAST];

	/* ... and if we've set a program for this format.
	 */
	gboolean vector_program[VIPS_FORMAT_LAST];
} VipsArithmeticClass;

GType vips_arithmetic_get_type( void );

void vips_arithmetic_set_format_table( VipsArithmeticClass *klass, 
	VipsBandFormat *format_table );
VipsVector *vips_arithmetic_get_vector( VipsArithmeticClass *klass, 
	VipsBandFormat fmt );
void vips_arithmetic_compile( VipsArithmeticClass *klass ); 
VipsVector *vips_arithmetic_get_program( VipsArithmeticClass *klass, 
	VipsBandFormat fmt );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_ARITHMETIC_H*/


