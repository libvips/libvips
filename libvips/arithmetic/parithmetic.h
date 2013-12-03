/* base class for all arithmetic operations
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

#ifndef VIPS_PARITHMETIC_H
#define VIPS_PARITHMETIC_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vips.h>
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

struct _VipsArithmetic;
typedef void (*VipsArithmeticProcessFn)( struct _VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width );

typedef struct _VipsArithmetic {
	VipsOperation parent_instance;

	/* All have an output image.
	 */
	VipsImage *out;

	/* Array of input arguments, set these from a subclass.
	 */
	VipsImage **in;
	int n;

	/* The minimum number of output bands. For example, VipsLinear with a
	 * three element constant must make at least a three-band output.
	 */
	int base_bands;

	/* The input images, ready for the operation.
	 */
	VipsImage **ready;
} VipsArithmetic;

typedef struct _VipsArithmeticClass {
	VipsOperationClass parent_class;

	/* For each input format, what output format. Used for arithmetic
	 * too, since we cast inputs to match.
	 */
	const VipsBandFormat *format_table;

	/* A vector program for each input type.
	 */
	VipsVector *vectors[VIPS_FORMAT_LAST];

	/* ... and if we've set a program for this format.
	 */
	gboolean vector_program[VIPS_FORMAT_LAST];

	/* The buffer processor.
	 */
	VipsArithmeticProcessFn process_line;
} VipsArithmeticClass;

GType vips_arithmetic_get_type( void );

void vips_arithmetic_set_format_table( VipsArithmeticClass *klass, 
	const VipsBandFormat *format_table );
VipsVector *vips_arithmetic_get_vector( VipsArithmeticClass *klass, 
	VipsBandFormat fmt );
void vips_arithmetic_compile( VipsArithmeticClass *klass ); 
VipsVector *vips_arithmetic_get_program( VipsArithmeticClass *klass, 
	VipsBandFormat fmt );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PARITHMETIC_H*/


