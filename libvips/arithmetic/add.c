/* add operation
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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "arithmetic.h"
#include "binary.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* VipsAdd class
 */

#define VIPS_TYPE_ADD (vips_add_get_type())
#define VIPS_ADD( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_ADD, VipsAdd ))
#define VIPS_ADD_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_ADD, VipsAddClass))
#define VIPS_IS_ADD( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_ADD ))
#define VIPS_IS_ADD_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_ADD ))
#define VIPS_ADD_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_ADD, VipsAddClass ))

typedef VipsBinary VipsAdd;
typedef VipsBinaryClass VipsAddClass;

G_DEFINE_TYPE( VipsAdd, vips_add, VIPS_TYPE_BINARY );

#define LOOP( IN, OUT ) { \
	IN *p1 = (IN *) left; \
	IN *p2 = (IN *) right; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = p1[x] + p2[x]; \
}

static void
add_buffer( VipsBinary *binary, PEL *out, PEL *left, PEL *right, int width )
{
	VipsArithmeticClass *class = VIPS_ARITHMETIC_GET_CLASS( binary );
	VipsImage *im = binary->left_processed;

	/* Complex just doubles the size.
	 */
	const int sz = width * im->Bands * 
		(vips_band_format_iscomplex( im->BandFmt ) ? 2 : 1);

	VipsVector *v;

	if( (v = vips_arithmetic_get_vector( class, im->BandFmt )) ) {
		VipsExecutor ex;

		vips_executor_set_program( &ex, v, sz );
		vips_executor_set_array( &ex, v->s[0], left );
		vips_executor_set_array( &ex, v->s[1], right );
		vips_executor_set_destination( &ex, out );

		vips_executor_run( &ex );
	}
	else {
		int x;

		/* Add all input types. Keep types here in sync with 
		 * bandfmt_add[] below.
		 */
		switch( im->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			LOOP( unsigned char, unsigned short ); break; 
		case VIPS_FORMAT_CHAR: 	
			LOOP( signed char, signed short ); break; 
		case VIPS_FORMAT_USHORT: 
			LOOP( unsigned short, unsigned int ); break; 
		case VIPS_FORMAT_SHORT: 	
			LOOP( signed short, signed int ); break; 
		case VIPS_FORMAT_UINT: 	
			LOOP( unsigned int, unsigned int ); break; 
		case VIPS_FORMAT_INT: 	
			LOOP( signed int, signed int ); break; 

		case VIPS_FORMAT_FLOAT: 		
		case VIPS_FORMAT_COMPLEX: 
			LOOP( float, float ); break; 

		case VIPS_FORMAT_DOUBLE:	
		case VIPS_FORMAT_DPCOMPLEX: 
			LOOP( double, double ); break;

		default:
			g_assert( 0 );
		}
	}
}

/* Save a bit of typing.
 */
#define UC IM_BANDFMT_UCHAR
#define C IM_BANDFMT_CHAR
#define US IM_BANDFMT_USHORT
#define S IM_BANDFMT_SHORT
#define UI IM_BANDFMT_UINT
#define I IM_BANDFMT_INT
#define F IM_BANDFMT_FLOAT
#define X IM_BANDFMT_COMPLEX
#define D IM_BANDFMT_DOUBLE
#define DX IM_BANDFMT_DPCOMPLEX

/* Type promotion for addition. Sign and value preserving. Make sure these
 * match the case statement in add_buffer() above.
 */
static int bandfmt_add[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   US, S,  UI, I,  UI, I, F, X, D, DX
};

static void
vips_add_class_init( VipsAddClass *class )
{
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );
	VipsBinaryClass *bclass = VIPS_BINARY_CLASS( class );
	VipsVector *v;

	vips_arithmetic_set_format_table( aclass, bandfmt_add );

	v = vips_arithmetic_get_program( aclass, VIPS_FORMAT_UCHAR );
	vips_vector_asm2( v, "convubw", "t1", "s1" );
	vips_vector_asm2( v, "convubw", "t2", "s2" );
	vips_vector_asm3( v, "addw", "d1", "t1", "t2" ); 

	v = vips_arithmetic_get_program( aclass, VIPS_FORMAT_CHAR );
	vips_vector_asm2( v, "convsbw", "t1", "s1" );
	vips_vector_asm2( v, "convsbw", "t2", "s2" );
	vips_vector_asm3( v, "addw", "d1", "t1", "t2" ); 

	v = vips_arithmetic_get_program( aclass, VIPS_FORMAT_USHORT );
	vips_vector_asm2( v, "convuwl", "t1", "s1" );
	vips_vector_asm2( v, "convuwl", "t2", "s2" );
	vips_vector_asm3( v, "addl", "d1", "t1", "t2" );

	v = vips_arithmetic_get_program( aclass, VIPS_FORMAT_SHORT );
	vips_vector_asm2( v, "convswl", "t1", "s1" );
	vips_vector_asm2( v, "convswl", "t2", "s2" );
	vips_vector_asm3( v, "addl", "d1", "t1", "t2" );

	/*

	   uint/int are a little slower than C, on a c2d anyway

	   float/double/complex are not handled well

	v = vips_arithmetic_get_vector( aclass, VIPS_FORMAT_UINT );
	vips_vector_asm3( v, "addl", "d1", "s1", "s2" );

	v = vips_arithmetic_get_vector( aclass, VIPS_FORMAT_INT );
	vips_vector_asm3( v, "addl", "d1", "s1", "s2" );

	 */

	vips_arithmetic_compile( aclass );

	bclass->process_line = add_buffer;
}

static void
vips_add_init( VipsAdd *add )
{
}
