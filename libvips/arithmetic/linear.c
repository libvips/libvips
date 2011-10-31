/* im_lintra.c -- linear transform 
 *
 * Copyright: 1990, N. Dessipris, based on im_powtra()
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 23/4/93 JC
 *	- adapted to work with partial images
 * 1/7/93 JC
 *	- adapted for partial v2
 * 7/10/94 JC
 *	- new IM_NEW()
 *	- more typedefs 
 * 9/2/95 JC
 *	- adapted for im_wrap...
 *	- operations on complex images now just transform the real channel
 * 29/9/95 JC
 *	- complex was broken
 * 15/4/97 JC
 *	- return(0) missing from generate, arrgh!
 * 1/7/98 JC
 *	- im_lintra_vec added
 * 3/8/02 JC
 *	- fall back to im_copy() for a == 1, b == 0
 * 10/10/02 JC
 *	- auug, failing to multiply imag for complex! (thanks matt)
 * 10/12/02 JC
 *	- removed im_copy() fallback ... meant that output format could change
 *	  with value :-( very confusing
 * 30/6/04
 *	- added 1 band image * n band vector case
 * 8/12/06
 * 	- add liboil support
 * 9/9/09
 * 	- gtkdoc comment, minor reformat
 * 31/7/10
 * 	- remove liboil
 * 31/10/11
 * 	- rework as a class
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
#include "unary.h"

/**
 * VipsLinear:
 * @in: input #VipsImage
 * @out: output #VipsImage
 *
 * For unsigned formats, this operation calculates (max - @in), eg. (255 -
 * @in) for uchar. For signed and float formats, this operation calculates (-1
 * * @in). 
 *
 * See also: im_lintra().
 *
 * Returns: 0 on success, -1 on error
 */

typedef struct _VipsLinear {
	VipsUnary parent_instance;

	/* Our constants: multiply by a, add b.
	 */
	VipsArea *a;
	VipsArea *b;

} VipsLinear;

typedef VipsUnaryClass VipsLinearClass;

G_DEFINE_TYPE( VipsLinear, vips_linear, VIPS_TYPE_UNARY );

static int
vips_linear_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsLinear *linear = (VipsLinear *) object;

	if( VIPS_OBJECT_CLASS( vips_insert_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_vector( "VipsLinear", 
		linear->a->n, arithmetic->in[0] ) ||
		vips_check_vector( "VipsLinear", 
			linear->b->n, arithmetic->in[0] ) )
		return( -1 );

	how do we do this?? unary or arithmetic needs a bit of chopping about

	if( in->Bands == 1 )
		out->Bands = n;

	bandalike a and b

	return( 0 );
}

static void
vips_linear_buffer( VipsArithmetic *arithmetic, PEL *out, PEL **in, int width )
{
	VipsImage *im = arithmetic->ready[0];

	/* Complex just doubles the size.
	 */
	const int sz = width * vips_image_get_bands( im ) * 
		(vips_band_format_iscomplex( vips_image_get_format( im ) ) ? 
		 	2 : 1);

	int x;

	switch( vips_image_get_format( im ) ) {
	case VIPS_FORMAT_UCHAR: 	
		LOOP( unsigned char, UCHAR_MAX ); break; 
	case VIPS_FORMAT_CHAR: 	
		LOOPN( signed char ); break; 
	case VIPS_FORMAT_USHORT: 
		LOOP( unsigned short, USHRT_MAX ); break; 
	case VIPS_FORMAT_SHORT: 	
		LOOPN( signed short ); break; 
	case VIPS_FORMAT_UINT: 	
		LOOP( unsigned int, UINT_MAX ); break; 
	case VIPS_FORMAT_INT: 	
		LOOPN( signed int ); break; 

	case VIPS_FORMAT_FLOAT: 		
	case VIPS_FORMAT_COMPLEX: 
		LOOPN( float ); break; 

	case VIPS_FORMAT_DOUBLE:	
	case VIPS_FORMAT_DPCOMPLEX: 
		LOOPN( double ); break;

	default:
		g_assert( 0 );
	}
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

/* Format doesn't change with linear.
 */
static const VipsBandFormat vips_bandfmt_linear[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   F,  F   F,  F,  F,  F,  F,  X,  D,  DX 
};

static void
vips_invert_buffer( VipsArithmetic *arithmetic, PEL *out, PEL **in, int width )
{
	VipsImage *im = arithmetic->ready[0];

	/* Complex just doubles the size.
	 */
	const int sz = width * vips_image_get_bands( im ) * 
		(vips_band_format_iscomplex( vips_image_get_format( im ) ) ? 
		 	2 : 1);

	int x;

	switch( vips_image_get_format( im ) ) {
	case VIPS_FORMAT_UCHAR: 	
		LOOP( unsigned char, UCHAR_MAX ); break; 
	case VIPS_FORMAT_CHAR: 	
		LOOPN( signed char ); break; 
	case VIPS_FORMAT_USHORT: 
		LOOP( unsigned short, USHRT_MAX ); break; 
	case VIPS_FORMAT_SHORT: 	
		LOOPN( signed short ); break; 
	case VIPS_FORMAT_UINT: 	
		LOOP( unsigned int, UINT_MAX ); break; 
	case VIPS_FORMAT_INT: 	
		LOOPN( signed int ); break; 

	case VIPS_FORMAT_FLOAT: 		
	case VIPS_FORMAT_COMPLEX: 
		LOOPN( float ); break; 

	case VIPS_FORMAT_DOUBLE:	
	case VIPS_FORMAT_DPCOMPLEX: 
		LOOPN( double ); break;

	default:
		g_assert( 0 );
	}
}

static void
vips_linear_class_init( VipsLinearClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	object_class->nickname = "linear";
	object_class->description = _( "calculate (a * in + b)" );
	object_class->build = vips_linear_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_linear );

	aclass->process_line = vips_linear_buffer;

	VIPS_ARG_BOXED( class, "a", 4, 
		_( "a" ), 
		_( "Multiply by this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsLinear, a ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_BOXED( class, "b", 5, 
		_( "b" ), 
		_( "Add this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsLinear, b ),
		VIPS_TYPE_ARRAY_DOUBLE );

}

static void
vips_linear_init( VipsLinear *linear )
{
}

int
vips_linear( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "linear", ap, in, out );
	va_end( ap );

	return( result );
}
