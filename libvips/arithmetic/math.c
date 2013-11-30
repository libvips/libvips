/* VipsMath --- call various -lm functions (trig, log etc.) on images
 *
 * Copyright: 1990, N. Dessipris, based on im_powtra()
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 5/5/93 JC
 *	- adapted from im_lintra to work with partial images
 *	- incorrect implementation of complex logs removed
 * 1/7/93 JC
 *	- adapted for partial v2
 *	- ANSIfied
 * 24/2/95 JC
 *	- im_logtra() adapted to make im_sintra()
 *	- adapted for im_wrapone()
 * 26/1/96 JC
 *	- im_asintra() added
 * 30/8/09
 * 	- gtkdoc
 * 	- tiny cleanups
 * 	- use im__math()
 * 19/9/09
 * 	- im_sintra() adapted to make math.c
 * 4/11/11
 * 	- redone as a class
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

#include "unary.h"

typedef struct _VipsMath {
	VipsUnary parent_instance;

	VipsOperationMath math;

} VipsMath;

typedef VipsUnaryClass VipsMathClass;

G_DEFINE_TYPE( VipsMath, vips_math, VIPS_TYPE_UNARY );

static int
vips_math_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsUnary *unary = (VipsUnary *) object;

	if( unary->in &&
		vips_check_noncomplex( class->nickname, unary->in ) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_math_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

#define LOOP( IN, OUT, OP ) { \
	IN * __restrict__ p = (IN *) in[0]; \
	OUT * __restrict__ q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = OP( p[x] ); \
}

#define SWITCH( OP ) \
	switch( vips_image_get_format( im ) ) { \
	case VIPS_FORMAT_UCHAR: \
		LOOP( unsigned char, float, OP ); break; \
	case VIPS_FORMAT_CHAR: \
		LOOP( signed char, float, OP ); break; \
	case VIPS_FORMAT_USHORT: \
		LOOP( unsigned short, float, OP ); break; \
	case VIPS_FORMAT_SHORT: \
		LOOP( signed short, float, OP ); break; \
	case VIPS_FORMAT_UINT: \
		LOOP( unsigned int, float, OP ); break; \
	case VIPS_FORMAT_INT: \
		LOOP( signed int, float, OP ); break; \
	case VIPS_FORMAT_FLOAT: \
		LOOP( float, float, OP ); break; \
	case VIPS_FORMAT_DOUBLE: \
		LOOP( double, double, OP ); break;\
 	\
	default: \
		g_assert( 0 ); \
	} 

/* sin/cos/tan in degrees.
 */
#define DSIN( X ) (sin( IM_RAD( X ) ))
#define DCOS( X ) (cos( IM_RAD( X ) ))
#define DTAN( X ) (tan( IM_RAD( X ) ))
#define ADSIN( X ) (IM_DEG( asin( X ) ))
#define ADCOS( X ) (IM_DEG( acos( X ) ))
#define ADTAN( X ) (IM_DEG( atan( X ) ))

/* exp10() is a gnu extension, use pow().
 */
#define EXP10( X ) (pow( 10.0, (X) ))

static void
vips_math_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsMath *math = (VipsMath *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	switch( math->math ) {
	case VIPS_OPERATION_MATH_SIN: 	SWITCH( DSIN ); break;
	case VIPS_OPERATION_MATH_COS: 	SWITCH( DCOS ); break;
	case VIPS_OPERATION_MATH_TAN: 	SWITCH( DTAN ); break;
	case VIPS_OPERATION_MATH_ASIN: 	SWITCH( ADSIN ); break;
	case VIPS_OPERATION_MATH_ACOS: 	SWITCH( ADCOS ); break;
	case VIPS_OPERATION_MATH_ATAN: 	SWITCH( ADTAN ); break;
	case VIPS_OPERATION_MATH_LOG: 	SWITCH( log ); break;
	case VIPS_OPERATION_MATH_LOG10:	SWITCH( log10 ); break;
	case VIPS_OPERATION_MATH_EXP: 	SWITCH( exp ); break;
	case VIPS_OPERATION_MATH_EXP10:	SWITCH( EXP10 ); break;

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

static const VipsBandFormat vips_bandfmt_math[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   F,  F,  F,  F,  F,  F,  F,  X,  D,  DX 
};

static void
vips_math_class_init( VipsMathClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "math";
	object_class->description = _( "perform a math function on an image" );
	object_class->build = vips_math_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_math );

	aclass->process_line = vips_math_buffer;

	VIPS_ARG_ENUM( class, "math", 200, 
		_( "Operation" ), 
		_( "math to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMath, math ),
		VIPS_TYPE_OPERATION_MATH, VIPS_OPERATION_MATH_SIN ); 
}

static void
vips_math_init( VipsMath *math )
{
}

static int
vips_mathv( VipsImage *in, VipsImage **out, VipsOperationMath math, va_list ap )
{
	return( vips_call_split( "math", ap, in, out, math ) );
}

/**
 * vips_math:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @math: math operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform various functions in -lm, the maths library, on images. 
 *
 * Angles are expressed in degrees. The output type is float unless the 
 * input is double, in which case the output is double.  
 *
 * Non-complex images only.
 *
 * See also: vips_math2().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_math( VipsImage *in, VipsImage **out, VipsOperationMath math, ... )
{
	va_list ap;
	int result;

	va_start( ap, math );
	result = vips_mathv( in, out, math, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_sin:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_SIN on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_sin( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_SIN, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_cos:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_COS on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_cos( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_COS, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_tan:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_TAN on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_tan( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_TAN, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_asin:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_ASIN on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_asin( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_ASIN, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_acos:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_ACOS on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_acos( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_ACOS, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_atan:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_ATAN on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_atan( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_ATAN, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_log:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_LOG on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_log( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_LOG, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_log10:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_LOG10 on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_log10( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_LOG10, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_exp:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_EXP on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_exp( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_EXP, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_exp10:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_MATH_EXP10 on an image. See vips_math().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_exp10( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_mathv( in, out, VIPS_OPERATION_MATH_EXP10, ap );
	va_end( ap );

	return( result );
}
