/* complex.c ... various complex operations
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on : 09/05/1990
 * 15/6/93 JC
 *	- stupid stupid includes and externs fixed
 *	- I have been editing for 1 1/2 hours and I'm still drowning in
 *	  rubbish extetrnshh
 * 13/12/94 JC
 *	- modernised
 * 9/7/02 JC
 *	- degree output, for consistency
 *	- slightly better behaviour in edge cases
 * 27/1/10
 * 	- modernised
 * 	- gtk-doc
 * 19/11/11
 * 	- redo as a class
 * 21/11/11
 * 	- add vips_complexget()
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

#include "unary.h"
#include "binary.h"

typedef struct _VipsComplex {
	VipsUnary parent_instance;

	VipsOperationComplex cmplx;

} VipsComplex;

typedef VipsUnaryClass VipsComplexClass;

G_DEFINE_TYPE( VipsComplex, vips_complex, VIPS_TYPE_UNARY );

#define LOOP( IN, OUT, OP ) { \
	IN *p = (IN *) in[0]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		OP( q, p[x], 0.0 ); \
		\
		q += 2; \
	} \
}

#define CLOOP( IN, OUT, OP ) { \
	IN *p = (IN *) in[0]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		OP( q, p[0], p[1] ); \
		\
		p += 2; \
		q += 2; \
	} \
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
	case VIPS_FORMAT_COMPLEX: \
		CLOOP( float, float, OP ); break; \
	case VIPS_FORMAT_DPCOMPLEX: \
		CLOOP( double, double, OP ); break;\
 	\
	default: \
		g_assert( 0 ); \
	} 

#define POLAR( Q, X, Y ) { \
	double re = (X); \
	double im = (Y); \
	double am, ph; \
	\
	am = sqrt( re * re + im * im ); \
	ph = im_col_ab2h( re, im ); \
	\
	Q[0] = am; \
	Q[1] = ph; \
} 

#define RECT( Q, X, Y ) { \
	double am = (X); \
	double ph = (Y); \
	double re, im; \
	\
	re = am * cos( VIPS_RAD( ph ) ); \
	im = am * sin( VIPS_RAD( ph ) ); \
	\
	Q[0] = re; \
	Q[1] = im; \
}

#define CONJ( Q, X, Y ) { \
	double re = (X); \
	double im = (Y); \
	\
	im *= -1; \
	\
	Q[0] = re; \
	Q[1] = im; \
}

static void
vips_complex_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsComplex *cmplx = (VipsComplex *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	switch( cmplx->cmplx ) {
	case VIPS_OPERATION_COMPLEX_POLAR:	SWITCH( POLAR ); break;
	case VIPS_OPERATION_COMPLEX_RECT: 	SWITCH( RECT ); break;
	case VIPS_OPERATION_COMPLEX_CONJ: 	SWITCH( CONJ ); break;

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

static const VipsBandFormat vips_bandfmt_complex[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   X,  X,  X,  X,  X,  X,  X,  X,  DX, DX 
};

static void
vips_complex_class_init( VipsComplexClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "complex";
	object_class->description = 
		_( "perform a complex operation on an image" );

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_complex );

	aclass->process_line = vips_complex_buffer;

	VIPS_ARG_ENUM( class, "cmplx", 200, 
		_( "Operation" ), 
		_( "complex to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComplex, cmplx ),
		VIPS_TYPE_OPERATION_COMPLEX, VIPS_OPERATION_COMPLEX_POLAR ); 
}

static void
vips_complex_init( VipsComplex *cmplx )
{
}

static int
vips_complexv( VipsImage *in, VipsImage **out, 
	VipsOperationComplex cmplx, va_list ap )
{
	return( vips_call_split( "complex", ap, in, out, cmplx ) );
}

/**
 * vips_complex:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @cmplx: complex operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform various operations on complex images.
 *
 * Angles are expressed in degrees. The output type is complex unless the 
 * input is double or dpcomplex, in which case the output is dpcomplex.  
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_complex( VipsImage *in, VipsImage **out, VipsOperationComplex cmplx, ... )
{
	va_list ap;
	int result;

	va_start( ap, cmplx );
	result = vips_complexv( in, out, cmplx, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_polar:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_COMPLEX_POLAR on an image. See vips_complex().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_polar( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_complexv( in, out, VIPS_OPERATION_COMPLEX_POLAR, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_rect:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_COMPLEX_RECT on an image. See vips_complex().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_rect( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_complexv( in, out, VIPS_OPERATION_COMPLEX_POLAR, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_conj:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_COMPLEX_CONJ on an image. See vips_complex().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_conj( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_complexv( in, out, VIPS_OPERATION_COMPLEX_CONJ, ap );
	va_end( ap );

	return( result );
}

typedef struct _VipsComplexget {
	VipsUnary parent_instance;

	VipsOperationComplexget get;

} VipsComplexget;

typedef VipsUnaryClass VipsComplexgetClass;

G_DEFINE_TYPE( VipsComplexget, vips_complexget, VIPS_TYPE_UNARY );

static int
vips_complexget_build( VipsObject *object )
{
	VipsUnary *unary = (VipsUnary *) object;
	VipsComplexget *complexget = (VipsComplexget *) object;

	if( unary->in &&
		!vips_band_format_iscomplex( unary->in->BandFmt ) &&
		complexget->get == VIPS_OPERATION_COMPLEXGET_REAL ) 
		return( vips_unary_copy( unary ) ); 

	if( VIPS_OBJECT_CLASS( vips_complexget_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

#define GETLOOP( TYPE, OP ) { \
	TYPE *p __attribute__ ((unused)) = (TYPE *) in[0]; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		OP( q[x], p[x], 0.0 ); \
	} \
}

#define CGETLOOP( TYPE, OP ) { \
	TYPE *p __attribute__ ((unused)) = (TYPE *) in[0]; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		OP( q[x], p[0], p[1] ); \
		\
		p += 2; \
	} \
}

#define GETSWITCH( OP ) \
	switch( vips_image_get_format( im ) ) { \
	case VIPS_FORMAT_UCHAR: \
		GETLOOP( unsigned char, OP ); break; \
	case VIPS_FORMAT_CHAR: \
		GETLOOP( signed char, OP ); break; \
	case VIPS_FORMAT_USHORT: \
		GETLOOP( unsigned short, OP ); break; \
	case VIPS_FORMAT_SHORT: \
		GETLOOP( signed short, OP ); break; \
	case VIPS_FORMAT_UINT: \
		GETLOOP( unsigned int, OP ); break; \
	case VIPS_FORMAT_INT: \
		GETLOOP( signed int, OP ); break; \
	case VIPS_FORMAT_FLOAT: \
		GETLOOP( float, OP ); break; \
	case VIPS_FORMAT_DOUBLE: \
		GETLOOP( double, OP ); break;\
	case VIPS_FORMAT_COMPLEX: \
		CGETLOOP( float, OP ); break; \
	case VIPS_FORMAT_DPCOMPLEX: \
		CGETLOOP( double, OP ); break;\
 	\
	default: \
		g_assert( 0 ); \
	} 

#define REAL( Q, X, Y ) { \
	Q = X; \
} 

#define IMAG( Q, X, Y ) { \
	Q = Y; \
} 

static void
vips_complexget_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsComplexget *complexget = (VipsComplexget *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	switch( complexget->get ) {
	case VIPS_OPERATION_COMPLEXGET_REAL:	GETSWITCH( REAL ); break;
	case VIPS_OPERATION_COMPLEXGET_IMAG:	GETSWITCH( IMAG ); break;

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

static const VipsBandFormat vips_bandfmt_complexget[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, C,  US, S,  UI, I,  F,  F,  D,  D
};

static void
vips_complexget_class_init( VipsComplexgetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "complexget";
	object_class->description = _( "get a component from a complex image" );
	object_class->build = vips_complexget_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_complexget );

	aclass->process_line = vips_complexget_buffer;

	VIPS_ARG_ENUM( class, "get", 200, 
		_( "Operation" ), 
		_( "complex to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComplexget, get ),
		VIPS_TYPE_OPERATION_COMPLEXGET, 
			VIPS_OPERATION_COMPLEXGET_REAL ); 
}

static void
vips_complexget_init( VipsComplexget *complexget )
{
}

static int
vips_complexgetv( VipsImage *in, VipsImage **out, 
	VipsOperationComplexget get, va_list ap )
{
	return( vips_call_split( "complexget", ap, in, out, get ) );
}

/**
 * vips_complexget:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @get: complex operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * Get components of complex images. 
 *
 * The output type is the same as the input type, except #VIPS_FORMAT_COMPLEX
 * becomes #VIPS_FORMAT_FLOAT and #VIPS_FORMAT_DPCOMPLEX becomes 
 * #VIPS_FORMAT_DOUBLE.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_complexget( VipsImage *in, VipsImage **out, 
	VipsOperationComplexget get, ... )
{
	va_list ap;
	int result;

	va_start( ap, get );
	result = vips_complexgetv( in, out, get, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_real:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_COMPLEXGET_REAL on an image. See vips_complexget().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_real( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_complexgetv( in, out, 
		VIPS_OPERATION_COMPLEXGET_REAL, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_imag:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_COMPLEXGET_IMAG on an image. See vips_complexget().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_imag( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_complexgetv( in, out, 
		VIPS_OPERATION_COMPLEXGET_IMAG, ap );
	va_end( ap );

	return( result );
}

typedef VipsBinary VipsComplexform;
typedef VipsBinaryClass VipsComplexformClass;

G_DEFINE_TYPE( VipsComplexform, vips_complexform, VIPS_TYPE_BINARY );

static int
vips_complexform_build( VipsObject *object )
{
	VipsBinary *binary = (VipsBinary *) object;

	if( binary->left &&
		vips_check_noncomplex( "VipsComplexform", binary->left ) )
		return( -1 );
	if( binary->right &&
		vips_check_noncomplex( "VipsComplexform", binary->right ) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_complexform_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

#define CFORM( IN, OUT ) { \
	IN *left = (IN *) in[0]; \
	IN *right = (IN *) in[1]; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[0] = left[x]; \
		q[1] = right[x]; \
		\
		q += 2; \
	} \
}

static void
vips_complexform_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	/* Keep types here in sync with bandfmt_complexform[] 
	 * below.
         */
        switch( vips_image_get_format( im ) ) {
        case VIPS_FORMAT_CHAR: 	CFORM( signed char, float ); break; 
        case VIPS_FORMAT_UCHAR:	CFORM( unsigned char, float ); break; 
        case VIPS_FORMAT_SHORT:	CFORM( signed short, float ); break; 
        case VIPS_FORMAT_USHORT:CFORM( unsigned short, float ); break; 
        case VIPS_FORMAT_INT: 	CFORM( signed int, float ); break; 
        case VIPS_FORMAT_UINT: 	CFORM( unsigned int, float ); break; 
        case VIPS_FORMAT_FLOAT:	CFORM( float, float ); break; 
        case VIPS_FORMAT_DOUBLE: CFORM( double, double ); break;

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

/* Type promotion for division. Sign and value preserving. Make sure 
 * these match the case statement in complexform_buffer() above.
 */
static int vips_bandfmt_complexform[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   X,  X,  X,  X,  X,  X, X, X, DX,DX
};

static void
vips_complexform_class_init( VipsComplexformClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	object_class->nickname = "complexform";
	object_class->description = 
		_( "form a complex image from two real images" );
	object_class->build = vips_complexform_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_complexform );

	aclass->process_line = vips_complexform_buffer;
}

static void
vips_complexform_init( VipsComplexform *complexform )
{
}

/**
 * vips_complexform:
 * @left: input image 
 * @right: input image 
 * @out: output image
 *
 * Compose two real images to make a complex image. If either @left or @right 
 * are #VIPS_FORMAT_DOUBLE, @out is #VIPS_FORMAT_DPCOMPLEX. Otherwise @out 
 * is #VIPS_FORMAT_COMPLEX. @left becomes the real component of @out and 
 * @right the imaginary.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * See also: vips_complexget().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_complexform( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "complexform", ap, left, right, out );
	va_end( ap );

	return( result );
}





