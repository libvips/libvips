/* relational.c --- various relational operations
 *
 * Modified:
 * 26/7/93 JC
 *	- >,<,>=,<= tests now as (double) to prevent compiler warnings. Should
 *	  split into int/float cases really for speed.
 * 25/1/95 JC
 * 	- partialized
 * 	- updated
 * 7/2/95 JC
 *	- oops! bug with doubles fixed
 * 3/7/98 JC
 *	- vector versions added ... im_equal_vec(), im_lesseq_vec() etc
 * 	- small tidies
 *	- should be a bit faster, lots of *q++ changed to q[x]
 * 10/3/03 JC
 *	- reworked to remove nested #defines: a bit slower, but much smaller
 *	- all except _vec forms now work on complex
 * 31/7/03 JC
 *	- oops, relational_format was broken for some combinations
 * 23/9/09
 * 	- gtkdoc
 * 	- use new im__arith_binary*() functions
 * 	- more meta-programming
 * 23/6/10
 * 	- oops, moreconst and moreeqconst were the same
 * 4/11/11
 * 	- redone as a class
 * 1/2/12
 * 	- complex ==, != were broken
 * 16/7/12
 * 	- im1 > im2, im1 >= im2 were broken 
 * 17/9/14
 * 	- im1 > im2, im1 >= im2 were still broken, but in a more subtle way
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

#include <vips/vips.h>

#include "binary.h"
#include "unaryconst.h"

typedef struct _VipsRelational {
	VipsBinary parent_instance;

	VipsOperationRelational relational;

} VipsRelational;

typedef VipsBinaryClass VipsRelationalClass;

G_DEFINE_TYPE( VipsRelational, vips_relational, VIPS_TYPE_BINARY );

#define RLOOP( TYPE, ROP ) { \
	TYPE * restrict left = (TYPE *) in0; \
	TYPE * restrict right = (TYPE *) in1; \
	VipsPel * restrict q = (VipsPel *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = (left[x] ROP right[x]) ? 255 : 0; \
}

#define CLOOP( TYPE, COP ) { \
	TYPE * restrict left = (TYPE *) in0; \
	TYPE * restrict right = (TYPE *) in1; \
	VipsPel * restrict q = (VipsPel *) out; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[x] = COP( left[0], left[1], right[0], right[1]) ? 255 : 0; \
		\
		left += 2; \
		right += 2; \
	} \
}

#define SWITCH( R, C, ROP, COP ) \
	switch( vips_image_get_format( im ) ) { \
	case VIPS_FORMAT_UCHAR:		R( unsigned char, ROP ); break; \
	case VIPS_FORMAT_CHAR:		R( signed char, ROP ); break; \
	case VIPS_FORMAT_USHORT: 	R( unsigned short, ROP ); break; \
	case VIPS_FORMAT_SHORT: 	R( signed short, ROP ); break; \
	case VIPS_FORMAT_UINT: 		R( unsigned int, ROP ); break; \
	case VIPS_FORMAT_INT: 		R( signed int, ROP ); break; \
	case VIPS_FORMAT_FLOAT: 	R( float, ROP ); break; \
	case VIPS_FORMAT_DOUBLE: 	R( double, ROP ); break;\
	case VIPS_FORMAT_COMPLEX: 	C( float, COP ); break; \
	case VIPS_FORMAT_DPCOMPLEX: 	C( double, COP ); break;\
 	\
	default: \
		g_assert_not_reached(); \
	} 

#define CEQUAL( x1, y1, x2, y2 ) (x1 == x2 && y1 == y2)
#define CNOTEQ( x1, y1, x2, y2 ) (x1 != x2 || y1 != y2)
#define CLESS( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 < x2 * x2 + y2 * y2)
#define CLESSEQ( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 <= x2 * x2 + y2 * y2)
#define CMORE( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 > x2 * x2 + y2 * y2)
#define CMOREEQ( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 >= x2 * x2 + y2 * y2)

static void
vips_relational_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsRelational *relational = (VipsRelational *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	VipsOperationRelational op;
	VipsPel *in0;
	VipsPel *in1;
	int x;

	in0 = in[0];
	in1 = in[1];
	op = relational->relational;

	if( op == VIPS_OPERATION_RELATIONAL_MORE ) {
		op = VIPS_OPERATION_RELATIONAL_LESS;
		VIPS_SWAP( VipsPel *, in0, in1 );
	}

	if( op == VIPS_OPERATION_RELATIONAL_MOREEQ ) {
		op = VIPS_OPERATION_RELATIONAL_LESSEQ;
		VIPS_SWAP( VipsPel *, in0, in1 );
	}

	switch( op ) {
	case VIPS_OPERATION_RELATIONAL_EQUAL: 	
		SWITCH( RLOOP, CLOOP, ==, CEQUAL ); 
		break;

	case VIPS_OPERATION_RELATIONAL_NOTEQ:
		SWITCH( RLOOP, CLOOP, !=, CNOTEQ ); 
		break;

	case VIPS_OPERATION_RELATIONAL_LESS: 	
		SWITCH( RLOOP, CLOOP, <, CLESS ); 
		break;

	case VIPS_OPERATION_RELATIONAL_LESSEQ: 	
		SWITCH( RLOOP, CLOOP, <=, CLESSEQ ); 
		break;

	default:
		g_assert_not_reached();
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

static const VipsBandFormat vips_relational_format_table[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_relational_class_init( VipsRelationalClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "relational";
	object_class->description = _( "relational operation on two images" );

	aclass->process_line = vips_relational_buffer;

	vips_arithmetic_set_format_table( aclass, 
		vips_relational_format_table ); 

	VIPS_ARG_ENUM( class, "relational", 200, 
		_( "Operation" ), 
		_( "relational to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRelational, relational ),
		VIPS_TYPE_OPERATION_RELATIONAL, 
			VIPS_OPERATION_RELATIONAL_EQUAL ); 
}

static void
vips_relational_init( VipsRelational *relational )
{
}

static int
vips_relationalv( VipsImage *left, VipsImage *right, VipsImage **out, 
	VipsOperationRelational relational, va_list ap )
{
	return(  vips_call_split( "relational", ap, left, right, out, 
		relational ) );
}

/**
 * vips_relational:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @relational: relational operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform various relational operations on pairs of images. 
 *
 * The output type is always uchar, with 0 for FALSE and 255 for TRUE. 
 *
 * Less-than and greater-than for complex images compare the modulus. 
 *
 * If the images differ in size, the smaller image is enlarged to match the
 * larger by adding zero pixels along the bottom and right.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common format (see table 
 * Smallest common format in 
 * <link linkend="libvips-arithmetic">arithmetic</link>).
 *
 * To decide if pixels match exactly, that is have the same value in every
 * band, use vips_bandbool() after this operation to AND or OR image bands 
 * together. 
 *
 * See also: vips_boolean(), vips_bandbool(), vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_relational( VipsImage *left, VipsImage *right, VipsImage **out, 
	VipsOperationRelational relational, ... )
{
	va_list ap;
	int result;

	va_start( ap, relational );
	result = vips_relationalv( left, right, out, relational, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_equal:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_EQUAL on a pair of images. See
 * vips_relational().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_equal( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_relationalv( left, right, out, 
		VIPS_OPERATION_RELATIONAL_EQUAL, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_notequal:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_NOTEQ on a pair of images. See
 * vips_relational().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_notequal( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_relationalv( left, right, out, 
		VIPS_OPERATION_RELATIONAL_NOTEQ, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_more:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_MORE on a pair of images. See
 * vips_relational().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_more( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_relationalv( left, right, out, 
		VIPS_OPERATION_RELATIONAL_MORE, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_moreeq:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_MOREEQ on a pair of images. See
 * vips_relational().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_moreeq( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_relationalv( left, right, out, 
		VIPS_OPERATION_RELATIONAL_MOREEQ, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_less:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_LESS on a pair of images. See
 * vips_relational().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_less( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_relationalv( left, right, out, 
		VIPS_OPERATION_RELATIONAL_LESS, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_lesseq:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_LESSEQ on a pair of images. See
 * vips_relational().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_lesseq( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_relationalv( left, right, out, 
		VIPS_OPERATION_RELATIONAL_LESSEQ, ap );
	va_end( ap );

	return( result );
}

typedef struct _VipsRelationalConst {
	VipsUnaryConst parent_instance;

	VipsOperationRelational relational;
} VipsRelationalConst;

typedef VipsUnaryConstClass VipsRelationalConstClass;

G_DEFINE_TYPE( VipsRelationalConst, 
	vips_relational_const, VIPS_TYPE_UNARY_CONST );

static int
vips_relational_const_build( VipsObject *object )
{
	VipsUnary *unary = (VipsUnary *) object;
	VipsUnaryConst *uconst = (VipsUnaryConst *) object;

	if( unary->in )
		uconst->const_format = unary->in->BandFmt;

	if( VIPS_OBJECT_CLASS( vips_relational_const_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

#define RLOOPC( TYPE, OP ) { \
	TYPE * restrict p = (TYPE *) in[0]; \
	TYPE * restrict c = (TYPE *) uconst->c_ready; \
 	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			out[i] = (p[i] OP c[b]) ? 255 : 0; \
}

#define CLOOPC( TYPE, OP ) { \
	TYPE * restrict p = (TYPE *) in[0]; \
 	\
	for( i = 0, x = 0; x < width; x++ ) { \
		TYPE * restrict c = (TYPE *) uconst->c_ready; \
		\
		for( b = 0; b < bands; b++, i++ ) { \
			out[i] = OP( p[0], p[1], c[0], c[1]) ? 255 : 0; \
			\
			p += 2; \
			c += 2; \
		} \
	} \
}

static void
vips_relational_const_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsUnaryConst *uconst = (VipsUnaryConst *) arithmetic;
	VipsRelationalConst *rconst = (VipsRelationalConst *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	int bands = im->Bands;

	int i, x, b;

	switch( rconst->relational ) {
	case VIPS_OPERATION_RELATIONAL_EQUAL: 	
		SWITCH( RLOOPC, CLOOPC, ==, CEQUAL ); 
		break;

	case VIPS_OPERATION_RELATIONAL_NOTEQ:
		SWITCH( RLOOPC, CLOOPC, !=, CNOTEQ ); 
		break;

	case VIPS_OPERATION_RELATIONAL_LESS: 	
		SWITCH( RLOOPC, CLOOPC, <, CLESS ); 
		break;

	case VIPS_OPERATION_RELATIONAL_LESSEQ: 	
		SWITCH( RLOOPC, CLOOPC, <=, CLESSEQ ); 
		break;

	case VIPS_OPERATION_RELATIONAL_MORE: 	
		SWITCH( RLOOPC, CLOOPC, >, CMORE ); 
		break;

	case VIPS_OPERATION_RELATIONAL_MOREEQ: 	
		SWITCH( RLOOPC, CLOOPC, >=, CMOREEQ ); 
		break;

	default:
		g_assert_not_reached();
	}
}

static void
vips_relational_const_class_init( VipsRelationalConstClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "relational_const";
	object_class->description = 
		_( "relational operations against a constant" );
	object_class->build = vips_relational_const_build;

	aclass->process_line = vips_relational_const_buffer;

	vips_arithmetic_set_format_table( aclass, 
		vips_relational_format_table ); 

	VIPS_ARG_ENUM( class, "relational", 200, 
		_( "Operation" ), 
		_( "relational to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRelationalConst, relational ),
		VIPS_TYPE_OPERATION_RELATIONAL, 
			VIPS_OPERATION_RELATIONAL_EQUAL ); 
}

static void
vips_relational_const_init( VipsRelationalConst *relational_const )
{
}

static int
vips_relational_constv( VipsImage *in, VipsImage **out, 
	double *c, int n, VipsOperationRelational relational, va_list ap )
{
	VipsArea *area_c;
	double *array; 
	int result;
	int i;

	area_c = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n ); 
	array = (double *) area_c->data;
	for( i = 0; i < n; i++ ) 
		array[i] = c[i];

	result = vips_call_split( "relational_const", ap, 
		in, out, area_c, relational );

	vips_area_unref( area_c );

	return( result );
}

/**
 * vips_relational_const:
 * @in: input image
 * @out: output image
 * @c: array of constants 
 * @n: number of constants in @c
 * @relational: relational operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform various relational operations on an image and an array of
 * constants.
 *
 * The output type is always uchar, with 0 for FALSE and 255 for TRUE. 
 *
 * If the array of constants has just one element, that constant is used for 
 * all image bands. If the array has more than one element and they have 
 * the same number of elements as there are bands in the image, then 
 * one array element is used for each band. If the arrays have more than one
 * element and the image only has a single band, the result is a many-band
 * image where each band corresponds to one array element.
 *
 * See also: vips_boolean(), vips_relational().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_relational_const( VipsImage *in, VipsImage **out, 
	double *c, int n, VipsOperationRelational relational, ... )
{
	va_list ap;
	int result;

	va_start( ap, relational );
	result = vips_relational_constv( in, out, c, n, relational, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_equal_const:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_EQUAL on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_equal_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_relational_constv( in, out, 
		c, n, VIPS_OPERATION_RELATIONAL_EQUAL, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_notequal_const:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_NOTEQ on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_notequal_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_relational_constv( in, out, 
		c, n, VIPS_OPERATION_RELATIONAL_NOTEQ, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_less_const:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_LESS on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_less_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_relational_constv( in, out, 
		c, n, VIPS_OPERATION_RELATIONAL_LESS, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_lesseq_const:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_LESSEQ on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_lesseq_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_relational_constv( in, out, 
		c, n, VIPS_OPERATION_RELATIONAL_LESSEQ, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_more_const:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_MORE on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_more_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_relational_constv( in, out, 
		c, n, VIPS_OPERATION_RELATIONAL_MORE, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_moreeq_const:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @c: array of constants 
 * @n: number of constants in @c
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_MOREEQ on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_moreeq_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_relational_constv( in, out, 
		c, n, VIPS_OPERATION_RELATIONAL_MOREEQ, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_relational_const1:
 * @in: input image
 * @out: output image
 * @c: constant 
 * @relational: relational operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform various relational operations on an image and a constant. See
 * vips_relational_const().
 *
 * See also: vips_boolean(), vips_relational().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_relational_const1( VipsImage *in, VipsImage **out, 
	double c, VipsOperationRelational relational, ... )
{
	va_list ap;
	int result;

	va_start( ap, relational );
	result = vips_relational_constv( in, out, &c, 1, relational, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_equal_const1:
 * @in: input image
 * @out: output image
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_EQUAL on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_equal_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_relational_constv( in, out, 
		&c, 1, VIPS_OPERATION_RELATIONAL_EQUAL, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_notequal_const1:
 * @in: input image
 * @out: output image
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_NOTEQ on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_notequal_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_relational_constv( in, out, 
		&c, 1, VIPS_OPERATION_RELATIONAL_NOTEQ, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_less_const1:
 * @in: input image
 * @out: output image
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_LESS on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_less_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_relational_constv( in, out, 
		&c, 1, VIPS_OPERATION_RELATIONAL_LESS, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_lesseq_const1:
 * @in: input image
 * @out: output image
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_LESSEQ on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_lesseq_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_relational_constv( in, out, 
		&c, 1, VIPS_OPERATION_RELATIONAL_LESSEQ, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_more_const1:
 * @in: input image
 * @out: output image
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_MORE on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_more_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_relational_constv( in, out, 
		&c, 1, VIPS_OPERATION_RELATIONAL_MORE, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_moreeq_const1:
 * @in: input image
 * @out: output image
 * @c: constant 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Perform #VIPS_OPERATION_RELATIONAL_MOREEQ on an image and a constant. See
 * vips_relational_const().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_moreeq_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_relational_constv( in, out, 
		&c, 1, VIPS_OPERATION_RELATIONAL_MOREEQ, ap );
	va_end( ap );

	return( result );
}

