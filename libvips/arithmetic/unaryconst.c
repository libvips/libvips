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

#include <vips/vips.h>

#include "arithmetic.h"
#include "binary.h"
#include "unary.h"

/**
 * VipsRelational:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @relational: relational operation to perform
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
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: #VipsBoolean, #VipsRelationalConst.
 */

typedef struct _VipsRelational {
	VipsBinary parent_instance;

	VipsOperationRelational relational;

} VipsRelational;

typedef VipsBinaryClass VipsRelationalClass;

G_DEFINE_TYPE( VipsRelational, vips_relational, VIPS_TYPE_BINARY );

static int
vips_relational_build( VipsObject *object )
{
	VipsRelational *relational = (VipsRelational *) object;
	VipsArithmetic *arithmetic = (VipsArithmetic *) object;

	if( relational->relational == VIPS_OPERATION_RELATIONAL_MORE ) {
		relational->relational = VIPS_OPERATION_RELATIONAL_LESS;
		VIPS_SWAP( VipsImage *, 
			arithmetic->ready[0], arithmetic->ready[1] );
	}

	if( relational->relational == VIPS_OPERATION_RELATIONAL_MOREEQ ) {
		relational->relational = VIPS_OPERATION_RELATIONAL_LESSEQ;
		VIPS_SWAP( VipsImage *, 
			arithmetic->ready[0], arithmetic->ready[1] );
	}

	if( VIPS_OBJECT_CLASS( vips_relational_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

#define RLOOP( TYPE, ROP ) { \
	TYPE *left = (TYPE *) in[0]; \
	TYPE *right = (TYPE *) in[1]; \
	PEL *q = (PEL *) out; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = (left[x] ROP right[x]) ? 255 : 0; \
}

#define CLOOP( TYPE, COP ) { \
	TYPE *left = (TYPE *) in[0]; \
	TYPE *right = (TYPE *) in[1]; \
	PEL *q = (PEL *) out; \
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
		g_assert( 0 ); \
	} 

#define CEQUAL( x1, y1, x2, y2 ) (x1 == y1 && x2 == y2)
#define CNOTEQUAL( x1, y1, x2, y2 ) (x1 != y1 || x2 != y2)
#define CLESS( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 < x2 * x2 + y2 * y2)
#define CLESSEQ( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 <= x2 * x2 + y2 * y2)
#define CMORE( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 > x2 * x2 + y2 * y2)
#define CMOREEQ( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 >= x2 * x2 + y2 * y2)

static void
vips_relational_buffer( VipsArithmetic *arithmetic, 
	PEL *out, PEL **in, int width )
{
	VipsRelational *relational = (VipsRelational *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	switch( relational->relational ) {
	case VIPS_OPERATION_RELATIONAL_EQUAL: 	
		SWITCH( RLOOP, CLOOP, ==, CEQUAL ); 
		break;

	case VIPS_OPERATION_RELATIONAL_NOTEQUAL:
		SWITCH( RLOOP, CLOOP, !=, CNOTEQUAL ); 
		break;

	case VIPS_OPERATION_RELATIONAL_LESS: 	
		SWITCH( RLOOP, CLOOP, <, CLESS ); 
		break;

	case VIPS_OPERATION_RELATIONAL_LESSEQ: 	
		SWITCH( RLOOP, CLOOP, <=, CLESSEQ ); 
		break;

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

static const VipsBandFormat vips_bandfmt_relational[10] = {
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
	object_class->description = 
		_( "a relational operation on a pair of images" );
	object_class->build = vips_relational_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_relational );

	aclass->process_line = vips_relational_buffer;

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

int
vips_relational( VipsImage *left, VipsImage *right, VipsImage **out, 
	VipsOperationRelational relational, ... )
{
	va_list ap;
	int result;

	va_start( ap, relational );
	result = vips_call_split( "relational", ap, left, right, out, 
		relational );
	va_end( ap );

	return( result );
}

/**
 * VipsRelationalConst:
 * @in: input image
 * @out: output image
 * @a: array of constants 
 * @relational: relational operation to perform
 *
 * Perform various relational operations on an image against a constant.
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
 * See also: #VipsBoolean, #VipsRelational.
 */

typedef struct _VipsRelationalConst {
	VipsUnary parent_instance;

	/* Our constants.
	 */
	VipsArea *c;

	/* Our constants expanded to match arith->ready in size.
	 */
	int n;
	double *c_ready;

} VipsRelationalConst;

typedef VipsUnaryClass VipsRelationalConstClass;

G_DEFINE_TYPE( VipsRelationalConst, vips_relationalconst, VIPS_TYPE_UNARY );

/* Cast a vector of double to a vector of TYPE, clipping to a range.
 */
#define CAST_CLIP( TYPE, N, X ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < n; i++ ) \
		tq[i] = (TYPE) IM_CLIP( N, p[i], X ); \
}

/* Cast a vector of double to a vector of TYPE.
 */
#define CAST( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < n; i++ ) \
		tq[i] = (TYPE) p[i]; \
}

/* Cast a vector of double to a complex vector of TYPE.
 */
#define CASTC( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
	\
	for( i = 0; i < n; i++ ) { \
		tq[0] = (TYPE) p[i]; \
		tq[1] = 0; \
		tq += 2; \
	} \
}

/* Cast a vector of double to a passed format.
 */
static PEL *
make_pixel( IMAGE *out, VipsBandFmt fmt, int n, double *p )
{
	PEL *q;
	int i;

	if( !(q = IM_ARRAY( out, n * (im_bits_of_fmt( fmt ) >> 3), PEL )) )
		return( NULL );

        switch( fmt ) {
        case IM_BANDFMT_CHAR:		
		CAST_CLIP( signed char, SCHAR_MIN, SCHAR_MAX ); 
		break;

        case IM_BANDFMT_UCHAR:  	
		CAST_CLIP( unsigned char, 0, UCHAR_MAX ); 
		break;

        case IM_BANDFMT_SHORT:  	
		CAST_CLIP( signed short, SCHAR_MIN, SCHAR_MAX ); 
		break;

        case IM_BANDFMT_USHORT: 	
		CAST_CLIP( unsigned short, 0, USHRT_MAX ); 
		break;

        case IM_BANDFMT_INT:    	
		CAST_CLIP( signed int, INT_MIN, INT_MAX ); 
		break;

        case IM_BANDFMT_UINT:   	
		CAST_CLIP( unsigned int, 0, UINT_MAX ); 
		break;

        case IM_BANDFMT_FLOAT: 		
		CAST( float ); 
		break; 

        case IM_BANDFMT_DOUBLE:		
		CAST( double ); 
		break;

        case IM_BANDFMT_COMPLEX: 	
		CASTC( float ); 
		break; 

        case IM_BANDFMT_DPCOMPLEX:	
		CASTC( double ); 
		break;

        default:
                g_assert( 0 );
        }

	return( q );
}

static int
vips_relationalconst_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );
	VipsUnary *unary = (VipsUnary *) object;
	VipsRelationalConst *relationalconst = (VipsRelationalConst *) object;

	int i;

	/* If we have a three-element vector we need to bandup the image to
	 * match.
	 */
	relationalconst->n = 1;
	if( relationalconst->c )
		relationalconst->n = relationalconst->c->n;
	if( unary->in )
		relationalconst->n = VIPS_MAX( relationalconst->n, 
			unary->in->Bands );
	arithmetic->base_bands = relationalconst->n;

	if( unary->in && relational->c ) {
		if( vips_check_vector( "VipsRelationalConst", 
			relationalconst->c->n, unary->in ) )
		return( -1 );
	}

	/* Make up-banded versions of our constants.
	 */
	if( relationalconst->c ) {
		double *ary = (double *) relationalconst->c->data;

		relationalconst->c_ready = g_new( double, relationalconst->n );

		for( i = 0; i < relationalconst->n; i++ ) {
			int j = VIPS_MIN( i, relationalconst->c->n - 1 );

			relationalconst->c_ready[i] = ary[j];
		}
	}

	/* Some operations need the vector in the input type (eg.
	 * im_equal_vec() where the output type is always uchar and is useless
	 * for comparisons), some need it in the output type (eg.
	 * im_andimage_vec() where we want to get the double to an int so we
	 * can do bitwise-and without having to cast for each pixel), some
	 * need a fixed type (eg. im_powtra_vec(), where we want to keep it as
	 * double).
	 *
	 * Therefore pass in the desired vector type as a param.
	 */
	if( !(vector = make_pixel( out, vfmt, n, c )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_relationalconst_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

#define RLOOPC( TYPE, OP ) { \
	TYPE *p = (TYPE *) in[0]; \
 	\
	for( i = 0, x = 0; x < width; x++ ) \
		for( b = 0; b < bands; b++, i++ ) \
			q[i] = (p[i] OP c[b]) ? 255 : 0; \
}

#define CLOOPC( TYPE, OP ) { \
	TYPE *p = (TYPE *) in[0]; \
 	\
	for( i = 0, x = 0; x < width; x++ ) { \
		for( b = 0; b < bands; b++, i++ ) { \
			q[i] = COP( p[0], p[1], c[i], 0.0) ? 255 : 0; \
			\
			p += 2; \
		} \
	} \
}

/* Lintra a buffer, n set of scale/offset.
 */
static void
vips_relationalconst_buffer( VipsArithmetic *arithmetic, 
	PEL *out, PEL **in, int width )
{
	VipsRelationalConst *relationalconst = (VipsRelationalConst *) 
		arithmetic;
	VipsImage *im = arithmetic->ready[0];
	int nb = im->Bands;
	double *c = relationalconst->c_ready;

	int i, x, k;

	switch( relationalconst->relational ) {
	case VIPS_OPERATION_RELATIONAL_EQUAL: 	
		SWITCH( RLOOPC, CLOOPC, ==, CEQUAL ); 
		break;

	case VIPS_OPERATION_RELATIONAL_NOTEQUAL:
		SWITCH( RLOOPC, CLOOPC, !=, CNOTEQUAL ); 
		break;

	case VIPS_OPERATION_RELATIONAL_LESS: 	
		SWITCH( RLOOPC, CLOOPC, <, CLESS ); 
		breakC;

	case VIPS_OPERATION_RELATIONAL_LESSEQ: 	
		SWITCH( RLOOPC, CLOOPC, <=, CLESSEQ ); 
		break;

	case VIPS_OPERATION_RELATIONAL_MORE: 	
		SWITCH( RLOOPC, CLOOPC, >, CMORE ); 
		breakC;

	case VIPS_OPERATION_RELATIONAL_MOREEQ: 	
		SWITCH( RLOOPC, CLOOPC, >=, CMOREEQ ); 
		break;

	default:
		g_assert( 0 );
	}
}

static void
vips_relationalconst_class_init( VipsRelationalConstClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "relationalconst";
	object_class->description = 
		_( "relational operations against a constant" );
	object_class->build = vips_relationalconst_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_relational );

	aclass->process_line = vips_relationalconst_buffer;

	VIPS_ARG_ENUM( class, "relational", 200, 
		_( "Operation" ), 
		_( "relational operation to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRelational, relational ),
		VIPS_TYPE_OPERATION_RELATIONAL, 
			VIPS_OPERATION_RELATIONAL_EQUAL ); 

	VIPS_ARG_BOXED( class, "c", 210, 
		_( "c" ), 
		_( "Array of constants" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRelationalConst, c ),
		VIPS_TYPE_ARRAY_DOUBLE );
}

static void
vips_relationalconst_init( VipsRelationalConst *relationalconst )
{
}

int
vips_relationalconst( VipsImage *in, VipsImage **out, 
	VipsOperationRelational relational, double *c, int n, ... )
{
	va_list ap;
	VipsArea *area_c;
	double *array; 
	int result;
	int i;

	area_c = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n ); 
	array = (double *) area_c->data;
	for( i = 0; i < n; i++ ) 
		array[i] = a[i];

	va_start( ap, n );
	result = vips_call_split( "relationalconst", ap, 
		in, out, relational, area_c );
	va_end( ap );

	vips_area_unref( area_c );

	return( result );
}

int
vips_relationalconst1( VipsImage *in, VipsImage **out, 
	VipsOperationRelational relational, double c, ... )
{
	va_list ap;
	VipsArea *area_c;
	double *array; 
	int result;

	area_c = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), 1 ); 
	array = (double *) area_c->data;
	array[0] = c;

	va_start( ap, b );
	result = vips_call_split( "relationalconst", ap, 
		in, out, relational, area_c );
	va_end( ap );

	vips_area_unref( area_c );

	return( result );
}
