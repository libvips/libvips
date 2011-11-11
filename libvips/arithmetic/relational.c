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

#define SWITCH( ROP, COP ) \
	switch( vips_image_get_format( im ) ) { \
	case VIPS_FORMAT_UCHAR:		RLOOP( unsigned char, ROP ); break; \
	case VIPS_FORMAT_CHAR:		RLOOP( signed char, ROP ); break; \
	case VIPS_FORMAT_USHORT: 	RLOOP( unsigned short, ROP ); break; \
	case VIPS_FORMAT_SHORT: 	RLOOP( signed short, ROP ); break; \
	case VIPS_FORMAT_UINT: 		RLOOP( unsigned int, ROP ); break; \
	case VIPS_FORMAT_INT: 		RLOOP( signed int, ROP ); break; \
	case VIPS_FORMAT_FLOAT: 	RLOOP( float, ROP ); break; \
	case VIPS_FORMAT_DOUBLE: 	RLOOP( double, ROP ); break;\
	case VIPS_FORMAT_COMPLEX: 	CLOOP( float, COP ); break; \
	case VIPS_FORMAT_DPCOMPLEX: 	CLOOP( double, COP ); break;\
 	\
	default: \
		g_assert( 0 ); \
	} 

#define CEQUAL( x1, y1, x2, y2 ) (x1 == y1 && x2 == y2)
#define CNOTEQUAL( x1, y1, x2, y2 ) (x1 != y1 || x2 != y2)
#define CLESS( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 < x2 * x2 + y2 * y2)
#define CLESSEQ( x1, y1, x2, y2 ) (x1 * x1 + y1 * y1 <= x2 * x2 + y2 * y2)

static void
vips_relational_buffer( VipsArithmetic *arithmetic, 
	PEL *out, PEL **in, int width )
{
	VipsRelational *relational = (VipsRelational *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	switch( relational->relational ) {
	case VIPS_OPERATION_RELATIONAL_EQUAL: 	SWITCH( ==, CEQUAL ); break;
	case VIPS_OPERATION_RELATIONAL_NOTEQUAL:SWITCH( !=, CNOTEQUAL ); break;
	case VIPS_OPERATION_RELATIONAL_LESS: 	SWITCH( <, CLESS ); break;
	case VIPS_OPERATION_RELATIONAL_LESSEQ: 	SWITCH( <=, CLESSEQ ); break;

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
