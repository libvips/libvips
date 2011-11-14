/* im_ifthenelse.c --- use a condition image to join two images together
 *
 * Modified:
 * 9/2/95 JC
 *	- partialed and ANSIfied
 * 11/9/95 JC
 *	- return( 0 ) missing! oops
 * 15/4/05
 *	- now just evals left/right if all zero/all one
 * 7/10/06
 * 	- set THINSTRIP
 * 23/9/09
 * 	- gtkdoc comment
 * 23/9/09
 * 	- use im_check*()
 * 	- allow many-band conditional and single-band a/b
 * 	- allow a/b to differ in format and bands
 * 25/6/10
 * 	- let the conditional image be any format by adding a (!=0) if
 * 	  necessary
 * 17/5/11
 * 	- added sizealike
 * 14/11/11
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

#include "binary.h"
#include "unaryconst.h"

/**
 * VipsIfthenelse:
 * @left: left-hand input #VipsImage
 * @right: right-hand input #VipsImage
 * @out: output #VipsImage
 * @ifthenelse: ifthenelse operation to perform
 *
 * Perform various ifthenelse operations on pairs of images. 
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
 * See also: #VipsBoolean, #VipsIfthenelseConst.
 */

typedef struct _VipsIfthenelse {
	VipsBinary parent_instance;

	/* The condition image is always uchar.
	 */
	VipsImage *condition;

} VipsIfthenelse;

typedef VipsBinaryClass VipsIfthenelseClass;

G_DEFINE_TYPE( VipsIfthenelse, vips_ifthenelse, VIPS_TYPE_BINARY );

static int
vips_ifthenelse_build( VipsObject *object )
{
	VipsIfthenelse *ifthenelse = (VipsIfthenelse *) object;
	VipsArithmetic *arithmetic = (VipsArithmetic *) object;

	if( VIPS_OBJECT_CLASS( vips_ifthenelse_parent_class )->build( object ) )
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

static void
vips_ifthenelse_buffer( VipsArithmetic *arithmetic, 
	PEL *out, PEL **in, int width )
{
	VipsIfthenelse *ifthenelse = (VipsIfthenelse *) arithmetic;
	VipsImage *im = arithmetic->ready[0];
	const int sz = width * vips_image_get_bands( im );

	int x;

	switch( vips_image_get_format( im ) ) { 
	case VIPS_FORMAT_UCHAR:		R( unsigned char, ROP ); break; 
	case VIPS_FORMAT_CHAR:		R( signed char, ROP ); break; 
	case VIPS_FORMAT_USHORT: 	R( unsigned short, ROP ); break; 
	case VIPS_FORMAT_SHORT: 	R( signed short, ROP ); break; 
	case VIPS_FORMAT_UINT: 		R( unsigned int, ROP ); break; 
	case VIPS_FORMAT_INT: 		R( signed int, ROP ); break; 
	case VIPS_FORMAT_FLOAT: 	R( float, ROP ); break; 
	case VIPS_FORMAT_DOUBLE: 	R( double, ROP ); break;
	case VIPS_FORMAT_COMPLEX: 	C( float, COP ); break; 
	case VIPS_FORMAT_DPCOMPLEX: 	C( double, COP ); break;

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

static const VipsBandFormat vips_bandfmt_ifthenelse[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, C,  US, S,  UI, I,  F,  X,  D,  DX
};

static void
vips_ifthenelse_class_init( VipsIfthenelseClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "ifthenelse";
	object_class->description = 
		_( "a ifthenelse operation on a pair of images" );
	object_class->build = vips_ifthenelse_build;

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_ifthenelse );

	aclass->process_line = vips_ifthenelse_buffer;

}

static void
vips_ifthenelse_init( VipsIfthenelse *ifthenelse )
{
}

int
vips_ifthenelse( VipsImage *left, VipsImage *right, VipsImage **out, 
	VipsOperationIfthenelse ifthenelse, ... )
{
	va_list ap;
	int result;

	va_start( ap, ifthenelse );
	result = vips_call_split( "ifthenelse", ap, left, right, out, 
		ifthenelse );
	va_end( ap );

	return( result );
}
