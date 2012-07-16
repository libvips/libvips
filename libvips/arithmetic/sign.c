/* im_sign.c
 *
 * 9/7/02 JC
 *	- from im_cmulnorm
 * 9/9/09
 * 	- gtkdoc, tidies
 * 6/11/11
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
#include <math.h>

#include <vips/vips.h>

#include "unary.h"

typedef VipsUnary VipsSign;
typedef VipsUnaryClass VipsSignClass;

G_DEFINE_TYPE( VipsSign, vips_sign, VIPS_TYPE_UNARY );

#define CSIGN( TYPE ) { \
	TYPE *p = (TYPE *) in[0]; \
	TYPE *q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE re = p[0]; \
		TYPE im = p[1]; \
		double fac = sqrt( re * re + im * im ); \
		\
		p += 2; \
		\
		if( fac == 0.0 ) { \
			q[0] = 0.0; \
			q[1] = 0.0; \
		} \
		else { \
			q[0] = re / fac; \
			q[1] = im / fac; \
		} \
		\
		q += 2; \
	} \
}

#define SIGN( TYPE ) { \
	TYPE *p = (TYPE *) in[0]; \
	signed char *q = (signed char *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE v = p[x]; \
 		\
		if( v > 0 ) \
			q[x] = 1; \
		else if( v == 0 ) \
			q[x] = 0; \
		else \
			q[x] = -1; \
	} \
}

static void
vips_sign_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsUnary *unary = VIPS_UNARY( arithmetic );
	const int bands = vips_image_get_bands( unary->in );
	int sz = width * bands;

	switch( vips_image_get_format( unary->in ) ) {
        case VIPS_FORMAT_UCHAR: 	SIGN( unsigned char ); break;
        case VIPS_FORMAT_CHAR: 		SIGN( signed char ); break; 
        case VIPS_FORMAT_USHORT: 	SIGN( unsigned short ); break; 
        case VIPS_FORMAT_SHORT: 	SIGN( signed short ); break; 
        case VIPS_FORMAT_UINT: 		SIGN( unsigned int ); break; 
        case VIPS_FORMAT_INT: 		SIGN( signed int );  break; 
        case VIPS_FORMAT_FLOAT: 	SIGN( float ); break; 
        case VIPS_FORMAT_DOUBLE:	SIGN( double ); break; 
	case VIPS_FORMAT_COMPLEX:	CSIGN( float ); break;
	case VIPS_FORMAT_DPCOMPLEX:	CSIGN( double ); break; 

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

static const VipsBandFormat vips_bandfmt_sign[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   C,  C,  C,  C,  C,  C,  C,  X,  C,  DX 
};

static void
vips_sign_class_init( VipsSignClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	object_class->nickname = "sign";
	object_class->description = _( "unit vector of pixel" );

	vips_arithmetic_set_format_table( aclass, vips_bandfmt_sign );

	aclass->process_line = vips_sign_buffer;
}

static void
vips_sign_init( VipsSign *sign )
{
}

/**
 * vips_sign:
 * @in: input image
 * @out: output image
 *
 * Finds the unit vector in the direction of the pixel value. For non-complex
 * images, it returns a signed char image with values -1, 0, and 1 for negative,
 * zero and positive pixels. For complex images, it returns a
 * complex normalised to length 1.
 *
 * See also: vips_abs().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_sign( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sign", ap, in, out );
	va_end( ap );

	return( result );
}
