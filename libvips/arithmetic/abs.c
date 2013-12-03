/* absolute value
 *
 * Copyright: 1990, N. Dessipris, based on im_powtra()
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 5/5/93 J.Cupitt
 *	- adapted from im_lintra to work with partial images
 *	- complex and signed support added
 * 30/6/93 JC
 *	- adapted for partial v2
 *	- ANSI conversion
 *	- spe29873r6k3h()**!@lling errors removed
 * 9/2/95 JC
 *	- adapted for im_wrap...
 * 20/6/02 JC
 *	- tiny speed up
 * 8/12/06
 * 	- add liboil support
 * 28/8/09
 * 	- gtkdoc
 * 	- tiny polish
 * 31/7/10
 * 	- remove liboil
 * 6/11/11
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

typedef VipsUnary VipsAbs;
typedef VipsUnaryClass VipsAbsClass;

G_DEFINE_TYPE( VipsAbs, vips_abs, VIPS_TYPE_UNARY );

static int
vips_abs_build( VipsObject *object )
{
	VipsUnary *unary = (VipsUnary *) object;

	if( unary->in &&
		vips_band_format_isuint( unary->in->BandFmt ) ) 
		return( vips_unary_copy( unary ) ); 

	if( VIPS_OBJECT_CLASS( vips_abs_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

/* Integer abs operation: just test and negate.
 */
#define ABS_INT( TYPE ) { \
	TYPE * restrict p = (TYPE *) in[0]; \
	TYPE * restrict q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = p[x] < 0 ? 0 - p[x] : p[x]; \
}

/* Float abs operation: call fabs().
 */
#define ABS_FLOAT( TYPE ) { \
	TYPE * restrict p = (TYPE *) in[0]; \
	TYPE * restrict q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) \
		q[x] = fabs( p[x] ); \
}

/* Complex abs operation: calculate modulus.
 */

#ifdef HAVE_HYPOT

#define ABS_COMPLEX( TYPE ) { \
	TYPE * restrict p = (TYPE *) in[0]; \
	TYPE * restrict q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) { \
		q[x] = hypot( p[0], p[1] ); \
		p += 2; \
	} \
}

#else /*HAVE_HYPOT*/

#define ABS_COMPLEX( TYPE ) { \
	TYPE * restrict p = (TYPE *) in[0]; \
	TYPE * restrict q = (TYPE *) out; \
	int x; \
	\
	for( x = 0; x < sz; x++ ) { \
		double rp = p[0]; \
		double ip = p[1]; \
		double abs_rp = fabs( rp ); \
		double abs_ip = fabs( ip ); \
		\
		if( abs_rp > abs_ip ) { \
			double temp = ip / rp; \
			\
			q[x] = abs_rp * sqrt( 1.0 + temp * temp ); \
		} \
		else { \
			double temp = rp / ip; \
			\
			q[x] = abs_ip * sqrt( 1.0 + temp * temp ); \
		} \
		\
		p += 2; \
	} \
}

#endif /*HAVE_HYPOT*/

static void
vips_abs_buffer( VipsArithmetic *arithmetic, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsUnary *unary = VIPS_UNARY( arithmetic );
	const int bands = vips_image_get_bands( unary->in );
	int sz = width * bands;

	switch( vips_image_get_format( unary->in ) ) {
        case VIPS_FORMAT_CHAR: 		ABS_INT( signed char ); break; 
        case VIPS_FORMAT_SHORT: 	ABS_INT( signed short ); break; 
        case VIPS_FORMAT_INT: 		ABS_INT( signed int ); break; 
        case VIPS_FORMAT_FLOAT: 	ABS_FLOAT( float ); break; 
        case VIPS_FORMAT_DOUBLE:	ABS_FLOAT( double ); break; 
        case VIPS_FORMAT_COMPLEX:	ABS_COMPLEX( float ); break;
        case VIPS_FORMAT_DPCOMPLEX:	ABS_COMPLEX( double ); break;

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

/* Format doesn't change with abs, other than complex -> real.
 */
static const VipsBandFormat vips_abs_format_table[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, C,  US, S,  UI, I,  F,  F,  D,  D 
};

static void
vips_abs_class_init( VipsAbsClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsArithmeticClass *aclass = VIPS_ARITHMETIC_CLASS( class );

	object_class->nickname = "abs";
	object_class->description = _( "absolute value of an image" );
	object_class->build = vips_abs_build;

	aclass->format_table = vips_abs_format_table;

	aclass->process_line = vips_abs_buffer;
}

static void
vips_abs_init( VipsAbs *abs )
{
}

/** 
 * vips_abs:
 * @in: input #VipsImage
 * @out: output #VipsImage
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation finds the absolute value of an image. It does a copy for 
 * unsigned integer types, negate for negative values in 
 * signed integer types, <function>fabs(3)</function> for 
 * float types, and calculates modulus for complex 
 * types. 
 *
 * See also: vips_sign().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_abs( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "abs", ap, in, out );
	va_end( ap );

	return( result );
}
