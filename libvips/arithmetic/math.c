/* math.c --- call various -lm functions (trig, log etc.) on imags
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
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* What we do for each band element. Non-complex only.
 */
#define FUN_LOOP( IN, OUT, FUN ) { \
	IN *p = (IN *) in; \
	OUT *q = (OUT *) out; \
	\
	for( x = 0; x < ne; x++ ) \
		q[x] = FUN( (double) p[x] ); \
}

/* Operate on a buffer of PELs
 */
#define FUN_BUFFER( FUN ) \
static void \
FUN ## _buffer( PEL *in, PEL *out, int width, IMAGE *im ) \
{ \
	const int ne = width * im->Bands; \
	\
	int x; \
	\
	/* Switch for all input types. \
         */ \
        switch( im->BandFmt ) { \
        case IM_BANDFMT_UCHAR: 	FUN_LOOP( unsigned char, float, FUN ); break; \
        case IM_BANDFMT_CHAR: 	FUN_LOOP( signed char, float, FUN ); break; \
        case IM_BANDFMT_USHORT: FUN_LOOP( unsigned short, float, FUN ); break; \
        case IM_BANDFMT_SHORT: 	FUN_LOOP( signed short, float, FUN ); break; \
        case IM_BANDFMT_UINT: 	FUN_LOOP( unsigned int, float, FUN ); break; \
        case IM_BANDFMT_INT: 	FUN_LOOP( signed int, float, FUN );  break; \
        case IM_BANDFMT_FLOAT: 	FUN_LOOP( float, float, FUN ); break; \
        case IM_BANDFMT_DOUBLE:	FUN_LOOP( double, double, FUN ); break; \
	\
        default: \
		g_assert( 0 ); \
        } \
}

/* Do a math (eg. sin(), acos(), log()) type-function. No complex, everything
 * goes to float except double.
 */
int 
im__math( const char *name, IMAGE *in, IMAGE *out, im_wrapone_fn gen )
{
	if( im_piocheck( in, out ) ||
		im_check_uncoded( name, in ) ||
		im_check_noncomplex( name, in ) )
		return( -1 );

	if( im_cp_desc( out, in ) )
		return( -1 );
	if( im_isint( in ) ) 
		out->BandFmt = IM_BANDFMT_FLOAT;

	if( im_wrapone( in, out, gen, in, NULL ) )
		return( -1 );

	return( 0 );
}

/* Sin in degrees.
 */
#define DSIN( X ) (sin( IM_RAD( X ) ))

FUN_BUFFER( DSIN )

/**
 * im_sintra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>sin(3)</function> (sine). Angles are 
 * expressed in degrees. The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_asintra(), im_costra(), im_tantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_sintra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_sintra", in, out, (im_wrapone_fn) DSIN_buffer ) );
}

/* Asin in degrees.
 */
#define ADSIN( X ) (IM_DEG( asin( X ) ))

FUN_BUFFER( ADSIN )

/**
 * im_asintra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>asin(3)</function> (arc, or inverse sine). 
 * Angles are 
 * expressed in degrees. The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_asintra(), im_costra(), im_tantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_asintra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_asintra", in, out, 
		(im_wrapone_fn) ADSIN_buffer ) );
}

/* Cos in degrees.
 */
#define DCOS( X ) (cos( IM_RAD( X ) ))

FUN_BUFFER( DCOS )

/**
 * im_costra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>cos(3)</function> (cosine). Angles are 
 * expressed in degrees. The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_acostra(), im_sintra(), im_tantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_costra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_costra", in, out, (im_wrapone_fn) DCOS_buffer ) );
}

/* Acos in degrees.
 */
#define ADCOS( X ) (IM_DEG( acos( X ) ))

FUN_BUFFER( ADCOS )

/**
 * im_acostra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>acos(3)</function> (arc or inverse cosine). 
 * Angles are expressed in
 * degrees. The output type is float, unless the input is double, in which 
 * case the output is double.  Non-complex images only.
 *
 * See also: im_costra(), im_asintra(), im_atantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_acostra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_acostra", in, out, 
		(im_wrapone_fn) ADCOS_buffer ) );
}

/* Tan in degrees.
 */
#define DTAN( X ) (tan( IM_RAD( X ) ))

FUN_BUFFER( DTAN )

/**
 * im_tantra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>tan(3)</function> (tangent). Angles are 
 * expressed in degrees. The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_atantra(), im_sintra(), im_tantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_tantra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_tantra", in, out, (im_wrapone_fn) DTAN_buffer ) );
}

/* Atan in degrees.
 */
#define ADTAN( X ) (IM_DEG( atan( X ) ))

FUN_BUFFER( ADTAN )

/**
 * im_atantra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>atan(3)</function> (arc or inverse tangent). 
 * Angles are expressed in
 * degrees. The output type is float, unless the input is double, in which 
 * case the output is double.  Non-complex images only.
 *
 * See also: im_tantra(), im_asintra(), im_atantra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_atantra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_atantra", in, out, 
		(im_wrapone_fn) ADTAN_buffer ) );
}

FUN_BUFFER( log10 )

/**
 * im_log10tra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>log10(3)</function> (base 10 logarithm). 
 * The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_exp10tra(), im_logntra(), im_sintra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_log10tra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_log10tra", in, out, 
		(im_wrapone_fn) log10_buffer ) );
}

FUN_BUFFER( log )

/**
 * im_logtra
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, call <function>log(3)</function> (natural logarithm). 
 * The output type is float, unless the input is 
 * double, in which case the output is double.  Non-complex images only.
 *
 * See also: im_exp10tra(), im_logntra(), im_sintra().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_logtra( IMAGE *in, IMAGE *out )
{
	return( im__math( "im_logtra", in, out, (im_wrapone_fn) log_buffer ) );
}
