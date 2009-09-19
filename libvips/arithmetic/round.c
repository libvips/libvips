/* round.c --- various rounding operations
 *
 * 20/6/02 JC
 *	- adapted from im_abs()
 * 29/8/09
 * 	- gtkdoc
 * 	- tiny cleanups
 * 19/9/09
 * 	- im_ceil.c adapted to make round.c
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define ROUND_LOOP( TYPE, FUN ) { \
	TYPE *p = (TYPE *) in; \
	TYPE *q = (TYPE *) out; \
	\
	for( x = 0; x < ne; x++ ) \
		q[x] = FUN( p[x] ); \
}

#define ROUND_BUFFER( FUN ) \
static void \
FUN ## _buffer( PEL *in, PEL *out, int width, IMAGE *im ) \
{ \
	/* Complex just doubles the size. \
	 */ \
	const int ne = width * im->Bands * (im_iscomplex( im ) ? 2 : 1); \
	\
	int x; \
	\
        switch( im->BandFmt ) { \
        case IM_BANDFMT_COMPLEX: \
        case IM_BANDFMT_FLOAT: \
		ROUND_LOOP( float, FUN ); \
		break; \
	\
        case IM_BANDFMT_DOUBLE: \
        case IM_BANDFMT_DPCOMPLEX: \
		ROUND_LOOP( double, FUN ); \
		break; \
	\
        default: \
		g_assert( 0 ); \
        } \
}

static int 
im__round( const char *name, IMAGE *in, IMAGE *out, im_wrapone_fn gen )
{	
	if( im_piocheck( in, out ) ||
		im_check_uncoded( name, in ) )
		return( -1 );

	/* Is this one of the int types? Degenerate to im_copy() if it
	 * is.
	 */
	if( im_isint( in ) )
		return( im_copy( in, out ) );

	/* Output type == input type.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );

	/* Generate!
	 */
	if( im_wrapone( in, out, (im_wrapone_fn) gen, in, NULL ) )
		return( -1 );

	return( 0 );
}

ROUND_BUFFER( ceil )

/**
 * im_ceil:
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, find the smallest integral value not less than.
 * Copy for integer types, call <function>ceil(3)</function> for float and 
 * complex types. 
 * Output type == input type.
 *
 * See also: im_floor(), im_rint(), im_clip2fmt()
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_ceil( IMAGE *in, IMAGE *out )
{	
	return( im__round( "im_ceil", in, out, (im_wrapone_fn) ceil_buffer ) );
}

ROUND_BUFFER( floor )

/**
 * im_floor:
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * For each pixel, find the largest integral value not less than.
 * Copy for integer types, call <function>floor()</function> for float and 
 * complex types. 
 * Output type == input type.
 *
 * See also: im_ceil(), im_rint(), im_clip2fmt()
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_floor( IMAGE *in, IMAGE *out )
{	
	return( im__round( "im_floor", in, out, 
		(im_wrapone_fn) floor_buffer ) );
}

ROUND_BUFFER( IM_RINT )

/**
 * im_rint:
 * @in: input #IMAGE
 * @out: output #IMAGE
 *
 * Finds the nearest integral value. Copy for integer types, 
 * call IM_RINT() for float and complex types. Output type == input type.
 *
 * IM_RINT() is a pseudo-round-to-nearest. It is much faster than
 * <function>rint</function>(3), but does not give the same result for
 * negative integral values.
 *
 * See also: im_ceil(), im_floor(), im_clip2fmt()
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_rint( IMAGE *in, IMAGE *out )
{	
	return( im__round( "im_rint", in, out, (im_wrapone_fn) IM_RINT_buffer ) );
}
