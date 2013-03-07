/* Inline maths functions if they are missing from libm
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_INLINE_H
#define VIPS_INLINE_H

/* glib promises to define inline in a portable way 
 */

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#ifdef HAVE_HYPOT

#define vips__hypot hypot

#else /* HAVE_HYPOT */

static inline double 
vips__hypot( double a, double b ) 
{
	double ta = fabs( a );
	double tb = fabs( b );

	if( ta > tb ) {
		tb = b / a;

		return( ta * sqrt( 1.0 + tb * tb ) );
	}
	else {
		ta = a / b;

		return( tb * sqrt( 1.0 + ta * ta ) );
	}
}

#endif /* HAVE_HYPOT */

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_INLINE_H*/
