/* @(#) Find the phase of the cross power spectrum of two complex images,
 * @(#) expressed as a complex image where the modulus of each pixel is
 * @(#) one.
 * @(#)
 * @(#) I.E. find (a.b*)/|a.b*| where
 * @(#) .  represents complex multiplication
 * @(#) *  represents the complex conjugate
 * @(#) || represents the complex modulus
 * @(#)
 * @(#) int im_cross_phase( IMAGE *a, IMAGE *b, IMAGE *out );
 * @(#)
 * @(#) All functions return 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 2008, Nottingham Trent University
 *
 * Author: Tom Vajzovic
 * Written on: 2008-01-09
 *
 * 2008-02-04 tcv:
 *   - exp( i.th ) == cos(th)+i.sin(th) NOT sin(th)+i.cos(th)
 *   - add quadratic version (ifdef'd out ATM - still using trigonometric one)
 *
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

#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/


/* There doesn't seem to be much difference in speed between these two methods (on an Athlon64),
 * so I use the modulus argument version, since atan2() is in c89 but hypot() is c99.
 *
 * If you think that it might be faster on your platform, uncomment the following:
 */
#define USE_MODARG_DIV

#ifdef USE_MODARG_DIV

#define COMPLEX_PHASE_FN( TYPE, ABS )                      \
static void                                                \
complex_phase_ ## TYPE ( void *in1, void *in2, void *out, int n, void *im, void *unrequired ){ \
                                                           \
  TYPE *X= (TYPE*) in1;                                    \
  TYPE *Y= (TYPE*) in2;                                    \
  TYPE *Z= (TYPE*) out;                                    \
  TYPE *Z_stop= Z + 2 * n * ((IMAGE*)im)-> Bands;          \
                                                           \
  for( ; Z < Z_stop; X+= 2, Y+= 2 ){                       \
    double arg= atan2( X[1], X[0] ) - atan2( Y[1], Y[0] ); \
    *Z++= cos( arg );                                      \
    *Z++= sin( arg );                                      \
  }                                                        \
}

#else /* USE_MODARG_DIV */

#define COMPLEX_PHASE_FN( TYPE, ABS )             \
static void                                       \
complex_phase_ ## TYPE ( void *in1, void *in2, void *out, int n, void *im, void *unrequired ){ \
                                                  \
  TYPE *X= (TYPE*) in1;                           \
  TYPE *Y= (TYPE*) in2;                           \
  TYPE *Z= (TYPE*) out;                           \
  TYPE *Z_stop= Z + 2 * n * ((IMAGE*)im)-> Bands; \
                                                  \
  for( ; Z < Z_stop; X+= 2, Y+= 2 )               \
                                                  \
    if( ABS( Y[0] ) > ABS( Y[1] )){               \
      double a= Y[1] / Y[0];                      \
      double b= Y[0] + Y[1] * a;                  \
      double re= ( X[0] + X[1] * a ) / b;         \
      double im= ( X[1] - X[0] * a ) / b;         \
      double mod= im__hypot( re, im );            \
      *Z++= re / mod;                             \
      *Z++= im / mod;                             \
    }                                             \
    else {                                        \
      double a= Y[0] / Y[1];                      \
      double b= Y[1] + Y[0] * a;                  \
      double re= ( X[0] * a + X[1] ) / b;         \
      double im= ( X[1] * a - X[0] ) / b;         \
      double mod= im__hypot( re, im );            \
      *Z++= re / mod;                             \
      *Z++= im / mod;                             \
    }                                             \
}

#endif /* USE_MODARG_DIV */

COMPLEX_PHASE_FN( float, fabsf )
COMPLEX_PHASE_FN( double, fabs )

int im_cross_phase( IMAGE *a, IMAGE *b, IMAGE *out ){
#define FUNCTION_NAME "im_phase"

  if( im_pincheck( a ) || im_pincheck( b ) || im_poutcheck( out ))
    return -1;

  if( im_check_size( FUNCTION_NAME, a, b ) ||
    im_check_bands( FUNCTION_NAME, a, b ) ||
    im_check_uncoded( FUNCTION_NAME, a ) ||
    im_check_uncoded( FUNCTION_NAME, b ) ||
    im_check_format( FUNCTION_NAME, a, b ) ||
    im_check_complex( FUNCTION_NAME, a ) ||
    im_check_complex( FUNCTION_NAME, b ) )
    return -1;

  return im_cp_descv( out, a, b, NULL ) || im_wraptwo( a, b, out,
    IM_BANDFMT_COMPLEX == a-> BandFmt ? complex_phase_float : complex_phase_double, a, NULL );
}
