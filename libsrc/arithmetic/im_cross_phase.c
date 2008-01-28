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

static void double_complex_phase( void *in1, void *in2, void *out, int n, void *im, void *unrequired );
static void float_complex_phase( void *in1, void *in2, void *out, int n, void *im, void *unrequired );

int im_cross_phase( IMAGE *a, IMAGE *b, IMAGE *out ){
#define FUNCTION_NAME "im_phase"

  if( im_pincheck( a ) || im_pincheck( b ) || im_poutcheck( out ))
    return -1;

  if( a-> Xsize != b-> Xsize || a-> Ysize != b-> Ysize ){
    im_error( FUNCTION_NAME, "not same size" );
    return -1;
  }
  if( a-> Bands != b-> Bands ){
    im_error( FUNCTION_NAME, "numbers of bands differ" );
    return -1;
  }
  if( a-> Coding || b-> Coding ){
    im_error( FUNCTION_NAME, "not uncoded" );
    return -1;
  }      
  if( a-> BandFmt != b-> BandFmt ){
    im_error( FUNCTION_NAME, "formats differ" );
    return -1;
  }
  if( IM_BANDFMT_COMPLEX != a-> BandFmt && IM_BANDFMT_DPCOMPLEX != a-> BandFmt ){
    im_error( FUNCTION_NAME, "not complex format" );
    return -1;   
  }
  if( im_cp_descv( out, a, b, NULL )
    || im_wraptwo( a, b, out, 
    IM_BANDFMT_COMPLEX == a-> BandFmt ? float_complex_phase : double_complex_phase, a, NULL ))
    return -1;

  return 0;
}

static void double_complex_phase( void *in1, void *in2, void *out, int n, void *im, void *unrequired ){
  double *a= (double*) in1;
  double *b= (double*) in2;
  double *o= (double*) out;
  double *o_end= o + 2 * n * ((IMAGE*)im)-> Bands;

  for( ; o < o_end; a+= 2, b+= 2 ){
    double arg= atan2( a[1], a[0] ) - atan2( b[1], b[0] );
    *o++= sin( arg );
    *o++= cos( arg );
#if 0
    /* FIXME very prone to overflow */
    double re= a[0] * b[0] + a[1] * b[1];
    double im= a[1] * b[0] - a[0] * b[1];
    double mod= hypot( re, im );    
    *o++= re / mod;
    *o++= im / mod;
#endif    
  }
}

static void float_complex_phase( void *in1, void *in2, void *out, int n, void *im, void *unrequired ){
  float *a= (float*) in1;
  float *b= (float*) in2;
  float *o= (float*) out;
  float *o_end= o + 2 * n * ((IMAGE*)im)-> Bands;

  for( ; o < o_end; a+= 2, b+= 2 ){
    double arg= atan2( a[1], a[0] ) - atan2( b[1], b[0] );
    *o++= sin( arg );
    *o++= cos( arg );
#if 0
    /* FIXME very prone to overflow */
    double re= (double)a[0] * (double)b[0] + (double)a[1] * (double)b[1];
    double im= (double)a[1] * (double)b[0] - (double)a[0] * (double)b[1];
    double mod= hypot( re, im );     
    *o++= re / mod;
    *o++= im / mod;
#endif
  }
}
