/* im_linreg.c
 *
 * Copyright: 2006, The Nottingham Trent University
 *
 * Author: Tom Vajzovic
 *
 * Written on: 2006-12-26
 *
 * 12/5/09
 *	- make x_anal() static, fix some signed/unsigned warnings
 * 3/9/09
 * 	- gtkdoc comment
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


/** HEADERS **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#include <vips/intl.h>

#include <stdlib.h>
#include <math.h>
#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC */


/** TYPES **/

typedef struct {

  unsigned int n;
  double *xs;
  double *difs;
  double mean;
  double nsig2;
  double err_term;

} x_set;

#define LINREG_SEQ( TYPE ) typedef struct {                                                         \
  REGION **regs;                                                                                    \
  TYPE **ptrs;                                                                                      \
  size_t *skips;                                                                                    \
} linreg_seq_ ## TYPE

LINREG_SEQ( gint8 );
LINREG_SEQ( guint8 );
LINREG_SEQ( gint16 );
LINREG_SEQ( guint16 );
LINREG_SEQ( gint32 );
LINREG_SEQ( guint32 );
LINREG_SEQ( float );
LINREG_SEQ( double );


/** LOCAL FUNCTION DECLARATIONS **/

static x_set *x_anal( IMAGE *im, double *xs, unsigned int n );

#define LINREG_START_DECL( TYPE ) static void * linreg_start_ ## TYPE( IMAGE *, void *, void * );
#define LINREG_GEN_DECL( TYPE ) static int linreg_gen_ ## TYPE( REGION *, void *, void *, void * );
#define LINREG_STOP_DECL( TYPE ) static int linreg_stop_ ## TYPE( void *, void *, void * );
#define INCR_ALL_DECL( TYPE ) static void incr_all_ ## TYPE( TYPE **ptrs, unsigned int n )
#define SKIP_ALL_DECL( TYPE ) static void skip_all_ ## TYPE( TYPE **ptrs, size_t *skips, unsigned int n )

LINREG_START_DECL( gint8 );
LINREG_START_DECL( guint8 );
LINREG_START_DECL( gint16 );
LINREG_START_DECL( guint16 );
LINREG_START_DECL( gint32 );
LINREG_START_DECL( guint32 );
LINREG_START_DECL( float );
LINREG_START_DECL( double );

LINREG_GEN_DECL( gint8 );
LINREG_GEN_DECL( guint8 );
LINREG_GEN_DECL( gint16 );
LINREG_GEN_DECL( guint16 );
LINREG_GEN_DECL( gint32 );
LINREG_GEN_DECL( guint32 );
LINREG_GEN_DECL( float );
LINREG_GEN_DECL( double );

LINREG_STOP_DECL( gint8 );
LINREG_STOP_DECL( guint8 );
LINREG_STOP_DECL( gint16 );
LINREG_STOP_DECL( guint16 );
LINREG_STOP_DECL( gint32 );
LINREG_STOP_DECL( guint32 );
LINREG_STOP_DECL( float );
LINREG_STOP_DECL( double );

INCR_ALL_DECL( gint8 );
INCR_ALL_DECL( guint8 );
INCR_ALL_DECL( gint16 );
INCR_ALL_DECL( guint16 );
INCR_ALL_DECL( gint32 );
INCR_ALL_DECL( guint32 );
INCR_ALL_DECL( float );
INCR_ALL_DECL( double );

SKIP_ALL_DECL( gint8 );
SKIP_ALL_DECL( guint8 );
SKIP_ALL_DECL( gint16 );
SKIP_ALL_DECL( guint16 );
SKIP_ALL_DECL( gint32 );
SKIP_ALL_DECL( guint32 );
SKIP_ALL_DECL( float );
SKIP_ALL_DECL( double );


/** EXPORTED FUNCTION DEFINITION **/

/** im_linreg:
 * @ins: NULL-terminated array of input images
 * @out: results of analysis
 * @xs:	X position of each image (pixel value is Y)
 *
 * Function to find perform pixelwise linear regression on an array of 
 * single band images. The output is a seven-band douuble image
 *
 * TODO: figure out how this works and fix up these docs!
 */
int im_linreg( IMAGE **ins, IMAGE *out, double *xs ){
#define FUNCTION_NAME "im_linreg"
  int n;
  x_set *x_vals;

  if( im_poutcheck( out ) )
    return( -1 );

  for( n= 0; ins[ n ]; ++n ){
/*
    if( ! isfinite( xs[ n ] ) ){
      im_error( FUNCTION_NAME, "invalid argument" );
      return( -1 );
    }
*/
    if( im_pincheck( ins[ n ] ) )
      return( -1 );

    if( 1 != ins[ n ]-> Bands ){
      im_error( FUNCTION_NAME, "image is not single band" );
      return( -1 );
    }
    if( ins[ n ]-> Coding ){
      im_error( FUNCTION_NAME, "image is not uncoded" );
      return( -1 );
    }
    if( n ){
      if( ins[ n ]-> BandFmt != ins[ 0 ]-> BandFmt ){
        im_error( FUNCTION_NAME, "image band formats differ" );
        return( -1 );
      }
    }
    else {
      if( ! im_isscalar( ins[ 0 ] ) ){
        im_error( FUNCTION_NAME, "image has non-scalar band format" );
        return( -1 );
      }
    }
    if( n && ( ins[ n ]-> Xsize != ins[ 0 ]-> Xsize
        || ins[ n ]-> Ysize != ins[ 0 ]-> Ysize ) ){

      im_error( FUNCTION_NAME, "image sizes differ" );
      return( -1 );
    }
  }
  if( n < 3 ){
    im_error( FUNCTION_NAME, "not enough input images" );
    return( -1 );
  }
  if( im_cp_desc_array( out, ins ) )
    return( -1 );

  out-> Bands= 7;
  out-> BandFmt= IM_BANDFMT_DOUBLE;
  out-> Bbits= IM_BBITS_DOUBLE;
  out-> Type= 0;

  if( im_demand_hint_array( out, IM_THINSTRIP, ins ) )
    return( -1 );

  x_vals= x_anal( out, xs, n );

  if( ! x_vals )
    return( -1 );

  switch( ins[ 0 ]-> BandFmt ){
#define LINREG_RET( TYPE )  return im_generate( out, linreg_start_ ## TYPE, linreg_gen_ ## TYPE, linreg_stop_ ## TYPE, ins, x_vals )

    case IM_BANDFMT_CHAR:
      LINREG_RET( gint8 );

    case IM_BANDFMT_UCHAR:
      LINREG_RET( guint8 );

    case IM_BANDFMT_SHORT:
      LINREG_RET( gint16 );

    case IM_BANDFMT_USHORT:
      LINREG_RET( guint16 );

    case IM_BANDFMT_INT:
      LINREG_RET( gint32 );

    case IM_BANDFMT_UINT:
      LINREG_RET( guint32 );

    case IM_BANDFMT_FLOAT:
      LINREG_RET( float );

    case IM_BANDFMT_DOUBLE:
      LINREG_RET( double );

    default:  /* keep -Wall happy */
      return( -1 );
  }
#undef FUNCTION_NAME
}


/** LOCAL FUNCTION DECLARATIONS **/

static x_set *x_anal( IMAGE *im, double *xs, unsigned int n ){
  unsigned int i;

  x_set *x_vals= IM_NEW( im, x_set );

  if( ! x_vals )
    return( NULL );

  x_vals-> xs= IM_ARRAY( im, 2 * n, double );

  if( ! x_vals-> xs )
    return( NULL );

  x_vals-> difs= x_vals-> xs + n;
  x_vals-> n= n;
  x_vals-> mean= 0.0;

  for( i= 0; i < n; ++i ){
    x_vals-> xs[ i ]= xs[ i ];
    x_vals-> mean+= xs[ i ];
  }
  x_vals-> mean/= n;
  x_vals-> nsig2= 0.0;

  for( i= 0; i < n; ++i ){
    x_vals-> difs[ i ]= xs[ i ] - x_vals-> mean;
    x_vals-> nsig2+= x_vals-> difs[ i ] * x_vals-> difs[ i ];
  }
  x_vals-> err_term= ( 1.0 / (double) n ) + ( ( x_vals-> mean * x_vals-> mean ) / x_vals-> nsig2 );

  return( x_vals );
}

#define LINREG_START_DEFN( TYPE ) static void *linreg_start_ ## TYPE( IMAGE *out, void *a, void *b ){ \
  IMAGE **ins= (IMAGE **) a; 			                                                    \
  x_set *x_vals= (x_set *) b;                                                                       \
  linreg_seq_ ## TYPE *seq= IM_NEW( out, linreg_seq_ ## TYPE );                                     \
                                                                                                    \
  if( ! seq )                                                                                       \
    return NULL;                                                                                    \
                                                                                                    \
  seq-> regs= im_start_many( NULL, ins, NULL );                                                     \
  seq-> ptrs= IM_ARRAY( out, x_vals-> n, TYPE* );                                                   \
  seq-> skips= IM_ARRAY( out, x_vals-> n, size_t );                                                 \
                                                                                                    \
  if( ! seq-> ptrs || ! seq-> regs || ! seq-> skips ){                                              \
    linreg_stop_ ## TYPE( seq, NULL, NULL );                                                        \
    return NULL;                                                                                    \
  }                                                                                                 \
  return (void *) seq;                                                                              \
}

#define N       ( (double) n )
#define y(a)    ( (double) (* seq-> ptrs[(a)] ) )
#define x(a)    ( (double) ( x_vals-> xs[(a)] ) )
#define xd(a)   ( (double) ( x_vals-> difs[(a)] ) )
#define Sxd2    ( x_vals-> nsig2 )
#define mean_x  ( x_vals-> mean )
#define mean_y  ( out[0] )
#define dev_y   ( out[1] )
#define y_x0    ( out[2] )
#define d_y_x0  ( out[3] )
#define dy_dx   ( out[4] )
#define d_dy_dx ( out[5] )
#define R       ( out[6] )

#define LINREG_GEN_DEFN( TYPE ) static int linreg_gen_ ## TYPE( REGION *to_make, void *vseq, void *unrequired, void *b ){ \
  linreg_seq_ ## TYPE *seq= (linreg_seq_ ## TYPE *) vseq;                                           \
  x_set *x_vals= (x_set *) b;                                                                       \
  unsigned int n= x_vals-> n;                                                                       \
  double *out= (double*) IM_REGION_ADDR_TOPLEFT( to_make );                                         \
  size_t out_skip= IM_REGION_LSKIP( to_make ) / sizeof( double );                                   \
  double *out_end= out + out_skip * to_make-> valid. height;                                        \
  double *out_stop;                                                                                 \
  size_t out_n= IM_REGION_N_ELEMENTS( to_make );                                                    \
  unsigned int i;                                                                                            \
                                                                                                    \
  out_skip-= out_n;                                                                                 \
                                                                                                    \
  if( im_prepare_many( seq-> regs, & to_make-> valid ) )                                            \
    return -1;                                                                                      \
                                                                                                    \
  for( i= 0; i < n; ++i ){                                                                          \
    seq-> ptrs[ i ]= (TYPE*) IM_REGION_ADDR( seq-> regs[ i ], to_make-> valid. left, to_make-> valid. top ); \
    seq-> skips[ i ]= ( IM_REGION_LSKIP( seq-> regs[ i ] ) / sizeof( TYPE ) ) - IM_REGION_N_ELEMENTS( seq-> regs[ i ] ); \
  }                                                                                                 \
                                                                                                    \
  for( ; out < out_end; out+= out_skip, skip_all_ ## TYPE( seq-> ptrs, seq-> skips, n ) )           \
    for( out_stop= out + out_n; out < out_stop; out+= 7, incr_all_ ## TYPE( seq-> ptrs, n ) ){      \
      double Sy= 0.0;                                                                               \
      double Sxd_y= 0.0;                                                                            \
      double Syd2= 0.0;                                                                             \
      double Sxd_yd= 0.0;                                                                           \
      double Se2= 0.0;                                                                              \
                                                                                                    \
      for( i= 0; i < n; ++i ){                                                                      \
        Sy+= y(i);                                                                                  \
        Sxd_y+= xd(i) * y(i);                                                                       \
      }                                                                                             \
      mean_y= Sy / N;                                                                               \
      dy_dx= Sxd_y / Sxd2;                                                                          \
      y_x0= mean_y - dy_dx * mean_x;                                                                \
                                                                                                    \
      for( i= 0; i < n; ++i ){                                                                      \
        double yd= y(i) - mean_y;                                                                   \
        double e= y(i) - dy_dx * x(i) - y_x0;                                                       \
        Syd2+= yd * yd;                                                                             \
        Sxd_yd+= xd(i) * yd;                                                                        \
        Se2+= e * e;                                                                                \
      }                                                                                             \
      dev_y= sqrt( Syd2 / N );                                                                      \
      Se2/= ( N - 2.0 );                                                                            \
      d_dy_dx= sqrt( Se2 / Sxd2 );                                                                  \
      d_y_x0= sqrt( Se2 * x_vals-> err_term );                                                      \
      R= Sxd_yd / sqrt( Sxd2 * Syd2 );                                                              \
    }                                                                                               \
  return 0;                                                                                         \
}

#define LINREG_STOP_DEFN( TYPE ) static int linreg_stop_ ## TYPE( void *vseq, void *a, void *b ){   \
  linreg_seq_ ## TYPE *seq = (linreg_seq_ ## TYPE *) vseq;                                          \
  if( seq-> regs )                                                                                  \
    im_stop_many( seq-> regs, NULL, NULL );                                                         \
  return 0;                                                                                         \
}

#define INCR_ALL_DEFN( TYPE ) static void incr_all_ ## TYPE( TYPE **ptrs, unsigned int n ){         \
  TYPE **stop= ptrs + n;                                                                            \
  for( ; ptrs < stop; ++ptrs )                                                                      \
    ++*ptrs;                                                                                        \
}

#define SKIP_ALL_DEFN( TYPE ) static void skip_all_ ## TYPE( TYPE **ptrs, size_t *skips, unsigned int n ){ \
  TYPE **stop= ptrs + n;                                                                            \
  for( ; ptrs < stop; ++ptrs, ++skips )                                                             \
    *ptrs+= *skips;                                                                                 \
}

LINREG_START_DEFN( gint8 );
LINREG_START_DEFN( guint8 );
LINREG_START_DEFN( gint16 );
LINREG_START_DEFN( guint16 );
LINREG_START_DEFN( gint32 );
LINREG_START_DEFN( guint32 );
LINREG_START_DEFN( float );
LINREG_START_DEFN( double );

LINREG_GEN_DEFN( gint8 );
LINREG_GEN_DEFN( guint8 );
LINREG_GEN_DEFN( gint16 );
LINREG_GEN_DEFN( guint16 );
LINREG_GEN_DEFN( gint32 );
LINREG_GEN_DEFN( guint32 );
LINREG_GEN_DEFN( float );
LINREG_GEN_DEFN( double );

LINREG_STOP_DEFN( gint8 );
LINREG_STOP_DEFN( guint8 );
LINREG_STOP_DEFN( gint16 );
LINREG_STOP_DEFN( guint16 );
LINREG_STOP_DEFN( gint32 );
LINREG_STOP_DEFN( guint32 );
LINREG_STOP_DEFN( float );
LINREG_STOP_DEFN( double );

INCR_ALL_DEFN( gint8 );
INCR_ALL_DEFN( guint8 );
INCR_ALL_DEFN( gint16 );
INCR_ALL_DEFN( guint16 );
INCR_ALL_DEFN( gint32 );
INCR_ALL_DEFN( guint32 );
INCR_ALL_DEFN( float );
INCR_ALL_DEFN( double );

SKIP_ALL_DEFN( gint8 );
SKIP_ALL_DEFN( guint8 );
SKIP_ALL_DEFN( gint16 );
SKIP_ALL_DEFN( guint16 );
SKIP_ALL_DEFN( gint32 );
SKIP_ALL_DEFN( guint32 );
SKIP_ALL_DEFN( float );
SKIP_ALL_DEFN( double );
