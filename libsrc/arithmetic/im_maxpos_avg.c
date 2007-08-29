/* @(#) Function to find the maximum of an image.  Returns coords and value at
 * @(#) double precision.  In the event of a draw, returns average of all 
 * @(#) drawing coords, and interpolated value at that position.
 * @(#)
 * @(#) int im_maxpos_avg(
 * @(#)   IMAGE *im,
 * @(#)   double *xpos,
 * @(#)   double *ypos,
 * @(#)   double *out
 * @(#) );
 * @(#) 
 *
 * Copyright: 2006, The Nottingham Trent University
 * Copyright: 2006, Tom Vajzovic
 *
 * Author: Tom Vajzovic
 *
 * Written on: 2006-09-25
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC */


/** LOCAL TYPES **/

typedef struct {
  double x_avg;
  double y_avg;
  double val;
  unsigned int occurances;

} pos_avg_t;


/** LOCAL FUNCTIONS DECLARATIONS **/

static pos_avg_t *
maxpos_avg_start( 
    IMAGE *im 
);
static int /* should be void (always returns 0) */
maxpos_avg_scan( 
    REGION *reg, 
    pos_avg_t *seq 
);
static int
maxpos_avg_stop( 
    pos_avg_t *seq, 
    pos_avg_t *master 
);


/** EXPORTED FUNCTION **/

int im_maxpos_avg( IMAGE *im, double *xpos, double *ypos, double *out ){
#define FUNCTION_NAME "im_maxpos_avg"

  pos_avg_t master= { 0.0, 0.0, 0.0, 0 };

  if( im_pincheck( im ) )
    return -1;

  if( im-> Coding ){
    im_error( FUNCTION_NAME, _("uncoded images only") );
    return -1;
  }
  if( !( im_isint( im ) || im_isfloat( im ) ) ){
    im_error( FUNCTION_NAME, _("scalar images only") );
    return -1;
  }
  if( 1 != im-> Bands ){
    im_error( FUNCTION_NAME, _("single band images only") );
    return -1;
  }
  if( ! xpos || ! ypos || ! out ){
    im_error( FUNCTION_NAME, _("invalid argument") );
    return -1;
  }
  if( im_iterate( im, (void*)maxpos_avg_start, maxpos_avg_scan, maxpos_avg_stop, &master, NULL ) )
    return -1;

  *xpos= master. x_avg / master. occurances;
  *ypos= master. y_avg / master. occurances;

  return im_point_bilinear( im, *xpos, *ypos, 0, out );

#undef FUNCTION_NAME
}

static pos_avg_t *maxpos_avg_start( IMAGE *im ){
  pos_avg_t *seq;

  seq= im_malloc( NULL, sizeof( pos_avg_t ) );
  if( ! seq )
    return NULL; 

  seq-> x_avg= 0.0;
  seq-> y_avg= 0.0;
  seq-> val= 0.0;
  seq-> occurances= 0;

  return seq;
}

/* should be void (always returns 0) */
static int maxpos_avg_scan( REGION *reg, pos_avg_t *seq ){
  
  const int right= reg-> valid. left + reg-> valid. width;
  const int bottom= reg-> valid. top + reg-> valid. height;
  int x;
  int y;

#define LOOPS(type){                                                                                  \
  type *read= (type*) IM_REGION_ADDR( reg, reg-> valid. left, reg-> valid. top ) - reg-> valid. left; \
  size_t skip= IM_REGION_LSKIP( reg ) / sizeof( type );                                               \
                                                                                                      \
  for( y= reg-> valid. top; y < bottom; ++y, read+= skip )                                            \
    for( x= reg-> valid. left; x < right; ++x )                                                       \
      if( read[x] > seq-> val ){                                                                      \
        seq-> val= read[x];                                                                           \
        seq-> x_avg= x;                                                                               \
        seq-> y_avg= y;                                                                               \
        seq-> occurances= 1;                                                                          \
      }                                                                                               \
      else if( read[x] == seq-> val ){                                                                \
        seq-> x_avg+= x;                                                                              \
        seq-> y_avg+= y;                                                                              \
        ++ (seq-> occurances);                                                                        \
      }                                                                                               \
}

  switch( reg-> im-> BandFmt ){
    case IM_BANDFMT_CHAR:   LOOPS( gint8 )   break;
    case IM_BANDFMT_UCHAR:  LOOPS( guint8 )  break;
    case IM_BANDFMT_SHORT:  LOOPS( gint16 )  break;
    case IM_BANDFMT_USHORT: LOOPS( guint16 ) break;
    case IM_BANDFMT_INT:    LOOPS( gint32 )  break;
    case IM_BANDFMT_UINT:   LOOPS( guint32 ) break;
    case IM_BANDFMT_FLOAT:  LOOPS( float )   break;
    case IM_BANDFMT_DOUBLE: LOOPS( double )  break;
  }

  return 0;
#undef LOOPS
}

/* should be void (always returns 0) */
static int maxpos_avg_stop( pos_avg_t *seq, pos_avg_t *master ){

  if( seq-> val > master-> val ){
    master-> val= seq-> val;
    master-> x_avg= seq-> x_avg;
    master-> y_avg= seq-> y_avg;
    master-> occurances= seq-> occurances;
  }
  else if( seq-> val == master-> val ){
    master-> x_avg+= seq-> x_avg;
    master-> y_avg+= seq-> y_avg;
    master-> occurances+= seq-> occurances;
  }
  return im_free( seq );
}

