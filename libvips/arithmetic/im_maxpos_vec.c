/* im_maxpos_vec.c
 *
 * Copyright: 2006, The Nottingham Trent University
 * Copyright: 2006, Tom Vajzovic
 *
 * Author: Tom Vajzovic
 *
 * Written on: 2006-09-01
 *
 * 9/9/09
 * 	- gtkdoc comments
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
#include <float.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC */


/** TYPE DEFINITIONS **/

typedef struct {

  int *xs;
  int *ys;
  double *vals;
  int *ptrs;
  int start;

} maxpos_list;


/** LOCAL FUNCTIONS DECLARATIONS **/

static maxpos_list   *maxpos_list_alloc( int n );
static void           maxpos_list_free( maxpos_list *list );

static void           maxpos_list_init( maxpos_list *list, int n );
static void          *maxpos_vec_start( IMAGE *unrequired, void *, void * );
static int            maxpos_vec_scan( REGION *reg, void *seq, void *, void * );
static void           add_to_maxpos_list( maxpos_list *list, int x, int y, double val );
static int            maxpos_vec_stop( void *seq, void *, void * );

static void           minpos_list_init( maxpos_list *list, int n );
static void          *minpos_vec_start( IMAGE *unrequired, void *, void * );
static int            minpos_vec_scan( REGION *reg, void *seq, void *, void * );
static void           add_to_minpos_list( maxpos_list *list, int x, int y, double val );
static int            minpos_vec_stop( void *seq, void *, void * );


/** EXPORTED FUNCTIONS **/

/**
 * im_maxpos_vec:
 * @im: image to scan
 * @xpos: array to return x positions
 * @ypos: array to return y positions
 * @maxima: array to return values
 * @n: number of maxima to search for
 *
 * Find the coordinates and values of the n maxima of an image.
 *
 * For 8 and 16-bit images, it's much faster to find the histogram and then
 * calculate a threshold from that. See im_mpercent().
 *
 * See also: im_minpos(), im_min(), im_stats(), im_maxpos_avg().
 *
 * Returns: 0 on success, -1 on error
 */

int im_maxpos_vec( IMAGE *im, int *xpos, int *ypos, double *maxima, int n ){ 
#define FUNCTION_NAME "im_maxpos_vec"
  /* number of sequences used is beyond my control at this level, but I note that */
  /* efficiency decreases as more sequences are used - speed may still increase   */
  
  int result;
  int *pointers= im_malloc( NULL, n * sizeof( int* ) );
  maxpos_list master_list= { xpos, ypos, maxima, pointers, 0 };

  if( im_pincheck( im ) )
    return -1;

  if( !pointers )
    return -1;

  if( ! ( vips_bandfmt_isint( im->BandFmt ) || 
	vips_bandfmt_isfloat( im->BandFmt ) ) ){
    im_error( FUNCTION_NAME, "%s", _( "scalar images only" ) );
    return -1;
  }

  if( 1 != im-> Bands ){
    im_error( FUNCTION_NAME, "%s", _( "single band images only" ) );
    return -1;
  }

  if( IM_CODING_NONE != im-> Coding ){
    im_error( FUNCTION_NAME, "%s", _( "uncoded images only" ) );
    return -1;
  }

  if( ! xpos || ! ypos || ! maxima || n < 1 ){
    im_error( FUNCTION_NAME, "%s", _( "invalid argument" ) );
    return -1;
  }

  maxpos_list_init( &master_list, n );

  result= im_iterate( im, maxpos_vec_start, maxpos_vec_scan, maxpos_vec_stop, &n, &master_list );

  im_free( pointers );

  return result;
#undef FUNCTION_NAME
}


/**
 * im_minpos_vec:
 * @im: image to scan
 * @xpos: array to return x positions
 * @ypos: array to return y positions
 * @maxima: array to return values
 * @n: number of minima to search for
 *
 * Find the coordinates and values of the n minima of an image.
 *
 * For 8 and 16-bit images, it's much faster to find the histogram and then
 * calculate a threshold from that. See im_mpercent().
 *
 * See also: im_minpos(), im_min(), im_stats(), im_maxpos_avg().
 *
 * Returns: 0 on success, -1 on error
 */

int im_minpos_vec( IMAGE *im, int *xpos, int *ypos, double *minima, int n ){ 
#define FUNCTION_NAME "im_minpos_vec"
  /* number of sequences used is beyond my control at this level, but I note that */
  /* effeciency decreases as more sequences are used - speed may still increase   */
  
  int result;
  int *pointers= im_malloc( NULL, n * sizeof( int* ) );
  maxpos_list master_list= { xpos, ypos, minima, pointers, 0 };

  if( im_pincheck( im ) )
    return -1;

  if( !pointers )
    return -1;

  if( ! ( vips_bandfmt_isint( im->BandFmt ) || 
	vips_bandfmt_isfloat( im->BandFmt ) ) ){
    im_error( FUNCTION_NAME, "%s", _( "scalar images only" ) );
    return -1;
  }

  if( 1 != im-> Bands ){
    im_error( FUNCTION_NAME, "%s", _( "single band images only" ) );
    return -1;
  }

  if( IM_CODING_NONE != im-> Coding ){
    im_error( FUNCTION_NAME, "%s", _( "uncoded images only" ) );
    return -1;
  }

  if( ! xpos || ! ypos || ! minima || n < 1 ){
    im_error( FUNCTION_NAME, "%s", _( "invalid argument" ) );
    return -1;
  }

  minpos_list_init( &master_list, n );

  result= im_iterate( im, minpos_vec_start, minpos_vec_scan, minpos_vec_stop, &n, &master_list );

  im_free( pointers );

  return result;
#undef FUNCTION_NAME
}


/** LOCAL FUNCTION DEFINITIONS **/

static maxpos_list *maxpos_list_alloc( int n ){

  maxpos_list *list= im_malloc( NULL, sizeof( maxpos_list ) );

  if( ! list )
    return NULL;

  list-> xs= im_malloc( NULL, 3 * n * sizeof( int ) );
  list-> vals= im_malloc( NULL, n * sizeof( double ) );

  if( ! list-> xs || ! list-> vals ){
    im_free( list-> xs );
    im_free( list-> vals );
    im_free( list );
    return NULL;
  }
  list-> ys= list-> xs + n;
  list-> ptrs= list-> ys + n;

  return list;
}

static void maxpos_list_free( maxpos_list *list ){
  im_free( list-> xs );
  im_free( list-> vals );
  im_free( list );
}


static void maxpos_list_init( maxpos_list *list, int n ){
  int i;
  
  for( i= 0; i < n; ++i ){
    list-> xs[ i ]= 0;
    list-> ys[ i ]= 0;
    list-> vals[ i ]= 0;
    list-> ptrs[ i ]= i + 1;
  }
    
  list-> ptrs[ n - 1 ]= -1;
  list-> start= 0;
}

static void *maxpos_vec_start( IMAGE *unrequired, void *a, void *b ){

  int *n = (int *) a;
  maxpos_list *list= maxpos_list_alloc( *n );
  
  if( ! list )
    return NULL;

  maxpos_list_init( list, *n );

  return list;
}

static int maxpos_vec_scan( REGION *reg, void *seq, void *a, void *b ){
  
  maxpos_list *list = (maxpos_list *) seq;

#define MAXPOS_VEC_SCAN( type ){                                                        \
                                                                                        \
  int y= reg-> valid. top;                                                              \
  int x;                                                                                \
  int ymax= y + reg-> valid. height;                                                    \
  int xmax= reg-> valid. left + reg-> valid. width;                                     \
                                                                                        \
  type *row= (type*)IM_REGION_ADDR( reg, reg-> valid. left, y ) - reg-> valid. left;    \
  size_t skip= IM_REGION_LSKIP( reg ) / sizeof( type );                                 \
                                                                                        \
  for( ; y < ymax; ++y, row+= skip )                                                    \
    for( x= reg-> valid. left; x < xmax; ++x )                                          \
      if( row[ x ] > list-> vals[ list-> start ] )                                      \
        add_to_maxpos_list( list, x, y, row[ x ] );                                     \
}

  switch( reg-> im-> BandFmt ){
    case IM_BANDFMT_UCHAR:   MAXPOS_VEC_SCAN( guint8 )   break; 
    case IM_BANDFMT_CHAR:    MAXPOS_VEC_SCAN( gint8 )    break;
    case IM_BANDFMT_USHORT:  MAXPOS_VEC_SCAN( guint16 )  break;
    case IM_BANDFMT_SHORT:   MAXPOS_VEC_SCAN( gint16 )   break;
    case IM_BANDFMT_UINT:    MAXPOS_VEC_SCAN( guint32 )  break;
    case IM_BANDFMT_INT:     MAXPOS_VEC_SCAN( gint32 )   break;
    case IM_BANDFMT_FLOAT:   MAXPOS_VEC_SCAN( float )    break;
    case IM_BANDFMT_DOUBLE:  MAXPOS_VEC_SCAN( double )   break;
    default:
			     g_assert( 0 );
  }

#undef MAXPOS_VEC_SCAN

  return 0;
}

static void add_to_maxpos_list( maxpos_list *list, int x, int y, double val ){

  int pointer= list-> start;

  while( -1 != list-> ptrs[ pointer ] && val > list-> vals[ list-> ptrs[ pointer ] ] )
    pointer= list-> ptrs[ pointer ];

  list-> xs[ list-> start ]= x;
  list-> ys[ list-> start ]= y;
  list-> vals[ list-> start ]= val;

  if( list-> start != pointer ){  
    /* we are adding mid-chain not at the very bottom */
    int second= list-> ptrs[ list-> start ];

    list-> ptrs[ list-> start ]= list-> ptrs[ pointer ];
    list-> ptrs[ pointer ]= list-> start;
    list-> start= second;
  }
}

static int maxpos_vec_stop( void *seq, void *a, void *b ){

  /* reverse list */
  
  maxpos_list *list = (maxpos_list *) seq;
  maxpos_list *master_list = (maxpos_list *) b;

  int prev= -1;
  int pointer= list-> start;

  while( -1 != list-> ptrs[ pointer ] ){

    int next= list-> ptrs[ pointer ];

    list-> ptrs[ pointer ]= prev;
    prev= pointer;
    pointer= next;
  }
  list-> ptrs[ pointer ]= prev;
  list-> start= pointer;

  /* add to main list */

  for( ; -1 != pointer; pointer= list-> ptrs[ pointer ] )
    /* loop over all the ones found in this sequence */
    
    if( list-> vals[ pointer ] > master_list-> vals[ master_list-> start ] )
      add_to_maxpos_list( master_list, list-> xs[ pointer ], list-> ys[ pointer ], list-> vals[ pointer ] );
    else
      break;
      /* since we are now high->low, if this one isn't big enough, none of the rest are */

  maxpos_list_free( list );

  return 0;
}


static void minpos_list_init( maxpos_list *list, int n ){
  int i;
  
  for( i= 0; i < n; ++i ){
    list-> xs[ i ]= 0;
    list-> ys[ i ]= 0;
    list-> vals[ i ]= DBL_MAX;
    list-> ptrs[ i ]= i + 1;
  }
    
  list-> ptrs[ n - 1 ]= -1;
  list-> start= 0;
}

static void *minpos_vec_start( IMAGE *unrequired, void *a, void *b ){

  int *n = (int *) a;
  maxpos_list *list= maxpos_list_alloc( *n );
  
  if( ! list )
    return NULL;

  minpos_list_init( list, *n );

  return list;
}

static int minpos_vec_scan( REGION *reg, void *seq, void *a, void *b ){
  
  maxpos_list *list = (maxpos_list *) seq;

#define MINPOS_VEC_SCAN( type ){                                                        \
                                                                                        \
  int y= reg-> valid. top;                                                              \
  int x;                                                                                \
  int ymax= y + reg-> valid. height;                                                    \
  int xmax= reg-> valid. left + reg-> valid. width;                                     \
                                                                                        \
  type *row= (type*)IM_REGION_ADDR( reg, reg-> valid. left, y ) - reg-> valid. left;    \
  size_t skip= IM_REGION_LSKIP( reg ) / sizeof( type );                                 \
                                                                                        \
  for( ; y < ymax; ++y, row+= skip )                                                    \
    for( x= reg-> valid. left; x < xmax; ++x )                                          \
      if( row[ x ] < list-> vals[ list-> start ] )                                      \
        add_to_minpos_list( list, x, y, row[ x ] );                                     \
}

  switch( reg-> im-> BandFmt ){
    case IM_BANDFMT_UCHAR:   MINPOS_VEC_SCAN( guint8 )   break; 
    case IM_BANDFMT_CHAR:    MINPOS_VEC_SCAN( gint8 )    break;
    case IM_BANDFMT_USHORT:  MINPOS_VEC_SCAN( guint16 )  break;
    case IM_BANDFMT_SHORT:   MINPOS_VEC_SCAN( gint16 )   break;
    case IM_BANDFMT_UINT:    MINPOS_VEC_SCAN( guint32 )  break;
    case IM_BANDFMT_INT:     MINPOS_VEC_SCAN( gint32 )   break;
    case IM_BANDFMT_FLOAT:   MINPOS_VEC_SCAN( float )    break;
    case IM_BANDFMT_DOUBLE:  MINPOS_VEC_SCAN( double )   break;
    default:
			     g_assert( 0 );
  }

#undef MINPOS_VEC_SCAN

  return 0;
}

static void add_to_minpos_list( maxpos_list *list, int x, int y, double val ){

  int pointer= list-> start;

  while( -1 != list-> ptrs[ pointer ] && val < list-> vals[ list-> ptrs[ pointer ] ] )
    pointer= list-> ptrs[ pointer ];

  list-> xs[ list-> start ]= x;
  list-> ys[ list-> start ]= y;
  list-> vals[ list-> start ]= val;

  if( list-> start != pointer ){  
    /* we are adding mid-chain not at the very bottom */
    int second= list-> ptrs[ list-> start ];

    list-> ptrs[ list-> start ]= list-> ptrs[ pointer ];
    list-> ptrs[ pointer ]= list-> start;
    list-> start= second;
  }
}

static int minpos_vec_stop( void *seq, void *a, void *b ){

  /* reverse list */
  
  maxpos_list *list = (maxpos_list *) seq;
  maxpos_list *master_list = (maxpos_list *) b;
  int prev= -1;
  int pointer= list-> start;

  while( -1 != list-> ptrs[ pointer ] ){

    int next= list-> ptrs[ pointer ];

    list-> ptrs[ pointer ]= prev;
    prev= pointer;
    pointer= next;
  }
  list-> ptrs[ pointer ]= prev;
  list-> start= pointer;

  /* add to main list */

  for( ; -1 != pointer; pointer= list-> ptrs[ pointer ] )
    /* loop over all the ones found in this sequence */
    
    if( list-> vals[ pointer ] < master_list-> vals[ master_list-> start ] )
      add_to_minpos_list( master_list, list-> xs[ pointer ], list-> ys[ pointer ], list-> vals[ pointer ] );
    else
      break;
      /* since we are now high->low, if this one isn't big enough, none of the rest are */

  maxpos_list_free( list );

  return 0;
}

