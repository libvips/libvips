/* @(#) Like im_spcor(), but with a new metric.
 * @(#)
 * @(#) takes the gradient images of the two images, and takes the dot-product
 * @(#) correlation of the two vector images.
 * @(#)
 * @(#) (vector images are never really used, the two components are
 * @(#) calculated separately)
 * @(#)
 * @(#) The vector expression of this method is my (tcv) own creation. It is
 * @(#) equivalent to the complex-number method of:
 * @(#)
 * @(#) ARGYRIOU, V. et al. 2003.  Estimation of sub-pixel motion using
 * @(#) gradient cross correlation.  Electronics Letters, 39 (13).
 * @(#)
 * @(#) It's suitability for sub-pixel alignment is not (yet) tested.
 *
 * Copyright: 2007 Nottingham Trent University
 *
 * Author: Tom Vajzovic
 * Written on: 2007-06-07
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
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdlib.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/


/** LOCAL TYPES **/

typedef struct {
  REGION *reg;
  int *region_xgrad;
  int *region_ygrad;
  size_t region_xgrad_area;
  size_t region_ygrad_area;
}
gradcor_seq_t;


/** LOCAL FUNCTION DECLARATIONS **/

static void *gradcor_start( IMAGE *out, void *vptr_large, void *unrequired );
static int gradcor_stop( void *vptr_seq, void *unrequired, void *unreq2 );
static int gradcor_gen( REGION *to_make, void *vptr_seq, void *unrequired, void *vptr_grads );

#define XGRAD_GEN_DECLARATION( TYPE )  static int xgrad_gen_ ## TYPE( REGION *to_make, void *vptr_make_from, void *unrequired, void *unreq2 )
#define YGRAD_GEN_DECLARATION( TYPE )  static int ygrad_gen_ ## TYPE( REGION *to_make, void *vptr_make_from, void *unrequired, void *unreq2 )

XGRAD_GEN_DECLARATION( guint8 );
YGRAD_GEN_DECLARATION( guint8 );
XGRAD_GEN_DECLARATION( gint8 );
YGRAD_GEN_DECLARATION( gint8 );
XGRAD_GEN_DECLARATION( guint16 );
YGRAD_GEN_DECLARATION( guint16 );
XGRAD_GEN_DECLARATION( gint16 );
YGRAD_GEN_DECLARATION( gint16 );
XGRAD_GEN_DECLARATION( guint32 );
YGRAD_GEN_DECLARATION( guint32 );
XGRAD_GEN_DECLARATION( gint32 );
YGRAD_GEN_DECLARATION( gint32 );
#if 0
XGRAD_GEN_DECLARATION( float );
YGRAD_GEN_DECLARATION( float );
XGRAD_GEN_DECLARATION( double );
YGRAD_GEN_DECLARATION( double );
#endif


/** EXPORTED FUNCTION DEFINITIONS **/

int im_gradcor_raw( IMAGE *large, IMAGE *small, IMAGE *out ){
#define FUNCTION_NAME "im_gradcor_raw"

  if( im_piocheck( large, out ) || im_pincheck( small ) )
    return -1;

  if( ! vips_bandfmt_isint( large->BandFmt ) || 
	! vips_bandfmt_isint( small->BandFmt ) ){
    im_error( FUNCTION_NAME, "image does not have integer band format" );
    return -1;
  }
  if( large-> Coding || small-> Coding ){
    im_error( FUNCTION_NAME, "image is not uncoded" );
    return -1;
  }
  if( 1 != large-> Bands || 1 != small-> Bands ){
    im_error( FUNCTION_NAME, "image is multi-band" );
    return -1;
  }
  if( large-> Xsize < small-> Xsize || large-> Ysize < small-> Ysize ){
    im_error( FUNCTION_NAME, "second image must be smaller than first" );
    return -1;
  }
  if( im_cp_desc( out, large ) )
    return -1;

  out-> Xsize= 1 + large-> Xsize - small-> Xsize;
  out-> Ysize= 1 + large-> Ysize - small-> Ysize;
  out-> BandFmt= IM_BANDFMT_FLOAT;

  if( im_demand_hint( out, IM_FATSTRIP, large, NULL ) )
    return -1;

  {
    IMAGE *xgrad= im_open_local( out, FUNCTION_NAME ": xgrad", "t" );
    IMAGE *ygrad= im_open_local( out, FUNCTION_NAME ": ygrad", "t" );
    IMAGE **grads= im_allocate_input_array( out, xgrad, ygrad, NULL );

    return ! xgrad || ! ygrad || ! grads
      || im_grad_x( small, xgrad )
      || im_grad_y( small, ygrad )
      || im_generate( out, gradcor_start, gradcor_gen, gradcor_stop, (void*) large, (void*) grads );
  }
#undef FUNCTION_NAME
}

int 
im_gradcor( IMAGE *in, IMAGE *ref, IMAGE *out )
{
#define FUNCTION_NAME "im_gradcor"
	IMAGE *t1 = im_open_local( out, FUNCTION_NAME " intermediate", "p" );

	if( !t1 ||
		im_embed( in, t1, 1, 
			ref->Xsize / 2, ref->Ysize / 2, 
			in->Xsize + ref->Xsize - 1, 
			in->Ysize + ref->Ysize - 1 ) ||
		im_gradcor_raw( t1, ref, out ) ) 
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
#undef FUNCTION_NAME
}

int im_grad_x( IMAGE *in, IMAGE *out ){
#define FUNCTION_NAME "im_grad_x"

  if( im_piocheck( in, out ) )
    return -1;

  if( ! vips_bandfmt_isint( in->BandFmt ) ){
    im_error( FUNCTION_NAME, "image does not have integer band format" );
    return -1;
  }
  if( in-> Coding ){
    im_error( FUNCTION_NAME, "image is not uncoded" );
    return -1;
  }
  if( 1 != in-> Bands ){
    im_error( FUNCTION_NAME, "image is multi-band" );
    return -1;
  }
  if( im_cp_desc( out, in ) )
    return -1;

  -- out-> Xsize;
  out-> BandFmt= IM_BANDFMT_INT; /* do not change without updating im_gradcor() */

  if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
    return -1;

#define RETURN_GENERATE( TYPE ) return im_generate( out, im_start_one, xgrad_gen_ ## TYPE, im_stop_one, (void*) in, NULL )

  switch( in-> BandFmt ){

    case IM_BANDFMT_UCHAR:
      RETURN_GENERATE( guint8 );

    case IM_BANDFMT_CHAR:
      RETURN_GENERATE( gint8 );

    case IM_BANDFMT_USHORT:
      RETURN_GENERATE( guint16 );

    case IM_BANDFMT_SHORT:
      RETURN_GENERATE( gint16 );

    case IM_BANDFMT_UINT:
      RETURN_GENERATE( guint32 );

    case IM_BANDFMT_INT:
      RETURN_GENERATE( gint32 );
#if 0
    case IM_BANDFMT_FLOAT:
      RETURN_GENERATE( float );
    case IM_BANDFMT_DOUBLE:
      RETURN_GENERATE( double );
#endif
#undef RETURN_GENERATE
    default:
      g_assert( 0 );
  }

  /* Keep gcc happy.
   */
  return 0;
#undef FUNCTION_NAME
}

int im_grad_y( IMAGE *in, IMAGE *out ){
#define FUNCTION_NAME "im_grad_y"

  if( im_piocheck( in, out ) )
    return -1;

  if( ! vips_bandfmt_isint( in->BandFmt ) ){
    im_error( FUNCTION_NAME, "image does not have integer band format" );
    return -1;
  }
  if( in-> Coding ){
    im_error( FUNCTION_NAME, "image is not uncoded" );
    return -1;
  }
  if( 1 != in-> Bands ){
    im_error( FUNCTION_NAME, "image is multi-band" );
    return -1;
  }
  if( im_cp_desc( out, in ) )
    return -1;

  -- out-> Ysize;
  out-> BandFmt= IM_BANDFMT_INT; /* do not change without updating im_gradcor() */

  if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
    return -1;

#define RETURN_GENERATE( TYPE ) return im_generate( out, im_start_one, ygrad_gen_ ## TYPE, im_stop_one, (void*) in, NULL )

  switch( in-> BandFmt ){

    case IM_BANDFMT_UCHAR:
      RETURN_GENERATE( guint8 );

    case IM_BANDFMT_CHAR:
      RETURN_GENERATE( gint8 );

    case IM_BANDFMT_USHORT:
      RETURN_GENERATE( guint16 );

    case IM_BANDFMT_SHORT:
      RETURN_GENERATE( gint16 );

    case IM_BANDFMT_UINT:
      RETURN_GENERATE( guint32 );

    case IM_BANDFMT_INT:
      RETURN_GENERATE( gint32 );
#if 0
    case IM_BANDFMT_FLOAT:
      RETURN_GENERATE( float );
    case IM_BANDFMT_DOUBLE:
      RETURN_GENERATE( double );
#endif
#undef RETURN_GENERATE
    default:
      g_assert( 0 );
  }

  /* Keep gcc happy.
   */
  return 0;
#undef FUNCTION_NAME
}


/** LOCAL FUNCTION DEFINITIONS **/

static void *gradcor_start( IMAGE *out, void *vptr_large, void *unrequired ){

  gradcor_seq_t *seq= IM_NEW( NULL, gradcor_seq_t );
  if( ! seq )
    return NULL;

  seq-> region_xgrad= (int*) NULL;
  seq-> region_ygrad= (int*) NULL;
  seq-> region_xgrad_area= 0;
  seq-> region_ygrad_area= 0;

  seq-> reg= im_region_create( (IMAGE*) vptr_large );
  if( ! seq-> reg ){
    im_free( (void*) seq );
    return NULL;
  }
  return (void*) seq;
}

static int gradcor_stop( void *vptr_seq, void *unrequired, void *unreq2 ){

  gradcor_seq_t *seq= (gradcor_seq_t*) vptr_seq;
  if( seq ){
    im_free( (void*) seq-> region_xgrad );
    im_free( (void*) seq-> region_ygrad );
    im_region_free( seq-> reg );
    seq-> region_xgrad= (int*) NULL;
    seq-> region_ygrad= (int*) NULL;
    seq-> reg= (REGION*) NULL;
    im_free( (void*) seq );
  }
  return 0;
}

static int gradcor_gen( REGION *to_make, void *vptr_seq, void *unrequired, void *vptr_grads ){

  gradcor_seq_t *seq= (gradcor_seq_t*) vptr_seq;
  REGION *make_from= seq-> reg;

  IMAGE **grads= (IMAGE**) vptr_grads;
  IMAGE *small_xgrad= grads[0];
  IMAGE *small_ygrad= grads[1];

  Rect require= {
    to_make-> valid. left,
    to_make-> valid. top,
    to_make-> valid. width + small_xgrad-> Xsize,
    to_make-> valid. height + small_ygrad-> Ysize
  };
  size_t region_xgrad_width= require. width - 1;
  size_t region_ygrad_height= require. height - 1;

  if( im_prepare( make_from, &require ) )
    return -1;

#define FILL_BUFFERS( TYPE )        /* fill region_xgrad */                                         \
  {                                                                                                 \
    TYPE *reading= (TYPE*) IM_REGION_ADDR( make_from, require. left, require. top );                \
    size_t read_skip= ( IM_REGION_LSKIP( make_from ) / sizeof(TYPE) ) - region_xgrad_width;         \
    size_t area_need= region_xgrad_width * require. height;                                         \
                                                                                                    \
    if( seq-> region_xgrad_area < area_need ){                                                      \
      free( seq-> region_xgrad );                                                                   \
      seq-> region_xgrad= malloc( area_need * sizeof(int) );                                        \
      if( ! seq-> region_xgrad )                                                                    \
        return -1;                                                                                  \
      seq-> region_xgrad_area= area_need;                                                           \
    }                                                                                               \
    {                                                                                               \
      int *writing= seq-> region_xgrad;                                                             \
      int *write_end= writing + area_need;                                                          \
      int *write_stop;                                                                              \
      for( ; writing < write_end; reading+= read_skip )                                             \
        for( write_stop= writing + region_xgrad_width; writing < write_stop; ++reading, ++writing ) \
          *writing= reading[1] - reading[0];                                                        \
    }                                                                                               \
  }                                                                                                 \
  {     /* fill region_ygrad */                                                                     \
    TYPE *reading= (TYPE*) IM_REGION_ADDR( make_from, require. left, require. top );                \
    size_t read_line= IM_REGION_LSKIP( make_from ) / sizeof(TYPE);                                  \
    size_t read_skip= read_line - require. width;                                                   \
    size_t area_need= require. width * region_ygrad_height;                                         \
                                                                                                    \
    if( seq-> region_ygrad_area < area_need ){                                                      \
      free( seq-> region_ygrad );                                                                   \
      seq-> region_ygrad= malloc( area_need * sizeof(int) );                                        \
      if( ! seq-> region_ygrad )                                                                    \
        return -1;                                                                                  \
      seq-> region_ygrad_area= area_need;                                                           \
    }                                                                                               \
    {                                                                                               \
      int *writing= seq-> region_ygrad;                                                             \
      int *write_end= writing + area_need;                                                          \
      int *write_stop;                                                                              \
      for( ; writing < write_end; reading+= read_skip )                                             \
        for( write_stop= writing + require. width; writing < write_stop; ++reading, ++writing )     \
          *writing= reading[ read_line ] - reading[0];                                              \
    }                                                                                               \
  }
  switch( make_from-> im-> BandFmt ){
    case IM_BANDFMT_UCHAR:
      FILL_BUFFERS( unsigned char )
      break;
    case IM_BANDFMT_CHAR:
      FILL_BUFFERS( signed char )
      break;
    case IM_BANDFMT_USHORT:
      FILL_BUFFERS( unsigned short int )
      break;
    case IM_BANDFMT_SHORT:
      FILL_BUFFERS( signed short int )
      break;
    case IM_BANDFMT_UINT:
      FILL_BUFFERS( unsigned int )
      break;
    case IM_BANDFMT_INT:
      FILL_BUFFERS( signed int )
      break;
    default:
      g_assert( 0 );
  }
  { /* write to output */
    size_t write_skip= IM_REGION_LSKIP( to_make ) / sizeof( float );
    float *writing= (float*) IM_REGION_ADDR_TOPLEFT( to_make );
    float *write_end= writing + write_skip * to_make-> valid. height;
    float *write_stop;
    size_t write_width= to_make-> valid. width;

    size_t small_xgrad_width= small_xgrad-> Xsize;
    size_t small_ygrad_width= small_ygrad-> Xsize;
    int *small_xgrad_end= (int*) small_xgrad-> data + small_xgrad_width * small_xgrad-> Ysize;
    int *small_ygrad_end= (int*) small_ygrad-> data + small_ygrad_width * small_ygrad-> Ysize;

    int *region_xgrad_start= seq-> region_xgrad;
    int *region_ygrad_start= seq-> region_ygrad;
    size_t region_xgrad_start_skip= region_xgrad_width - write_width;
    size_t region_ygrad_start_skip= require. width - write_width;

    size_t region_xgrad_read_skip= region_xgrad_width - small_xgrad_width;
    size_t region_ygrad_read_skip= require. width - small_ygrad_width;

    write_skip-= write_width;

    for( ; writing < write_end; writing+= write_skip, region_xgrad_start+= region_xgrad_start_skip, region_ygrad_start+= region_ygrad_start_skip )
      for( write_stop= writing + write_width; writing < write_stop; ++writing, ++region_xgrad_start, ++region_ygrad_start ){
        gint64 sum= 0;
        {
          int *small_xgrad_read= (int*) small_xgrad-> data;
          int *small_xgrad_stop;
          int *region_xgrad_read= region_xgrad_start;

          for( ; small_xgrad_read < small_xgrad_end; region_xgrad_read+= region_xgrad_read_skip )
            for( small_xgrad_stop= small_xgrad_read + small_xgrad_width; small_xgrad_read < small_xgrad_stop; ++small_xgrad_read, ++region_xgrad_read )
              sum+= *small_xgrad_read * *region_xgrad_read;
        }
        {
          int *small_ygrad_read= (int*) small_ygrad-> data;
          int *small_ygrad_stop;
          int *region_ygrad_read= region_ygrad_start;

          for( ; small_ygrad_read < small_ygrad_end; region_ygrad_read+= region_ygrad_read_skip )
            for( small_ygrad_stop= small_ygrad_read + small_ygrad_width; small_ygrad_read < small_ygrad_stop; ++small_ygrad_read, ++region_ygrad_read )
              sum+= *small_ygrad_read * *region_ygrad_read;
        }
        *writing= sum;
      }
  }
  return 0;
}

#define XGRAD_GEN_DEFINITION( TYPE ) \
static int xgrad_gen_ ## TYPE( REGION *to_make, void *vptr_make_from, void *unrequired, void *unreq2 ){   \
                                                                                                          \
  REGION *make_from= (REGION*) vptr_make_from;                                                            \
  Rect require= {                                                                                         \
    to_make-> valid. left,                                                                                \
    to_make-> valid. top,                                                                                 \
    to_make-> valid. width + 1,                                                                           \
    to_make-> valid. height                                                                               \
  };                                                                                                      \
  if( im_prepare( make_from, &require ) )                                                                 \
    return -1;                                                                                            \
                                                                                                          \
  {                                                                                                       \
    int *writing= (int*) IM_REGION_ADDR_TOPLEFT( to_make );                                               \
    size_t write_skip= IM_REGION_LSKIP( to_make ) / sizeof(int);                                          \
    int *write_end= writing + write_skip * to_make-> valid. height;                                       \
    size_t write_width= to_make-> valid. width;                                                           \
    int *write_stop;                                                                                      \
                                                                                                          \
    TYPE *reading= (TYPE*) IM_REGION_ADDR( make_from, require. left, require. top );                      \
    size_t read_skip= ( IM_REGION_LSKIP( make_from ) / sizeof(TYPE) ) - write_width;                      \
                                                                                                          \
    write_skip-= write_width;                                                                             \
                                                                                                          \
    for( ; writing < write_end; writing+= write_skip, reading+= read_skip )                               \
      for( write_stop= writing + write_width; writing < write_stop; ++writing, ++reading )                \
        *writing= (int)( reading[1] - reading[0] );                                                       \
  }                                                                                                       \
  return 0;                                                                                               \
}

#define YGRAD_GEN_DEFINITION( TYPE ) \
static int ygrad_gen_ ## TYPE( REGION *to_make, void *vptr_make_from, void *unrequired, void *unreq2 ){   \
                                                                                                          \
  REGION *make_from= (REGION*) vptr_make_from;                                                            \
  Rect require= {                                                                                         \
    to_make-> valid. left,                                                                                \
    to_make-> valid. top,                                                                                 \
    to_make-> valid. width,                                                                               \
    to_make-> valid. height + 1                                                                           \
  };                                                                                                      \
  if( im_prepare( make_from, &require ) )                                                                 \
    return -1;                                                                                            \
                                                                                                          \
  {                                                                                                       \
    int *writing= (int*) IM_REGION_ADDR_TOPLEFT( to_make );                                               \
    size_t write_skip= IM_REGION_LSKIP( to_make ) / sizeof(int);                                          \
    int *write_end= writing + write_skip * to_make-> valid. height;                                       \
    size_t write_width= to_make-> valid. width;                                                           \
    int *write_stop;                                                                                      \
                                                                                                          \
    TYPE *reading= (TYPE*) IM_REGION_ADDR( make_from, require. left, require. top );                      \
    size_t read_line= IM_REGION_LSKIP( make_from ) / sizeof(TYPE);                                        \
    size_t read_skip= read_line - write_width;                                                            \
                                                                                                          \
    write_skip-= write_width;                                                                             \
                                                                                                          \
    for( ; writing < write_end; writing+= write_skip, reading+= read_skip )                               \
      for( write_stop= writing + write_width; writing < write_stop; ++writing, ++reading )                \
        *writing= (int)( reading[ read_line ] - reading[0] );                                             \
  }                                                                                                       \
  return 0;                                                                                               \
}

XGRAD_GEN_DEFINITION( guint8 )
YGRAD_GEN_DEFINITION( guint8 )
XGRAD_GEN_DEFINITION( gint8 )
YGRAD_GEN_DEFINITION( gint8 )
XGRAD_GEN_DEFINITION( guint16 )
YGRAD_GEN_DEFINITION( guint16 )
XGRAD_GEN_DEFINITION( gint16 )
YGRAD_GEN_DEFINITION( gint16 )
XGRAD_GEN_DEFINITION( guint32 )
YGRAD_GEN_DEFINITION( guint32 )
XGRAD_GEN_DEFINITION( gint32 )
YGRAD_GEN_DEFINITION( gint32 )
#if 0
XGRAD_GEN_DEFINITION( float )
YGRAD_GEN_DEFINITION( float )
XGRAD_GEN_DEFINITION( double )
YGRAD_GEN_DEFINITION( double )
#endif
