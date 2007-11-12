/* @(#) Functions which calculates the correlation coefficient between two 
 * @(#) images. 
 * @(#) 
 * @(#) int im_spcor( IMAGE *in, IMAGE *ref, IMAGE *out )
 * @(#) 
 * @(#) We calculate:
 * @(#) 
 * @(#) 	 sumij (ref(i,j)-mean(ref))(inkl(i,j)-mean(inkl))
 * @(#) c(k,l) = ------------------------------------------------
 * @(#) 	 sqrt(sumij (ref(i,j)-mean(ref))^2) *
 * @(#) 		       sqrt(sumij (inkl(i,j)-mean(inkl))^2)
 * @(#) 
 * @(#) where inkl is the area of in centred at position (k,l).
 * @(#) 
 * @(#) Writes float to out. in and ref must be 1 band uchar, or 1 band
 * @(#) ushort.
 * @(#)
 * @(#) Returns 0 on sucess  and -1 on error.
 *
 * Copyright: 1990, N. Dessipris; 2006, 2007 Nottingham Trent University.
 *
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 
 * 20/2/95 JC
 *	- updated
 *	- ANSIfied, a little
 * 21/2/95 JC
 *	- rewritten
 *	- partialed 
 *	- speed-ups
 *	- new correlation coefficient (see above), from Niblack "An
 *	  Introduction to Digital Image Processing,", Prentice/Hall, pp 138.
 * 4/9/97 JC
 *	- now does short/ushort as well
 * 13/2/03 JC
 *	- oops, could segv for short images
 * 14/4/04 JC
 *	- sets Xoffset / Yoffset
 * 8/3/06 JC
 *	- use im_embed() with edge stretching on the input, not the output
 *
 * 2006-10-24 tcv
 *      - add im_spcor2
 *
 * 2007-11-12 tcv
 *      - make im_spcor a wrapper selecting either im__spcor1 or im__spcor2
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
#include <string.h>
#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Hold global stuff here.
 */
typedef struct {
	IMAGE *ref;		/* Image we are searching for */
	double rmean;		/* Mean of search window */
	double c1;		/* sqrt(sumij (ref(i,j)-mean(ref))^2) */
} SpcorInfo;

typedef struct {
  
  REGION *f;
  int *f_cols;
  size_t max_cols;

} spcor2_seq;

typedef struct {
  
  IMAGE *w;
  gint64 area;
  double recip_area;
  double mean;
  double n_var;

} spcor2_w_inf;

static void *spcor2_start( IMAGE *r, void *a, void *b );
static int spcor2_gen( REGION *r, void *seq, void *a, void *b );
static int spcor2_stop( void *seq, void *a, void *b );

/* spcor1 generate function.
 */
static int
spcor1_gen( REGION *or, void *seq, void *a, void *b )
{
#define LOOP(IN) \
{ \
	IN *a = (IN *) p; \
	IN *b = (IN *) ref->data; \
	int in_lsk = lsk / sizeof( IN ); \
	IN *a1, *b1; \
 	\
	/* For each pel in or, loop over ref. First, \
	 * calculate mean of area in ir corresponding to ref. \
	 */ \
	for( a1 = a, sum1 = 0, j = 0; j < ref->Ysize; j++, a1 += in_lsk )  \
		for( i = 0; i < ref->Xsize; i++ ) \
			sum1 += a1[i]; \
	imean = (double) sum1 / (ref->Xsize * ref->Ysize); \
 	\
	/* Loop over ir again, this time calculating  \
	 * sum-of-squares-of-differences for this window on \
	 * ir, and also sum-of-products-of-differences. \
	 */ \
	for( a1 = a, b1 = b, sum2 = 0.0, sum3 = 0.0, j = 0; \
		j < ref->Ysize; j++, a1 += in_lsk, b1 += ref->Xsize ) { \
		for( i = 0; i < ref->Xsize; i++ ) { \
			/* Reference pel, and input pel. \
			 */ \
			IN rp = b1[i]; \
			IN ip = a1[i]; \
			\
			/* Accumulate sum-of-squares-of- \
			 * differences for input image. \
			 */ \
			double t = ip - imean; \
			sum2 += t * t; \
			\
			/* Accumulate product-of-differences. \
			 */ \
			sum3 += (rp - inf->rmean) * (ip - imean); \
		} \
	} \
}
	REGION *ir = (REGION *) seq;
	SpcorInfo *inf = (SpcorInfo *) b;
	IMAGE *ref = inf->ref;
	Rect irect;
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int ri = IM_RECT_RIGHT(r);

	int x, y, i, j;
	int lsk;

	double imean;
	double sum1;
	double sum2, sum3;
	double c2, cc;

	/* What part of ir do we need?
	 */
	irect.left = or->valid.left;
	irect.top = or->valid.top;
	irect.width = or->valid.width + ref->Xsize - 1;
	irect.height = or->valid.height + ref->Ysize - 1;

	if( im_prepare( ir, &irect ) )
		return( -1 );
	lsk = IM_REGION_LSKIP( ir );

	/* Loop over or.
	 */
	for( y = to; y < bo; y++ ) {
		float *q = (float *) IM_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			PEL *p = (PEL *) IM_REGION_ADDR( ir, x, y );

			/* Find sums for this position.
			 */
			switch( ref->BandFmt ) {
			case IM_BANDFMT_UCHAR:	LOOP(unsigned char); break;
			case IM_BANDFMT_USHORT: LOOP(unsigned short); break;
			case IM_BANDFMT_SHORT:	LOOP(signed short); break;
			default:
				error_exit( "im_spcor1: internal error #7934" );

				/* Keep gcc -Wall happy.
				 */
				return( -1 );
			}

			/* Now: calculate correlation coefficient!
			 */
			c2 = sqrt( sum2 );
			cc = sum3 / (inf->c1 * c2);

			*q++ = cc;
		}
	}

	return( 0 );
#undef LOOP
}

/* Pre-calculate stuff for our reference image.
 */
static SpcorInfo *
make_inf( IMAGE *out, IMAGE *ref )
{
	SpcorInfo *inf = IM_NEW( out, SpcorInfo );
	int sz = ref->Xsize * ref->Ysize;
	PEL *p = (PEL *) ref->data;
	double s;
	int i;

	if( !inf )
		return( NULL );

	/* Pre-calculate stuff on our reference image.
	 */
	inf->ref = ref;
	if( im_avg( inf->ref, &inf->rmean ) )
		return( NULL );
	
	/* Find sqrt-of-sum-of-squares-of-differences.
	 */
	for( s = 0.0, i = 0; i < sz; i++ ) {
		double t = (int) p[i] - inf->rmean;
		s += t * t;
	}
	inf->c1 = sqrt( s );

	return( inf );
}

static int 
im__spcor1_raw( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	SpcorInfo *inf;

	/* PIO between in and out; WIO from ref.
	 */
	if( im_piocheck( in, out ) || im_incheck( ref ) )
		return( -1 );

	/* Check sizes.
	 */
	if( in->Xsize < ref->Xsize || in->Ysize < ref->Ysize ) {
		im_errormsg( "im_spcor1_raw: ref not smaller than in" );
		return( -1 );
	}

	/* Check types.
	 */
	if( in->Coding != IM_CODING_NONE || in->Bands != 1 ||
		ref->Coding != IM_CODING_NONE || ref->Bands != 1 ||
		in->BandFmt != ref->BandFmt ) {
		im_errormsg( "im_spcor1_raw: input not uncoded 1 band" );
		return( -1 );
	}
	if( in->BandFmt != IM_BANDFMT_UCHAR && 
		in->BandFmt != IM_BANDFMT_SHORT &&
		in->BandFmt != IM_BANDFMT_USHORT ) {
		im_errormsg( "im_spcor1_raw: input not char/short/ushort" );
		return( -1 );
	}

	/* Prepare the output image. 
	 */
	if( im_cp_descv( out, in, ref, NULL ) )
		return( -1 );
	out->Bbits = IM_BBITS_FLOAT;
	out->BandFmt = IM_BANDFMT_FLOAT;
	out->Xsize = in->Xsize - ref->Xsize + 1;
	out->Ysize = in->Ysize - ref->Ysize + 1;

	/* Pre-calculate some stuff.
	 */
	if( !(inf = make_inf( out, ref )) )
		return( -1 );

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
		return( -1 );

	/* Write the correlation.
	 */
	if( im_generate( out,
		im_start_one, spcor1_gen, im_stop_one, in, inf ) )
		return( -1 );

	out->Xoffset = -ref->Xsize / 2;
	out->Yoffset = -ref->Ysize / 2;

	return( 0 );
}

/* The above, with the input expanded to make out the same size as in.
 */
static int
im__spcor1( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	IMAGE *t1 = im_open_local( out, "im_spcor1 intermediate", "p" );

	if( !t1 ||
		im_embed( in, t1, 1, 
			ref->Xsize / 2, ref->Ysize / 2, 
			in->Xsize + ref->Xsize - 1, 
			in->Ysize + ref->Ysize - 1 ) ||
		im__spcor1_raw( t1, ref, out ) ) 
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}

static int
im__spcor2_raw( 
    IMAGE *f, 
    IMAGE *w, 
    IMAGE *r 
){
#define FUNCTION_NAME "im_spcor2_raw"

  DOUBLEMASK *w_stats;
  spcor2_w_inf *w_inf;

  if( im_piocheck( f, r ) || im_incheck( w ) )
    return -1;

  if( f-> Xsize < w-> Xsize || f-> Ysize < w-> Ysize ){
    im_error( FUNCTION_NAME, "window must be smaller than search area" );
    return -1;
  }
  if( f-> Coding || w-> Coding ){
    im_error( FUNCTION_NAME, "uncoded images only" );
    return -1;
  }
  if( 1 != f-> Bands || 1 != w-> Bands ){
    im_error( FUNCTION_NAME, "single band images only" );
    return -1;
  }
  if( !(  IM_BANDFMT_UCHAR == f-> BandFmt 
      ||   IM_BANDFMT_CHAR == f-> BandFmt 
      || IM_BANDFMT_USHORT == f-> BandFmt 
      ||  IM_BANDFMT_SHORT == f-> BandFmt ) ){
    im_error( FUNCTION_NAME, "short or char images only" );
    return -1;
  }
  if( f-> BandFmt != w-> BandFmt ){
    im_error( FUNCTION_NAME, "band formats must match" );
    return -1;
  }
  if( im_cp_descv( r, f, w, NULL ) )
    return -1;

  r-> Xsize-= ( w-> Xsize - 1 );
  r-> Ysize-= ( w-> Ysize - 1 );
  r-> BandFmt= IM_BANDFMT_FLOAT;
  r-> Bbits= IM_BBITS_FLOAT;
  r-> Xoffset= - w-> Xsize / 2;
  r-> Yoffset= - w-> Ysize / 2;

  if( im_demand_hint( r, IM_FATSTRIP, f, NULL ) )
    return -1;

  w_inf= IM_NEW( r, spcor2_w_inf );
  w_stats= im_stats( w );

  if( ! w_inf || ! w_stats )
    return -1;

  w_inf-> w= w;
  w_inf-> area= w-> Xsize * w-> Ysize;
  w_inf-> recip_area= 1.0 / (double) w_inf-> area;
  w_inf-> mean= w_stats-> coeff[ 4 ];
  w_inf-> n_var= w_stats-> coeff[ 3 ] - w_stats-> coeff[ 2 ] * w_stats-> coeff[ 2 ] * w_inf-> recip_area;

  im_free_dmask( w_stats );

  return im_generate( r, spcor2_start, spcor2_gen, spcor2_stop, f, w_inf );

#undef FUNCTION_NAME
}

static void *
spcor2_start( IMAGE *r, void *a, void *b ){

  IMAGE *f= (IMAGE *) a;
  spcor2_seq *seq;

  seq= IM_NEW( r, spcor2_seq );
  if( ! seq )
    return NULL;
    
  seq-> f= im_region_create( f );
  seq-> f_cols= NULL;
  seq-> max_cols= 0;

  if( ! seq-> f )
    return NULL;

  return seq;
}

static int 
spcor2_gen( 
    REGION *r, 
    void *vseq, void *a, void *b
){

  spcor2_seq *seq= (spcor2_seq *) vseq; 
  spcor2_w_inf *w_inf= (spcor2_w_inf *) b;
  Rect need= { 
    r-> valid. left, 
    r-> valid. top, 
    r-> valid. width + w_inf-> w-> Xsize - 1, 
    r-> valid. height + w_inf-> w-> Ysize - 1
  };
  int j;
  float *r_data= (float*) IM_REGION_ADDR( r, r-> valid. left, r-> valid. top );
  size_t r_skip= IM_REGION_LSKIP( r ) / sizeof( float ); 
  float *r_end= r_data + r-> valid. height * r_skip;

  r_skip-= r-> valid. width;

  if( im_prepare( seq-> f, & need ) )
    return -1;

  if( need. width > seq-> max_cols ){
    im_free( seq-> f_cols );
    
    seq-> f_cols= IM_ARRAY( NULL, need. width + 1, int );  /* one spare for the last right move */
    if( ! seq-> f_cols )
      return -1;

    seq-> max_cols= need. width;
  }
  memset( seq-> f_cols, 0, seq-> max_cols * sizeof( int ) );

#define LOOPS(TYPE) {                                                                                   \
    TYPE *f_start= (TYPE*) IM_REGION_ADDR( seq-> f, need. left, need. top );                            \
    size_t f_skip= IM_REGION_LSKIP( seq-> f ) / sizeof( TYPE );                                         \
    size_t f_row_skip= f_skip - r-> valid. width;                                                       \
    size_t f_win_skip= f_skip - w_inf-> w-> Xsize;                                                      \
                                                                                                        \
    TYPE *f_win_end= f_start;                                                                           \
    TYPE *f_stop= f_win_end + f_skip * w_inf-> w-> Ysize;                                               \
                                                                                                        \
    for( ; f_win_end < f_stop; f_win_end+= f_skip )                                                     \
      for( j= 0; j < need. width; ++j )                                                                 \
        seq-> f_cols[ j ]+= f_win_end[ j ];                                                             \
                                                                                                        \
    for( ; r_data < r_end; r_data+= r_skip, f_start+= f_row_skip, f_win_end+= f_skip ){                 \
      double f_mean= 0.0;                                                                               \
                                                                                                        \
      for( j= 0; j < w_inf-> w-> Xsize; ++j )                                                           \
        f_mean+= seq-> f_cols[ j ];                                                                     \
                                                                                                        \
      f_mean*= w_inf-> recip_area;                                                                      \
                                                                                                        \
      for( j= 0; j < r-> valid. width; ++f_start, ++r_data,                                             \
          f_mean+= ( seq-> f_cols[ w_inf-> w-> Xsize + j ] - seq-> f_cols[ j ] ) * w_inf-> recip_area,  \
          ++j ){                                                                                        \
                                                                                                        \
        double num_sum= 0.0;                                                                            \
        double den_sum= 0.0;                                                                            \
        TYPE *w_data= (TYPE*) w_inf-> w-> data;                                                         \
        TYPE *w_end= w_data + w_inf-> area;                                                             \
        TYPE *w_stop;                                                                                   \
        TYPE *f_data= f_start;                                                                          \
                                                                                                        \
        for( ; w_data < w_end; f_data+= f_win_skip )                                                    \
          for( w_stop= w_data + w_inf-> w-> Xsize; w_data < w_stop; ++w_data, ++f_data ){               \
                                                                                                        \
            double f_term= *f_data - f_mean;                                                            \
                                                                                                        \
            num_sum+= f_term * ( *w_data - w_inf-> mean );                                              \
            den_sum+= f_term * f_term;                                                                  \
          }                                                                                             \
                                                                                                        \
        *r_data= num_sum * pow( den_sum * w_inf-> n_var, -0.5 );                                        \
      }                                                                                                 \
                                                                                                        \
      if( r_data + r_skip < r_end )                                                                     \
        for( j= 0; j < need. width; ++j )                                                               \
          seq-> f_cols[ j ]+= f_win_end[ j ] - f_start[ j ];                                            \
    }                                                                                                   \
  }

  switch( w_inf-> w-> BandFmt ){
    case IM_BANDFMT_UCHAR: LOOPS( guint8 ) break;
    case IM_BANDFMT_CHAR: LOOPS( gint8 ) break;
    case IM_BANDFMT_USHORT: LOOPS( guint16 ) break;
    case IM_BANDFMT_SHORT: LOOPS( gint16 ) break;
  }

#undef LOOPS
  return 0;
}

static int 
spcor2_stop( void *vseq, void *a, void *b ){

  spcor2_seq *seq= (spcor2_seq *) vseq;

  IM_FREEF( im_region_free, seq-> f );
  IM_FREE( seq-> f_cols );

  return 0;
}

static int 
im__spcor2( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	IMAGE *t1 = im_open_local( out, "im_spcor2 intermediate", "p" );

	if( !t1 ||
		im_embed( in, t1, 1, 
			ref->Xsize / 2, ref->Ysize / 2, 
			in->Xsize + ref->Xsize - 1, 
			in->Ysize + ref->Ysize - 1 ) ||
		im__spcor2_raw( t1, ref, out ) ) 
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}

int
im_spcor_raw( 
    IMAGE *f, 
    IMAGE *w, 
    IMAGE *r 
){
  if( im_incheck( w ))
    return -1;

  if( 3 <= w-> Xsize || 3 <= w-> Ysize )
    return im__spcor2( f, w, r );

  else
    return im__spcor1( f, w, r );
}

int
im_spcor( 
    IMAGE *f, 
    IMAGE *w, 
    IMAGE *r 
){
  if( im_incheck( w ))
    return -1;

  if( 3 <= w-> Xsize || 3 <= w-> Ysize )
    return im__spcor2( f, w, r );

  else
    return im__spcor1( f, w, r );
}
