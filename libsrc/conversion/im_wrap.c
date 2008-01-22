/* Wrap an image so that what was the origin is at (x,y).
 *
 * int im_wrap( IMAGE *in, IMAGE *out, int x, int y );
 *
 * All functions return 0 on success and -1 on error
 *
 * Copyright: 2008, Nottingham Trent University
 * Author: Tom Vajzovic
 * Written on: 2008-01-15
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

static int wrap( REGION *out, void *seq, void *a, void *b ){
#define IM ((IMAGE*)a)
#define X (((int*)b)[0])
#define Y (((int*)b)[1])
  int left= out-> valid. left - X;
  int top= out-> valid. top - Y;
  int right= left + out-> valid. width;
  int bot= top + out-> valid. height;
  Rect source_a= {
    left: IM-> Xsize + left,
    top: IM-> Ysize + top,
    width: 0 < right ? -left : out-> valid. width,
    height: 0 < bot ? -top : out-> valid. height
  };
  Rect source_b= {
    left: source_a. left,
    top: 0 > top ? 0 : top,
    width: source_a. width,
    height: 0 > top ? bot : out-> valid. height
  };
  Rect source_c= {
    left: 0 > left ? 0 : left,
    top: source_a. top,
    width: 0 > left ? right : out-> valid. width,
    height: source_a. height
  };
  Rect source_d= {
    left: source_c. left,
    top: source_b. top,
    width: source_c. width,
    height: source_b. height
  };
  if( 0 > left ){
    if( 0 > top && im_prepare_to( (REGION*)seq, out, & source_a, 
          out-> valid. left, out-> valid. top ))
      return -1;
    
    if( 0 < bot && im_prepare_to( (REGION*)seq, out, & source_b, 
          out-> valid. left, 0 > top ? Y : out-> valid. top ))
      return -1;
  }
  if( 0 < right ){
    if( 0 > top && im_prepare_to( (REGION*)seq, out, & source_c, 
          0 > left ? X : out-> valid. left, out-> valid. top ))
      return -1;
    
    if( 0 < bot && im_prepare_to( (REGION*)seq, out, & source_d, 
          0 > left ? X : out-> valid. left, 0 > top ? Y : out-> valid. top ))
      return -1;    
  }
  return 0;
#undef IM
#undef X
#undef Y 
}

int im_wrap( IMAGE *in, IMAGE *out, int x, int y ){
  if( im_piocheck( in, out ))
    return -1;
  {
    int *params= IM_ARRAY( out, 2, int );
    if( ! params )
      return -1;

    params[ 0 ]= x % in-> Xsize;
    params[ 1 ]= y % in-> Ysize;
    if( 0 > x )
      params[ 0 ]+= in-> Xsize;
    if( 0 > y )
      params[ 1 ]+= in-> Ysize;
    
    return im_cp_desc( out, in )
      || im_demand_hint( out, IM_THINSTRIP, in, NULL )
      || im_generate( out, im_start_one, wrap, im_stop_one, (void*)in, (void*)params );
  }
}
