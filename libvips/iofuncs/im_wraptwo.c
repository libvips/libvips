/* As im_wrapmany, but just allow one input and one output.
 *
 * The types become:
 *
 * 	int im_wrapone( IMAGE *in, IMAGE *out, 
 *		im_wrapone_fn fn, void *a, void *b )
 *
 * where im_wrapone_fn has type:
 *
 *	process_buffer( void *in, void *out, int n,
 *		void *a, void *b )
 * 28/7/97 JC
 *	- amazing error ... failed if or and ir were different sizes
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

typedef struct {
	im_wraptwo_fn fn;	/* Function we call */ 
	void *a, *b;		/* User values for function */
} UserBundle;

/* Build or->valid a line at a time from ir.
 */
static int
process_region( REGION *or, void *seq, void *unrequired, void *b )
{
  if( im_prepare_many( (REGION**)seq, & or-> valid ))
    return -1;
  {
    void *out= IM_REGION_ADDR_TOPLEFT( or );
    void *in1= IM_REGION_ADDR( ((REGION**)seq)[0], or-> valid. left, or-> valid. top );
    void *in2= IM_REGION_ADDR( ((REGION**)seq)[1], or-> valid. left, or-> valid. top );
    size_t out_skip= IM_REGION_LSKIP( or );
    size_t in1_skip= IM_REGION_LSKIP( ((REGION**)seq)[0] );
    size_t in2_skip= IM_REGION_LSKIP( ((REGION**)seq)[1] );
    void *out_stop= out + out_skip * or-> valid. height;

    for( ; out < out_stop; out+= out_skip, in1+= in1_skip, in2+= in2_skip )
      ((UserBundle*) b)-> fn( in1, in2, out, or-> valid. width, ((UserBundle*) b)-> a, ((UserBundle*) b)-> b );
  
    return 0;
  }
}

/* Wrap up as a partial.
 */
int
im_wraptwo( IMAGE *in1, IMAGE *in2, IMAGE *out, im_wraptwo_fn fn, void *a, void *b )
{
  if( im_pincheck( in1 ) || im_pincheck( in2 ) || im_poutcheck( out ))
    return -1;
  {
    UserBundle *bun= IM_NEW( out, UserBundle );
    IMAGE **ins= im_allocate_input_array( out, in1, in2, NULL );

    if( ! bun || ! ins )
      return -1;

    bun-> fn= fn;
    bun-> a= a;
    bun-> b= b;

    return im_demand_hint( out, IM_THINSTRIP, in1, in2, NULL )
      || im_generate( out, im_start_many, process_region, im_stop_many, (void*) ins, (void*) bun );
  }
}
