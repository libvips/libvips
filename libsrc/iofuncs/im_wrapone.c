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

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

typedef struct {
	im_wrapone_fn fn;	/* Function we call */ 
	void *a, *b;		/* User values for function */
} UserBundle;

/* Build or->valid a line at a time from ir.
 */
static int
process_region( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	UserBundle *bun = (UserBundle *) b;

	PEL *p, *q;
	int y;

	/* Prepare input region and make buffer pointers.
	 */
	if( im_prepare( ir, &or->valid ) ) 
		return( -1 );
	p = (PEL *) IM_REGION_ADDR( ir, or->valid.left, or->valid.top );
	q = (PEL *) IM_REGION_ADDR( or, or->valid.left, or->valid.top );

	/* Convert linewise.
	 */
	for( y = 0; y < or->valid.height; y++ ) {
		bun->fn( p, q, or->valid.width, bun->a, bun->b );
		p += IM_REGION_LSKIP( ir );
		q += IM_REGION_LSKIP( or );
	}

	return( 0 );
}

/* Wrap up as a partial.
 */
int
im_wrapone( IMAGE *in, IMAGE *out, im_wrapone_fn fn, void *a, void *b )
{
	UserBundle *bun = IM_NEW( out, UserBundle );

	/* Save args.
	 */
	if( !bun )
		return( -1 );
	bun->fn = fn;
	bun->a = a;
	bun->b = b;

	/* Check descriptors.
	 */
	if( im_piocheck( in, out ) )
		return( -1 );

	/* Hint demand style. Being a buffer processor, we are happiest with
	 * thin strips.
	 */
        if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
                return( -1 );

	/* Generate!
	 */
	if( im_generate( out,
		im_start_one, process_region, im_stop_one,
		in, bun ) )
		return( -1 );

	return( 0 );
}
