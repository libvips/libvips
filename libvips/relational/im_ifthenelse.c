/* im_ifthenelse.c --- use a condition image to join two images together
 *
 * Modified:
 * 9/2/95 JC
 *	- partialed and ANSIfied
 * 11/9/95 JC
 *	- return( 0 ) missing! oops
 * 15/4/05
 *	- now just evals left/right if all zero/all one
 * 7/10/06
 * 	- set THINSTRIP
 * 23/9/09
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

static int
ifthenelse_gen( REGION *or, void *seq, void *client1, void *client2 )
{
	REGION **ir = (REGION **) seq;
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);

	IMAGE *c = ir[0]->im;
	IMAGE *a = ir[1]->im;

	int size, width;
	int i, x, y, z;

	int all0, alln0;

	if( c->Bands == 1 ) {
		/* Copying PEL-sized units with a one-band conditional.
		 */
		size = IM_IMAGE_SIZEOF_PEL( a );
		width = r->width;
	}
	else {
		/* Copying ELEMENT sized-units with an n-band conditional.
		 */
		size = IM_IMAGE_SIZEOF_ELEMENT( a );
		width = r->width * a->Bands;
	}

	if( im_prepare( ir[0], r ) )
		return( -1 );

	/* Is the conditional all zero or all non-zero? We can avoid asking
	 * for one of the inputs to be calculated.
	 */
	all0 = *((PEL *) IM_REGION_ADDR( ir[0], le, to )) == 0;
	alln0 = *((PEL *) IM_REGION_ADDR( ir[0], le, to )) != 0;
	for( y = to; y < bo; y++ ) {
		PEL *p = (PEL *) IM_REGION_ADDR( ir[0], le, y );

		for( x = 0; x < width; x++ ) {
			all0 &= p[x] == 0;
			alln0 &= p[x] != 0;
		}

		if( !all0 && !alln0 )
			break;
	}

	if( alln0 ) {
		/* All non-zero. Point or at the then image.
		 */
		if( im_prepare( ir[1], r ) ||
			im_region_region( or, ir[1], r, r->left, r->top ) )
			return( -1 );
	}
	else if( all0 ) {
		/* All zero. Point or at the else image.
		 */
		if( im_prepare( ir[2], r ) ||
			im_region_region( or, ir[2], r, r->left, r->top ) )
			return( -1 );
	}
	else {
		/* Mix of set and clear ... ask for both then and else parts 
		 * and interleave.
		 */
		if( im_prepare( ir[1], r ) || im_prepare( ir[2], r ) ) 
			return( -1 );

		for( y = to; y < bo; y++ ) {
			PEL *cp = (PEL *) IM_REGION_ADDR( ir[0], le, y );
			PEL *ap = (PEL *) IM_REGION_ADDR( ir[1], le, y );
			PEL *bp = (PEL *) IM_REGION_ADDR( ir[2], le, y );
			PEL *q = (PEL *) IM_REGION_ADDR( or, le, y );

			for( x = 0, i = 0; i < width; i++, x += size ) {
				if( cp[i] )
					for( z = x; z < x + size; z++ )
						q[z] = ap[z];
				else
					for( z = x; z < x + size; z++ )
						q[z] = bp[z];
			}
		}
	}

	return( 0 );
}

/**
 * im_ifthenelse:
 * @c: condition #IMAGE
 * @a: then #IMAGE
 * @b: else #IMAGE
 * @out: output #IMAGE
 *
 * This operation scans the condition image @c (which must be unsigned char) 
 * and uses it to select pixels from either the then image @a or the else
 * image @b. Non-zero means @a, 0 means @b.
 *
 * The conditional image @c can have either 1 band, in which case entire pels
 * come either from @a or @b, or n bands, where n is the number of bands in 
 * both @a and @b, in which case individual band elements are chosen from 
 * @a and @b.
 *
 * Images @a and @b must match exactly in size, bands and format.
 *
 * See also: im_blend(), im_equal().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_ifthenelse( IMAGE *c, IMAGE *a, IMAGE *b, IMAGE *out )
{
	IMAGE **in;

	/* Check args.
	 */
	if( a->Coding != IM_CODING_NONE && a->Coding != IM_CODING_LABQ ) {
		im_error( "im_ifthenelse", 
			"%s", _( "then image must be uncoded or labpack" ) );
		return( -1 );
	}
	if( b->Coding != IM_CODING_NONE && b->Coding != IM_CODING_LABQ ) {
		im_error( "im_ifthenelse", 
			"%s", _( "else image must be uncoded or labpack" ) );
		return( -1 );
	}
	if( c->Coding != IM_CODING_NONE ) {
		im_error( "im_ifthenelse", 
			"%s", _( "condition image must be uncoded" ) );
		return( -1 );
	}
	if( a->BandFmt != b->BandFmt ||
		a->Bands != b->Bands ) {
		im_error( "im_ifthenelse", 
			"%s", _( "size and format of then and else "
			"must match" ) );
		return( -1 );
	}
	if( c->BandFmt != IM_BANDFMT_UCHAR ) {
		im_error( "im_ifthenelse", 
			"%s", _( "conditional image must be uchar" ) );
		return( -1 );
	}
	if( c->Bands != 1 && c->Bands != a->Bands ) {
		im_error( "im_ifthenelse", 
			"%s", _( "conditional image must be one band or same "
			"as then and else images" ) );
		return( -1 );
	}

	/* Make output image.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, c, a, b, NULL ) ||
		im_cp_descv( out, a, b, c, NULL ) || 
		!(in = im_allocate_input_array( out, c, a, b, NULL )) ||
		im_generate( out, 
			im_start_many, ifthenelse_gen, im_stop_many, 
				in, NULL ) )
		return( -1 );

	return( 0 );
}
