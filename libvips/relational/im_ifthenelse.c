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
 * 23/9/09
 * 	- use im_check*()
 * 	- allow many-band conditional and single-band a/b
 * 	- allow a/b to differ in format and bands
 * 25/6/10
 * 	- let the conditional image be any format by adding a (!=0) if
 * 	  necessary
 * 17/5/11
 * 	- added sizealike
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

#include <vips/vips.h>
#include <vips/internal.h>

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

static int
ifthenelse( IMAGE *c, IMAGE *a, IMAGE *b, IMAGE *out )
{
	IMAGE **in;

	/* Check args.
	 */
	if( im_check_uncoded( "im_ifthenelse", c ) ||
		im_check_coding_known( "im_ifthenelse", a ) ||
		im_check_coding_known( "im_ifthenelse", b ) ||
		im_check_format( "ifthenelse", c, IM_BANDFMT_UCHAR ) || 
		im_check_format_same( "ifthenelse", a, b ) ||
		im_check_bands_same( "ifthenelse", a, b ) ||
		im_check_bands_1orn( "im_ifthenelse", c, a ) || 
		im_piocheck( c, out ) || 
		im_pincheck( a ) || 
		im_pincheck( b ) )
                return( -1 );

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

/**
 * im_ifthenelse:
 * @c: condition #IMAGE
 * @a: then #IMAGE
 * @b: else #IMAGE
 * @out: output #IMAGE
 *
 * This operation scans the condition image @c 
 * and uses it to select pixels from either the then image @a or the else
 * image @b. Non-zero means @a, 0 means @b.
 *
 * Any image can have either 1 band or n bands, where n is the same for all
 * the non-1-band images. Single band images are then effectively copied to 
 * make n-band images.
 *
 * Images @a and @b are cast up to the smallest common format.
 *
 * If the images differ in size, the smaller image is enlarged to match the
 * larger by adding zero pixels along the bottom and right.
 *
 * See also: im_blend(), im_equal().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_ifthenelse( IMAGE *c, IMAGE *a, IMAGE *b, IMAGE *out )
{
	IMAGE *t[9];

	if( im_open_local_array( out, t, 9, "im_ifthenelse", "p" ) )
		return( -1 );

	/* Make a and b match in bands and format. Don't make c match: we
	 * special-case this in code above ^^^ for speed.
	 */
	if( im__formatalike( a, b, t[0], t[1] ) ||
		im__bandalike( "im_ifthenelse", t[0], t[1], t[2], t[3] ) )
		return( -1 );

	/* All 3 must match in size.
	 */
	t[4] = c;
	if( im__sizealike_vec( t + 2, t + 5, 3 ) )
		return( -1 );
	c = t[7];

	/* If c is not uchar, do (!=0) to make a uchar image.
	 */
	if( c->BandFmt != IM_BANDFMT_UCHAR ) {
		if( im_notequalconst( c, t[8], 0 ) )
			return( -1 );

		c = t[8];
	}

	if( ifthenelse( c, t[5], t[6], out ) )
		return( -1 );

	return( 0 );
}
