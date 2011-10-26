/* im_insert
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/08/1990
 * Modified on : 
 * 31/8/93 JC
 *	- ANSIfied
 *	- Nicos' reformatting undone. Grr!
 * 22/12/94
 *	- modernised
 *	- now does IM_CODING_LABQ too
 * 22/6/95 JC
 *	- partialized
 * 10/2/02 JC
 *	- adapted for im_prepare_to() stuff
 * 14/4/04
 *	- sets Xoffset / Yoffset
 * 3/7/06
 * 	- add sanity range checks
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 30/1/10
 * 	- cleanups
 * 	- formatalike/bandalike
 * 	- gtkdoc
 * 26/10/11
 * 	- just a rump now, remove entirely soon
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
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

/* The common part of most binary conversion
 * operators. We:
 *
 * - check in and out
 * - cast in1 and in2 up to a common format
 * - equalise bands 
 * - make an input array
 * - return the matched images in vec[0] and vec[1]
 */
IMAGE **
im__insert_base( const char *domain, 
	IMAGE *in1, IMAGE *in2, IMAGE *out ) 
{
	IMAGE *t[4];
	IMAGE **vec;

	if( im_piocheck( in1, out ) || 
		im_pincheck( in2 ) ||
		im_check_bands_1orn( domain, in1, in2 ) ||
		im_check_coding_known( domain, in1 ) ||
		im_check_coding_same( domain, in1, in2 ) )
		return( NULL );

	/* Cast our input images up to a common format and bands.
	 */
	if( im_open_local_array( out, t, 4, domain, "p" ) ||
		im__formatalike( in1, in2, t[0], t[1] ) ||
		im__bandalike( domain, t[0], t[1], t[2], t[3] ) ||
		!(vec = im_allocate_input_array( out, t[2], t[3], NULL )) )
		return( NULL );

	/* Generate the output.
	 */
	if( im_cp_descv( out, vec[0], vec[1], NULL ) ||
		im_demand_hint_array( out, IM_SMALLTILE, vec ) )
		return( NULL );

	return( vec );
}

/**
 * im_insertset:
 * @main: big image
 * @sub: small image
 * @out: output image
 * @n: number of positions
 * @x: left positions of @sub
 * @y: top positions of @sub
 *
 * Insert @sub repeatedly into @main at the positions listed in the arrays @x,
 * @y of length @n. @out is the same
 * size as @main. @sub is clipped against the edges of @main. 
 *
 * This operation is fast for large @n, but will use a memory buffer the size
 * of @out. It's useful for things like making scatter plots.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: im_insert(), im_lrjoin().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_insertset( IMAGE *main, IMAGE *sub, IMAGE *out, int n, int *x, int *y )
{
	IMAGE **vec;
	IMAGE *t;
	int i;

	if( !(vec = im__insert_base( "im_insert", main, sub, out )) )
		return( -1 );

	/* Copy to a memory image, zap that, then copy to out.
	 */
	if( !(t = im_open_local( out, "im_insertset", "t" )) ||
		im_copy( vec[0], t ) )
		return( -1 );

	for( i = 0; i < n; i++ ) 
		if( im_insertplace( t, vec[1], x[i], y[i] ) )
			return( -1 );

	if( im_copy( t, out ) )
		return( -1 );

	return( 0 );
}
