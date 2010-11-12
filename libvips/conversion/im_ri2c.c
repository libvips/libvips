/* im_ri2c
 *
 * Author: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on : 10/04/1990
 * 16/11/94 JC
 *	- rewritten with partials
 *	- more general
 * 1/2/10
 * 	- bandalike
 * 	- better upcasting
 * 	- gtkdoc
 * 	- cleanups
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define JOIN( TYPE ) { \
	TYPE *p1 = (TYPE *) p[0]; \
	TYPE *p2 = (TYPE *) p[1]; \
	TYPE *q0 = (TYPE *) q; \
 	\
	for( x = 0; x < len; x++ ) { \
		q0[0] = *p1++; \
		q0[1] = *p2++; \
 		\
		q0 += 2; \
	} \
}

/* Join two buffers to make a complex.
 */
static void
join_buffer( PEL **p, PEL *q, int n, IMAGE *im )
{
	int x;
	int len = n * im->Bands;

	switch( im->BandFmt ) {
	case IM_BANDFMT_FLOAT:
		JOIN( float );
		break;

	case IM_BANDFMT_DOUBLE:
		JOIN( double );
		break;

	default:
		g_assert( 0 );
	}
}

/**
 * im_ri2c:
 * @in1: input image 
 * @in2: input image 
 * @out: output image
 *
 * Compose two real images to make a complex image. If either @in1 or @in2 are
 * %IM_BANDFMT_DOUBLE, @out is %IM_BANDFMT_DPCOMPLEX. Otherwise @out is
 * %IM_BANDFMT_COMPLEX. @in1 becomes the real component of @out and @in2 the
 * imaginary.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * See also: im_c2real(), im_c2imag().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_ri2c( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *t[5];
	VipsBandFmt fmt;

	/* Check input image. We don't need to check that sizes match --
	 * im_wrapmany does this for us.
	 */
	if( im_check_uncoded( "im_ri2c", in1 ) ||
		im_check_uncoded( "im_ri2c", in2 ) ||
		im_check_noncomplex( "im_ri2c", in1 ) ||
		im_check_noncomplex( "im_ri2c", in2 ) ||
		im_check_bands_1orn( "im_ri2c", in1, in2 ) )
		return( -1 );

	/* If either of the inputs is DOUBLE, we are
	 * DPCOMPLEX; otherwise we are COMPLEX.
	 */
	if( in1->BandFmt == IM_BANDFMT_DOUBLE || 
		in2->BandFmt == IM_BANDFMT_DOUBLE ) 
		fmt = IM_BANDFMT_DOUBLE;
	else 
		fmt = IM_BANDFMT_FLOAT;

	if( im_open_local_array( out, t, 4, "im_ri2c", "p" ) ||
		im_clip2fmt( in1, t[0], fmt ) ||
		im_clip2fmt( in2, t[1], fmt ) ||
		im__bandalike( "im_ri2c", t[0], t[1], t[2], t[3] ) )
		return( -1 );

	/* Remember to NULL-terminate.
	 */
	t[4] = NULL;

	if( im_cp_descv( out, t[2], t[3], NULL ) )
		return( -1 );
	out->BandFmt = fmt == IM_BANDFMT_DOUBLE ? 
		IM_BANDFMT_DPCOMPLEX : IM_BANDFMT_COMPLEX;

	if( im_wrapmany( t + 2, out, (im_wrapmany_fn) join_buffer, out, NULL ) )
		return( -1 );

	return( 0 );
}
