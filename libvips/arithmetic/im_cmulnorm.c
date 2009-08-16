/* @(#)  Multiplies two complex images. complex output is normalised to 1
 * @(#)  Inputs can be complex double or complex float
 * @(#)  Result (double complex or float complex) depends on inputs
 * @(#) Function im_cmulnorm() assumes that the both input files
 * @(#) are either memory mapped or in a buffer.
 * @(#) Images must have the same no of bands and must be complex
 * @(#)  No check for overflow is carried out.
 * @(#)
 * @(#) int im_cmulnorm(in1, in2, out)
 * @(#) IMAGE *in1, *in2, *out;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 15/4/97 JC
 *	- thrown away and redone in terms of im_multiply()
 * 9/7/02 JC
 *	- im_sign() broken out, done in terms of that
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

#include <stdio.h>
#include <stdlib.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int 
im_cmulnorm( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *t1 = im_open_local( out, "im_cmulnorm:1", "p" );

	if( !t1 || im_multiply( in1, in2, t1 ) || im_sign( t1, out ) )
		return( -1 );
	
	return( 0 );
}
