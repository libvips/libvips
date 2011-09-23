/* im_cmulnorm.c
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
 * 28/8/09
 * 	- gtkdoc
 * 	- tiny polish
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

/**
 * im_cmulnorm
 * @in1: input #IMAGE 1
 * @in2: input #IMAGE 2
 * @out: output #IMAGE
 *
 * im_cmulnorm() multiplies two complex images. The complex output is
 * normalised to 1 by dividing both the real and the imaginary part of each
 * pel with the norm. This is useful for phase correlation.  
 *
 * This operation used to be important, but now simply calls im_multiply() 
 * then im_sign().
 *
 * See also: im_multiply(), im_sign().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_cmulnorm( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_cmulnorm:1", "p" )) ||
		im_multiply( in1, in2, t1 ) || 
		im_sign( t1, out ) )
		return( -1 );
	
	return( 0 );
}
