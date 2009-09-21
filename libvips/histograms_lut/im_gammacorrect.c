/* @(#) Gamma-correct uchar image with factor gammafactor.
 * @(#)
 * @(#)  int im_gammacorrect(in, out, exponent)
 * @(#)  IMAGE *in, *out;
 * @(#)  double exponent;
 * @(#)
 * @(#)  Returns 0 on sucess and -1 on error
 * @(#)
 *
 *
 * Copyright: 1990, N. Dessipris.
 * 
 * Written on: 19/07/1990
 * Modified on:
 * 19/6/95 JC
 *	- redone as library function
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

int 
im_gammacorrect( IMAGE *in, IMAGE *out, double exponent )
{
	IMAGE *t1 = im_open_local( out, "im_gammacorrect:#1", "p" );
	IMAGE *t2 = im_open_local( out, "im_gammacorrect:#2", "p" );
	IMAGE *t3 = im_open_local( out, "im_gammacorrect:#2", "p" );

	if( !t1 || !t2 || !t3 )
		return( -1 );

        if( im_piocheck( in, out ) )
                return( -1 );
	if( in->BandFmt != IM_BANDFMT_UCHAR ) {
		im_error( "im_gammacorrect", "%s", _( "uchar images only" ) );
		return( -1 );
	}

	if( im_identity( t1, 1 ) ||
		im_powtra( t1, t2, exponent ) ||
		im_scale( t2, t3 ) ||
		im_maplut( in, out, t3 ) )
		return( -1 );

	return( 0 );
}
