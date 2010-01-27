/* @(#) Scale an image so that min(im) maps to 0 and max(im) maps to 255. If
 * @(#) min(im)==max(im), then we return black. Any non-complex type.
 * @(#)
 * @(#) int 
 * @(#) im_scale( in, out )
 * @(#) IMAGE *in, *out;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Author: John Cupitt
 * Written on: 22/4/93
 * Modified on: 
 * 30/6/93 JC
 *	- adapted for partial v2
 * 	- ANSI
 * 31/8/93 JC
 *	- calculation of offset now includes scale
 * 8/5/06
 * 	- set Type on output too
 * 16/10/06
 * 	- what? no, don't set Type, useful to be able to scale histograms, for
 * 	  example
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

/* Scale, as noted above.
 */
int 
im_scale( IMAGE *in, IMAGE *out )
{	
	DOUBLEMASK *stats;
	IMAGE *t = im_open_local( out, "im_scale:1", "p" );
	double mx, mn;
	double scale, offset;

	/* Measure min and max, calculate transform.
	 */
	if( !t || !(stats = im_stats( in )) )
		return( -1 );
	mn = stats->coeff[0];
	mx = stats->coeff[1];
	im_free_dmask( stats );

	if( mn == mx ) 
		/* Range of zero: just return black.
		 */
		return( im_black( out, in->Xsize, in->Ysize, in->Bands ) );
	scale = 255.0 / (mx - mn);
	offset = -(mn * scale);

	/* Transform!
	 */
	if( im_lintra( scale, in, offset, t ) ||
		im_clip2fmt( t, out, IM_BANDFMT_UCHAR ) )
		return( -1 );

	return( 0 );
}
