/* im_Lab2LabS: quantise FLOAT Lab image into signed short format
 *
 * 12/12/02 JC
 *	- from im_Lab2LabQ
 * 1/11/09
 *	- gtkdoc
 *	- cleanups
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

void
imb_Lab2LabS( float *in, signed short *out, int n )
{
	float *p = in;
	signed short *q = out;
	int c;
	
	for( c = 0; c < n; c++ ) {
		q[0] = p[0] * (32767.0 / 100.0);
		q[1] = p[1] * (32768.0 / 128.0);
		q[2] = p[2] * (32768.0 / 128.0);

		q += 3;
		p += 3;
	}
}

/**
 * im_Lab2LabS:
 * @in: input image
 * @out: output image
 *
 * Turn Lab to LabS, signed 16-bit int fixed point.
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_Lab2LabS( IMAGE *in, IMAGE *out )
{
	IMAGE *t[1];

	if( im_check_uncoded( "im_Lab2LabS", in ) ||
		im_check_bands( "im_Lab2LabS", in, 3 ) ||
		im_open_local_array( out, t, 1, "im_Lab2LabS", "p" ) ||
		im_clip2fmt( in, t[0], IM_BANDFMT_FLOAT ) )
		return( -1 );

	if( im_cp_desc( out, t[0] ) )
		return( -1 );
	out->Type = IM_TYPE_LABS;
	out->BandFmt = IM_BANDFMT_SHORT;
	out->Bbits = IM_BBITS_SHORT;

	if( im_wrapone( t[0], out, 
		(im_wrapone_fn) imb_Lab2LabS, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
