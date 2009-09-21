/* @(#) Turn LCh to Lab.
 * @(#) 
 * @(#) Usage: 	
 * @(#) 	im_LCh2Lab( imagein, imageout )
 * @(#) 	IMAGE *imagein, *imageout;
 * @(#) 
 * @(#) Float in, float out.
 * @(#) 
 * @(#) Returns: -1 on error, else 0
 * 15/11/94 JC
 *	- error messages added
 *	- memory leak fixed
 * 16/11/94 JC
 *	- uses im_wrap_oneonebuf() now
 * 8/2/95 JC
 *	- im_wrap v2
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

/* Process a buffer of data.
 */
void
imb_LCh2Lab( float *p, float *q, int n )
{		
	int x;

	for( x = 0; x < n; x++ ) {
		float L = p[0];
		float C = p[1];
		float h = p[2];
		float a, b;

		p += 3;

		a = C * cos( IM_RAD( h ) );
		b = C * sin( IM_RAD( h ) );

		q[0] = L;
		q[1] = a;
		q[2] = b;
		q += 3;
	}
}

int 
im_LCh2Lab( IMAGE *in, IMAGE *out )
{	
	/* Check input image.
	 */
	if( in->Bands != 3 || in->BandFmt != IM_BANDFMT_FLOAT || 
		in->Coding != IM_CODING_NONE ) {
		im_error( "im_LCh2Lab", "%s", 
			_( "3-band float uncoded input only" ) );
		return( -1 );
	}

	/* Prepare the output image 
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Type = IM_TYPE_LAB;

	/* Do the processing.
	 */
	if( im_wrapone( in, out, 
		(im_wrapone_fn) imb_LCh2Lab, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
