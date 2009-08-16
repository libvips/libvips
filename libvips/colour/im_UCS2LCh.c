/* @(#) Turn UCS to LCh
 * @(#) 
 * @(#) Usage: 	
 * @(#) 	im_UCS2LCh( imagein, imageout )
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
imb_UCS2LCh( float *p, float *q, int n )
{		
	int x;

	for( x = 0; x < n; x++ ) {
		float Lucs = p[0];
		float Cucs = p[1];
		float hucs = p[2];

		/* Turn from UCS.
		 */
		float C = im_col_Cucs2C( Cucs );
		float h = im_col_Chucs2h( C, hucs );
		float L = im_col_Lucs2L( Lucs );

		p += 3;

		q[0] = L;
		q[1] = C;
		q[2] = h;
		q += 3;
	}
}

int 
im_UCS2LCh( IMAGE *in, IMAGE *out )
{
	/* Check input image.
	 */
	if( in->Bands != 3 || in->BandFmt != IM_BANDFMT_FLOAT || 
		in->Coding != IM_CODING_NONE ) {
		im_errormsg( "im_UCS2LCh: 3-band float uncoded input only" );
		return( -1 );
	}

	/* Prepare the output image 
	 */
	if( im_cp_desc( out, in) )
		return( -1 );
	out->Type = IM_TYPE_LCH;

	/* Do the processing.
	 */
	im_col_make_tables_UCS();
	if( im_wrapone( in, out, 
		(im_wrapone_fn) imb_UCS2LCh, NULL, NULL ) )
		return( -1 );

	return( 0 );
}
