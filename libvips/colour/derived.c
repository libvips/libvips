/* Derived colour space functions.
 * 
 * 14/9/95 JC
 *	- horrible error killed im_dE_fromXYZ() and im_dE_fromdisp()
 * 4/3/98 JC
 *	- sRGB added
 * 17/6/99 JC
 *	- minor reformatting
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

/* LabQ to XYZ.
 */
int 
im_LabQ2XYZ( IMAGE *in, IMAGE *out )
{	
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_LabQ2XYZ:1", "p" )) ||
		im_LabQ2Lab( in, t1 ) ||
		im_Lab2XYZ( t1, out ) )
		return( -1 );

	return( 0 );
}

/* Lab to UCS.
 */
int 
im_Lab2UCS( IMAGE *in, IMAGE *out )
{	
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_Lab2UCS:1", "p" )) ||
		im_Lab2LCh( in, t1 ) ||
		im_LCh2UCS( t1, out ) )
		return( -1 );

	return( 0 );
}

int 
im_UCS2Lab( IMAGE *in, IMAGE *out )
{	
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_UCS2Lab intermediate", "p" )) ||
		im_UCS2LCh( in, t1 ) ||
		im_LCh2Lab( t1, out ) )
		return( -1 );

	return( 0 );
}

int 
im_UCS2XYZ( IMAGE *in, IMAGE *out )
{
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_UCS2XYZ intermediate", "p" )) ||
		im_UCS2Lab( in, t1 ) ||
		im_Lab2XYZ( t1, out ) )
		return( -1 );

	return( 0 );
}

int 
im_XYZ2UCS( IMAGE *in, IMAGE *out )
{	
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_XYZ2UCS intermediate", "p" )) ||
		im_XYZ2Lab( in, t1 ) ||
		im_Lab2UCS( t1, out ) )
		return( -1 );

	return( 0 );
}

int 
im_Lab2disp( IMAGE *in, IMAGE *out, struct im_col_display *disp )
{	
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_Lab2disp:1", "p" )) ||
		im_Lab2XYZ( in, t1 ) ||
		im_XYZ2disp( t1, out, disp ) )
		return( -1 );

	return( 0 );
}

int 
im_XYZ2sRGB( IMAGE *in, IMAGE *out )
{	
	if( im_XYZ2disp( in, out, im_col_displays( 7 ) ) )
		return( -1 );

	out->Type = IM_TYPE_sRGB;

	return( 0 );
}

int 
im_sRGB2XYZ( IMAGE *in, IMAGE *out )
{
	if( im_disp2XYZ( in, out, im_col_displays( 7 ) ) )
		return( -1 );

	return( 0 );
}

int 
im_dECMC_fromdisp( IMAGE *im1, IMAGE *im2, 
	IMAGE *out, struct im_col_display *d )
{	
	IMAGE *t1, *t2, *t3, *t4;

	if( !(t1 = im_open_local( out, "im_dECMC_fromdisp:1", "p" )) ||
		!(t2 = im_open_local( out, "im_dECMC_fromdisp:2", "p" )) ||
		!(t3 = im_open_local( out, "im_dECMC_fromdisp:3", "p" )) ||
		!(t4 = im_open_local( out, "im_dECMC_fromdisp:4", "p" )) ||
		im_disp2XYZ( im1, t1, d ) ||
		im_XYZ2Lab( t1, t2 ) ||
		im_disp2XYZ( im2, t3, d ) ||
		im_XYZ2Lab( t3, t4 ) ||
		im_dECMC_fromLab( t2, t4, out ) )
		return( -1 );

	return( 0 );
}

int 
im_dE_fromXYZ( IMAGE *im1, IMAGE *im2, IMAGE *out )
{	
	IMAGE *t1, *t2;

	if( !(t1 = im_open_local( out, "im_dE_fromXYZ:1", "p" )) ||
		!(t2 = im_open_local( out, "im_dE_fromXYZ:2", "p" )) ||
		im_XYZ2Lab( im1, t1 ) ||
		im_XYZ2Lab( im2, t2 ) ||
		im_dE_fromLab( t1, t2, out ) )
		return( -1 );

	return( 0 );
}

int 
im_dE_fromdisp( IMAGE *im1, IMAGE *im2, IMAGE *out, struct im_col_display *d )
{
	IMAGE *t1, *t2;

	if( !(t1 = im_open_local( out, "im_dE_fromdisp:1", "p" )) ||
		!(t2 = im_open_local( out, "im_dE_fromdisp:2", "p" )) ||
		im_disp2XYZ( im1, t1, d ) ||
		im_disp2XYZ( im2, t2, d ) ||
		im_dE_fromXYZ( t1, t2, out ) )
		return( -1 );

	return( 0 );
}

int 
im_disp2Lab( IMAGE *in, IMAGE *out, struct im_col_display *d )
{
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_disp2Lab:1", "p" )) ||
		im_disp2XYZ( in, t1, d ) ||
		im_XYZ2Lab( t1, out ) )
		return( -1 );
	
	return( 0 );
}
