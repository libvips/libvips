/* Derived colour space functions.
 * 
 * 14/9/95 JC
 *	- horrible error killed im_dE_fromXYZ() and im_dE_fromdisp()
 * 4/3/98 JC
 *	- sRGB added
 * 17/6/99 JC
 *	- minor reformatting
 * 30/10/09
 * 	- gtkdoc comments
 * 	- minor cleanups
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

/**
 * im_LabQ2XYZ:
 * @in: input image
 * @out: output image
 *
 * Convert an image from LabQ (Coding == IM_CODING_LABQ) to XYZ.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_LabQ2XYZ( IMAGE *in, IMAGE *out )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_LabQ2XYZ:1", "p" ) ||
		im_LabQ2Lab( in, t[0] ) ||
		im_Lab2XYZ( t[0], out ) )
		return( -1 );

	return( 0 );
}

/**
 * im_Lab2UCS:
 * @in: input image
 * @out: output image
 *
 * Convert an image from Lab to UCS.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_Lab2UCS( IMAGE *in, IMAGE *out )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_Lab2UCS:1", "p" ) ||
		im_Lab2LCh( in, t[0] ) ||
		im_LCh2UCS( t[0], out ) )
		return( -1 );

	return( 0 );
}


/**
 * im_UCS2Lab:
 * @in: input image
 * @out: output image
 *
 * Convert an image from UCS to Lab.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_UCS2Lab( IMAGE *in, IMAGE *out )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_UCS2Lab:1", "p" ) ||
		im_UCS2LCh( in, t[0] ) ||
		im_LCh2Lab( t[0], out ) )
		return( -1 );

	return( 0 );
}

/**
 * im_UCS2XYZ:
 * @in: input image
 * @out: output image
 *
 * Convert an image from UCS to XYZ.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_UCS2XYZ( IMAGE *in, IMAGE *out )
{
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_UCS2XYZ:1", "p" ) ||
		im_UCS2Lab( in, t[0] ) ||
		im_Lab2XYZ( t[0], out ) )
		return( -1 );

	return( 0 );
}


/**
 * im_XY2UCS:
 * @in: input image
 * @out: output image
 *
 * Convert an image from XYZ to UCS.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_XYZ2UCS( IMAGE *in, IMAGE *out )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_XYZ2UCS:1", "p" ) ||
		im_XYZ2Lab( in, t[0] ) ||
		im_Lab2UCS( t[0], out ) )
		return( -1 );

	return( 0 );
}

/**
 * im_XYZ2sRGB:
 * @in: input image
 * @out: output image
 *
 * Convert an image from XYZ to sRGB. The conversion is supposed to be quick
 * rather than accurate. Use an ICC profile with im_icc_transform() for more
 * precision.
 *
 * See also: im_icc_transform.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_XYZ2sRGB( IMAGE *in, IMAGE *out )
{	
	if( im_XYZ2disp( in, out, im_col_displays( 7 ) ) )
		return( -1 );

	out->Type = IM_TYPE_sRGB;

	return( 0 );
}

/**
 * im_sRGB2XYZ:
 * @in: input image
 * @out: output image
 *
 * Convert an image from sRGB to XYZ. 
 * The conversion is supposed to be quick
 * rather than accurate. Use an ICC profile with im_icc_transform() for more
 * precision.
 *
 * See also: im_icc_transform.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_sRGB2XYZ( IMAGE *in, IMAGE *out )
{
	if( im_disp2XYZ( in, out, im_col_displays( 7 ) ) )
		return( -1 );

	return( 0 );
}

/**
 * im_dE_fromXYZ:
 * @in: input image
 * @out: output image
 *
 * Calculate CIELAB dE 1976 from a pair of XYZ images. 
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_dE_fromXYZ( IMAGE *im1, IMAGE *im2, IMAGE *out )
{	
	IMAGE *t[2];

	if( im_open_local_array( out, t, 2, "im_dE_fromXYZ:1", "p" ) ||
		im_XYZ2Lab( im1, t[0] ) ||
		im_XYZ2Lab( im2, t[1] ) ||
		im_dE_fromLab( t[0], t[1], out ) )
		return( -1 );

	return( 0 );
}
