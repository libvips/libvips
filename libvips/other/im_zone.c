/* @(#) square zone plate of size
 * @(#)   The center of the zone plate is at (xpos/2, ypos/2)
 * @(#) 
 * @(#) Usage:
 * @(#) 
 * @(#) int im_zone( image, size )
 * @(#) IMAGE *image;
 * @(#) int size;
 * @(#) 
 * @(#) int im_fzone( image, size )
 * @(#) IMAGE *image;
 * @(#) int size;
 * @(#) 
 * @(#) Returns 0 on sucess and -1 on error
 * @(#) 
 * N. Dessipris 01/02/1991
 *
 * 22/7/93 JC
 *	- externs removed
 *	- im_outcheck() added
 * 30/8/95 JC
 *	- modernized
 *	- memory leaks fixed
 *	- split into im_zone() and im_fzone()
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
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

int
im_fzone( IMAGE *image, int size )
{
	int x, y;
	int i, j;

	float *buf;
	const int size2 = size/2;

	/* Check args.
	 */
	if( im_outcheck( image ) )
		return( -1 );
	if( size <= 0 || (size % 2) != 0 ) {
		im_errormsg( "im_zone: size must be even and positive" );
		return( -1 );
	}

	/* Set up output image.
	 */
        im_initdesc( image, size, size, 1, IM_BBITS_FLOAT, IM_BANDFMT_FLOAT,
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0 );
        if( im_setupout( image ) )
                return( -1 );

	/* Create output buffer.
	 */
        if( !(buf = IM_ARRAY( image, size, float )) )
                return( -1 );

	/* Make zone plate.
	 */
	for( y = 0, j = -size2; j < size2; j++, y++ ) {
		for( x = 0, i = -size2; i < size2; i++, x++ )
			buf[x] = cos( (IM_PI/size) * (i*i + j*j) );
		if( im_writeline( y, image, (PEL *) buf ) )
			return( -1 );
	}

	return( 0 );
}

/* As above, but make a IM_BANDFMT_UCHAR image.
 */
int
im_zone( IMAGE *im, int size )
{
	IMAGE *t1 = im_open_local( im, "im_zone:1", "p" );
	IMAGE *t2 = im_open_local( im, "im_zone:2", "p" );

	if( !t1 || !t2 )
		return( -1 );
	
	if( im_fzone( t1, size ) || 
		im_lintra( 127.5, t1, 127.5, t2 ) ||
		im_clip( t2, im ) )
		return( -1 );

	return( 0 );
}
