/* @(#) creates a pattern showing the similtaneous constrast effect
 * @(#)
 * @(#) Usage: int im_simcontr(image, xs, ys)
 * @(#) IMAGE *image;
 * @(#) int xs, ys;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 19/07/1991
 * Modified on:
 * 22/7/93 JC
 *	- externs removed
 *	- im_outcheck() added
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
im_simcontr( IMAGE *image, int xs, int ys )
{
	int x, y;
	unsigned char *line1, *line2, *cpline;


/* Check input args */
	if( im_outcheck( image ) )
		return( -1 );

/* Set now image properly */
        im_initdesc(image, xs, ys, 1, IM_BBITS_BYTE, IM_BANDFMT_UCHAR,
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0 );

/* Set up image checking whether the output is a buffer or a file */
        if (im_setupout( image ) == -1 )
                { im_errormsg("im_simcontr: im_setupout failed"); return(-1); }
/* Create data */
        line1 = (unsigned char *)calloc((unsigned)xs, sizeof(char));
        line2 = (unsigned char *)calloc((unsigned)xs, sizeof(char));
        if ( (line1 == NULL) || (line2 == NULL) )
                { im_errormsg("im_simcontr: calloc failed"); return(-1); }

	cpline = line1;
	for (x=0; x<xs; x++)
		*cpline++ = (PEL)255;
	cpline = line1;
	for (x=0; x<xs/2; x++)
		*cpline++ = (PEL)0;
	
	cpline = line2;
	for (x=0; x<xs; x++)
		*cpline++ = (PEL)255;
	cpline = line2;
	for (x=0; x<xs/8; x++)
		*cpline++ = (PEL)0;
	for (x=0; x<xs/4; x++)
		*cpline++ = (PEL)128;
	for (x=0; x<xs/8; x++)
		*cpline++ = (PEL)0;
	for (x=0; x<xs/8; x++)
		*cpline++ = (PEL)255;
	for (x=0; x<xs/4; x++)
		*cpline++ = (PEL)128;

	for (y=0; y<ys/4; y++)
		{
		if ( im_writeline( y, image, (PEL *)line1 ) == -1 )
			{
			free ( (char *)line1 ); free ( (char *)line2 );
			return( -1 );
			}
		}
	for (y=ys/4; y<(ys/4+ys/2); y++)
		{
		if ( im_writeline( y, image, (PEL *)line2 ) == -1 )
			{
			free ( (char *)line1 ); free ( (char *)line2 );
			return( -1 );
			}
		}
	for (y=(ys/4 + ys/2); y<ys; y++)
		{
		if ( im_writeline( y, image, (PEL *)line1 ) == -1 )
			{
			free ( (char *)line1 ); free ( (char *)line2 );
			return( -1 );
			}
		}
	free ( (char *)line1 ); free ( (char *)line2 );
	return(0);
}
