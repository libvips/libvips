/* @(#) creates a sinewave with horfreq cycles per horizontal direction and
 * @(#) verfreq cycles per vertical direction
 * @(#)  If horfreq and verfreq are integers the resultant image is periodical
 * @(#) and therfore the Fourier transform doesnot present spikes
 * @(#)  Image should have been set by a call to im_setbuf() or im_openout()
 * @(#)
 * @(#) Usage: int im_sines(image, xsize, ysize, horfreq, verfreq)
 * @(#) IMAGE *image;
 * @(#) int xsize, ysize;
 * @(#) double horfreq, verfreq;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/02/1990
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
im_sines( IMAGE *image, int xsize, int ysize, double horfreq, double verfreq )
{
	int x, y;
	float *line, *cpline;
	int size;
	double cons, factor;
	double theta_rad, costheta, sintheta, ysintheta;

/* Check input args */
	if( im_outcheck( image ) )
		return( -1 );
        if ( xsize <= 0 || ysize <= 0 )
                { im_errormsg("im_sines: wrong sizes"); return(-1); }

/* Set now image properly */
        im_initdesc(image, xsize, ysize, 1, IM_BBITS_FLOAT, IM_BANDFMT_FLOAT,
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0);

/* Set up image checking whether the output is a buffer or a file */
        if (im_setupout( image ) == -1 )
                { im_errormsg("im_sines: im_setupout failed"); return(-1); }
/* Create data */
	size = image->Xsize;
        if ( (line=(float *)calloc((unsigned)size, sizeof(float))) == NULL )
                { im_errormsg("im_sines: calloc failed"); return(-1); }

/* make angle in rad */
	if (horfreq == 0)
		theta_rad = IM_PI/2.0;
	else
		theta_rad = atan(verfreq/horfreq);
	costheta = cos(theta_rad); sintheta = sin(theta_rad);
	factor = sqrt ((double)(horfreq*horfreq + verfreq*verfreq));
	cons =  factor * IM_PI * 2.0/(double)image->Xsize;
/* There is a bug (rounding error ?) for horfreq=0,
 *so do this calculation independantly */
	if ( horfreq != 0 )
		{
		for (y=0; y<image->Ysize; y++)
			{
			ysintheta = y * sintheta;
			cpline = line;
			for (x=0; x<image->Xsize; x++)
				*cpline++ =
				(float)(cos(cons*(x*costheta-ysintheta)));
			if ( im_writeline( y, image, (PEL *)line ) == -1 )
				{
				im_errormsg("im_sines: im_writeline failed");
				free ( (char *)line );
				return( -1 );
				}
			}
		}
	else
		{
		for (y=0; y<image->Ysize; y++)
			{
			cpline = line;
			ysintheta = cos (- cons * y * sintheta);
			for (x=0; x<image->Xsize; x++)
				*cpline++ = (float)ysintheta;
			if ( im_writeline( y, image, (PEL *)line ) == -1 )
				{
				im_errormsg("im_sines: im_writeline failed");
				free ( (char *)line );
				return( -1 );
				}
			}
		}
	free ( (char *)line );
	return(0);
}
