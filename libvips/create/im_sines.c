/* creates a 2d sinewave 
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/02/1990
 * Modified on:
 * 22/7/93 JC
 *	- externs removed
 *	- im_outcheck() added
 * 1/2/11
 * 	- gtk-doc
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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

/**
 * im_sines:
 * @out: output image
 * @xsize: image size
 * @ysize: image size
 * @horfreq: horizontal frequency
 * @verfreq: vertical frequency
 *
 * im_sines() creates a float one band image of the a sine waveform in two
 * dimensions.  
 *
 * The number of horizontal and vertical spatial frequencies are
 * determined by the variables @horfreq and @verfreq respectively.  The
 * function is useful for creating displayable sine waves and
 * square waves in two dimensions.
 *
 * If horfreq and verfreq are integers the resultant image is periodical
 * and therfore the Fourier transform doesnot present spikes
 * 
 * See also: im_grey(), im_make_xy(). 
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_sines( IMAGE *out, int xsize, int ysize, double horfreq, double verfreq )
{
	int x, y;
	float *line, *cpline;
	int size;
	double cons, factor;
	double theta_rad, costheta, sintheta, ysintheta;

/* Check input args */
	if( im_outcheck( out ) )
		return( -1 );
        if ( xsize <= 0 || ysize <= 0 ) { 
		im_error( "im_sines", "%s", _( "wrong sizes") ); 
		return(-1); }

/* Set now out properly */
        im_initdesc(out, xsize, ysize, 1, IM_BBITS_FLOAT, IM_BANDFMT_FLOAT,
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0);

/* Set up out checking whether the output is a buffer or a file */
        if (im_setupout( out ) == -1 )
                return( -1 );
/* Create data */
	size = out->Xsize;
        if ( (line=(float *)calloc((unsigned)size, sizeof(float))) == NULL ) { 
		im_error( "im_sines", "%s", _( "calloc failed") ); 
		return(-1); }

/* make angle in rad */
	if (horfreq == 0)
		theta_rad = IM_PI/2.0;
	else
		theta_rad = atan(verfreq/horfreq);
	costheta = cos(theta_rad); sintheta = sin(theta_rad);
	factor = sqrt ((double)(horfreq*horfreq + verfreq*verfreq));
	cons =  factor * IM_PI * 2.0/(double)out->Xsize;
/* There is a bug (rounding error ?) for horfreq=0,
 *so do this calculation independantly */
	if ( horfreq != 0 )
		{
		for (y=0; y<out->Ysize; y++)
			{
			ysintheta = y * sintheta;
			cpline = line;
			for (x=0; x<out->Xsize; x++)
				*cpline++ =
				(float)(cos(cons*(x*costheta-ysintheta)));
			if ( im_writeline( y, out, (PEL *)line ) == -1 )
				{
				free ( (char *)line );
				return( -1 );
				}
			}
		}
	else
		{
		for (y=0; y<out->Ysize; y++)
			{
			cpline = line;
			ysintheta = cos (- cons * y * sintheta);
			for (x=0; x<out->Xsize; x++)
				*cpline++ = (float)ysintheta;
			if ( im_writeline( y, out, (PEL *)line ) == -1 )
				{
				free ( (char *)line );
				return( -1 );
				}
			}
		}
	free ( (char *)line );
	return(0);
}
