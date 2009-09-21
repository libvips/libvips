/* @(#) Function which changes the spatial resolution of an image according to
 * @(#) step
 * @(#)
 * @(#) int im_spatres(in, out, step)
 * @(#) IMAGE *in, *out;
 * @(#) int step;
 * @(#) Returns either 0 (sucess) or -1 (fail)
 * @(#)
 * @(#) Picture can have any number of channels (max 64).
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 08/11/1989.
 * Modified on: 19/01/1990.
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
im_spatres( IMAGE *in,  IMAGE *out, int step )
{
	int x, y;	/* horizontal and vertical direction */
	int z;		/* 0 <= z < channel	*/
	int i, j;
	int rounding, step2, sum;
	unsigned char *values;
	unsigned char *input, *cpinput, *cp2input, *line, *cpline, *pnt, *cpnt;
	int os;

/* Check args */
	if ( step < 1 ) {
		im_error( "im_spatres", _( "Invalid step %d" ), step );
		return(-1);}

	if ( (in->Xsize/step == 0)||(in->Ysize/step == 0) )
		{im_error("im_spatres", _( "Invalid step %d" ), step);return(-1);}

	if (im_iocheck(in, out) == -1)
		return( -1 );
        
        if((in->Coding != IM_CODING_NONE)||(in->Bbits != 8)||(in->BandFmt !=IM_BANDFMT_UCHAR)) { 
		im_error( "im_spatres", "%s", _( "wrong input") ); 
		return(-1); }

/* Prepare output */
        if (im_cp_desc(out, in) == -1)
		return( -1 );
	out->Xsize = in->Xsize - in->Xsize%step;
	out->Ysize = in->Ysize - in->Ysize%step;
         
        if( im_setupout(out) == -1)
		return( -1 );

	/* Malloc buffer for one 'line' of input data */
	os = in->Xsize * in->Bands;
	line = (unsigned char *)calloc((unsigned)os, sizeof(char));
	/* Malloc space for values */
	values = (unsigned char *)calloc((unsigned)out->Bands, sizeof(char));
	if ( line == NULL || values == NULL ) { 
		im_error( "im_spatres", "%s", _( "calloc failed") ); 
		return(-1); }

	step2 = step * step;
	rounding = step2/2;
	input = (unsigned char *)in->data;
	for ( y = 0; y < out->Ysize; y += step )
		{
		cpinput = input;
		input += os * step;
		/* do the x loop out->Xsize / step times */
		cpline = line;
		for (x = 0; x < out->Xsize; x += step)
			{
			cp2input = cpinput;
			cpinput += step * out->Bands; /* ??? */
			for ( z = 0; z < out->Bands; z++ )
				{
				pnt = cp2input + z;
				sum = 0;
				for ( j = 0; j < step; j++ )
					{
					cpnt = pnt;
					pnt += os;
					for ( i = 0; i < step; i++ )
						{
						sum += (int)*cpnt;
						cpnt += out->Bands;
						}
					}
				*(values + z) = (PEL)((sum + rounding)/step2);
				}
			/* for this x, write step*bands data  */
			for ( j = 0; j < step; j++ )
				for ( z = 0; z < out->Bands; z++ )
					*cpline++ = *(values + z);
			}
		/* line is now ready. Write now step lines */
		for (j = 0; j < step; j++)
			if ( im_writeline ( y+j, out, (PEL *)line ) == -1 )
				{
				free ( (char *)line ); free ( (char *)values );
				return( -1 );
				}
		}		/* end of the for (..y..) loop */
	
	free ( (char *)line ); free ( (char *)values );
	return(0);
}
