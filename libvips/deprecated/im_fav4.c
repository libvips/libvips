/* @(#) Optimised 4 frame average
Copyright (C) 1992, Kirk Martinez, History of Art Dept, Birkbeck College
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

#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define ARGS "fav4: frame average 4 frames\nARGS: im1 im2 im3 im4 outfile"
#define NFRAMES 4

/**
 * im_fav4:
 * @in: array of 4 input #IMAGE s
 * @out: output #IMAGE
 *
 * Average four identical images. 
 *
 * Deprecated.
*/
int
im_fav4( IMAGE **in, IMAGE *out)
{
	PEL *result, *buffer, *p1, *p2, *p3, *p4;
	int x,y;
	int linebytes, PICY;

/* check IMAGEs parameters 
*/
if(im_iocheck(in[1], out)) return(-1);

/* BYTE images only!
*/
if( (in[0]->BandFmt != IM_BANDFMT_CHAR) &&  (in[0]->BandFmt != IM_BANDFMT_UCHAR)) return(-1);

if ( im_cp_desc(out, in[1]) == -1)   /* copy image descriptors */
      return(-1);
if ( im_setupout(out) == -1)
      return(-1);

linebytes = in[0]->Xsize * in[0]->Bands;
PICY = in[0]->Ysize;
buffer = (PEL*)im_malloc(NULL,linebytes);
memset(buffer, 0, linebytes);

	p1 = (PEL*)in[0]->data;
	p2 = (PEL*)in[1]->data;
	p3 = (PEL*)in[2]->data;
	p4 = (PEL*)in[3]->data;

for (y = 0; y < PICY; y++)
	{
	result = buffer;
	/* average 4 pels with rounding, for whole line*/
	for (x = 0; x < linebytes; x++) {
		*result++ = (PEL)((int)((int)*p1++ + (int)*p2++ + (int)*p3++ + (int)*p4++ +2) >> 2);
		}
	im_writeline(y,out, buffer);
	}
im_free(buffer);
return(0);
}

