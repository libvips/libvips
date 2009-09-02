/* @(#)  Generalised addition of two vasari images  using the routines 
 * @(#) im_gaddim or im_gfadd
 * @(#) Convention to ease the complilation time.
 * @(#) Function im_gadd() assumes that the both input files
 * @(#) are either memory mapped or in a buffer.
 * @(#) Images must have the same no of bands and must not be complex
 * @(#)  No check for overflow is carried out.  
 * @(#)
 * @(#) int im_gadd(a, in1, b, in2, c, out)
 * @(#) IMAGE *in1, *in2, *out;
 * @(#) double a, b, c;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
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
#include <assert.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

extern int im_gfadd();
extern int im_gaddim();

/* This function works on either mmaped files or on images in buffer
 */

/**
 * im_gadd:
 *
 * Deprecated.
 */
int im_gadd(a, in1, b, in2, c, out)
IMAGE *in1, *in2, *out;
double a, b, c;
{
	int flagint = 0;
	int flagfloat = 0;
	int value = 0;

	switch(in1->BandFmt) {
		case IM_BANDFMT_UCHAR:
		case IM_BANDFMT_CHAR:
		case IM_BANDFMT_USHORT:
		case IM_BANDFMT_SHORT:
		case IM_BANDFMT_UINT:
		case IM_BANDFMT_INT:
			flagint = 1;
			break;
		case IM_BANDFMT_FLOAT:
		case IM_BANDFMT_DOUBLE:	
			flagfloat = 1;
			break;
		default: im_error("im_gadd","%s", _("Unable to accept image1"));
			return(-1);
		}
	switch(in2->BandFmt) {
		case IM_BANDFMT_UCHAR:
		case IM_BANDFMT_CHAR:
		case IM_BANDFMT_USHORT:
		case IM_BANDFMT_SHORT:
		case IM_BANDFMT_UINT:
		case IM_BANDFMT_INT:
			flagint = 1;
			break;
		case IM_BANDFMT_FLOAT:
		case IM_BANDFMT_DOUBLE:	
			flagfloat = 1;
			break;
		default: im_error("im_gadd","%s", _("Unable to accept image1"));
			return(-1);
		}
	/* Select output routines */
	if (flagfloat == 1)
		{
		value = im_gfadd(a, in1, b, in2, c, out);
		if (value == -1)
			return(-1);
		}
	else if (flagint == 1)
		{
		value = im_gaddim(a, in1, b, in2, c, out);
		if (value == -1)
			return(-1);
		}
	else 
		assert( 0 );

	return(0);
}
