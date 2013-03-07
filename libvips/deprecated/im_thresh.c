/* @(#) Thresholds an image.  Works for any non-complex type.
 * @(#) Output is a binary image with 0 and 255 only
 * @(#) Input is either memory mapped or in a buffer.
 * @(#)
 * @(#) int im_thresh(imin, imout, threshold)
 * @(#) IMAGE *imin, *imout;
 * @(#) double threshold;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 *
 * Copyright: 1991, N. Dessipris, J Cupitt
 *
 * Author: N. Dessipris, J. Cupitt
 * Written on: 15/03/1991
 * Modified on : 
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

#include <vips/vips.h>

/* Useful: Call a macro with the name, type pairs for all VIPS functions.  */
#define BRIGHT 255
#define DARK 0
#define im_for_all_types(A) \
	case IM_BANDFMT_UCHAR:	A(unsigned char); break; \
	case IM_BANDFMT_CHAR:	A(signed char); break; \
	case IM_BANDFMT_USHORT:	A(unsigned short); break; \
	case IM_BANDFMT_SHORT:	A(signed short); break; \
	case IM_BANDFMT_UINT:	A(unsigned int); break; \
	case IM_BANDFMT_INT:	A(signed int); break; \
	case IM_BANDFMT_FLOAT:	A(float); break; \
	case IM_BANDFMT_DOUBLE:	A(double); break; 

/* Replacement for im_thresh */
int
im_thresh( in, out, threshold )
IMAGE *in, *out;
double threshold;
{	
	int x, y;
	PEL *bu;		/* Buffer we write to */
	int s, epl;		/* Size and els per line */

/* Check our args. */
	if( im_iocheck( in, out ) ) 
		return( -1 );
	if( in->Coding != IM_CODING_NONE ) { 
		im_error( "im_thresh", "%s", _( "input should be uncoded") );
		return(-1);
	}

/* Set up the output header.  */
	if( im_cp_desc( out, in ) ) 
		return( -1 );
	out->BandFmt = IM_BANDFMT_UCHAR;
	if( im_setupout( out ) ) 
		return( -1 );

/* Make buffer for building o/p in.  */
	epl = in->Xsize * in->Bands;
	s = epl * sizeof( PEL );
	if( (bu = (PEL *) im_malloc( out, (unsigned)s )) == NULL )
		return( -1 );

/* Define what we do for each band element type.  */
#define im_thresh_loop(TYPE)\
	{	TYPE *a = (TYPE *) in->data;\
		\
		for( y = 0; y < in->Ysize; y++ ) {\
			PEL *b = bu;\
			\
			for( x = 0; x < epl; x++ ) {\
				double f = (double) *a++;\
				if ( f >= threshold)\
					*b++ = (PEL)BRIGHT;\
				else\
					*b++ = (PEL)DARK;\
				}\
			\
			if( im_writeline( y, out, bu ) ) \
				return( -1 );\
		}\
	}

/* Do the above for all image types.  */
	switch( in->BandFmt ) {
	im_for_all_types( im_thresh_loop );

	default:
		im_error( "im_thresh", "%s", _( "Unknown input format") );
		return( -1 );
	}

	return( 0 );
}
