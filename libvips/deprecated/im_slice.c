/* @(#) Slices an image using two thresholds.  Works for any non-complex type.
 * @(#) Output has three levels 0 128 and 255.  Values below  or = t1 are 0,
 * @(#) above t2 are 255 and the remaining are 128.
 * @(#) Input is either memory mapped or in a buffer.
 * @(#)  It is implied that t1 is less than t2; however the program checks
 * @(#) if they are the wrong way and swaps them
 * @(#)
 * @(#) int im_slice(in, out, t1, t2)
 * @(#) IMAGE *in, *out;
 * @(#) double t1, t2;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 *
 * Copyright: 1991, N. Dessipris
 *
 * Author: N. Dessipris
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

#define BRIGHT 255
#define GREY 128
#define DARK 0

/* Useful: Call a macro with the name, type pairs for all VIPS functions.  
 */
#define im_for_all_types(A) \
	case IM_BANDFMT_UCHAR:	A(unsigned char); break; \
	case IM_BANDFMT_CHAR:	A(signed char); break; \
	case IM_BANDFMT_USHORT:	A(unsigned short); break; \
	case IM_BANDFMT_SHORT:	A(signed short); break; \
	case IM_BANDFMT_UINT:	A(unsigned int); break; \
	case IM_BANDFMT_INT:	A(signed int); break; \
	case IM_BANDFMT_FLOAT:	A(float); break; 

/* Replacement for im_slice */
int
im_slice( in, out, t1, t2 )
IMAGE *in, *out;
double t1, t2;
{	
	int x, y, z;
	PEL *bu;		/* Buffer we write to */
	int s, epl;		/* Size and els per line */
	double thresh1, thresh2;

/* Check our args. */
	if( im_iocheck( in, out ) ) 
		{
		im_error( "im_slice", "%s", _( "im_iocheck failed") );
		return( -1 );
		}
	if( in->Coding != IM_CODING_NONE ) 
		{
		im_error( "im_slice", "%s", _( "input should be uncoded") );
		return( -1 );
		}

/* Set up the output header.  */
	if( im_cp_desc( out, in ) ) 
		{
		im_error( "im_slice", "%s", _( "im_cp_desc failed") );
		return( -1 );
		}
	out->BandFmt = IM_BANDFMT_UCHAR;
	if( im_setupout( out ) ) 
		{
		im_error( "im_slice", "%s", _( "im_setupout failed") );
		return( -1 );
		}

	if ( t1 <= t2 )
		{ thresh1 = t1; thresh2 = t2; }
	else
		{ thresh1 = t2; thresh2 = t1; }
/* Make buffer for building o/p in.  */
	epl = in->Xsize * in->Bands;
	s = epl * sizeof( PEL );
	if( (bu = (PEL *) im_malloc( out, (unsigned)s )) == NULL )
		return( -1 );

/* Define what we do for each band element type.  */
#define im_slice_loop(TYPE)\
	{	TYPE *a = (TYPE *) in->data;\
		\
		for( y = 0; y < in->Ysize; y++ ) {\
			PEL *b = bu;\
			\
			for( x = 0; x < in->Xsize; x++ )\
				for( z = 0; z < in->Bands; z++ ) {\
					double f = (double) *a++;\
					if ( f <= thresh1)\
						*b++ = (PEL)DARK;\
					else if ( f > thresh2 )\
						*b++ = (PEL)BRIGHT;\
					else \
						*b++ = (PEL)GREY;\
				}\
			\
			if( im_writeline( y, out, bu ) )\
				return( -1 );\
		}\
	}

/* Do the above for all image types.  */
	switch( in->BandFmt ) {
	im_for_all_types( im_slice_loop );

	default:
		im_error( "im_slice", "%s", _( "Unknown input format") );
		return( -1 );
	}

	return( 0 );
}
