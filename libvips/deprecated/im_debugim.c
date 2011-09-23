/* @(#) Function which prints in stdout the values of a picture
 * @(#)
 * @(#) For debuging only
 * @(#) is either memory mapped or in a buffer.
 * @(#)
 * @(#) void 
 * @(#) im_debugim( in )
 * @(#) IMAGE *in;
 * @(#)
 *
 * Copyright: 1991 N. Dessipris
 *
 * Author: N. Dessipris
 * Written on: 18/03/1991
 * Modified on:
 * 15/4/93 J.Cupitt
 *      - returns int, not void now, so error messages work
 *      - detects im->data invalid.
 * 15/4/93 J.Cupitt
 *      - uses %g format, not %f for printf()
 * 23/7/93 JC
 *	- im_incheck() added
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

#include <vips/vips.h>

int 
im_debugim( IMAGE *in )
{
/* Check our args. */
	if( im_incheck( in ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_debugim", "%s", _( "input must be uncoded" ) );
		return( -1 );
	}

/* What type? First define the loop we want to perform for all types. */
#define loopuc(TYPE) \
	{	TYPE *p = (TYPE *) in->data; \
		int x, y, z; \
		\
		for ( y=0; y<in->Ysize; y++ ) {\
			for ( x=0; x<in->Xsize; x++ ) {\
				for ( z=0; z<in->Bands; z++ ) {\
					fprintf(stderr, "%4d", (TYPE)*p++ );\
				} \
			} \
			fprintf(stderr, "\n");\
		} \
	} 

#define loop(TYPE) \
	{	TYPE *p = (TYPE *) in->data; \
		int x, y, z; \
		\
		for ( y=0; y<in->Ysize; y++ ) {\
			for ( x=0; x<in->Xsize; x++ ) {\
				for ( z=0; z<in->Bands; z++ ) {\
					fprintf(stderr, "%g\t", (double)*p++ );\
				} \
			} \
			fprintf(stderr, "\n");\
		} \
	} 

#define loopcmplx(TYPE) \
	{	TYPE *p = (TYPE *) in->data; \
		int x, y, z; \
		\
		for ( y=0; y<in->Ysize; y++ ) {\
			for ( x=0; x<in->Xsize; x++ ) {\
				for ( z=0; z<in->Bands; z++ ) {\
					fprintf(stderr,"re=%g\t",(double)*p++);\
					fprintf(stderr,"im=%g\t",(double)*p++);\
				} \
			} \
			fprintf(stderr, "\n");\
		} \
	} 

/* Now generate code for all types. */
	switch( in->BandFmt ) {
	case IM_BANDFMT_UCHAR:		loopuc(unsigned char); break; 
	case IM_BANDFMT_CHAR:		loop(char); break; 
	case IM_BANDFMT_USHORT:		loop(unsigned short); break; 
	case IM_BANDFMT_SHORT:		loop(short); break; 
	case IM_BANDFMT_UINT:		loop(unsigned int); break; 
	case IM_BANDFMT_INT:		loop(int); break; 
	case IM_BANDFMT_FLOAT:		loop(float); break; 
	case IM_BANDFMT_DOUBLE:		loop(double); break; 
	case IM_BANDFMT_COMPLEX:	loopcmplx(float); break; 
	case IM_BANDFMT_DPCOMPLEX:	loopcmplx(double); break; 

	default: 
		im_error( "im_debugim", "%s", _( "unknown input format") ); 
		return( -1 );
	}

	return( 0 );
}
