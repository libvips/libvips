/* @(#) Function to find the minimim of an image. Works for any 
 * @(#) image type. Returns a double and the location of min
 * @(#)
 * @(#) Function im_minpos() assumes that input
 * @(#) is either memory mapped or in a buffer.
 * @(#)
 * @(#) int im_minpos(in, xpos, ypos, out)
 * @(#) IMAGE *in;
 * @(#) int *xpos, *ypos;
 * @(#) double *out;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/05/1990
 * Modified on : 18/03/1991, N. Dessipris
 * 23/11/92 JC
 *	- correct result for more than 1 band now.
 * 23/7/93 JC
 *	- im_incheck() added
 * 20/6/95 JC
 *	- now returns double for value, like im_max()
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
#include <assert.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Find the minimum of an image. Take any format, returns a double.  */
int
im_minpos( IMAGE *in, int *xpos, int *ypos, double *out )
{
	double m;
	int xp=0, yp=0;
	int os;

/* Check our args. */
	if( im_incheck( in ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE )
		{
		im_error("im_minpos", "%s", _("input must be uncoded"));
		return( -1 );
		}

/* What type? First define the loop we want to perform for all types. */
#define loop(TYPE) \
	{	TYPE *p = (TYPE *) in->data; \
		int x, y; \
		m = (double) *p; \
		\
		for ( y=0; y<in->Ysize; y++ ) \
			for ( x=0; x<os; x++ ) {\
				if( (double) *p < m ) {\
					m = (double) *p; \
					xp = x; yp = y; \
				}\
			p++ ;\
			}\
	} 

#define loopcmplx(TYPE) \
	{	TYPE *p = (TYPE *) in->data; \
		double re=(double)*p;\
		double im=(double)*(p+1);\
		double mod = re * re + im * im;\
		int x, y; \
		m = mod; \
		\
		for ( y=0; y<in->Ysize; y++ ) \
			for ( x=0; x<os; x++ ) {\
				re = (double)*p++; im = (double)*p++; \
				mod = re * re + im * im; \
				if( mod < m ) {\
					m = mod; \
					xp = x; yp = y; \
				}\
			}\
	} 

/* Now generate code for all types. */
	os = in->Xsize * in->Bands;
	switch( in->BandFmt ) {
	case IM_BANDFMT_UCHAR:		loop(unsigned char); break; 
	case IM_BANDFMT_CHAR:		loop(signed char); break; 
	case IM_BANDFMT_USHORT:		loop(unsigned short); break; 
	case IM_BANDFMT_SHORT:		loop(signed short); break; 
	case IM_BANDFMT_UINT:		loop(unsigned int); break; 
	case IM_BANDFMT_INT:		loop(signed int); break; 
	case IM_BANDFMT_FLOAT:		loop(float); break; 
	case IM_BANDFMT_DOUBLE:		loop(double); break; 
	case IM_BANDFMT_COMPLEX:	loopcmplx(float); break; 
	case IM_BANDFMT_DPCOMPLEX:	loopcmplx(double); break; 

	default: 
		assert( 0 );
	}

	/* Take out bands on x.
	 */
	*out = m;
	*xpos = xp / in->Bands;
	*ypos = yp;
	return( 0 );
}
