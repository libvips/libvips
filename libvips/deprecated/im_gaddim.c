/* @(#)  Generalised addition of two vasari images. 
 * @(#)Inputs, outputs are neither float nor double
 * @(#) Result at each point is a*in1 + b*in2 + c
 * @(#) Result depends on inputs, rounding is carried out;
 * @(#) Function im_gaddim() assumes that the both input files
 * @(#) are either memory mapped or in a buffer.
 * @(#) Images must have the same no of bands and must not be complex
 * @(#)  No check for overflow is done; 
 * @(#)
 * @(#) int im_gaddim(a, in1, b, in2, c, out)
 * @(#) double a, b, c;
 * @(#) IMAGE *in1, *in2, *out;
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
#include <math.h>

#include <vips/vips.h>
#include <vips/deprecated.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* This function works on either mmaped files or on images in buffer
 */

/*		 uchar char ushort short uint   int */
static int array[6][6] = { 
/* uchar */	{  2,    3,    2,    3,    4,    5 },
/* char */	{  3,    3,    3,    3,    5,    5 },
/* ushort */	{  2,    3,    2,    3,    4,    5 },
/* short */	{  3,    3,    3,    3,    5,    5 },
/* uint */	{  4,    5,    4,    5,    4,    5 },
/* int */	{  5,    5,    5,    5,    5,    5 }
	};

#define select_tmp2_for_out_int(OUT)  \
	case IM_BANDFMT_UCHAR:	select_tmp1_for_out_int(unsigned char, OUT); break;  \
	case IM_BANDFMT_CHAR:	select_tmp1_for_out_int(signed char, OUT); break;  \
	case IM_BANDFMT_USHORT:	select_tmp1_for_out_int(unsigned short, OUT); break; \
	case IM_BANDFMT_SHORT:	select_tmp1_for_out_int(signed short, OUT); break; \
	case IM_BANDFMT_UINT:	select_tmp1_for_out_int(unsigned int, OUT); break; \
	case IM_BANDFMT_INT:	select_tmp1_for_out_int(signed int, OUT); break; \
\
	default:	\
		im_error("im_gaddim","Wrong tmp2 format(1)"); \
		free( line); \
		return(-1);

#define select_tmp1_for_out_int(IN2, OUT)  \
	switch(tmp1->BandFmt) { \
		case IM_BANDFMT_UINT:	loop(unsigned int, IN2, OUT); break; \
		case IM_BANDFMT_INT:	loop(int, IN2, OUT); break; \
		default:      im_error("im_gaddim","Wrong tmp2 format(2)");\
				free( line);\
				return(-1); \
	}

#define select_tmp2_for_out_short(OUT)  \
	case IM_BANDFMT_UCHAR:	select_tmp1_for_out_short(unsigned char, OUT); break;  \
	case IM_BANDFMT_CHAR:	select_tmp1_for_out_short(signed char, OUT); break;  \
	case IM_BANDFMT_USHORT:	select_tmp1_for_out_short(unsigned short, OUT); break; \
	case IM_BANDFMT_SHORT:	select_tmp1_for_out_short(signed short, OUT); break;
#define select_tmp1_for_out_short(IN2, OUT)  \
	switch(tmp1->BandFmt)	{ \
		case IM_BANDFMT_UCHAR:	loop(unsigned char, IN2, OUT); break;  \
		case IM_BANDFMT_CHAR:	loop(signed char, IN2, OUT); break;  \
		case IM_BANDFMT_USHORT:	loop(unsigned short, IN2, OUT); break; \
		case IM_BANDFMT_SHORT:	loop(signed short, IN2, OUT); break; \
		default:      im_error("im_gaddim","Wrong image1 format(4)");\
				free( line);\
				return(-1); \
	}




/**
 * im_gaddim:
 *
 * Deprecated.
 */
int im_gaddim(a, in1, b, in2, c, out)
IMAGE *in1, *in2, *out;
double a, b, c;
{
	static int fmt[] = { IM_BANDFMT_UCHAR, IM_BANDFMT_CHAR,
	IM_BANDFMT_USHORT, IM_BANDFMT_SHORT, 
		IM_BANDFMT_UINT, IM_BANDFMT_INT };
	int y, x;
	int first, second, result;
	IMAGE *tmp1, *tmp2;
	PEL *line;
	int os; 	/* size of a line of output image */

/* fd, data filename must have been set before the function is called
 * Check whether they are set properly */
        if ((im_iocheck(in1, out) == -1) || (im_iocheck(in2, out) == -1))
		{
                return(-1);
		}
/* Checks the arguments entered in in and prepares out */
	if ( (in1->Xsize != in2->Xsize) || (in1->Ysize != in2->Ysize) ||
	     (in1->Bands != in2->Bands) || (in1->Coding != in2->Coding) )
		{ im_error("im_gaddim"," Input images differ"); return(-1); }
	if (in1->Coding != IM_CODING_NONE)
		{ im_error("im_gaddim"," images must be uncoded"); return(-1);}

	switch(in1->BandFmt) {
		case IM_BANDFMT_UCHAR:	first = 0; break;
		case IM_BANDFMT_CHAR:	first = 1; break;
		case IM_BANDFMT_USHORT:	first = 2; break;
		case IM_BANDFMT_SHORT:	first = 3; break;
		case IM_BANDFMT_UINT:	first = 4; break;
		case IM_BANDFMT_INT:	first = 5; break;
		default: im_error("im_gaddim"," Unable to accept image1");
			return(-1);
		}
	switch(in2->BandFmt) {
		case IM_BANDFMT_UCHAR:	second = 0; break;
		case IM_BANDFMT_CHAR:	second = 1; break;
		case IM_BANDFMT_USHORT:	second = 2; break;
		case IM_BANDFMT_SHORT:	second = 3; break;
		case IM_BANDFMT_UINT:	second = 4; break;
		case IM_BANDFMT_INT:	second = 5; break;
		default: im_error("im_gaddim"," Unable to accept image2");
			return(-1);
		}
/* Define the output */
	result = array[first][second];

/* Prepare the output header */
	if ( im_cp_desc(out, in1) == -1)
		{ im_error("im_gaddim"," im_cp_desc failed"); return(-1); }
	out->BandFmt = fmt[result];

	if( im_setupout(out) == -1)
		{ im_error("im_gaddim"," im_setupout failed"); return(-1); }

/* Order in1 and in2 */
	if ( first >= second )
		{ tmp1 = in1; tmp2 = in2; }
	else
		{ tmp1 = in2; tmp2 = in1; }

/* Define what we do for each band element type. */

#define loop(IN1, IN2, OUT) \
	{	IN1 *input1 = (IN1 *) tmp1->data; \
	 	IN2 *input2 = (IN2 *) tmp2->data; \
		\
		for (y=0; y <out->Ysize; y++) {\
			OUT *cpline = (OUT*)line; \
			for (x=0; x<os; x++)\
				*cpline++ = (OUT) \
				      (a*(*input1++)+b*(*input2++)+c +0.5);\
			if (im_writeline(y, out, line) == -1) {\
				free( line);\
				return ( -1 );\
			}\
		}\
	}

	os = out->Xsize * out->Bands;
	line = (PEL *) calloc ( (unsigned)os, sizeof(double) );
	if (line == NULL)
		{
		im_error("im_gaddim"," Unable to calloc");
		return(-1);
		}

	switch (out->BandFmt)	{
		case IM_BANDFMT_INT:
			switch (tmp2->BandFmt)	{
				select_tmp2_for_out_int(int);
			}
			break;

		case IM_BANDFMT_UINT:
			switch (tmp2->BandFmt)	{
				select_tmp2_for_out_int(unsigned int);
				}
			break;
		case IM_BANDFMT_SHORT:
			switch (tmp2->BandFmt)	{
				select_tmp2_for_out_short(short);
				}
			break;
		case IM_BANDFMT_USHORT:
			switch (tmp2->BandFmt)	{
				select_tmp2_for_out_short(unsigned short);
				}
			break;
		default:
			im_error("im_gaddim"," Impossible output state");
			free( line);
			return(-1);
		}

	free( line);

	return(0);
}
