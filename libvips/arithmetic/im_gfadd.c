/* @(#)  Generalised addition of two vasari images. Result (double or float)
 * @(#)depends on inputs
 * @(#) Function im_gfadd() assumes that the both input files
 * @(#) are either memory mapped or in a buffer.
 * @(#) Images must have the same no of bands and can be of any type
 * @(#)  No check for overflow is carried out.  If in doubt use im_clip2...
 * @(#) Result at eachpoint is a*in1 + b*in2 + c
 * @(#)
 * @(#) int im_gfadd(a, in1, b, in2, c, out)
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
 * 15/6/93 J.Cupitt
 *	- externs removed
 *	- casts added to please ANSI C
 *	- includes rationalised
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

/*               uchar char ushort short uint   int float double */
static int array[8][8] = {
/* uchar */     {  0,    0,    0,    0,    0,    0,    0,    1 },
/* char */      {  0,    0,    0,    0,    0,    0,    0,    1 },
/* ushort */    {  0,    0,    0,    0,    0,    0,    0,    1 },
/* short */     {  0,    0,    0,    0,    0,    0,    0,    1 },
/* uint */      {  0,    0,    0,    0,    0,    0,    0,    1 },
/* int */       {  0,    0,    0,    0,    0,    0,    0,    1 },
/* float */     {  0,    0,    0,    0,    0,    0,    0,    1 },
/* double */    {  1,    1,    1,    1,    1,    1,    1,    1 }
	};

#define select_outdouble(IN2, OUT)\
	switch(tmp1->BandFmt) {\
		case IM_BANDFMT_DOUBLE:	loop(double, IN2, OUT); break;\
		default:       im_error("im_gfadd","Wrong tmp1 format(d)");\
				free( line); return( -1 );\
	}

#define outfloat_2uchar(IN2, OUT)\
		case IM_BANDFMT_UCHAR:	loop(unsigned char, IN2, OUT); break;\
		case IM_BANDFMT_CHAR:	loop(signed char, IN2, OUT); break;\
		case IM_BANDFMT_USHORT:	loop(unsigned short, IN2, OUT); break;\
		case IM_BANDFMT_SHORT:	loop(signed short, IN2, OUT); break;\
		case IM_BANDFMT_UINT:	loop(unsigned int, IN2, OUT); break;\
		case IM_BANDFMT_INT:	loop(signed int, IN2, OUT); break;\
		case IM_BANDFMT_FLOAT:	loop(float, IN2, OUT); break; 

#define outfloat_2char(IN2, OUT)\
		case IM_BANDFMT_CHAR:	loop(signed char, IN2, OUT); break;\
		case IM_BANDFMT_USHORT:	loop(unsigned short, IN2, OUT); break;\
		case IM_BANDFMT_SHORT:	loop(signed short, IN2, OUT); break;\
		case IM_BANDFMT_UINT:	loop(unsigned int, IN2, OUT); break;\
		case IM_BANDFMT_INT:	loop(signed int, IN2, OUT); break;\
		case IM_BANDFMT_FLOAT:	loop(float, IN2, OUT); break; 

#define outfloat_2ushort(IN2, OUT)\
		case IM_BANDFMT_USHORT:	loop(unsigned short, IN2, OUT); break;\
		case IM_BANDFMT_SHORT:	loop(signed short, IN2, OUT); break;\
		case IM_BANDFMT_UINT:	loop(unsigned int, IN2, OUT); break;\
		case IM_BANDFMT_INT:	loop(signed int, IN2, OUT); break;\
		case IM_BANDFMT_FLOAT:	loop(float, IN2, OUT); break; 

#define outfloat_2short(IN2, OUT)\
		case IM_BANDFMT_SHORT:	loop(signed short, IN2, OUT); break;\
		case IM_BANDFMT_UINT:	loop(unsigned int, IN2, OUT); break;\
		case IM_BANDFMT_INT:	loop(signed int, IN2, OUT); break;\
		case IM_BANDFMT_FLOAT:	loop(float, IN2, OUT); break; 

#define outfloat_2uint(IN2, OUT)\
		case IM_BANDFMT_UINT:	loop(unsigned int, IN2, OUT); break;\
		case IM_BANDFMT_INT:	loop(signed int, IN2, OUT); break;\
		case IM_BANDFMT_FLOAT:	loop(float, IN2, OUT); break; 

#define outfloat_2int(IN2, OUT)\
		case IM_BANDFMT_INT:	loop(signed int, IN2, OUT); break;\
		case IM_BANDFMT_FLOAT:	loop(float, IN2, OUT); break; 

#define outfloat_2float(IN2, OUT)\
		case IM_BANDFMT_FLOAT:	loop(float, IN2, OUT); break; 

int im_gfadd(a, in1, b, in2, c, out)
double a, b, c;
IMAGE *in1, *in2, *out;
{
	static int bb[] = { IM_BBITS_FLOAT, IM_BBITS_DOUBLE };
	static int fmt[] = { IM_BANDFMT_FLOAT, IM_BANDFMT_DOUBLE };
	int y, x;
	int first, second, result;
	IMAGE *tmp1, *tmp2;
	PEL *line;
	int os; 	/* size of a line of output image */

/* fd, data filename must have been set before the function is called
 * Check whether they are set properly */
        if ((im_iocheck(in1, out) == -1) || (im_iocheck(in2, out) == -1))
		{ im_error("im_gfadd"," im_iocheck failed"); return( -1 ); }
/* Checks the arguments entered in in and prepares out */
	if ( (in1->Xsize != in2->Xsize) || (in1->Ysize != in2->Ysize) ||
	     (in1->Bands != in2->Bands) || (in1->Coding != in2->Coding) )
		{ im_error("im_gfadd"," Input images differ"); return( -1 );}
	if (in1->Coding != IM_CODING_NONE)
		{ im_error("im_gfadd"," images are coded"); return( -1 ); }

	switch(in1->BandFmt) {
		case IM_BANDFMT_UCHAR:	first = 0; break;
		case IM_BANDFMT_CHAR:	first = 1; break;
		case IM_BANDFMT_USHORT:	first = 2; break;
		case IM_BANDFMT_SHORT:	first = 3; break;
		case IM_BANDFMT_UINT:	first = 4; break;
		case IM_BANDFMT_INT:	first = 5; break;
		case IM_BANDFMT_FLOAT:	first = 6; break;
		case IM_BANDFMT_DOUBLE:	first = 7; break;
		default: im_error("im_gfadd"," unable to accept image1");
				return( -1 );
		}
	switch(in2->BandFmt) {
		case IM_BANDFMT_UCHAR:	second = 0; break;
		case IM_BANDFMT_CHAR:	second = 1; break;
		case IM_BANDFMT_USHORT:	second = 2; break;
		case IM_BANDFMT_SHORT:	second = 3; break;
		case IM_BANDFMT_UINT:	second = 4; break;
		case IM_BANDFMT_INT:	second = 5; break;
		case IM_BANDFMT_FLOAT:	second = 6; break;
		case IM_BANDFMT_DOUBLE:	second = 7; break;
		default: im_error("im_gfadd"," unable to accept image2");
			return( -1 );
		}
/* Define the output */
	result = array[first][second];
/* Prepare output */
	if ( im_cp_desc(out, in1) == -1)
		{ im_error("im_gfadd"," im_cp_desc failed"); return( -1 ); }
	out->Bbits = bb[result];
	out->BandFmt = fmt[result];
	if( im_setupout(out) == -1)
		{ im_error("im_gfadd"," im_setupout failed"); return( -1 ); }

/* Order in1 and in2 */
	if ( first >= second )
		{ tmp1 = in1; tmp2 = in2; }
	else
		{ tmp1 = in2; tmp2 = in1; }

/* Define what we do for each band element type.  */

#define loop(IN1, IN2, OUT)\
	{	IN1 *input1 = (IN1 *) tmp1->data;\
	 	IN2 *input2 = (IN2 *) tmp2->data;\
		\
		for (y=0; y <out->Ysize; y++) {\
			OUT *cpline = (OUT*)line;\
			for (x=0; x<os; x++)\
				*cpline++ = (a*((OUT)*input1++) + \
					b*((OUT)*input2++) + c);\
			if (im_writeline(y, out, line) ) {\
				im_error("im_gfadd"," im_writeline failed");\
				free( line);\
				return( -1 );\
			}\
		}\
	}

	os = out->Xsize * out->Bands;
	line = (PEL *) calloc ( (unsigned)os, sizeof(double) );
	if (line == NULL)
		{ im_error("im_gfadd"," unable to calloc"); return( -1 ); }

	switch (out->BandFmt)	{
		case IM_BANDFMT_DOUBLE: 
			switch (tmp2->BandFmt)	{
			case IM_BANDFMT_UCHAR:	
				select_outdouble(unsigned char, double); 
				break;

			case IM_BANDFMT_CHAR:	
				select_outdouble(signed char, double); 
				break;

			case IM_BANDFMT_USHORT:	
				select_outdouble(unsigned short, double); 
				break;

			case IM_BANDFMT_SHORT:	
				select_outdouble(signed short, double); 
				break;

			case IM_BANDFMT_UINT:	
				select_outdouble(unsigned int, double); 
				break;

			case IM_BANDFMT_INT:	
				select_outdouble(signed int, double); 
				break;

			case IM_BANDFMT_FLOAT:	
				select_outdouble(float, double); 
				break;

			case IM_BANDFMT_DOUBLE:	
				select_outdouble(double, double); 
				break;

			default:	
				im_error("im_gfadd","Wrong tmp2 format(d)");
				free( line ); 
				return( -1 );
			}

			break;

		case IM_BANDFMT_FLOAT :
			switch (tmp2->BandFmt)	{
			case IM_BANDFMT_UCHAR:	
				switch (tmp1->BandFmt) {
				outfloat_2uchar(unsigned char, float);

				default:
					im_error("im_gfadd"," Error (a)");
					free( line ); 
					return( -1 );
				}
				break;

			case IM_BANDFMT_CHAR:	
				switch (tmp1->BandFmt) {
				outfloat_2char(signed char, float);

				default:
					im_error("im_gfadd"," Error (b)");
					free( line); return( -1 );
				}
				break;

			case IM_BANDFMT_USHORT:	
				switch (tmp1->BandFmt) {
				outfloat_2ushort(unsigned short, float);

				default:
					im_error("im_gfadd"," Error (c)");
					free( line); return( -1 );
				}
				break;

			case IM_BANDFMT_SHORT:	
				switch (tmp1->BandFmt) {
				outfloat_2short(signed short, float);

				default:
					im_error("im_gfadd"," Error (d)");
					free( line); return( -1 );
				}
				break;

			case IM_BANDFMT_UINT:	
				switch (tmp1->BandFmt) {
				outfloat_2uint(unsigned int, float);

				default:
					im_error("im_gfadd"," Error (e)");
					free( line); return( -1 );
				}
				break;

			case IM_BANDFMT_INT:	
				switch (tmp1->BandFmt) {
				outfloat_2int(signed int,  float);

				default:
					im_error("im_gfadd"," Error (f)");
					free( line ); 
					return( -1 );
				}
				break;

			case IM_BANDFMT_FLOAT:	
				switch (tmp1->BandFmt) {
				outfloat_2float(float,  float);

				default:
					im_error("im_gfadd"," Error (g)");
					free( line ); 
					return( -1 );
				}
				break;

			default:	
				im_error("im_gfadd"," Wrong tmp2 format(f)");
				free( line ); 
				return( -1 );
			}

			break;

		default:
			im_error("im_gfadd"," Impossible output state");
			free( line ); 
			return( -1 );
		}

	free( line );

	return( 0 );
}
