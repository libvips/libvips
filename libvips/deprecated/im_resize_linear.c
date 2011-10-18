/* im_lowpass()
 * History:
 * 27/10/94 JC
 *	- IM_ARRAY modified to use local allocation
 *	- im_iscomplex() call added
 * 17/2/95 JC
 *	- modernised a little
 * 18/8/95 JC
 *	- name changed to reflect function more closely
 * 2/6/04
 *	- was detecting edges incorrectly, segv for some images (thanks Javi)
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

/* What we do for each pel.
 */
#define LOOP( TYPE ) \
	if( Xint >= 0 && Yint >=0 &&  \
		Xint < in->Xsize-1 && Yint < in->Ysize-1 )  \
		for( bb = 0; bb < in->Bands; bb++ ) { \
			TYPE s1 = *((TYPE *) p); \
			TYPE s2 = *((TYPE *) (p + ips)); \
			TYPE s3 = *((TYPE *) (p + ils)); \
			TYPE s4 = *((TYPE *) (p + ips + ils)); \
			TYPE *t = (TYPE *) q; \
			\
			*t = (1-dx)*(1-dy)*s1 + dx*(1-dy)*s2 + \
				dy*(1-dx)*s3 + dx*dy*s4; \
			\
			p += ies; \
			q += oes; \
		} \
	else if( Xint == in->Xsize-1 && Yint >= 0 && Yint < in->Ysize - 1 )  \
		for( bb = 0; bb < in->Bands; bb++ ) { \
			TYPE s1 = *((TYPE *) p); \
			TYPE s3 = *((TYPE *) (p + ils)); \
			TYPE *t = (TYPE *) q; \
			\
			*t = (1-dy)*s1 + dy*s3; \
			\
			p += ies; \
			q += oes; \
		} \
	else if( Yint == in->Ysize-1 && Xint >= 0 && Xint < in->Xsize - 1 ) \
		for( bb = 0; bb < in->Bands; bb++ ) { \
			TYPE s1 = *((TYPE *) p); \
			TYPE s2 = *((TYPE *) (p + ips)); \
			TYPE *t = (TYPE *) q; \
			\
			*t = (1-dx)*s1 + dx*s2; \
			\
			p += ies; \
			q += oes; \
		} \
	else  \
		for( bb = 0; bb < in->Bands; bb++ ) { \
			unsigned char s1 = *((unsigned char *) p); \
			TYPE *t = (TYPE *) q; \
			\
			*t = s1; \
			\
			p += ies; \
			q += oes; \
		} 

int 
im_resize_linear( IMAGE *in, IMAGE *out, int X, int Y )
{
    double	dx, dy, xscale, yscale;
    double	Xnew, Ynew;	/* inv. coord. of the interpolated pt */

    int		x, y;
    int		Xint, Yint;
    int		bb;

    PEL		*input, *opline;
    PEL 	*q, *p;

    int 	ils, ips, ies;		/* Input and output line, pel and */
    int 	ols, oes;		/* element sizes */

	if( im_iocheck( in, out ) )
		return( -1 );
	if( vips_bandfmt_iscomplex( in->BandFmt ) ) {
		im_error( "im_lowpass", "%s", _( "non-complex input only" ) );
		return( -1 );
	}
	if( in->Coding != IM_CODING_NONE ) {
		im_error("im_lowpass: ", "%s", _( "put should be uncoded") );
		return( -1 );
	}
	if( im_cp_desc( out, in ) ) 
		return( -1 );

	out->Xsize = X;
	out->Ysize = Y;

	if( im_setupout( out ) )
		return( -1 );

	ils = IM_IMAGE_SIZEOF_LINE( in );
	ips = IM_IMAGE_SIZEOF_PEL( in );
	ies = IM_IMAGE_SIZEOF_ELEMENT( in );

	ols = IM_IMAGE_SIZEOF_LINE( out );
	oes = IM_IMAGE_SIZEOF_ELEMENT( out );

/* buffer lines
***************/
	if( !(opline = IM_ARRAY( out, ols, PEL )) ) 
		return( -1 );

/* Resampling
*************/
	input = (PEL*) in->data;
	xscale = ((double)in->Xsize-1)/(X-1);
	yscale = ((double)in->Ysize-1)/(Y-1);

for (y=0; y<Y; y++)
  {
    q = opline;
    for (x=0; x<X; x++)
      {
	Xnew = x*xscale;
	Ynew = y*yscale;
	Xint = floor(Xnew);
	Yint = floor(Ynew);
	dx = Xnew - Xint;
	dy = Ynew - Yint;
	p = input + Xint*ips + Yint*ils;

	switch( in->BandFmt ) {
	case IM_BANDFMT_UCHAR:		LOOP( unsigned char); break;
	case IM_BANDFMT_USHORT:		LOOP( unsigned short ); break;
	case IM_BANDFMT_UINT:		LOOP( unsigned int ); break;
	case IM_BANDFMT_CHAR:		LOOP( signed char ); break;
	case IM_BANDFMT_SHORT:		LOOP( signed short ); break;
	case IM_BANDFMT_INT:		LOOP( signed int ); break;
	case IM_BANDFMT_FLOAT:		LOOP( float ); break;
	case IM_BANDFMT_DOUBLE:		LOOP( double ); break;

	default:
		im_error( "im_lowpass", "%s", _( "unsupported image type" ) );
		return( -1 );
		/*NOTREACHED*/
	}
      }

    if (im_writeline(y, out, opline) )
	    return(-1);
  } 
return(0);
}
