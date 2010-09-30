/* Smudge a piece of image. 
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * ? JC
 *	- im_makerw() changed to im_rwcheck()
 * 5/12/06
 * 	- im_invalidate() after paint
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Smudge a section of an IMAGE. Smudge area r offset by x, y. Take average
 * of pixels in 3x3 area surrounding current pixel for every pixel in r. We do
 * not change the outermost pixels in the image, although we do read them.
 */
int
im_smudge( IMAGE *im, int ix, int iy, Rect *r )
{	
	int x, y, a, b, c;
	int ba = im->Bands;
	int el = ba * im->Xsize;
	Rect area, image, clipped;
	double total[ 256 ];

	if( im_rwcheck( im ) )
		return( -1 );

	/* Don't do the margins.
	 */
	area = *r;
	area.left += ix;
	area.top += iy;
	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	im_rect_marginadjust( &image, -1 );
	im_rect_intersectrect( &area, &image, &clipped );

	/* Any left?
	 */
	if( im_rect_isempty( &clipped ) )
		return( 0 );

/* What we do for each type.
 */
#define SMUDGE(TYPE) \
	for( y = clipped.top; y < clipped.top + clipped.height; y++ ) \
		for( x = clipped.left;  \
			x < clipped.left + clipped.width; x++ ) { \
			TYPE *to = (TYPE *) im->data + x * ba + y * el; \
			TYPE *from = to - el - ba; \
			TYPE *f; \
 			\
			for( a = 0; a < ba; a++ ) \
				total[a] = 0.0; \
			\
			for( a = 0; a < 3; a++ ) { \
				f = from; \
				for( b = 0; b < 3; b++ ) \
					for( c = 0; c < ba; c++ ) \
						total[c] += *f++; \
				from += el; \
			} \
 			\
			for( a = 0; a < ba; a++ ) \
				to[a] = (16 * (double) to[a] + total[a]) \
					/ 25.0; \
		}

	/* Loop through the remaining pixels.
	 */
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR: 
		SMUDGE(unsigned char); 
		break; 

	case IM_BANDFMT_CHAR: 
		SMUDGE(char); 
		break; 

	case IM_BANDFMT_USHORT: 
		SMUDGE(unsigned short); 
		break; 

	case IM_BANDFMT_SHORT: 
		SMUDGE(short); 
		break; 

	case IM_BANDFMT_UINT: 
		SMUDGE(unsigned int); 
		break; 

	case IM_BANDFMT_INT: 
		SMUDGE(int); 
		break; 

	case IM_BANDFMT_FLOAT: 
		SMUDGE(float); 
		break; 

	case IM_BANDFMT_DOUBLE: 
		SMUDGE(double); 
		break; 

	/* Do complex types too. Just treat as float and double, but with
	 * twice the number of bands.
	 */
	case IM_BANDFMT_COMPLEX:
		/* Twice number of bands: double size and bands.
		 */
		ba *= 2;
		el *= 2;

		SMUDGE(float);

		break;

	case IM_BANDFMT_DPCOMPLEX:
		/* Twice number of bands: double size and bands.
		 */
		ba *= 2;
		el *= 2;

		SMUDGE(double);

		break;

	default:
		im_error( "im_smudge", "%s", _( "unknown band format" ) );
		return( -1 );

	}

	return( 0 );
}
