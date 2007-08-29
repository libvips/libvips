/* @(#) Smudge and smear a piece of image. Smudge is a low-pass filter,
 * @(#) smear is an early version of smudge which contains a bug: it 
 * @(#) pushes pels to the left a little too. Looks cute though.
 * @(#) 
 * @(#) r is the area to smudge/smear. Clipped against the image edges
 * @(#) properly.
 * @(#) 
 * @(#) int
 * @(#) im_smudge( IMAGE *im, int ix, int iy, Rect *r )
 * @(#) 
 * @(#) int
 * @(#) im_smear( IMAGE *im, int ix, int iy, Rect *r )
 * @(#) 
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
		im_error( "im_smudge", _( "unknown band format" ) );
		return( -1 );

	}

	im_invalidate( im );

	return( 0 );
}

/* Smear a section of an IMAGE. As above, but shift it left a bit.
 */
int
im_smear( IMAGE *im, int ix, int iy, Rect *r )
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
	image.left--;
	im_rect_intersectrect( &area, &image, &clipped );

	/* Any left?
	 */
	if( im_rect_isempty( &clipped ) )
		return( 0 );

/* What we do for each type.
 */
#define SMEAR(TYPE) \
	for( y = clipped.top; y < clipped.top + clipped.height; y++ ) \
		for( x = clipped.left;  \
			x < clipped.left + clipped.width; x++ ) { \
			TYPE *to = (TYPE *) im->data + x * ba + y * el; \
			TYPE *from = to - el; \
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
				to[a] = (40 * (double) to[a+ba] + total[a]) \
					/ 49.0; \
		}

	/* Loop through the remaining pixels.
	 */
	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR: 
		SMEAR(unsigned char); 
		break; 

	case IM_BANDFMT_CHAR: 
		SMEAR(char); 
		break; 

	case IM_BANDFMT_USHORT: 
		SMEAR(unsigned short); 
		break; 

	case IM_BANDFMT_SHORT: 
		SMEAR(short); 
		break; 

	case IM_BANDFMT_UINT: 
		SMEAR(unsigned int); 
		break; 

	case IM_BANDFMT_INT: 
		SMEAR(int); 
		break; 

	case IM_BANDFMT_FLOAT: 
		SMEAR(float); 
		break; 

	case IM_BANDFMT_DOUBLE: 
		SMEAR(double); 
		break; 

	/* Do complex types too. Just treat as float and double, but with
	 * twice the number of bands.
	 */
	case IM_BANDFMT_COMPLEX:
		/* Twice number of bands: double size and bands.
		 */
		ba *= 2;
		el *= 2;

		SMEAR(float);

		break;

	case IM_BANDFMT_DPCOMPLEX:
		/* Twice number of bands: double size and bands.
		 */
		ba *= 2;
		el *= 2;

		SMEAR(double);

		break;

	default:
		im_error( "im_smear", _( "unknown band format" ) );
		return( -1 );
	}

	im_invalidate( im );

	return( 0 );
}
