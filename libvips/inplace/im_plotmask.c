/* @(#) Plot many points in a single call. Pass ink, array containing
 * @(#) 0/255 showing where to plot and Rect showing size of array and 
 * @(#) offset to get to centre of array. ix and iy are where to plot. Rect
 * @(#) can be any size, any position - we clip against the edges of the
 * @(#) image.
 * @(#) 
 * @(#) int
 * @(#) im_plotmask( IMAGE *im, int ix, int iy, PEL *ink, PEL *mask, Rect *r )
 * @(#) 
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 24/10/03 JC
 *	- now blends with 0-255 mask
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
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Paint ink into an 8 or 16 bit integer image.
 */
#define IBLEND( TYPE, TO, INK, B, W ) {  \
	TYPE *tto = (TYPE *) (TO); \
	TYPE *tink = (TYPE *) (INK); \
 	\
	int x, i, j; \
 	\
	for( j = 0, x = 0; x < (W); x++ ) \
		for( i = 0; i < (B); i++, j++ ) \
			tto[j] = (tink[i] * mask_line[x] + \
				tto[j] * (255 - mask_line[x])) / 255; \
}

/* Do the blend with doubles.
 */
#define DBLEND( TYPE, TO, INK, B, W ) {  \
	TYPE *tto = (TYPE *) (TO); \
	TYPE *tink = (TYPE *) (INK); \
 	\
	int x, i, j; \
 	\
	for( j = 0, x = 0; x < (W); x++ ) \
		for( i = 0; i < (B); i++, j++ ) \
			tto[j] = ((double) tink[i] * mask_line[x] + \
				(double) tto[j] * (255 - mask_line[x])) / 255;\
}

/* Blend of complex.
 */
#define CBLEND( TYPE, TO, INK, B, W ) {  \
	TYPE *tto = (TYPE *) (TO); \
	TYPE *tink = (TYPE *) (INK); \
 	\
	int x, i, j; \
 	\
	for( j = 0, x = 0; x < (W); x++ ) \
		for( i = 0; i < (B) * 2; i += 2, j += 2 ) { \
			tto[j] = ((double) tink[i] * mask_line[x] + \
				(double) tto[j] * (255 - mask_line[x])) / 255;\
			tto[j + 1] = ((double) tink[i + 1] * mask_line[x] + \
				(double) tto[j + 1] * (255 - mask_line[x])) / \
				255;\
		} \
}

/* Plot lots of points! Pass ink, array of 0/255 showing where to plot, rect
 * showing size and offset for array. Used for fat lines and text.
 */
int
im_plotmask( IMAGE *im, int ix, int iy, PEL *ink, PEL *mask, Rect *r )
{	
	Rect area, image, clipped;
	int y;
	int mx, my;

	if( im_rwcheck( im ) )
		return( -1 );

	/* Find area we plot.
	 */
	area = *r;
	area.left += ix;
	area.top += iy;
	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	im_rect_intersectrect( &area, &image, &clipped );

	/* Any points left to plot?
	 */
	if( im_rect_isempty( &clipped ) )
		return( 0 );

	/* Find area of mask we use.
	 */
	mx = IM_MAX( 0, clipped.left - area.left );
	my = IM_MAX( 0, clipped.top - area.top );

	/* Loop through image plotting where required.
	 */
	if( im->Coding == IM_CODING_LABQ ) {
		float *lab_buffer;
		float ink_buffer[3];

		if( !(lab_buffer = 
			IM_ARRAY( NULL, clipped.width * 3, float )) )
			return( -1 );

		imb_LabQ2Lab( ink, ink_buffer, 1 );

		for( y = 0; y < clipped.height; y++ ) {
			PEL *to = (PEL *) IM_IMAGE_ADDR( im, 
				clipped.left, y + clipped.top );
			PEL *mask_line = mask + 
				mx + (y + my) * area.width;

			imb_LabQ2Lab( to, lab_buffer, clipped.width );
			DBLEND( float, 
				lab_buffer, ink_buffer, 3, clipped.width ); 
			imb_Lab2LabQ( lab_buffer, to, clipped.width );
		}

		im_free( lab_buffer );
	}
	else {
		for( y = 0; y < clipped.height; y++ ) {
			PEL *to = (PEL *) IM_IMAGE_ADDR( im, 
				clipped.left, y + clipped.top );
			PEL *mask_line = mask + 
				mx + (y + my) * area.width;

			switch( im->BandFmt ) {
			case IM_BANDFMT_UCHAR: 		
				IBLEND( unsigned char, 
					to, ink, im->Bands, clipped.width ); 
				break;

			case IM_BANDFMT_CHAR:  
				IBLEND( signed char, 
					to, ink, im->Bands, clipped.width ); 
				break;

			case IM_BANDFMT_USHORT: 
				IBLEND( unsigned short, 
					to, ink, im->Bands, clipped.width ); 
				break;

			case IM_BANDFMT_SHORT: 
				IBLEND( signed short, 
					to, ink, im->Bands, clipped.width ); 
				break;

			case IM_BANDFMT_UINT: 
				DBLEND( unsigned int, 
					to, ink, im->Bands, clipped.width ); 
				break;

			case IM_BANDFMT_INT: 
				DBLEND( signed int, 
					to, ink, im->Bands, clipped.width ); 
				break;

			case IM_BANDFMT_FLOAT:  
				DBLEND( float, 
					to, ink, im->Bands, clipped.width ); 
				break;

			case IM_BANDFMT_DOUBLE:
				DBLEND( double, 
					to, ink, im->Bands, clipped.width ); 
				break;

			case IM_BANDFMT_COMPLEX:
				CBLEND( float, 
					to, ink, im->Bands, clipped.width ); 
				break;

			case IM_BANDFMT_DPCOMPLEX:
				CBLEND( double, 
					to, ink, im->Bands, clipped.width ); 
				break;

			default:
				im_error( "im_plotmask", 
					"%s", _( "internal error" ) );
				return( -1 );
			}
		}
	}

	im_invalidate( im );

	return( 0 );
}

