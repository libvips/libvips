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
 * 30/9/10
 * 	- gtk-doc
 * 	- deprecate im_smear()
 * 30/1/12
 * 	- back to the custom smear, the conv one was too slow
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

/**
 * im_draw_smudge:
 * @image: image to smudge
 * @left: area to smudge
 * @top: area to smudge
 * @width: area to smudge
 * @height: area to smudge
 *
 * Smudge a section of @image. Each pixel in the area @left, @top, @width,
 * @height is replaced by the average of the surrounding 3x3 pixels. 
 *
 * This an inplace operation, so @image is changed. It does not thread and will
 * not work well as part of a pipeline. On 32-bit machines it will be limited
 * to 2GB images.
 *
 * See also: im_draw_line().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_smudge( VipsImage *im, int left, int top, int width, int height )
{
	/* Double bands for complex images.
	 */
	int bands = vips_image_get_bands( im ) * 
		(vips_band_format_iscomplex( vips_image_get_format( im ) ) ? 
		 	2 : 1);
	int elements = bands * vips_image_get_width( im );

	VipsRect area, image, clipped;
	double *total;
	int x, y, i, j, b;

	area.left = left;
	area.top = top;
	area.width = width;
	area.height = height;

	/* Don't do the margins.
	 */
	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;
	vips_rect_marginadjust( &image, -1 );

	vips_rect_intersectrect( &area, &image, &clipped );
	if( vips_rect_isempty( &clipped ) )
		return( 0 );

	if( !(total = VIPS_ARRAY( im, bands, double )) ||
		im_rwcheck( im ) )
		return( -1 );

/* What we do for each type.
 */
#define SMUDGE(TYPE) \
	for( y = 0; y < clipped.height; y++ ) { \
		TYPE *q; \
		TYPE *p; \
		\
		q = (TYPE *) VIPS_IMAGE_ADDR( im, \
			clipped.left, clipped.top + y ); \
		p = q - elements - bands; \
		for( x = 0; x < clipped.width; x++ ) { \
			TYPE *p1, *p2; \
 			\
			for( b = 0; b < bands; b++ ) \
				total[b] = 0.0; \
			\
			p1 = p; \
			for( i = 0; i < 3; i++ ) { \
				p2 = p1; \
				for( j = 0; j < 3; j++ ) \
					for( b = 0; b < bands; b++ ) \
						total[b] += *p2++; \
				\
				p1 += elements; \
			} \
 			\
			for( b = 0; b < bands; b++ ) \
				q[b] = (16 * (double) q[b] + total[b]) / 25.0; \
			\
			p += bands; \
			q += bands; \
		} \
	}

	switch( vips_image_get_format( im ) ) { 
	case VIPS_FORMAT_UCHAR: 	SMUDGE( unsigned char ); break; 
	case VIPS_FORMAT_CHAR: 		SMUDGE( char ); break; 
	case VIPS_FORMAT_USHORT: 	SMUDGE( unsigned short ); break; 
	case VIPS_FORMAT_SHORT: 	SMUDGE( short ); break; 
	case VIPS_FORMAT_UINT: 		SMUDGE( unsigned int ); break; 
	case VIPS_FORMAT_INT: 		SMUDGE( int ); break; 
	case VIPS_FORMAT_FLOAT: 	SMUDGE( float ); break; 
	case VIPS_FORMAT_DOUBLE: 	SMUDGE( double ); break; 
	case VIPS_FORMAT_COMPLEX: 	SMUDGE( float ); break;
	case VIPS_FORMAT_DPCOMPLEX: 	SMUDGE( double ); break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}
