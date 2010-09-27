/* draw straight lines
 *
 * Copyright: J. Cupitt
 * Written: 15/06/1992
 * Modified : 22/10/92 - clipping constraints changed
 * 22/7/93 JC
 *	- im_incheck() added
 * 16/8/94 JC
 *	- im_incheck() changed to im_makerw()
 * 5/12/06
 * 	- im_invalidate() after paint
 * 1/3/10
 * 	- oops, lineset needs to ask for WIO of mask and ink
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 27/9/10
 * 	- gtk-doc
 * 	- use draw.c base class
 * 	- do pointwise clipping
 * 	- rename as im_draw_line() for consistency
 * 	- cleanups!
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

#include "draw.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define SWAP(A,B) {int t; t = (A); (A) = (B); (B) = t;}

typedef struct _Line {
	Draw draw;

	int x1, y1;
	int x2, y2;

	int dx;
	int dy;

	VipsPlotFn plot;
	void *a;
	void *b;
	void *c;
} Line;

static void
line_free( Line *line )
{
	im__draw_free( DRAW( line ) );
	im_free( line );
}

static Line *
line_new( VipsImage *im, int x1, int y1, int x2, int y2, PEL *ink )
{
	Line *line;

	if( !(line = IM_NEW( NULL, Line )) )
		return( NULL );
	if( !im__draw_init( DRAW( line ), im, ink ) ) {
		line_free( line );
		return( NULL );
	}

	/* Find offsets.
	 */
	line->dx = x2 - x1;
	line->dy = y2 - y1;

	/* Swap endpoints to reduce number of cases. 
	 */
	if( abs( line->dx ) >= abs( line->dy ) && line->dx < 0 ) {
		/* Swap to get all x greater or equal cases going to the 
		 * right. Do diagonals here .. just have up and right and down
		 * and right now.
		 */
		SWAP( x1, x2 );
		SWAP( y1, y2 );
	}
	else if( abs( line->dx ) < abs( line->dy ) && line->dy < 0 ) {
		/* Swap to get all y greater cases going down the screen.
		 */
		SWAP( x1, x2 );
		SWAP( y1, y2 );
	}

	/* Recalculate dx, dy.
	 */
	line->dx = x2 - x1;
	line->dy = y2 - y1;

	line->x1 = x1;
	line->y1 = y1;
	line->x2 = x2;
	line->y2 = y2;

	line->plot = NULL;
	line->a = NULL;
	line->b = NULL;
	line->c = NULL;

	if( x1 < im->Xsize && x1 >= 0 &&
		x2 < im->Xsize && x2 >= 0 &&
		y1 < im->Ysize && y1 >= 0 &&
		y2 < im->Ysize && y2 >= 0 )
		DRAW( line )->noclip = TRUE;

	return( line );
}

static inline int
line_plot( Line *line, int x, int y )
{
	return( line->plot( DRAW( line )->im, x, y, 
		line->a, line->b, line->c ) );
}

static int
line_draw( Line *line )
{
	int x, y, err;

	/* Start point and offset.
	 */
	x = line->x1; 
	y = line->y1;

	/* Special case: zero width and height is single point.
	 */
	if( line->dx == 0 && line->dy == 0 ) {
		if( line_plot( line, x, y ) )
			return( -1 );
	}
	/* Special case vertical and horizontal lines for speed.
	 */
	else if( line->dx == 0 ) {
		/* Vertical line going down.
		 */
		for( ; y <= line->y2; y++ ) {
			if( line_plot( line, x, y ) )
				return( -1 );
		}
	}
	else if( line->dy == 0 ) {
		/* Horizontal line to the right.
		 */
		for( ; x <= line->x2; x++ ) {
			if( line_plot( line, x, y ) )
				return( -1 );
		}
	}
	/* Special case diagonal lines.
	 */
	else if( abs( line->dy ) == abs( line->dx ) && line->dy > 0 ) {
		/* Diagonal line going down and right.
		 */
		for( ; x <= line->x2; x++, y++ ) {
			if( line_plot( line, x, y ) )
				return( -1 );
		}
	}
	else if( abs( line->dy ) == abs( line->dx ) && line->dy < 0 ) {
		/* Diagonal line going up and right.
		 */
		for( ; x <= line->x2; x++, y-- ) {
			if( line_plot( line, x, y ) )
				return( -1 );
		}
	}
	else if( abs( line->dy ) < abs( line->dx ) && line->dy > 0 ) {
		/* Between -45 and 0 degrees.
		 */
		for( err = 0; x <= line->x2; x++ ) {
			if( line_plot( line, x, y ) )
				return( -1 );

			err += line->dy;
			if( err >= line->dx ) {
				err -= line->dx;
				y++;
			}
		}
	}
	else if( abs( line->dy ) < abs( line->dx ) && line->dy < 0 ) {
		/* Between 0 and 45 degrees.
		 */
		for( err = 0; x <= line->x2; x++ ) {
			if( line_plot( line, x, y ) )
				return( -1 );

			err -= line->dy;
			if( err >= line->dx ) {
				err -= line->dx;
				y--;
			}
		}
	}
	else if( abs( line->dy ) > abs( line->dx ) && line->dx > 0 ) {
		/* Between -45 and -90 degrees.
		 */
		for( err = 0; y <= line->y2; y++ ) {
			if( line_plot( line, x, y ) )
				return( -1 );

			err += line->dx;
			if( err >= line->dy ) {
				err -= line->dy;
				x++;
			}
		}
	}
	else if( abs( line->dy ) > abs( line->dx ) && line->dx < 0 ) {
		/* Between -90 and -135 degrees.
		 */
		for( err = 0; y <= line->y2; y++ ) {
			if( line_plot( line, x, y ) )
				return( -1 );

			err -= line->dx;
			if( err >= line->dy ) {
				err -= line->dy;
				x--;
			}
		}
	}
	else
		g_assert( 0 );

	return( 0 );
}

/**
 * im_draw_line_user:
 * @im: image to draw on
 * @x1: start point
 * @y1: start point
 * @x2: end point
 * @y2: end point
 * @ink: value to draw
 *
 * Draws a 1-pixel-wide line on an image. @x1, @y1 and @x2, @y2 must be 
 * within the image.
 *
 * @ink is an array of bytes 
 * containing a valid pixel for the image's format.
 * It must have at least IM_IMAGE_SIZEOF_PEL( @im ) bytes.
 *
 * See also: im_draw_circle().
 *
 * Returns: 0 on success, or -1 on error.
 */

/* Draw a line on a image with a user plot function. We do no clipping: the
 * user function should check ranges for each pixel when it is called.
 */
int 
im_draw_line_user( VipsImage *im, 
	int x1, int y1, int x2, int y2, 
	VipsPlotFn plot, void *a, void *b, void *c )
{
	Line *line;

	if( im_check_coding_known( "im_draw_line", im ) ||
		!(line = line_new( im, x1, y1, x2, y2, NULL )) )
		return( -1 );

	line->plot = plot;
	line->a = a;
	line->b = b;
	line->c = c;

	if( line_draw( line ) ) {
		line_free( line );
		return( -1 );
	}
	line_free( line );

	return( 0 );
}

static int
line_plot_point( VipsImage *im, int x, int y, 
	void *a, void *b, void *c )
{
	Draw *draw = (Draw *) a;

	if( draw->noclip )
		im__draw_pel( draw, (PEL *) IM_IMAGE_ADDR( draw->im, x, y ) );
	else
		im__draw_pel_clip( draw, x, y );

	return( 0 );
}

/**
 * im_draw_line:
 * @im: image to draw on
 * @x1: start point
 * @y1: start point
 * @x2: end point
 * @y2: end point
 * @ink: value to draw
 *
 * Draws a 1-pixel-wide line on an image. 
 *
 * @ink is an array of bytes 
 * containing a valid pixel for the image's format.
 * It must have at least IM_IMAGE_SIZEOF_PEL( @im ) bytes.
 *
 * See also: im_draw_circle().
 *
 * Returns: 0 on success, or -1 on error.
 */
int 
im_draw_line( VipsImage *im, int x1, int y1, int x2, int y2, PEL *ink )
{
	Line *line;

	if( im_check_coding_known( "im_draw_line", im ) ||
		!(line = line_new( im, x1, y1, x2, y2, ink )) ) 
		return( -1 );

	line->plot = line_plot_point;
	line->a = line;

	if( line_draw( line ) ) {
		line_free( line );
		return( 0 );
	}

	line_free( line );

	return( 0 );
}

/* Draw a set of lines with an ink and a mask. A non-inplace operation, handy
 * for nip2.
 */
int
im_lineset( IMAGE *in, IMAGE *out, IMAGE *mask, IMAGE *ink,
	int n, int *x1v, int *y1v, int *x2v, int *y2v )
{
	Rect mask_rect;
	int i;

	if( mask->Bands != 1 || mask->BandFmt != IM_BANDFMT_UCHAR ||
		mask->Coding != IM_CODING_NONE ) {
		im_error( "im_lineset", 
			"%s", _( "mask image not 1 band 8 bit uncoded" ) );
		return( -1 );
	}
	if( ink->Bands != in->Bands || ink->BandFmt != in->BandFmt ||
		ink->Coding != in->Coding ) {
		im_error( "im_lineset", 
			"%s", _( "ink image does not match in image" ) );
		return( -1 );
	}
	if( ink->Xsize != 1 || ink->Ysize != 1 ) {
		im_error( "im_lineset", "%s", _( "ink image not 1x1 pixels" ) );
		return( -1 );
	}

	/* Copy the image then fastline to it ... this will render to a "t"
	 * usually.
	 */
	if( im_copy( in, out ) )
		return( -1 );

	mask_rect.left = mask->Xsize / 2;
	mask_rect.top = mask->Ysize / 2;
	mask_rect.width = mask->Xsize;
	mask_rect.height = mask->Ysize;

	if( im_incheck( ink ) ||
		im_incheck( mask ) )
		return( -1 );

	for( i = 0; i < n; i++ ) {
		if( im_fastlineuser( out, x1v[i], y1v[i], x2v[i], y2v[i], 
			im_plotmask, ink->data, mask->data, &mask_rect ) )
			return( -1 );
	}

	return( 0 );
}
