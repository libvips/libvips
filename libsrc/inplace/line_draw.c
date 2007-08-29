/* @(#) Line drawer. Faster than the old im_line. Any number of bands,
 * @(#) any type including complex. Instead of passing a PEL value, pass a 
 * @(#) pointer to the pel value you wish to plot. The correct number of 
 * @(#) bytes must be there! Both start and end points should be in the
 * @(#) image.
 * @(#) 
 * @(#) int 
 * @(#) im_fastline( im, x1, y1, x2, y2, pel )
 * @(#) IMAGE *im;
 * @(#) int x1, x2, y1, y2;
 * @(#) PEL *pel;
 * @(#) 
 * @(#) As above, but rather than plotting a point, call a passed function
 * @(#) for every point on the line. Up to three extra args passed down too.
 * @(#) If the passed function returns non-zero, im_fastlineuser stops and
 * @(#) returns non-zero. Start and end points may be outside the image -
 * @(#) clipping is the responsibility of the user function.
 * @(#) 
 * @(#) int 
 * @(#) im_fastlineuser( im, x1, y1, x2, y2, plot_fn, 
 * @(#) 	client1, client2, client3 )
 * @(#) IMAGE *im;
 * @(#) int x1, x2, y1, y2;
 * @(#) int (*plot_fn)();
 * @(#) void *client1, *client2, *client3;
 * @(#) 
 * @(#) int 
 * @(#) plot_fn( im, x, y, client1, client2, client3 )
 * @(#) IMAGE *im;
 * @(#) int x, y;
 * @(#) void *client1, *client2, *client3;
 * @(#) 
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

#define SWAP(A,B) {int t; t = (A); (A) = (B); (B) = t;}

/* Draw a line on a image.
 */
int 
im_fastline( IMAGE *im, int x1, int y1, int x2, int y2, PEL *pel )
{	
	int es = im->Bbits >> 3;
	int ps = es * im->Bands;
	int ls = ps * im->Xsize;
	PEL *p;

	int x, y, dx, dy;
	int err;
	int b;

	if( im_rwcheck( im ) )
		return( -1 );

	/* Check coordinates in range.
	 */
	if(  x1 > im->Xsize || x1 < 0 || 
		y1 > im->Ysize || y1 < 0 || 
	        x2 > im->Xsize || x2 < 0 || 
		y2 > im->Ysize || y2 < 0 ) { 
		im_errormsg( "im_fastline: invalid line cooordinates" ); 
		return( -1 ); 
	}

	/* Find offsets.
	 */
	dx = x2 - x1;
	dy = y2 - y1;

	/* Swap endpoints to reduce number of cases. 
	 */
	if( abs( dx ) >= abs( dy ) && dx < 0 ) {
		/* Swap to get all x greater or equal cases going to the 
		 * right. Do diagonals here .. just have up and right and down
		 * and right now.
		 */
		SWAP( x1, x2 );
		SWAP( y1, y2 );
	}
	else if( abs( dx ) < abs( dy ) && dy < 0 ) {
		/* Swap to get all y greater cases going down the screen.
		 */
		SWAP( x1, x2 );
		SWAP( y1, y2 );
	}

	/* Recalculate dx, dy.
	 */
	dx = x2 - x1;
	dy = y2 - y1;

	/* Start point and offset.
	 */
	x = x1; 
	y = y1;
	p = (PEL *) im->data + x * ps + y * ls;

	/* Plot point macro.
	 */
#define PLOT \
	for( b = 0; b < ps; b++ ) \
		p[b] = pel[b];

	/* Special case: zero width and height is single point.
	 */
	if( dx == 0 && dy == 0 ) {
		PLOT;
	}
	/* Special case vertical and horizontal lines for speed.
	 */
	else if( dx == 0 ) {
		/* Vertical line going down.
		 */
		for( ; y <= y2; y++ ) {
			PLOT;
			p += ls;
		}
	}
	else if( dy == 0 ) {
		/* Horizontal line to the right.
		 */
		for( ; x <= x2; x++ ) {
			PLOT;
			p += ps;
		}
	}
	/* Special case diagonal lines.
	 */
	else if( abs( dy ) == abs( dx ) && dy > 0 ) {
		/* Diagonal line going down and right.
		 */
		for( ; x <= x2; x++ ) {
			PLOT;
			p += ps + ls;
		}
	}
	else if( abs( dy ) == abs( dx ) && dy < 0 ) {
		/* Diagonal line going up and right.
		 */
		for( ; x <= x2; x++ ) {
			PLOT;
			p += ps - ls;
		}
	}
	else if( abs( dy ) < abs( dx ) && dy > 0 ) {
		/* Between -45 and 0 degrees.
		 */
		for( err = 0; x <= x2; x++ ) {
			PLOT;
			p += ps;
			err += dy;
			if( err >= dx ) {
				err -= dx;
				p += ls;
			}
		}
	}
	else if( abs( dy ) < abs( dx ) && dy < 0 ) {
		/* Between 0 and 45 degrees.
		 */
		for( err = 0; x <= x2; x++ ) {
			PLOT;
			p += ps;
			err -= dy;
			if( err >= dx ) {
				err -= dx;
				p -= ls;
			}
		}
	}
	else if( abs( dy ) > abs( dx ) && dx > 0 ) {
		/* Between -45 and -90 degrees.
		 */
		for( err = 0; y <= y2; y++ ) {
			PLOT;
			p += ls;
			err += dx;
			if( err >= dy ) {
				err -= dy;
				p += ps;
			}
		}
	}
	else if( abs( dy ) > abs( dx ) && dx < 0 ) {
		/* Between -90 and -135 degrees.
		 */
		for( err = 0; y <= y2; y++ ) {
			PLOT;
			p += ls;
			err -= dx;
			if( err >= dy ) {
				err -= dy;
				p -= ps;
			}
		}
	}
	else
		error_exit( "internal error #9872659823475982375" );

	im_invalidate( im );

	return( 0 );
}

/* Draw a line on a image with a user plot function. We do no clipping: the
 * user function should check ranges for each pixel when it is called.
 */
int 
im_fastlineuser( IMAGE *im, 
	int x1, int y1, int x2, int y2, 
	int (*fn)(), void *client1, void *client2, void *client3 )
{	
	int x, y, dx, dy;
	int err;

	if( im_rwcheck( im ) )
		return( -1 );

	/* Find offsets.
	 */
	dx = x2 - x1;
	dy = y2 - y1;

	/* Swap endpoints to reduce number of cases. 
	 */
	if( abs( dx ) >= abs( dy ) && dx < 0 ) {
		/* Swap to get all x greater or equal cases going to the 
		 * right. Do diagonals here .. just have up and right and down
		 * and right now.
		 */
		SWAP( x1, x2 );
		SWAP( y1, y2 );
	}
	else if( abs( dx ) < abs( dy ) && dy < 0 ) {
		/* Swap to get all y greater cases going down the screen.
		 */
		SWAP( x1, x2 );
		SWAP( y1, y2 );
	}

	/* Recalculate dx, dy.
	 */
	dx = x2 - x1;
	dy = y2 - y1;

	/* Start point and offset.
	 */
	x = x1; 
	y = y1;

	/* Special case: zero width and height is single point.
	 */
	if( dx == 0 && dy == 0 ) {
		if( fn( im, x, y, client1, client2, client3 ) )
			return( 1 );
	}
	/* Special case vertical and horizontal lines for speed.
	 */
	else if( dx == 0 ) {
		/* Vertical line going down.
		 */
		for( ; y <= y2; y++ ) {
			if( fn( im, x, y, client1, client2, client3 ) )
				return( 1 );
		}
	}
	else if( dy == 0 ) {
		/* Horizontal line to the right.
		 */
		for( ; x <= x2; x++ ) {
			if( fn( im, x, y, client1, client2, client3 ) )
				return( 1 );
		}
	}
	/* Special case diagonal lines.
	 */
	else if( abs( dy ) == abs( dx ) && dy > 0 ) {
		/* Diagonal line going down and right.
		 */
		for( ; x <= x2; x++, y++ ) {
			if( fn( im, x, y, client1, client2, client3 ) )
				return( 1 );
		}
	}
	else if( abs( dy ) == abs( dx ) && dy < 0 ) {
		/* Diagonal line going up and right.
		 */
		for( ; x <= x2; x++, y-- ) {
			if( fn( im, x, y, client1, client2, client3 ) )
				return( 1 );
		}
	}
	else if( abs( dy ) < abs( dx ) && dy > 0 ) {
		/* Between -45 and 0 degrees.
		 */
		for( err = 0; x <= x2; x++ ) {
			if( fn( im, x, y, client1, client2, client3 ) )
				return( 1 );
			err += dy;
			if( err >= dx ) {
				err -= dx;
				y++;
			}
		}
	}
	else if( abs( dy ) < abs( dx ) && dy < 0 ) {
		/* Between 0 and 45 degrees.
		 */
		for( err = 0; x <= x2; x++ ) {
			if( fn( im, x, y, client1, client2, client3 ) )
				return( 1 );
			err -= dy;
			if( err >= dx ) {
				err -= dx;
				y--;
			}
		}
	}
	else if( abs( dy ) > abs( dx ) && dx > 0 ) {
		/* Between -45 and -90 degrees.
		 */
		for( err = 0; y <= y2; y++ ) {
			if( fn( im, x, y, client1, client2, client3 ) )
				return( 1 );
			err += dx;
			if( err >= dy ) {
				err -= dy;
				x++;
			}
		}
	}
	else if( abs( dy ) > abs( dx ) && dx < 0 ) {
		/* Between -90 and -135 degrees.
		 */
		for( err = 0; y <= y2; y++ ) {
			if( fn( im, x, y, client1, client2, client3 ) )
				return( 1 );
			err -= dx;
			if( err >= dy ) {
				err -= dy;
				x--;
			}
		}
	}
	else
		error_exit( "internal error #9872659823475982375" );

	im_invalidate( im );

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
			_( "mask image not 1 band 8 bit uncoded" ) );
		return( -1 );
	}
	if( ink->Bands != in->Bands || ink->BandFmt != in->BandFmt ||
		ink->Coding != in->Coding ) {
		im_error( "im_lineset", 
			_( "ink image does not match in image" ) );
		return( -1 );
	}
	if( ink->Xsize != 1 || ink->Ysize != 1 ) {
		im_error( "im_lineset", _( "ink image not 1x1 pixels" ) );
		return( -1 );
	}

	/* Copy the image thenm fastline to it ... this will render to a "t"
	 * usually.
	 */
	if( im_incheck( mask ) ||
		im_incheck( ink ) ||
		im_copy( in, out ) )
		return( -1 );

	mask_rect.left = mask->Xsize / 2;
	mask_rect.top = mask->Ysize / 2;
	mask_rect.width = mask->Xsize;
	mask_rect.height = mask->Ysize;

	for( i = 0; i < n; i++ ) {
		if( im_fastlineuser( out, x1v[i], y1v[i], x2v[i], y2v[i], 
			im_plotmask, ink->data, mask->data, &mask_rect ) )
			return( -1 );
	}

	return( 0 );
}
