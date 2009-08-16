/* int im_flood( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
 *
 * Flood fill from point (x,y) with colour ink. Flood up to boundary == ink.
 * Any type, any number of bands, IM_CODING_LABQ too. Returns the bounding box 
 * of the modified pixels in dout, whether it succeeds or not.
 *
 * Currently a rather inefficient pixel-based algorithm, should put something
 * better in, really. Speed isn't likely to be a problem, except for very
 * large images.
 *
 * JC 30/8/97
 *	- VIPSified, cleaned up, from "John Robinson's prog to fill 
 *	  enclosed areas"
 *	- something Kirk gave me, so thanks John 
 * JC 1/10/97
 *	- swapped inner memcmp/cpy for a loop ... faster for small pixels
 * 13/7/02 JC
 *	- im_flood_blob() added
 * 5/12/06
 * 	- im_invalidate() after paint
 * 24/3/09
 * 	- added IM_CODING_RAD support
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
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Size of a point buffer. We allocate a list of these to hold points we need
 * to visit.
 */
#define PBUFSIZE (1000)

/* An xy position.
 */
typedef struct {
	int x, y;
} Point;

/* A buffer of points, and how many of them have been used. When full, alloc a
 * new buffer, and link it on.
 */
typedef struct _Buffer {
	struct _Buffer *next;
	int n;
	Point points[PBUFSIZE];
} Buffer;

/* Our state.
 */
typedef struct {
	/* Parameters.
	 */
	IMAGE *im;
	int x, y;
	PEL *ink;		/* Copy of ink param */
	Rect *dout;		/* Write dirty here at end */

	/* Derived stuff.
	 */
	PEL *edge;		/* Boundary colour */
	int equal;		/* Fill to == edge, or != edge */
	int ps;			/* sizeof( one pel ) */
	int ls;			/* sizeof( one line ) */
	int left, right;	/* Area will fill within */
	int top, bottom;
	Rect dirty;		/* Bounding box of pixels we have changed */

	/* Two buffers of points which we know need checking.
	 */
	Buffer *buf1;
	Buffer *buf2;
} State;

/* Alloc a new buffer.
 */
static Buffer *
build_buffer( void )
{
	Buffer *buf = IM_NEW( NULL, Buffer );

	if( !buf )
		return( NULL );
	buf->next = NULL;
	buf->n = 0;

	return( buf );
}

/* Free a chain of buffers.
 */
static void
free_buffer( Buffer *buf )
{
	IM_FREE( buf->next );
	im_free( buf );
}

/* Free a state.
 */
static void
free_state( State *st )
{
	/* Write dirty back to caller.
	 */
	if( st->dout )
		*st->dout = st->dirty;

	/* Free our stuff.
	 */
	IM_FREE( st->ink );
	IM_FREEF( free_buffer, st->buf1 );
	IM_FREEF( free_buffer, st->buf2 );
	im_free( st );
}

/* Build a state.
 */
static State *
build_state( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
{
	State *st = IM_NEW( NULL, State );

	if( !st )
		return( NULL );
	st->im = im;
	st->x = x;
	st->y = y;
	st->ink = NULL;
	st->dout = dout;
	st->ps = IM_IMAGE_SIZEOF_PEL( im );
	st->ls = IM_IMAGE_SIZEOF_LINE( im );
	st->buf1 = NULL;
	st->buf2 = NULL;
	st->left = 0;
	st->top = 0;
	st->right = im->Xsize;
	st->bottom = im->Ysize;
	st->dirty.left = x;
	st->dirty.top = y;
	st->dirty.width = 0;
	st->dirty.height = 0;

	if( !(st->ink = (PEL *) im_malloc( NULL, st->ps )) ||
		!(st->edge = (PEL *) im_malloc( NULL, st->ps )) ||
		!(st->buf1 = build_buffer()) ||
		!(st->buf2 = build_buffer()) ) {
		free_state( st );
		return( NULL );
	}
	memcpy( st->ink, ink, st->ps );

	return( st );
}

/* Add xy to buffer, move buffer on on overflow.
 */
#define ADD( BUF, X, Y ) { \
	BUF->points[BUF->n].x = X; \
	BUF->points[BUF->n].y = Y; \
	BUF->n++; \
	if( BUF->n == PBUFSIZE ) { \
		if( !BUF->next ) { \
			if( !(BUF->next = build_buffer()) ) \
				return( -1 ); \
		} \
		BUF = BUF->next; \
		BUF->n = 0; \
	} \
}

/* If point != edge, add it to out.
 */
#define ADDIFNOTEDGE( P, X, Y ) { \
	PEL *p1 = (P); \
 	\
	for( j = 0; j < st->ps; j++ ) \
		if( p1[j] != st->edge[j] ) { \
			ADD( out, X, Y ); \
			break; \
		} \
}

/* If point == edge, add it to out.
 */
#define ADDIFEDGE( P, X, Y ) { \
	PEL *p1 = (P); \
 	\
	for( j = 0; j < st->ps; j++ ) \
		if( p1[j] != st->edge[j] ) \
			break; \
	if( j == st->ps ) \
		ADD( out, X, Y ); \
}

/* Read points to fill from in, write new points to out.
 */
static int
dofill( State *st, Buffer *in, Buffer *out )
{
	int i, j;

	/* Clear output buffer.
	 */
	out->n = 0;

	/* Loop over chain of input buffers.
	 */
	for(;;) {
		/* Loop for this buffer.
		 */
		for( i = 0; i < in->n; i++ ) {
			/* Find this pixel.
			 */
			int x = in->points[i].x;
			int y = in->points[i].y;
			PEL *p = (PEL *) st->im->data + x*st->ps + y*st->ls;

			/* Is it still not fore? May have been set by us
			 * earlier.
			 */
			for( j = 0; j < st->ps; j++ )
				if( p[j] != st->ink[j] )
					break;
			if( j == st->ps )
				continue;

			/* Set this pixel.
			 */
			for( j = 0; j < st->ps; j++ )
				p[j] = st->ink[j];

			/* Changes bb of dirty area?
			 */
			if( x < st->dirty.left ) {
				st->dirty.left -= x;
				st->dirty.width += x;
			}
			else if( x > st->dirty.left + st->dirty.width )
				st->dirty.width += x;

			if( y < st->dirty.top ) {
				st->dirty.top -= y;
				st->dirty.height += y;
			}
			else if( y > st->dirty.top + st->dirty.height )
				st->dirty.height += y;

			/* Propogate to neighbours.
			 */
			if( st->equal ) {
				if( x < st->right - 1 )
					ADDIFEDGE( p + st->ps, x + 1, y );
				if( x > st->left )
					ADDIFEDGE( p - st->ps, x - 1, y );
				if( y < st->bottom - 1 )
					ADDIFEDGE( p + st->ls, x, y + 1 );
				if( y > st->top )
					ADDIFEDGE( p - st->ls, x, y - 1 );
			}
			else {
				if( x < st->right - 1 )
					ADDIFNOTEDGE( p + st->ps, x + 1, y );
				if( x > st->left )
					ADDIFNOTEDGE( p - st->ps, x - 1, y );
				if( y < st->bottom - 1 )
					ADDIFNOTEDGE( p + st->ls, x, y + 1 );
				if( y > st->top )
					ADDIFNOTEDGE( p - st->ls, x, y - 1 );
			}
		}

		if( in->n == PBUFSIZE )
			/* Buffer full ... must be another one.
			 */
			in = in->next;
		else
			break;
	}

	return( 0 );
}

int
im_flood( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
{
	State *st;
	Buffer *in, *out, *t;
	PEL *p;

	if( im_rwcheck( im ) )
		return( -1 );
	if( im->Coding != IM_CODING_NONE && 
		im->Coding != IM_CODING_LABQ &&
		im->Coding != IM_CODING_RAD ) {
		im_error( "im_flood", "%s", 
			_( "Coding should be NONE, LABQ or RAD" ) ); 
		return( -1 );
	}
	if( !(st = build_state( im, x, y, ink, dout )) )
		return( -1 );

	/* Test start pixel ... nothing to do?
	 */
	p = (PEL *) im->data + x*st->ps + y*st->ls;
	if( memcmp( p, ink, st->ps ) == 0 ) {
		free_state( st );
		return( 0 );
	}

	/* Flood to != ink.
	 */
	memcpy( st->edge, ink, st->ps );
	st->equal = 0;

	/* Add start pixel to the work buffer, and loop.
	 */
	ADD( st->buf1, x, y )
	for( in = st->buf1, out = st->buf2; 
		in->n > 0; t = in, in = out, out = t )
		if( dofill( st, in, out ) ) {
			free_state( st );
			return( -1 );
		}
	
	free_state( st );

	im_invalidate( im );

	return( 0 );
}

int
im_flood_blob( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
{
	State *st;
	Buffer *in, *out, *t;
	PEL *p;

	if( im_rwcheck( im ) )
		return( -1 );
	if( im->Coding != IM_CODING_NONE && 
		im->Coding != IM_CODING_LABQ &&
		im->Coding != IM_CODING_RAD ) {
		im_error( "im_flood", "%s", 
			_( "Coding should be NONE, LABQ or RAD" ) ); 
		return( -1 );
	}
	if( !(st = build_state( im, x, y, ink, dout )) )
		return( -1 );

	/* Edge is set by colour of start pixel.
	 */
	p = (PEL *) im->data + x*st->ps + y*st->ls;
	memcpy( st->edge, p, st->ps );
	st->equal = 1;

	/* Add start pixel to the work buffer, and loop.
	 */
	ADD( st->buf1, x, y )
	for( in = st->buf1, out = st->buf2; 
		in->n > 0; t = in, in = out, out = t )
		if( dofill( st, in, out ) ) {
			free_state( st );
			return( -1 );
		}
	
	free_state( st );

	im_invalidate( im );

	return( 0 );
}

/* A Flood blob we can call from nip. Grr! Should be a way to wrap these
 * automatically. Maybe nip could do it if it seems a RW image argument?
 */
int
im_flood_blob_copy( IMAGE *in, IMAGE *out, int x, int y, PEL *ink )
{
	IMAGE *t;

	if( !(t = im_open_local( out, "im_flood_blob_copy", "t" )) ||
		im_copy( in, t ) ||
		im_flood_blob( t, x, y, ink, NULL ) ||
		im_copy( t, out ) ) 
		return( -1 );

	return( 0 );
}


