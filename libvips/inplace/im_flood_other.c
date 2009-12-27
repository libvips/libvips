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
	IMAGE *mask;
	IMAGE *test;
	int x, y;
	unsigned int serial;	

	/* Derived stuff.
	 */
	PEL *edge;		/* Searching for these pixels */
	int ps;			/* sizeof( one pel ) */
	int ls;			/* sizeof( one line ) */
	int left, right;	/* Area will fill within */
	int top, bottom;

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
	IM_FREE( st->edge );
	IM_FREEF( free_buffer, st->buf1 );
	IM_FREEF( free_buffer, st->buf2 );
	im_free( st );
}

/* Build a state.
 */
static State *
build_state( IMAGE *mask, IMAGE *test, int x, int y, int serial )
{
	State *st = IM_NEW( NULL, State );

	if( !st )
		return( NULL );
	st->mask = mask;
	st->test = test;
	st->x = x;
	st->y = y;
	st->serial = serial;
	st->edge = NULL;
	st->ps = IM_IMAGE_SIZEOF_PEL( test );
	st->ls = IM_IMAGE_SIZEOF_LINE( test );
	st->buf1 = NULL;
	st->buf2 = NULL;
	st->left = 0;
	st->top = 0;
	st->right = test->Xsize;
	st->bottom = test->Ysize;

	if( !(st->edge = (PEL *) im_malloc( NULL, st->ps )) ||
		!(st->buf1 = build_buffer()) ||
		!(st->buf2 = build_buffer()) ) {
		free_state( st );
		return( NULL );
	}

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

/* If point == blob colour, add it to out.
 */
#define ADDIFEDGE( P, X, Y ) { \
	const PEL *p1 = (P); \
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
	const int width = st->mask->Xsize;

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
			const int x = in->points[i].x;
			const int y = in->points[i].y;
			const PEL *p = (PEL *) st->test->data + 
				x * st->ps + y * st->ls;
			int *m = (int *) st->mask->data + x + y * width;

			/* Has it been marked already? Done.
			 */
			if( *m == st->serial )
				continue;
			*m = st->serial;

			/* Propogate to neighbours.
			 */
			if( x < st->right - 1 && !m[1] )
				ADDIFEDGE( p + st->ps, x + 1, y );
			if( x > st->left && !m[-1] )
				ADDIFEDGE( p - st->ps, x - 1, y );
			if( y < st->bottom - 1 && !m[width] )
				ADDIFEDGE( p + st->ls, x, y + 1 );
			if( y > st->top && !m[-width]  )
				ADDIFEDGE( p - st->ls, x, y - 1 );
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
im_flood_other_old( IMAGE *mask, IMAGE *test, int x, int y, int serial )
{
	State *st;
	Buffer *in, *out, *t;
	PEL *p;
	int *m;

	if( im_rwcheck( mask ) ||
		im_incheck( test ) )
		return( -1 );

	if( im_check_known_coded( "im_flood_other", test ) ||
		im_check_uncoded( "im_flood_other", mask ) ||
		im_check_mono( "im_flood_other", mask ) ||
		im_check_format( "im_flood_other", mask, IM_BANDFMT_INT ) ||
		im_check_same_size( "im_flood_other", test, mask ) )
		return( -1 );

	/* Make sure the mask has zero at the start position. If it does, we
	 * must have filled with this serial already, so ... job done.
	 */
	m = (int *) mask->data + x + y * mask->Xsize;
	if( *m == serial )
		return( 0 );

	if( !(st = build_state( mask, test, x, y, serial )) )
		return( -1 );

	/* Edge is set by colour of start pixel.
	 */
	p = (PEL *) test->data + x * st->ps + y * st->ls;
	memcpy( st->edge, p, st->ps );

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

	im_invalidate( mask );

	return( 0 );
}

/* A Flood blob we can call from nip. Grr! Should be a way to wrap these
 * automatically. Maybe nip could do it if it sees a RW image argument?
 */
int
im_flood_other_copy_old( IMAGE *mask, IMAGE *test, IMAGE *out, 
	int x, int y, int serial )
{
	IMAGE *t;

	if( !(t = im_open_local( out, "im_flood_other_copy", "t" )) ||
		im_copy( mask, t ) ||
		im_flood_other_old( t, test, x, y, serial ) ||
		im_copy( t, out ) ) 
		return( -1 );

	return( 0 );
}
