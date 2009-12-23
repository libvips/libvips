/* flood-fill
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
 * 28/9/09
 * 	- ooops, tiny memleak
 * 17/12/09
 * 	- use inline rather than defines, so we can add scanline fills more
 * 	  easily
 * 	- gtk-doc comments
 * 21/12/09
 * 	- rewrite for a scanline based fill
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

/* Size of a scanline buffer. We allocate a list of these to hold scanlines 
 * we need to visit.
 */
#define PBUFSIZE (1000)

/* A scanline we know could contain pixels connected to us.
 */
typedef struct {
	int x1, x2;
	int y;
} Scan;

/* A buffer of scanlines, and how many of them have been used. If ->next is
 * non-NULL, the next block could contain more of them.
 *
 * We keep a pair of these, then loop over one and write to the other.
 */
typedef struct _Buffer {
	struct _Buffer *next;
	int n;
	Scan scan[PBUFSIZE];
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

	/* We need to flood above and below these scanlines.
	 */
	Buffer *up;
	Buffer *down;
	Buffer *read_up;
	Buffer *read_down;
} State;

/* Alloc a new buffer.
 */
static Buffer *
buffer_build( void )
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
buffer_free( Buffer *buf )
{
	IM_FREE( buf->next );
	im_free( buf );
}

/* Add a scanline to a buffer, prepending a new buffer if necessary. Return
 * the new head buffer.
 */
static inline Buffer * 
buffer_add( State *st, Buffer *buf, int x1, int x2, int y )
{
	/* Clip against image size.
	 */
	if( y < 0 || y > st->im->Ysize )
		return( buf );
	x1 = IM_CLIP( 0, x1, st->im->Xsize );
	x2 = IM_CLIP( 0, x2, st->im->Xsize );
	if( x2 - x1 <= 0 )
		return( buf );

	buf->scan[buf->n].x1 = x1;
	buf->scan[buf->n].x2 = x2;
	buf->scan[buf->n].y = y;
	buf->n++; 

	if( buf->n == PBUFSIZE ) { 
		Buffer *new;

		if( !(new = buffer_build()) ) 
			return( NULL ); 
		new->next = buf;
		buf = new;
	} 

	return( buf );
}

/* Is p "connected"? ie. is equal to or not equal to st->edge, depending on
 * whether we are flooding to the edge boundary, or flooding edge-coloured
 * pixels.
 */
static inline gboolean
pixel_connected( State *st, PEL *p )
{
 	int j;

	for( j = 0; j < st->ps; j++ ) 
		if( p[j] != st->edge[j] ) 
			break;

	return( st->equal ^ (j == st->ps) );
}

/* Faster than memcpy for n < about 20.
 */
static inline void
pixel_paint( State *st, PEL *q )
{
 	int j;

	for( j = 0; j < st->ps; j++ ) 
		q[j] = st->ink[j];
}

/* Fill a left and right, return the endpoints. The start point (x, y) must be 
 * connected.
 */
static void 
fill_scanline( State *st, int x, int y, int *x1, int *x2 )
{
	PEL *p = (PEL *) IM_IMAGE_ADDR( st->im, x, y );

	int i;
	PEL *q;

	g_assert( pixel_connected( st, p ) );

	/* Fill this pixel and to the right.
	 */
	for( q = p, i = 0; 
		i < st->im->Xsize - x && pixel_connected( st, q ); 
		q += st->ps, i++ ) 
		pixel_paint( st, q );
	*x2 = x + i - 1;

	/* Fill to the left.
	 */
	for( q = p - st->ps, i = 1;
		i > x && pixel_connected( st, q ); 
		q -= st->ps, i++ ) 
		pixel_paint( st, q );
	*x1 = x - (i - 1);
}

/* We know the line below or above us is filled between x1 and x2. Search our 
 * line in this range looking for an edge pixel we can flood from.
 *
 * "direction" is -1 if we're going up, +1 if we're filling down.
 */
static void
fill_around( State *st, Scan *scan, int dir )
{
	int x;

	g_assert( dir == 1 || dir == -1 );

	for( x = scan->x1; x <= scan->x2; x++ ) {
		PEL *p = (PEL *) IM_IMAGE_ADDR( st->im, x, scan->y );

		if( pixel_connected( st, p ) ) {
			int x1a;
			int x2a;

			fill_scanline( st, x, scan->y, &x1a, &x2a );

			/* Our new scanline can have up to three more
			 * scanlines connected to it: above, below left, below
			 * right.
			 */
			if( x1a < scan->x1 - 1 )
				st->down = buffer_add( st, st->down,
					x1a, scan->x1 - 1, scan->y - dir );
			if( x2a > scan->x2 + 1 )
				st->down = buffer_add( st, st->down,
					scan->x2 + 1, x2a, scan->y - dir );
			st->up = buffer_add( st, st->up,
				x1a, x2a, scan->y + dir );

			x = x2a;
		}
	}
}

static void
fill_buffer( State *st, Buffer *buf, int dir )
{
	Buffer *p;

	for( p = buf; p; p = p->next ) {
		int i;

		for( i = 0; i < p->n; i++ )
			fill_around( st, &buf->scan[i], dir );

		p->n = 0;
	}
}

static void
fill_all( State *st )
{
	while( st->read_up || st->read_down ) {
		Buffer *p;

		fill_buffer( st, st->read_up, -1 );
		fill_buffer( st, st->read_down, -1 );

		p = st->read_up;
		st->read_up = st->up;
		st->up = p;

		p = st->read_down;
		st->read_down = st->down;
		st->down = p;
	}
}

/* Free a state.
 */
static void
state_free( State *st )
{
	/* Write dirty back to caller.
	 */
	if( st->dout )
		*st->dout = st->dirty;

	/* Free our stuff.
	 */
	IM_FREE( st->ink );
	IM_FREE( st->edge );
	IM_FREEF( buffer_free, st->up );
	IM_FREEF( buffer_free, st->down );
	IM_FREEF( buffer_free, st->read_up );
	IM_FREEF( buffer_free, st->read_down );
	im_free( st );
}

/* Build a state.
 */
static State *
state_build( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
{
	State *st = IM_NEW( NULL, State );

	if( !st )
		return( NULL );
	st->im = im;
	st->x = x;
	st->y = y;
	st->ink = NULL;
	st->dout = dout;
	st->edge = NULL;
	st->ps = IM_IMAGE_SIZEOF_PEL( im );
	st->ls = IM_IMAGE_SIZEOF_LINE( im );
	st->left = 0;
	st->top = 0;
	st->right = im->Xsize;
	st->bottom = im->Ysize;
	st->dirty.left = x;
	st->dirty.top = y;
	st->dirty.width = 0;
	st->dirty.height = 0;

	st->up = NULL;
	st->down = NULL;
	st->read_up = NULL;
	st->read_down = NULL;

	if( !(st->ink = (PEL *) im_malloc( NULL, st->ps )) ||
		!(st->edge = (PEL *) im_malloc( NULL, st->ps )) ||
		!(st->up = buffer_build()) ||
		!(st->down = buffer_build()) ||
		!(st->read_up = buffer_build()) ||
		!(st->read_down = buffer_build()) ) {
		state_free( st );
		return( NULL );
	}
	memcpy( st->ink, ink, st->ps );

	return( st );
}

/**
 * im_flood:
 * @im: image to fill
 * @x: position to start fill
 * @y: position to start fill
 * @ink: colour to fill with
 * @dout: output the bounding box of the filled area 
 *
 * Flood-fill @im with @ink, starting at position @x, @y. The filled area is
 * bounded by pixels that are equal to the ink colour, in other words, it
 * searches for pixels enclosed by a line of @ink.
 *
 * The bounding box of the modified pixels is returned in @dout.
 *
 * This an inplace operation, so @im is changed. It does not thread and will
 * not work well as part of a pipeline. On 32-bit machines, it will be limited
 * to 2GB images.
 *
 * See also: im_flood_blob(), im_flood_other(), im_flood_blob_copy().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_flood_new( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
{
	State *st;
	Buffer *in, *out, *t;
	PEL *p;

	if( im_rwcheck( im ) ||
		im_check_known_coded( "im_flood", im ) )
	if( !(st = state_build( im, x, y, ink, dout )) )
		return( -1 );

	/* Test start pixel ... nothing to do?
	 */
	p = (PEL *) im->data + x*st->ps + y*st->ls;
	if( memcmp( p, ink, st->ps ) == 0 ) {
		state_free( st );
		return( 0 );
	}

	/* Flood to != ink.
	 */
	memcpy( st->edge, ink, st->ps );
	st->equal = 0;

	/* Add start pixel to the work buffer, and loop.
	st->buf1 = buffer_add( st, st->buf1, x, y );
	for( in = st->buf1, out = st->buf2; 
		in->n > 0; t = in, in = out, out = t )
		if( dofill( st, in, out ) ) {
			state_free( st );
			return( -1 );
		}
	 */

	state_free( st );

	im_invalidate( im );

	return( 0 );
}

int
im_flood_new_copy( IMAGE *in, IMAGE *out, int x, int y, PEL *ink )
{
	IMAGE *t;

	if( !(t = im_open_local( out, "im_flood_blob_copy", "t" )) ||
		im_copy( in, t ) ||
		im_flood_new( t, x, y, ink, NULL ) ||
		im_copy( t, out ) ) 
		return( -1 );

	return( 0 );
}


