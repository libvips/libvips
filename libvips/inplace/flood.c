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
 * 	- rewrite for a scanline based fill, 4x faster!
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

#define SWAP( TYPE, A, B ) { \
	TYPE t = (A); \
	(A) = (B); \
	(B) = t; \
}

/* Size of a scanline buffer. We allocate a list of these to hold scanlines 
 * we need to visit.
 */
#define PBUFSIZE (1000)

/* A scanline we know could contain pixels connected to us.
 *
 * Dir is the direction of connection: +1 means y is increasing, ie. the line 
 * above this one is filled. -1 if y is decreasing.
 */
typedef struct {
	int x1, x2;
	int y;
	int dir;
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
	IMAGE *test;		/* Test this image */
	IMAGE *mark;		/* Mark this image */
	int x, y;
	PEL *ink;		/* Copy of ink param */
	Rect *dout;		/* Write dirty here at end */

	/* Derived stuff.
	 */
	PEL *edge;		/* Boundary colour */
	int equal;		/* Fill to == edge, or != edge */
	int tsize;		/* sizeof( one pel in test ) */
	int msize;		/* sizeof( one pel in mark ) */
	int left, right;	/* Record bounding box of modified pixels */
	int top, bottom;

	/* Read from in, add new possibilities to out.
	 */
	Buffer *in;
	Buffer *out;
} Flood;

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
	while( buf ) {
		Buffer *p;

		p = buf->next;
		im_free( buf );
		buf = p;
	}
}

/* Add a scanline to a buffer, prepending a new buffer if necessary. Return
 * the new head buffer.
 */
static inline Buffer * 
buffer_add( Buffer *buf, Flood *flood, int x1, int x2, int y, int dir )
{
	/* Clip against image size.
	 */
	if( y < 0 || y >= flood->test->Ysize )
		return( buf );
	x1 = IM_CLIP( 0, x1, flood->test->Xsize - 1 );
	x2 = IM_CLIP( 0, x2, flood->test->Xsize - 1 );
	if( x2 - x1 < 0 )
		return( buf );

	buf->scan[buf->n].x1 = x1;
	buf->scan[buf->n].x2 = x2;
	buf->scan[buf->n].y = y;
	buf->scan[buf->n].dir = dir;
	buf->n += 1; 

	if( buf->n == PBUFSIZE ) { 
		Buffer *new;

		if( !(new = buffer_build()) ) 
			return( NULL ); 
		new->next = buf;
		buf = new;
	} 

	return( buf );
}

/* Is p "connected"? ie. is equal to or not equal to flood->edge, depending on
 * whether we are flooding to the edge boundary or flooding edge-coloured
 * pixels.
 */
static inline gboolean
flood_connected( Flood *flood, PEL *p )
{
 	int j;

	for( j = 0; j < flood->tsize; j++ ) 
		if( p[j] != flood->edge[j] ) 
			break;

	return( flood->equal ^ (j < flood->tsize) );
}

/* Faster than memcpy for n < about 20.
 */
static inline void
flood_paint( Flood *flood, PEL *q )
{
 	int j;

	for( j = 0; j < flood->msize; j++ ) 
		q[j] = flood->ink[j];
}

/* Fill left and right, return the endpoints. The start point (x, y) must be 
 * connected.
 */
static void 
flood_scanline( Flood *flood, int x, int y, int *x1, int *x2 )
{
	const int width = flood->mark->Xsize;

	PEL *tp;
	PEL *mp;
	int i;

	g_assert( flood_connected( flood, 
		(PEL *) IM_IMAGE_ADDR( flood->test, x, y ) ) );

	/* Fill this pixel and to the right.
	 */
	tp = (PEL *) IM_IMAGE_ADDR( flood->test, x, y );
	mp = (PEL *) IM_IMAGE_ADDR( flood->mark, x, y );
	for( i = x; i < width && flood_connected( flood, tp ); i++ ) {
		flood_paint( flood, mp );
		tp += flood->tsize;
		mp += flood->msize;
	}
	*x2 = i - 1;

	/* Fill to the left.
	 */
	tp = (PEL *) IM_IMAGE_ADDR( flood->test, x - 1, y );
	mp = (PEL *) IM_IMAGE_ADDR( flood->mark, x - 1, y );
	for( i = x - 1; i > 0 && flood_connected( flood, tp ); i-- ) {
		flood_paint( flood, mp );
		tp -= flood->tsize;
		mp -= flood->msize;
	}
	*x1 = i + 1;

	if( flood->dout ) {
		flood->left = IM_MIN( flood->left, *x1 );
		flood->right = IM_MAX( flood->right, *x2 );
		flood->top = IM_MIN( flood->top, y );
		flood->bottom = IM_MAX( flood->bottom, y );
	}
}

/* We know the line below or above us is filled between x1 and x2. Search our 
 * line in this range looking for an edge pixel we can flood from.
 */
static void
flood_around( Flood *flood, Scan *scan )
{
	int x;

	g_assert( scan->dir == 1 || scan->dir == -1 );

	for( x = scan->x1; x <= scan->x2; x++ ) {
		PEL *p = (PEL *) IM_IMAGE_ADDR( flood->test, x, scan->y );

		if( flood_connected( flood, p ) ) {
			int x1a;
			int x2a;

			flood_scanline( flood, x, scan->y, &x1a, &x2a );

			/* Our new scanline can have up to three more
			 * scanlines connected to it: above, below left, below
			 * right.
			 */
			if( x1a < scan->x1 - 1 )
				flood->out = buffer_add( flood->out, flood,
					x1a, scan->x1 - 1, 
					scan->y - scan->dir, -scan->dir );
			if( x2a > scan->x2 + 1 )
				flood->out = buffer_add( flood->out, flood,
					scan->x2 + 1, x2a, 
					scan->y - scan->dir, -scan->dir );
			flood->out = buffer_add( flood->out, flood,
				x1a, x2a, scan->y + scan->dir, 
				scan->dir );

			x = x2a;
		}
	}
}

static void
flood_buffer( Flood *flood, Buffer *buf )
{
	Buffer *p;

	for( p = buf; p; p = p->next ) {
		int i;

		for( i = 0; i < p->n; i++ )
			flood_around( flood, &buf->scan[i] );

		p->n = 0;
	}
}

static void
flood_all( Flood *flood, int x, int y )
{
	/* Test start pixel ... nothing to do?
	 */
	if( flood_connected( flood, 
		(PEL *) IM_IMAGE_ADDR( flood->test, x, y ) ) ) {
		int x1, x2;

		flood_scanline( flood, x, y, &x1, &x2 );
		flood->in = buffer_add( flood->in, flood, x1, x2, y + 1, 1 );
		flood->in = buffer_add( flood->in, flood, x1, x2, y - 1, -1 );

		while( flood->in->n ) {
			flood_buffer( flood, flood->in );

			SWAP( Buffer *, flood->in, flood->out );
		}
	}
}

static void
flood_free( Flood *flood )
{
	/* Write dirty back to caller.
	 */
	if( flood->dout ) {
		flood->dout->left = flood->left;
		flood->dout->top = flood->top;
		flood->dout->width = flood->right - flood->left + 1;
		flood->dout->height = flood->bottom - flood->top + 1;
	}

	IM_FREE( flood->ink );
	IM_FREE( flood->edge );
	IM_FREEF( buffer_free, flood->in );
	IM_FREEF( buffer_free, flood->out );
	im_free( flood );
}

static Flood *
flood_build( IMAGE *test, IMAGE *mark, int x, int y, PEL *ink, Rect *dout )
{
	Flood *flood = IM_NEW( NULL, Flood );

	if( !flood )
		return( NULL );
	flood->test = test;
	flood->mark = mark;
	flood->x = x;
	flood->y = y;
	flood->ink = NULL;
	flood->dout = dout;
	flood->edge = NULL;
	flood->tsize = IM_IMAGE_SIZEOF_PEL( test );
	flood->msize = IM_IMAGE_SIZEOF_PEL( mark );
	flood->left = x;
	flood->top = y;
	flood->right = x;
	flood->bottom = y;

	flood->in = NULL;
	flood->out = NULL;

	if( !(flood->ink = (PEL *) im_malloc( NULL, flood->msize )) ||
		!(flood->edge = (PEL *) im_malloc( NULL, flood->tsize )) ||
		!(flood->in = buffer_build()) ||
		!(flood->out = buffer_build()) ) {
		flood_free( flood );
		return( NULL );
	}
	memcpy( flood->ink, ink, flood->msize );

	return( flood );
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
im_flood( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
{
	Flood *flood;

	if( im_rwcheck( im ) ||
		im_check_known_coded( "im_flood", im ) )
		return( -1 );
	if( !(flood = flood_build( im, im, x, y, ink, dout )) )
		return( -1 );

	/* Flood to != ink.
	 */
	memcpy( flood->edge, ink, flood->tsize );
	flood->equal = 0;

	flood_all( flood, x, y );

	flood_free( flood );

	im_invalidate( im );

	return( 0 );
}

/**
 * im_flood_blob:
 * @im: image to fill
 * @x: position to start fill
 * @y: position to start fill
 * @ink: colour to fill with
 * @dout: output the bounding box of the filled area 
 *
 * Flood-fill @im with @ink, starting at position @x, @y. The filled area is
 * bounded by pixels that are equal to the start pixel, in other words, it
 * searches for a blob of same-coloured pixels.
 *
 * The bounding box of the modified pixels is returned in @dout.
 *
 * This an inplace operation, so @im is changed. It does not thread and will
 * not work well as part of a pipeline. On 32-bit machines, it will be limited
 * to 2GB images.
 *
 * See also: im_flood(), im_flood_other(), im_flood_blob_copy().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_flood_blob( IMAGE *im, int x, int y, PEL *ink, Rect *dout )
{
	Flood *flood;

	if( im_rwcheck( im ) ||
		im_check_known_coded( "im_flood", im ) )
		return( -1 );
	if( !(flood = flood_build( im, im, x, y, ink, dout )) )
		return( -1 );

	/* Edge is set by colour of start pixel.
	 */
	memcpy( flood->edge, IM_IMAGE_ADDR( im, x, y ), flood->tsize );
	flood->equal = 1;

	flood_all( flood, x, y );

	flood_free( flood );

	im_invalidate( im );

	return( 0 );
}

int
im_flood_other( IMAGE *test, IMAGE *mark, int x, int y, int serial, Rect *dout )
{
	int *m;
	Flood *flood;

	if( im_incheck( test ) ||
		im_rwcheck( mark ) ||
		im_check_known_coded( "im_flood_other", test ) ||
		im_check_uncoded( "im_flood_other", mark ) ||
		im_check_mono( "im_flood_other", mark ) ||
		im_check_format( "im_flood_other", mark, IM_BANDFMT_INT ) ||
		im_check_same_size( "im_flood_other", test, mark ) )
		return( -1 );

	/* Have we done this point already?
	 */
	m = (int *) IM_IMAGE_ADDR( mark, x, y ); 
	if( *m == serial )
		return( 0 );

	if( !(flood = flood_build( test, mark, x, y, (PEL *) &serial, dout )) )
		return( -1 );

	/* Edge is set by colour of start pixel.
	 */
	memcpy( flood->edge, IM_IMAGE_ADDR( test, x, y ), flood->tsize );
	flood->equal = 1;

	flood_all( flood, x, y );

	flood_free( flood );

	im_invalidate( mark );

	return( 0 );
}

/* A Flood blob we can call from nip. Grr! Should be a way to wrap these
 * automatically. Maybe nip could do it if it sees a RW image argument?
 */

int
im_flood_copy( IMAGE *in, IMAGE *out, int x, int y, PEL *ink )
{
	IMAGE *t;

	if( !(t = im_open_local( out, "im_flood_blob_copy", "t" )) ||
		im_copy( in, t ) ||
		im_flood( t, x, y, ink, NULL ) ||
		im_copy( t, out ) ) 
		return( -1 );

	return( 0 );
}

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

int
im_flood_other_copy( IMAGE *test, IMAGE *mark, IMAGE *out, 
	int x, int y, int serial )
{
	IMAGE *t;

	if( !(t = im_open_local( out, "im_flood_other_copy", "t" )) ||
		im_copy( mark, t ) ||
		im_flood_other( test, t, x, y, serial, NULL ) ||
		im_copy( t, out ) ) 
		return( -1 );

	return( 0 );
}

