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

/* Add an xy point to a buffer, appending a new buffer if necessary. Return
 * the new tail buffer.
 */
static inline Buffer * 
buffer_add( Buffer *buf, int x, int y )
{
	/* buf can be NULL if we've had an error.
	 */
	if( !buf )
		return( NULL );

	buf->points[buf->n].x = x;
	buf->points[buf->n].y = y;
	buf->n++; 

	if( buf->n == PBUFSIZE ) { 
		if( !buf->next ) { 
			if( !(buf->next = buffer_build()) ) 
				return( NULL ); 
		} 
		buf = buf->next; 
		buf->n = 0; 
	} 

	return( buf );
}

static inline Buffer *
buffer_add_ifnotedge( Buffer *buf, State *st, PEL *p, int x, int y )
{
 	int j;

	for( j = 0; j < st->ps; j++ ) 
		if( p[j] != st->edge[j] ) { 
			buf = buffer_add( buf, x, y ); 
			break; 
		} 

	return( buf );
}

static inline Buffer *
buffer_add_ifedge( Buffer *buf, State *st, PEL *p, int x, int y )
{
 	int j;

	for( j = 0; j < st->ps; j++ ) 
		if( p[j] != st->edge[j] ) 
			break; 
	if( j == st->ps ) 
		buf = buffer_add( buf, x, y );

	return( buf );
}

static inline gboolean
pixel_equals( PEL *p, PEL *ink, int n )
{
 	int j;

	for( j = 0; j < n; j++ ) 
		if( p[j] != ink[j] ) 
			break; 

	return( j == n ) 
}

/* Faster than memcpy for n < about 20.
 */
static inline void
pixel_copy( PEL *p, PEL *ink, int n )
{
 	int j;

	for( j = 0; j < n; j++ ) 
		p[j] = ink[j];
}

/* Fill a scanline with ink while pixels are equal to edge. We know x/y must
 * be equal to edge.
 */
static void 
fill_scanline_equal( State *st, int x, int y, int *x1, int *x2 )
{
	PEL *p = IM_IMAGE_ADDR( st->im, x, y );

	int i;
	PEL *q;


	g_assert( pixel_equals( p, st->edge, st->ps ) );

	/* Fill this pixel and to the right.
	 */
	for( q = p, i = 0; 
		i < im->Xsize - x && pixel_equals( q, st->edge, st->ps ); 
		q += st->ps, i++ ) 
		pixel_copy( q, st->ink, st->ps );
	*x2 = x + i - 1;

	/* Fill to the left.
	 */
	for( q = p - st->ps, i = 1;
		i > x && pixel_equals( q, st->edge, st->ps ); 
		q -= st->ps, i++ ) 
		pixel_copy( q, st->ink, st->ps );
	*x1 = x - (i - 1);
}

/* We know the line below us is filled between x1 and x2. Search our line in
 * this range looking for an edge pixel we can flood from.
 */
static void
fill_scanline_above( State *st, int x1, int x2, int y )
{
	PEL *p = IM_IMAGE_ADDR( st->im, x1, y );

	PEL *q;
	int x;

	for( x = x1, x <= x2; x++ ) 
		if( pixel_equals(   
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
	IM_FREEF( buffer_free, st->buf1 );
	IM_FREEF( buffer_free, st->buf2 );
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
		!(st->buf1 = buffer_build()) ||
		!(st->buf2 = buffer_build()) ) {
		state_free( st );
		return( NULL );
	}
	memcpy( st->ink, ink, st->ps );

	return( st );
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
					out = buffer_add_ifedge( out, st, 
						p + st->ps, x + 1, y );
				if( x > st->left )
					out = buffer_add_ifedge( out, st, 
						p - st->ps, x - 1, y );
				if( y < st->bottom - 1 )
					out = buffer_add_ifedge( out, st, 
						p + st->ls, x, y + 1 );
				if( y > st->top )
					out = buffer_add_ifedge( out, st, 
						p - st->ls, x, y - 1 );
			}
			else {
				if( x < st->right - 1 )
					out = buffer_add_ifnotedge( out, st, 
						p + st->ps, x + 1, y );
				if( x > st->left )
					out = buffer_add_ifnotedge( out, st, 
						p - st->ps, x - 1, y );
				if( y < st->bottom - 1 )
					out = buffer_add_ifnotedge( out, st, 
						p + st->ls, x, y + 1 );
				if( y > st->top )
					out = buffer_add_ifnotedge( out, st, 
						p - st->ls, x, y - 1 );
			}

			/* There was an error in one of the adds.
			 */
			if( !out )
				return( -1 );
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
	 */
	st->buf1 = buffer_add( st->buf1, x, y );
	for( in = st->buf1, out = st->buf2; 
		in->n > 0; t = in, in = out, out = t )
		if( dofill( st, in, out ) ) {
			state_free( st );
			return( -1 );
		}

	state_free( st );

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
 * bounded by pixels that are not equal to the colour of the start pixel, in 
 * other words, it searches for a blob of connected pixels of the same colour.
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
	State *st;
	Buffer *in, *out, *t;
	PEL *p;

	if( im_rwcheck( im ) ||
		im_check_known_coded( "im_flood", im ) )
		return( -1 );
	if( !(st = state_build( im, x, y, ink, dout )) )
		return( -1 );

	/* Edge is set by colour of start pixel.
	 */
	p = (PEL *) im->data + x*st->ps + y*st->ls;
	memcpy( st->edge, p, st->ps );
	st->equal = 1;

	/* Add start pixel to the work buffer, and loop.
	 */
	st->buf1 = buffer_add( st->buf1, x, y );
	for( in = st->buf1, out = st->buf2; 
		in->n > 0; t = in, in = out, out = t )
		if( dofill( st, in, out ) ) {
			state_free( st );
			return( -1 );
		}
	
	state_free( st );

	im_invalidate( im );

	return( 0 );
}

/**
 * im_flood_blob_copy:
 * @in: input image
 * @out: output image
 * @x: position to start fill
 * @y: position to start fill
 * @ink: colour to fill with
 *
 * Copy @in to a otemporary memory buffer, then flood-fill with @ink, 
 * starting at position @x, @y. The filled area is
 * bounded by pixels that are not equal to the colour of the start pixel, in 
 * other words, it searches for a blob of connected pixels of the same colour.
 * The temporary image is then copied to @out.
 *
 * See also: im_flood(), im_flood_other(), im_flood_blob_copy().
 *
 * Returns: 0 on success, or -1 on error.
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
