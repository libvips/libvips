/* flood-fill
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
 * 	- rewrite for a scanline based fill, about 4x faster!
 * 	- allow separate test and mark images
 * 22/1/10
 * 	- flood_blob could loop if start point == ink
 * 6/3/10
 * 	- don't im_invalidate() after paint, this now needs to be at a higher
 * 	  level
 * 27/9/10
 * 	- use Draw base class
 * 21/1/14
 * 	- redo as a class
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
#include <string.h>

#include <vips/vips.h>

#include "draw.h"

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

/* Base class.
 */
typedef struct _VipsFlood {
	VipsDraw draw;

	/* Parameters.
	 */
	int x;
	int y;
	VipsImage *test;	/* Test this image */
	gboolean equal;		/* Fill to == edge, or != edge */

	int left;		/* Record bounding box of modified pixels */
	int right;	
	int top;
	int bottom;
	int width;
	int height;

	/* Derived stuff.
	 */
	VipsPel *edge;		/* Boundary colour */
	int tsize;		/* sizeof( one pel in test ) */

	/* Read from in, add new possibilities to out.
	 */
	Buffer *in;
	Buffer *out;
} VipsFlood;

typedef VipsDrawClass VipsFloodClass;

G_DEFINE_ABSTRACT_TYPE( VipsFlood, vips_flood, VIPS_TYPE_DRAW );

/* Alloc a new buffer.
 */
static Buffer *
buffer_build( void )
{
	Buffer *buf;

	buf = g_new( Buffer, 1 );
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
		g_free( buf );
		buf = p;
	}
}

/* Add a scanline to a buffer, prepending a new buffer if necessary. Return
 * the new head buffer.
 */
static inline Buffer * 
buffer_add( Buffer *buf, VipsFlood *flood, int x1, int x2, int y, int dir )
{
	/* Clip against image size.
	 */
	if( y < 0 || 
		y >= flood->test->Ysize )
		return( buf );
	x1 = VIPS_CLIP( 0, x1, flood->test->Xsize - 1 );
	x2 = VIPS_CLIP( 0, x2, flood->test->Xsize - 1 );
	if( x2 - x1 < 0 )
		return( buf );

	buf->scan[buf->n].x1 = x1;
	buf->scan[buf->n].x2 = x2;
	buf->scan[buf->n].y = y;
	buf->scan[buf->n].dir = dir;
	buf->n += 1; 

	if( buf->n == PBUFSIZE ) { 
		Buffer *new;

		new = buffer_build();
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
vips_flood_connected( VipsFlood *flood, VipsPel *tp )
{
 	int j;

	for( j = 0; j < flood->tsize; j++ ) 
		if( tp[j] != flood->edge[j] ) 
			break;

	/* If flood->equal, true if point == edge.
	 */
	return( flood->equal ^ (j < flood->tsize) );
}

/* Fill left and right, return the endpoints. The start point (x, y) must be 
 * connected and unpainted.
 */
static void 
vips_flood_scanline( VipsFlood *flood, int x, int y, int *x1, int *x2 )
{
	VipsDraw *draw = VIPS_DRAW( flood );
	const int width = flood->test->Xsize;

	VipsPel *tp;
	int i;

	g_assert( vips_flood_connected( flood, 
		VIPS_IMAGE_ADDR( flood->test, x, y ) ) );
	g_assert( !vips__draw_painted( draw, 
		VIPS_IMAGE_ADDR( draw->im, x, y ) ) );

	/* Search to the right for the first non-connected pixel. If the start
	 * pixel is unpainted, we know all the intervening pixels must be
	 * unpainted too.
	 */
	tp = VIPS_IMAGE_ADDR( flood->test, x + 1, y );
	for( i = x + 1; i < width; i++ ) {
		if( !vips_flood_connected( flood, tp ) )
			break;
		tp += flood->tsize;
	}
	*x2 = i - 1;

	/* Search left.
	 */
	tp = VIPS_IMAGE_ADDR( flood->test, x - 1, y );
	for( i = x - 1; i >= 0; i-- ) {
		if( !vips_flood_connected( flood, tp ) )
			break;
		tp -= flood->tsize;
	}
	*x1 = i + 1;

	/* Paint the range we discovered.
	 */
	vips__draw_scanline( draw, y, *x1, *x2 );

	if( flood->dout ) {
		flood->left = VIPS_MIN( flood->left, *x1 );
		flood->right = VIPS_MAX( flood->right, *x2 );
		flood->top = VIPS_MIN( flood->top, y );
		flood->bottom = VIPS_MAX( flood->bottom, y );
	}
}

/* We know the line below or above us is filled between x1 and x2. Search our 
 * line in this range looking for an edge pixel we can flood from.
 */
static void
vips_flood_around( VipsFlood *flood, Scan *scan )
{
	VipsDraw *draw = VIPS_DRAW( flood );

	VipsPel *tp;
	int x;

	g_assert( scan->dir == 1 || 
		scan->dir == -1 );

	for( tp = VIPS_IMAGE_ADDR( flood->test, scan->x1, scan->y ), 
		x = scan->x1; 
		x <= scan->x2; 
		tp += flood->tsize, x++ ) {
		if( vips_flood_connected( flood, tp ) ) {
			int x1a;
			int x2a;

			/* If mark and test are different images, we also need
			 * to check for painted. Otherwise we can get stuck in
			 * connected loops.
			 */
			if( draw->im != flood->test ) {
				VipsPel *mp = VIPS_IMAGE_ADDR( 
					draw->im, x, scan->y );

				if( vips__draw_painted( draw, mp ) )
					continue;
			}

			vips_flood_scanline( flood, x, scan->y, &x1a, &x2a );

			/* Our new scanline can have up to three more
			 * scanlines connected to it: above, below left, below
			 * right.
			 */
			if( x1a < scan->x1 - 1 )
				flood->out = buffer_add( flood->out, flood,
					x1a, scan->x1 - 2, 
					scan->y - scan->dir, -scan->dir );
			if( x2a > scan->x2 + 1 )
				flood->out = buffer_add( flood->out, flood,
					scan->x2 + 2, x2a, 
					scan->y - scan->dir, -scan->dir );
			flood->out = buffer_add( flood->out, flood,
				x1a, x2a, scan->y + scan->dir, 
				scan->dir );

			x = x2a + 1;
			tp = VIPS_IMAGE_ADDR( flood->test, x, scan->y );
		}
	}
}

static void
vips_flood_all( VipsFlood *flood, int x, int y )
{
	int x1, x2;

	/* Test start pixel ... nothing to do?
	 */
	if( !vips_flood_connected( flood, 
		VIPS_IMAGE_ADDR( flood->test, x, y ) ) ) 
		return;

	vips_flood_scanline( flood, x, y, &x1, &x2 );
	flood->in = buffer_add( flood->in, flood, x1, x2, y + 1, 1 );
	flood->in = buffer_add( flood->in, flood, x1, x2, y - 1, -1 );

	while( flood->in->n ) {
		Buffer *p;

		for( p = flood->in; p; p = p->next ) {
			int i;

			for( i = 0; i < p->n; i++ )
				vips_flood_around( flood, &p->scan[i] );

			p->n = 0;
		}

		VIPS_SWAP( Buffer *, flood->in, flood->out );
	}
}

static void
vips_flood_finalize( VipsFlood *flood )
{
	/* Write dirty back to caller.
	 */
	if( flood->dout ) {
		flood->dout->left = flood->left;
		flood->dout->top = flood->top;
		flood->dout->width = flood->right - flood->left + 1;
		flood->dout->height = flood->bottom - flood->top + 1;
	}

	VIPS_FREE( flood->edge );
	VIPS_FREEF( buffer_free, flood->in );
	VIPS_FREEF( buffer_free, flood->out );
	vips_free( flood );
}

static int
vips_flood_build( VipsObject *object )
{
	VipsDraw *draw = VIPS_DRAW( object );
	VipsFlood *flood = (VipsFlood *) object;

	int x, y, d;

	if( VIPS_OBJECT_CLASS( vips_flood_parent_class )->build( object ) )
		return( -1 );

	flood->test = test;
	flood->x = x;
	flood->y = y;
	flood->dout = dout;
	flood->edge = NULL;
	flood->tsize = VIPS_IMAGE_SIZEOF_PEL( test );
	flood->left = x;
	flood->top = y;
	flood->right = x;
	flood->bottom = y;
	flood->in = buffer_build();
	flood->out = buffer_build();

	if( !(flood->edge = (VipsPel *) im_malloc( NULL, flood->tsize )) ) {
		flood_free( flood );
		return( NULL );
	}

	return( 0 );
}

static void
vips_flood_class_init( VipsCircleClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "flood";
	vobject_class->description = _( "draw a flood on an image" );
	vobject_class->build = vips_flood_build;

	VIPS_ARG_INT( class, "x", 3, 
		_( "x" ), 
		_( "Flood start point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFlood, x ),
		0, 1000000000, 0 );

	VIPS_ARG_INT( class, "y", 4, 
		_( "y" ), 
		_( "Flood start point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFlood, y ),
		0, 1000000000, 0 );

	VIPS_ARG_IMAGE( class, "test", 5, 
		_( "Test" ), 
		_( "Test pixels in this image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFlood, test ) ); 

	VIPS_ARG_BOOL( class, "equal", 6, 
		_( "Equal" ), 
		_( "Flood while equal to edge" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFlood, equal ),
		FALSE ); 

	VIPS_ARG_INT( class, "left", 7, 
		_( "Left" ), 
		_( "Left edge of modified area" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsFlood, left ),
		0, 1000000000, 0 );

	VIPS_ARG_INT( class, "top", 8, 
		_( "Top" ), 
		_( "top edge of modified area" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsFlood, top ),
		0, 1000000000, 0 );

	VIPS_ARG_INT( class, "width", 9, 
		_( "Width" ), 
		_( "width of modified area" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsFlood, width ),
		0, 1000000000, 0 );

	VIPS_ARG_INT( class, "height", 10, 
		_( "Height" ), 
		_( "height of modified area" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsFlood, height ),
		0, 1000000000, 0 );

}

/**
 * im_draw_flood:
 * @image: image to fill
 * @x: position to start fill
 * @y: position to start fill
 * @ink: colour to fill with
 * @dout: output the bounding box of the filled area 
 *
 * Flood-fill @image with @ink, starting at position @x, @y. The filled area is
 * bounded by pixels that are equal to the ink colour, in other words, it
 * searches for pixels enclosed by a line of @ink.
 *
 * The bounding box of the modified pixels is returned in @dout. @dout may be
 * NULL.
 *
 * See also: im_draw_flood_blob(), im_draw_flood_other().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_flood( VipsImage *image, int x, int y, VipsPel *ink, Rect *dout )
{
	VipsFlood *flood;

	if( im_check_coding_known( "im_draw_flood", image ) ||
		!(flood = vips_flood_new( image, image, x, y, ink, dout )) )
		return( -1 );

	/* Flood to != ink.
	 */
	memcpy( flood->edge, ink, flood->tsize );
	flood->equal = FALSE;

	vips_flood_all( flood, x, y );

	flood_free( flood );

	return( 0 );
}

/**
 * im_draw_flood_blob:
 * @image: image to fill
 * @x: position to start fill
 * @y: position to start fill
 * @ink: colour to fill with
 * @dout: output the bounding box of the filled area 
 *
 * Flood-fill @image with @ink, starting at position @x, @y. The filled area is
 * bounded by pixels that are equal to the start pixel, in other words, it
 * searches for a blob of same-coloured pixels.
 *
 * The bounding box of the modified pixels is returned in @dout. @dout may be
 * NULL.
 *
 * See also: im_draw_flood(), im_draw_flood_other(), im_draw_flood_blob().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_flood_blob( VipsImage *image, int x, int y, VipsPel *ink, Rect *dout )
{
	VipsFlood *flood;
 	int j;

	if( im_check_coding_known( "im_draw_flood_blob", image ) ||
		!(flood = vips_flood_new( image, image, x, y, ink, dout )) )
		return( -1 );

	/* Edge is set by colour of start pixel.
	 */
	memcpy( flood->edge, VIPS_IMAGE_ADDR( image, x, y ), flood->tsize );
	flood->equal = TRUE;

	/* If edge == ink, we'll never stop :-( or rather, there's nothing to
	 * do.
	 */
	for( j = 0; j < flood->tsize; j++ ) 
		if( flood->edge[j] != DRAW( flood )->ink[j] ) 
			break;
	if( j == flood->tsize )
		return( 0 );

	vips_flood_all( flood, x, y );

	flood_free( flood );

	return( 0 );
}

/**
 * im_draw_flood_other:
 * @image: image to mark
 * @test: image to test
 * @x: position to start fill
 * @y: position to start fill
 * @serial: mark pixels with this number
 * @dout: output the bounding box of the filled area 
 *
 * Flood-fill @image with @serial, starting at position @x, @y. The filled 
 * area is bounded by pixels in @test that are equal to the start pixel, in 
 * other words, it searches @test for a blob of same-coloured pixels, marking 
 * those pixels in @image with @serial.
 *
 * The bounding box of the modified pixels is returned in @dout. @dout may be
 * NULL.
 *
 * See also: im_draw_flood(), im_label_regions(), im_draw_flood_blob().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_draw_flood_other( VipsImage *image, 
	VipsImage *test, int x, int y, int serial, Rect *dout )
{
	int *m;
	VipsFlood *flood;

	if( im_incheck( test ) ||
		im_check_coding_known( "im_draw_flood_other", test ) ||
		im_check_uncoded( "im_draw_flood_other", image ) ||
		im_check_mono( "im_draw_flood_other", image ) ||
		im_check_format( "im_draw_flood_other", image, 
			VIPS_BANDFMT_INT ) ||
		im_check_size_same( "im_draw_flood_other", test, image ) )
		return( -1 );

	/* Have we done this point already?
	 */
	m = (int *) VIPS_IMAGE_ADDR( image, x, y ); 
	if( *m == serial )
		return( 0 );

	if( !(flood = vips_flood_new( image, test, x, y, (VipsPel *) &serial, dout )) )
		return( -1 );

	/* Edge is set by colour of start pixel.
	 */
	memcpy( flood->edge, VIPS_IMAGE_ADDR( test, x, y ), flood->tsize );
	flood->equal = TRUE;

	vips_flood_all( flood, x, y );

	flood_free( flood );

	return( 0 );
}
