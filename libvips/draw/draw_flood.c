/* draw_flood-fill
 *
 * JC 30/8/97
 *	- VIPSified, cleaned up, from "John Robinson's prog to fill 
 *	  enclosed areas"
 *	- something Kirk gave me, so thanks John 
 * JC 1/10/97
 *	- swapped inner memcmp/cpy for a loop ... faster for small pixels
 * 13/7/02 JC
 *	- im_draw_flood_blob() added
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
 * 	- draw_flood_blob could loop if start point == ink
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
#include <vips/internal.h>

#include "drawink.h"

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
typedef struct _VipsDrawFlood {
	VipsDrawink parent_object;

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
} VipsDrawFlood;

typedef VipsDrawinkClass VipsDrawFloodClass;

G_DEFINE_TYPE( VipsDrawFlood, vips_draw_flood, VIPS_TYPE_DRAWINK );

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
buffer_add( Buffer *buf, VipsDrawFlood *flood, int x1, int x2, int y, int dir )
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
vips_draw_flood_connected( VipsDrawFlood *flood, VipsPel *tp )
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
vips_draw_flood_scanline( VipsDrawFlood *flood, int x, int y, int *x1, int *x2 )
{
	VipsDraw *draw = VIPS_DRAW( flood );
	VipsDrawink *drawink = VIPS_DRAWINK( flood );
	const int width = flood->test->Xsize;

	VipsPel *tp;
	int i;

	g_assert( vips_draw_flood_connected( flood, 
		VIPS_IMAGE_ADDR( flood->test, x, y ) ) );
	g_assert( !vips__drawink_painted( drawink, 
		VIPS_IMAGE_ADDR( draw->image, x, y ) ) );

	/* Search to the right for the first non-connected pixel. If the start
	 * pixel is unpainted, we know all the intervening pixels must be
	 * unpainted too.
	 */
	tp = VIPS_IMAGE_ADDR( flood->test, x + 1, y );
	for( i = x + 1; i < width; i++ ) {
		if( !vips_draw_flood_connected( flood, tp ) )
			break;
		tp += flood->tsize;
	}
	*x2 = i - 1;

	/* Search left.
	 */
	tp = VIPS_IMAGE_ADDR( flood->test, x - 1, y );
	for( i = x - 1; i >= 0; i-- ) {
		if( !vips_draw_flood_connected( flood, tp ) )
			break;
		tp -= flood->tsize;
	}
	*x1 = i + 1;

	/* Paint the range we discovered.
	 */
	vips__drawink_scanline( drawink, y, *x1, *x2 );

	flood->left = VIPS_MIN( flood->left, *x1 );
	flood->right = VIPS_MAX( flood->right, *x2 );
	flood->top = VIPS_MIN( flood->top, y );
	flood->bottom = VIPS_MAX( flood->bottom, y );
}

/* We know the line below or above us is filled between x1 and x2. Search our 
 * line in this range looking for an edge pixel we can flood from.
 */
static void
vips_draw_flood_around( VipsDrawFlood *flood, Scan *scan )
{
	VipsDraw *draw = VIPS_DRAW( flood );
	VipsDrawink *drawink = VIPS_DRAWINK( flood );

	VipsPel *tp;
	int x;

	g_assert( scan->dir == 1 || 
		scan->dir == -1 );

	for( tp = VIPS_IMAGE_ADDR( flood->test, scan->x1, scan->y ), 
		x = scan->x1; 
		x <= scan->x2; 
		tp += flood->tsize, x++ ) {
		if( vips_draw_flood_connected( flood, tp ) ) {
			int x1a;
			int x2a;

			/* If mark and test are different images, we also need
			 * to check for painted. Otherwise we can get stuck in
			 * connected loops.
			 */
			if( draw->image != flood->test ) {
				VipsPel *mp = VIPS_IMAGE_ADDR( 
					draw->image, x, scan->y );

				if( vips__drawink_painted( drawink, mp ) )
					continue;
			}

			vips_draw_flood_scanline( flood, 
				x, scan->y, &x1a, &x2a );

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
vips_draw_flood_all( VipsDrawFlood *flood )
{
	int x1, x2;

	/* Test start pixel ... nothing to do?
	 */
	if( !vips_draw_flood_connected( flood, 
		VIPS_IMAGE_ADDR( flood->test, flood->x, flood->y ) ) ) 
		return;

	vips_draw_flood_scanline( flood, flood->x, flood->y, &x1, &x2 );
	flood->in = buffer_add( flood->in, flood, x1, x2, flood->y + 1, 1 );
	flood->in = buffer_add( flood->in, flood, x1, x2, flood->y - 1, -1 );

	while( flood->in->n ) {
		Buffer *p;

		for( p = flood->in; p; p = p->next ) {
			int i;

			for( i = 0; i < p->n; i++ )
				vips_draw_flood_around( flood, &p->scan[i] );

			p->n = 0;
		}

		VIPS_SWAP( Buffer *, flood->in, flood->out );
	}
}

static void
vips_draw_flood_dispose( GObject *gobject )
{
	VipsDrawFlood *flood = (VipsDrawFlood *) gobject;

	VIPS_FREEF( buffer_free, flood->in );
	VIPS_FREEF( buffer_free, flood->out );

	G_OBJECT_CLASS( vips_draw_flood_parent_class )->dispose( gobject );
}

static int
vips_draw_flood_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsDraw *draw = VIPS_DRAW( object );
	VipsDrawink *drawink = VIPS_DRAWINK( object );
	VipsDrawFlood *flood = (VipsDrawFlood *) object;

	int j; 

	if( VIPS_OBJECT_CLASS( vips_draw_flood_parent_class )->build( object ) )
		return( -1 );

	/* @test defaults to @image.
	 */
	if( !vips_object_argument_isset( object, "test" ) )
		g_object_set( object, "test", draw->image, NULL ); 

	flood->tsize = VIPS_IMAGE_SIZEOF_PEL( flood->test );
	flood->left = flood->x;
	flood->top = flood->y;
	flood->right = flood->x;
	flood->bottom = flood->y;
	flood->in = buffer_build();
	flood->out = buffer_build();

	if( vips_image_wio_input( flood->test ) ||
		vips_check_coding_known( class->nickname, flood->test ) ||
		vips_check_size_same( class->nickname, 
			flood->test, draw->image ) )
		return( -1 );

	if( flood->equal ) {
		/* Edge is set by colour of the start pixel in @test.
		 */
		if( !(flood->edge = 
			(VipsPel *) im_malloc( object, flood->tsize )) ) 
			return( -1 );
		memcpy( flood->edge, 
			VIPS_IMAGE_ADDR( flood->test, flood->x, flood->y ), 
			flood->tsize );

		/* If @test and @image are the same and edge == ink, we'll 
		 * never stop :-( or rather, there's nothing to do.
		 */
		if( flood->test == draw->image ) { 
			for( j = 0; j < flood->tsize; j++ ) 
				if( flood->edge[j] != drawink->pixel_ink[j] ) 
					break;

			if( j != flood->tsize )
				vips_draw_flood_all( flood );
		}
		else
			vips_draw_flood_all( flood );
	}
	else {
		/* Flood to ink colour. We need to be able to compare @test to
		 * @ink. 
		 */
		if( !(flood->edge = vips__vector_to_ink( class->nickname, 
			flood->test, drawink->ink->data, drawink->ink->n )) )
			return( -1 );

		vips_draw_flood_all( flood );
	}

	g_object_set( object, 
		"left", flood->left, 
		"top", flood->top, 
		"width", flood->right - flood->left + 1,
		"height", flood->bottom - flood->top + 1,
		NULL ); 

	return( 0 );
}

static void
vips_draw_flood_class_init( VipsDrawFloodClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->dispose = vips_draw_flood_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "draw_flood";
	vobject_class->description = _( "flood-fill an area" );
	vobject_class->build = vips_draw_flood_build;

	VIPS_ARG_INT( class, "x", 3, 
		_( "x" ), 
		_( "DrawFlood start point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawFlood, x ),
		0, 1000000000, 0 );

	VIPS_ARG_INT( class, "y", 4, 
		_( "y" ), 
		_( "DrawFlood start point" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDrawFlood, y ),
		0, 1000000000, 0 );

	VIPS_ARG_IMAGE( class, "test", 5, 
		_( "Test" ), 
		_( "Test pixels in this image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsDrawFlood, test ) ); 

	VIPS_ARG_BOOL( class, "equal", 6, 
		_( "Equal" ), 
		_( "DrawFlood while equal to edge" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsDrawFlood, equal ),
		FALSE ); 

	VIPS_ARG_INT( class, "left", 7, 
		_( "Left" ), 
		_( "Left edge of modified area" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsDrawFlood, left ),
		0, 1000000000, 0 );

	VIPS_ARG_INT( class, "top", 8, 
		_( "Top" ), 
		_( "top edge of modified area" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsDrawFlood, top ),
		0, 1000000000, 0 );

	VIPS_ARG_INT( class, "width", 9, 
		_( "Width" ), 
		_( "width of modified area" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsDrawFlood, width ),
		0, 1000000000, 0 );

	VIPS_ARG_INT( class, "height", 10, 
		_( "Height" ), 
		_( "height of modified area" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsDrawFlood, height ),
		0, 1000000000, 0 );

}

static void
vips_draw_flood_init( VipsDrawFlood *draw_flood )
{
}

/* Direct path to flood for vips_labelregions(). We need to avoid the function
 * dispatch system for speed.
 *
 * Equivalent to:
 *
 * vips_draw_flood1( image, serial, x, y,
 *       "test", test,
 *       "equal", TRUE,
 *       NULL )
 *
 * image must be 1-band int. 
 */
int
vips__draw_flood_direct( VipsImage *image, VipsImage *test, 
	int serial, int x, int y )
{
	VipsDrawFlood *flood = (VipsDrawFlood *) 
		vips_operation_new( "draw_flood" );
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( flood ); 

	if( vips_check_format( class->nickname, image, VIPS_FORMAT_INT ) ||
		vips_check_mono( class->nickname, image ) ||
		vips_check_coding_known( class->nickname, test ) ||
		vips_check_size_same( class->nickname, test, image ) ||
		vips_image_wio_input( test ) ) { 
		g_object_unref( flood );
		return( -1 );
	}

	((VipsDraw *) flood)->image = image;

	if( !(((VipsDrawink *) flood)->pixel_ink = VIPS_ARRAY( flood, 
		VIPS_IMAGE_SIZEOF_PEL( image ), VipsPel )) ) {
		g_object_unref( flood );
		return( -1 ); 
	}
	*((int *) (((VipsDrawink *) flood)->pixel_ink)) = serial; 

	flood->test = test;
	flood->tsize = VIPS_IMAGE_SIZEOF_PEL( test );
	flood->left = flood->x;
	flood->top = flood->y;
	flood->right = flood->x;
	flood->bottom = flood->y;
	flood->in = buffer_build();
	flood->out = buffer_build();

	if( !(flood->edge = 
		(VipsPel *) im_malloc( flood, flood->tsize )) ) {
		g_object_unref( flood );
		return( -1 );
	}
	memcpy( flood->edge, 
		VIPS_IMAGE_ADDR( test, x, y ), flood->tsize );

	vips_draw_flood_all( flood );

	g_object_unref( flood );

	return( 0 ); 
}

static int
vips_draw_floodv( VipsImage *image, 
	double *ink, int n, int x, int y, va_list ap )
{
	VipsArea *area_ink;
	int result;

	area_ink = (VipsArea *) vips_array_double_new( ink, n );
	result = vips_call_split( "draw_flood", ap, image, area_ink, x, y );
	vips_area_unref( area_ink );

	return( result );
}

/**
 * vips_draw_flood:
 * @image: image to draw on
 * @ink: (array length=n): value to draw
 * @n: length of ink array
 * @x: centre of circle
 * @y: centre of circle
 *
 * Optional arguments:
 *
 * @test: test this image
 * @equal: fill while equal to edge
 * @left: output left edge of bounding box of modified area
 * @top: output top edge of bounding box of modified area
 * @width: output width of bounding box of modified area
 * @height: output height of bounding box of modified area
 *
 * Flood-fill @image with @ink, starting at position @x, @y. The filled area is
 * bounded by pixels that are equal to the ink colour, in other words, it
 * searches for pixels enclosed by an edge of @ink.
 *
 * If @equal is set, it instead searches for pixels which are equal to the
 * start point and fills them with @ink.
 *
 * Normally it will test and set pixels in @image. If @test is set, it will 
 * test pixels in @test and set pixels in @image. This lets you search an
 * image (@test) for continuous areas of pixels without modifying it. 
 *
 * @left, @top, @width, @height output the bounding box of the modified
 * pixels. 
 *
 * @ink is an array of double containing values to draw. 
 *
 * See also: vips_draw_flood1().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_flood( VipsImage *image, 
	double *ink, int n, int x, int y, ... )
{
	va_list ap;
	int result;

	va_start( ap, y );
	result = vips_draw_floodv( image, ink, n, x, y, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_draw_flood1:
 * @image: image to draw on
 * @ink: value to draw
 * @x: centre of circle
 * @y: centre of circle
 *
 * Optional arguments:
 *
 * @test: test this image
 * @equal: fill while equal to edge
 * @left: output left edge of bounding box of modified area
 * @top: output top edge of bounding box of modified area
 * @width: output width of bounding box of modified area
 * @height: output height of bounding box of modified area
 *
 * As vips_draw_flood(), but just takes a single double for @ink. 
 *
 * See also: vips_draw_flood().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
vips_draw_flood1( VipsImage *image, double ink, int x, int y, ... )
{
	double array_ink[1];
	va_list ap;
	int result;

	array_ink[0] = ink; 

	va_start( ap, y );
	result = vips_draw_floodv( image, array_ink, 1, x, y, ap );
	va_end( ap );

	return( result );
}
