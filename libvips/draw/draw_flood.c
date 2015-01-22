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

/* What we track during a flood. We have this in a separate struct so that we
 * can support vips__draw_flood_direct() ... a fast path for 
 * vips_labelregions() that avoids all of the GObject call overhead. This
 * gives a huge speedup, >x10 in many cases.
 */
typedef struct _Flood {
	/* Test pixels here.
	 */
	VipsImage *test;

	/* Draw pixels here, can be equal to test.
	 */
	VipsImage *image; 

	/* Sizeof pel in test.
	 */
	int tsize;

	/* Pixel we compare test to for edges.
	 */
	VipsPel *edge;

	/* True for flood while test == edge, false for flood while test !=
	 * edge.
	 */
	gboolean equal;

	/* Sizeof pel in @image.
	 */
	int psize;

	/* Ink we write to @image.
	 */
	VipsPel *ink;

	/* Add to move down a line in @image.
	 */
	int lsize;

	/* Record bounding box of modified pixels.
	 */
	int left;
	int right;	
	int top;
	int bottom;

	/* Our todo list.
	 */
	Buffer *in;
	Buffer *out;

} Flood; 

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
static Buffer * 
buffer_add( Buffer *buf, Flood *flood, int x1, int x2, int y, int dir )
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
 * pixels. p is a pel in @test. 
 */
static gboolean
flood_connected( Flood *flood, VipsPel *p )
{
 	int j;

	for( j = 0; j < flood->tsize; j++ ) 
		if( p[j] != flood->edge[j] ) 
			break;

	/* If flood->equal, true if point == edge.
	 */
	return( flood->equal ^ (j < flood->tsize) );
}

/* Is p painted? p is a pel in @image. 
 */
static gboolean
flood_painted( Flood *flood, VipsPel *p )
{
 	int j;

	for( j = 0; j < flood->psize; j++ ) 
		if( p[j] != flood->ink[j] ) 
			break;

	return( j == flood->psize );
}

static void
flood_pel( Flood *flood, VipsPel *q )
{
 	int j;

	/* Faster than memcopy() for n < about 20.
	 */
	for( j = 0; j < flood->psize; j++ ) 
		q[j] = flood->ink[j];
}

/* Fill a scanline between points x1 and x2 inclusive. x1 < x2.
 */
static void 
flood_draw_scanline( Flood *flood, int y, int x1, int x2 )
{
	VipsPel *p;
	int i;
	int len;

	g_assert( x1 <= x2 );

	if( y < 0 || 
		y >= flood->image->Ysize )
		return;
	if( x1 < 0 && 
		x2 < 0 )
		return;
	if( x1 >= flood->image->Xsize && 
		x2 >= flood->image->Xsize )
		return;
	x1 = VIPS_CLIP( 0, x1, flood->image->Xsize - 1 );
	x2 = VIPS_CLIP( 0, x2, flood->image->Xsize - 1 );

	p = VIPS_IMAGE_ADDR( flood->image, x1, y );
	len = x2 - x1 + 1;

	for( i = 0; i < len; i++ ) {
		flood_pel( flood, p );
		p += flood->psize;
	}
}

/* Fill left and right, return the endpoints. The start point (x, y) must be 
 * connected and unpainted.
 */
static void 
flood_scanline( Flood *flood, int x, int y, int *x1, int *x2 )
{
	const int width = flood->test->Xsize;

	VipsPel *p;
	int i;

	g_assert( flood_connected( flood, 
		VIPS_IMAGE_ADDR( flood->test, x, y ) ) );
	g_assert( !flood_painted( flood, 
		VIPS_IMAGE_ADDR( flood->image, x, y ) ) );

	/* Search to the right for the first non-connected pixel. If the start
	 * pixel is unpainted, we know all the intervening pixels must be
	 * unpainted too.
	 */
	p = VIPS_IMAGE_ADDR( flood->test, x + 1, y );
	for( i = x + 1; i < width; i++ ) {
		if( !flood_connected( flood, p ) )
			break;
		p += flood->tsize;
	}
	*x2 = i - 1;

	/* Search left.
	 */
	p = VIPS_IMAGE_ADDR( flood->test, x - 1, y );
	for( i = x - 1; i >= 0; i-- ) {
		if( !flood_connected( flood, p ) )
			break;
		p -= flood->tsize;
	}
	*x1 = i + 1;

	/* Paint the range we discovered.
	 */
	flood_draw_scanline( flood, y, *x1, *x2 );

	flood->left = VIPS_MIN( flood->left, *x1 );
	flood->right = VIPS_MAX( flood->right, *x2 );
	flood->top = VIPS_MIN( flood->top, y );
	flood->bottom = VIPS_MAX( flood->bottom, y );
}

/* We know the line below or above us is filled between x1 and x2. Search our 
 * line in this range looking for an edge pixel we can flood from.
 */
static void
flood_around( Flood *flood, Scan *scan )
{
	VipsPel *p;
	int x;

	g_assert( scan->dir == 1 || 
		scan->dir == -1 );

	for( p = VIPS_IMAGE_ADDR( flood->test, scan->x1, scan->y ), 
		x = scan->x1; 
		x <= scan->x2; 
		p += flood->tsize, x++ ) {
		if( flood_connected( flood, p ) ) {
			int x1a;
			int x2a;

			/* If mark and test are different images, we also need
			 * to check for painted. Otherwise we can get stuck in
			 * connected loops.
			 */
			if( flood->image != flood->test ) {
				VipsPel *mp = VIPS_IMAGE_ADDR( 
					flood->image, x, scan->y );

				if( flood_painted( flood, mp ) )
					continue;
			}

			flood_scanline( flood, x, scan->y, &x1a, &x2a );

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
			p = VIPS_IMAGE_ADDR( flood->test, x, scan->y );
		}
	}
}

static void
flood_all( Flood *flood, int x, int y )
{
	int x1, x2;

	/* Test start pixel ... nothing to do?
	 */
	if( !flood_connected( flood, VIPS_IMAGE_ADDR( flood->test, x, y ) ) ) 
		return;

	flood->in = buffer_build();
	flood->out = buffer_build();

	flood_scanline( flood, x, y, &x1, &x2 );
	flood->in = buffer_add( flood->in, flood, x1, x2, y + 1, 1 );
	flood->in = buffer_add( flood->in, flood, x1, x2, y - 1, -1 );

	while( flood->in->n ) {
		Buffer *p;

		for( p = flood->in; p; p = p->next ) {
			int i;

			for( i = 0; i < p->n; i++ )
				flood_around( flood, &p->scan[i] );

			p->n = 0;
		}

		VIPS_SWAP( Buffer *, flood->in, flood->out );
	}

	VIPS_FREEF( buffer_free, flood->in );
	VIPS_FREEF( buffer_free, flood->out );
}

/* Base class.
 */
typedef struct _VipsDrawFlood {
	VipsDrawink parent_object;

	/* Parameters.
	 */
	int x;
	int y;
	VipsImage *test;
	gboolean equal;
	int left;		
	int top;	
	int width;
	int height;

} VipsDrawFlood;

typedef VipsDrawinkClass VipsDrawFloodClass;

G_DEFINE_TYPE( VipsDrawFlood, vips_draw_flood, VIPS_TYPE_DRAWINK );

static int
vips_draw_flood_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsDraw *draw = VIPS_DRAW( object );
	VipsDrawink *drawink = VIPS_DRAWINK( object );
	VipsDrawFlood *drawflood = (VipsDrawFlood *) object;

	Flood flood; 
	int j; 

	if( VIPS_OBJECT_CLASS( vips_draw_flood_parent_class )->build( object ) )
		return( -1 );

	/* @test defaults to @image.
	 */
	if( !vips_object_argument_isset( object, "test" ) )
		g_object_set( object, "test", draw->image, NULL ); 

	if( vips_image_wio_input( drawflood->test ) ||
		vips_check_coding_known( class->nickname, drawflood->test ) ||
		vips_check_size_same( class->nickname, 
			drawflood->test, draw->image ) )
		return( -1 );

	flood.test = drawflood->test;
	flood.image = draw->image;
	flood.tsize = VIPS_IMAGE_SIZEOF_PEL( flood.test );
	flood.equal = drawflood->equal;
	flood.psize = VIPS_IMAGE_SIZEOF_PEL( flood.image );
	flood.ink = drawink->pixel_ink;
	flood.lsize = VIPS_IMAGE_SIZEOF_LINE( flood.image );
	flood.left = drawflood->x;
	flood.right = drawflood->x;
	flood.top = drawflood->y;
	flood.bottom = drawflood->y;

	if( flood.equal ) {
		/* Edge is set by colour of the start pixel in @test.
		 */
		if( !(flood.edge = VIPS_ARRAY( object, flood.tsize, VipsPel )) )
			return( -1 );
		memcpy( flood.edge, 
			VIPS_IMAGE_ADDR( flood.test, 
				drawflood->x, drawflood->y ), 
			flood.tsize );

		/* If @test and @image are the same and edge == ink, we'll 
		 * never stop :-( or rather, there's nothing to do.
		 */
		if( flood.test == flood.image ) { 
			for( j = 0; j < flood.tsize; j++ ) 
				if( flood.edge[j] != flood.ink[j] ) 
					break;

			if( j != flood.tsize )
				flood_all( &flood, drawflood->x, drawflood->y );
		}
		else
			flood_all( &flood, drawflood->x, drawflood->y );
	}
	else {
		/* Flood to ink colour. We need to be able to compare @test to
		 * @ink. 
		 */
		if( !(flood.edge = vips__vector_to_ink( class->nickname, 
			flood.test, 
			VIPS_ARRAY_ADDR( drawink->ink, 0 ), NULL, 
			VIPS_AREA( drawink->ink )->n )) )
			return( -1 );

		flood_all( &flood, drawflood->x, drawflood->y );
	}

	g_object_set( object, 
		"left", flood.left, 
		"top", flood.top, 
		"width", flood.right - flood.left + 1,
		"height", flood.bottom - flood.top + 1,
		NULL ); 

	return( 0 );
}

static void
vips_draw_flood_class_init( VipsDrawFloodClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

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
	Flood flood; 

	if( vips_check_format( "vips__draw_flood_direct", 
			image, VIPS_FORMAT_INT ) ||
		vips_check_mono( "vips__draw_flood_direct", image ) ||
		vips_check_coding_known( "vips__draw_flood_direct", test ) ||
		vips_check_size_same( "vips__draw_flood_direct", 
			test, image ) ||
		vips_image_wio_input( test ) ||  
		vips_image_inplace( image ) )
		return( -1 );

	flood.test = test;
	flood.image = image;
	flood.tsize = VIPS_IMAGE_SIZEOF_PEL( test );
	flood.equal = TRUE;
	flood.psize = VIPS_IMAGE_SIZEOF_PEL( image );
	flood.ink = (VipsPel *) &serial;
	flood.lsize = VIPS_IMAGE_SIZEOF_LINE( image );
	flood.left = x;
	flood.right = x;
	flood.top = y;
	flood.bottom = y;

	if( !(flood.edge = VIPS_ARRAY( image, flood.tsize, VipsPel )) )
		return( -1 );
	memcpy( flood.edge, 
		VIPS_IMAGE_ADDR( test, x, y ), flood.tsize );

	flood_all( &flood, x, y );

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
 * @...: %NULL-terminated list of optional named arguments
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
 * @...: %NULL-terminated list of optional named arguments
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
