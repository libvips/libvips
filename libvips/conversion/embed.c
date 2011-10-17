/* im_embed
 *
 * Author: J. Cupitt
 * Written on: 21/2/95
 * Modified on: 
 * 6/4/04
 *	- added extend pixels from edge mode
 *	- sets Xoffset / Yoffset to x / y
 * 15/4/04 
 *	- added replicate and mirror modes
 * 4/3/05
 *	- added solid white mode
 * 4/1/07
 * 	- degenerate to im_copy() for 0/0/w/h
 * 1/8/07
 * 	- more general ... x and y can be negative
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 5/11/09
 * 	- gtkdoc
 * 27/1/10
 * 	- use im_region_paint()
 * 	- cleanups
 * 15/10/11
 * 	- rewrite as a class
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

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "conversion.h"

/**
 * VipsEmbed:
 * @in: input image
 * @out: output image
 * @extend: how to generate the edge pixels
 * @x: place @in at this x position in @out
 * @y: place @in at this y position in @out
 * @width: @out should be this many pixels across
 * @height: @out should be this many pixels down
 *
 * The opposite of im_extract(): embed @in within an image of size @width by
 * @height at position @x, @y.  @extend
 * controls what appears in the new pels, see #VipsExtend. 
 *
 * See also: im_extract_area(), im_insert().
 * 
 * Returns: 0 on success, -1 on error.
 */

typedef struct _VipsEmbed {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *input;

	VipsExtend extend;
	int x;
	int y;
	int width;
	int height;

	/* Geometry calculations. 
	 */
	VipsRect rout;		/* Whole output area */
	VipsRect rsub;		/* Rect occupied by image */

	/* The 8 border pieces. The 4 borders strictly up/down/left/right of
	 * the main image, and the 4 corner pieces.
	 */
	VipsRect border[8];
} VipsEmbed;

typedef VipsConversionClass VipsEmbedClass;

G_DEFINE_TYPE( VipsEmbed, vips_embed, VIPS_TYPE_CONVERSION );

/* r is the bit we are trying to paint, guaranteed to be entirely within
 * border area i. Set out to be the edge of the image we need to paint the
 * pixels in r.
 */
static void
vips_embed_find_edge( VipsEmbed *embed, VipsRect *r, int i, VipsRect *out )
{
	/* Expand the border by 1 pixel, intersect with the image area, and we
	 * get the edge. Usually too much though: eg. we could make the entire
	 * right edge.
	 */
	*out = embed->border[i];
	vips_rect_marginadjust( out, 1 );
	vips_rect_intersectrect( out, &embed->rsub, out );

	/* Usually too much though: eg. we could make the entire
	 * right edge. If we're strictly up/down/left/right of the image, we
	 * can trim.
	 */
	if( i == 0 || i == 2 ) {
		VipsRect extend;

		/* Above or below.
		 */
		extend = *r;
		extend.top = 0;
		extend.height = embed->height;
		vips_rect_intersectrect( out, &extend, out );
	}
	if( i == 1 || i == 3 ) {
		VipsRect extend;

		/* Left or right.
		 */
		extend = *r;
		extend.left = 0;
		extend.width = embed->width;
		vips_rect_intersectrect( out, &extend, out );
	}
}

/* Copy a single pixel sideways into a line of pixels.
 */
static void
vips_embed_copy_pixel( VipsEmbed *embed, PEL *q, PEL *p, int n )
{
	const int bs = VIPS_IMAGE_SIZEOF_PEL( embed->input );

	int x, b;

	for( x = 0; x < n; x++ )
		for( b = 0; b < bs; b++ )
			*q++ = p[b];
}

/* Paint r of region or. It's a border area, lying entirely within 
 * embed->border[i]. p points to the top-left source pixel to fill with. 
 * plsk is the line stride.
 */
static void
vips_embed_paint_edge( VipsEmbed *embed, 
	VipsRegion *or, int i, VipsRect *r, PEL *p, int plsk )
{
	const int bs = VIPS_IMAGE_SIZEOF_PEL( embed->input );

	VipsRect todo;
	PEL *q;
	int y;

	/* Pixels left to paint.
	 */
	todo = *r;

	/* Corner pieces ... copy the single pixel to paint the top line of
	 * todo, then use the line copier below to paint the rest of it.
	 */
	if( i > 3 ) {
		q = (PEL *) VIPS_REGION_ADDR( or, todo.left, todo.top );
		vips_embed_copy_pixel( embed, q, p, todo.width );

		p = q;
		todo.top += 1;
		todo.height -= 1;
	}

	if( i == 1 || i == 3 ) {
		/* Vertical line of pixels to copy.
		 */
		for( y = 0; y < todo.height; y++ ) {
			q = (PEL *) VIPS_REGION_ADDR( or, 
				todo.left, todo.top + y );
			vips_embed_copy_pixel( embed, q, p, todo.width );
			p += plsk;
		}
	}
	else {
		/* Horizontal line of pixels to copy.
		 */
		for( y = 0; y < todo.height; y++ ) {
			q = (PEL *) VIPS_REGION_ADDR( or, 
				todo.left, todo.top + y );
			memcpy( q, p, bs * todo.width );
		}
	}
}

static int
vips_embed_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsEmbed *embed = (VipsEmbed *) b;
	VipsRect *r = &or->valid;

	Rect ovl;
	int i;
	PEL *p;
	int plsk;

	/* Entirely within the input image? Generate the subimage and copy
	 * pointers.
	 */
	if( vips_rect_includesrect( &embed->rsub, r ) ) {
		VipsRect need;

		need = *r;
		need.left -= embed->x;
		need.top -= embed->y;
		if( vips_region_prepare( ir, &need ) ||
			vips_region_region( or, ir, r, need.left, need.top ) )
			return( -1 );

		return( 0 );
	}

	/* Does any of the input image appear in the area we have been asked 
	 * to make? Paste it in.
	 */
	vips_rect_intersectrect( r, &embed->rsub, &ovl );
	if( !vips_rect_isempty( &ovl ) ) {
		/* Paint the bits coming from the input image.
		 */
		ovl.left -= embed->x;
		ovl.top -= embed->y;
		if( vips_region_prepare_to( ir, or, &ovl, 
			ovl.left + embed->x, ovl.top + embed->y ) )
			return( -1 );
		ovl.left += embed->x;
		ovl.top += embed->y;
	}

	switch( embed->extend ) {
	case VIPS_EXTEND_BLACK:
	case VIPS_EXTEND_WHITE:
		/* Paint the borders a solid value.
		 */
		for( i = 0; i < 8; i++ )
			vips_region_paint( or, &embed->border[i], 
				embed->extend == 0 ? 0 : 255 );
		break;

	case VIPS_EXTEND_COPY:
		/* Extend the borders.
		 */
		for( i = 0; i < 8; i++ ) {
			VipsRect todo;
			VipsRect edge;

			vips_rect_intersectrect( r, &embed->border[i], &todo );
			if( !vips_rect_isempty( &todo ) ) {
				vips_embed_find_edge( embed, &todo, i, &edge );

				/* Did we paint any of the input image? If we
				 * did, we can fetch the edge pixels from
				 * that.
				 */
				if( !vips_rect_isempty( &ovl ) ) {
					p = (PEL *) VIPS_REGION_ADDR( or, 
						edge.left, edge.top );
					plsk = VIPS_REGION_LSKIP( or );
				}
				else {
					/* No pixels painted ... fetch
					 * directly from the input image.
					 */
					edge.left -= embed->x;
					edge.top -= embed->y;
					if( vips_region_prepare( ir, &edge ) )
						return( -1 );
					p = (PEL *) VIPS_REGION_ADDR( ir,
						 edge.left, edge.top );
					plsk = VIPS_REGION_LSKIP( ir );
				}

				vips_embed_paint_edge( embed, 
					or, i, &todo, p, plsk );
			}
		}

		break;

	default:	
		g_assert( 0 );
	}

	return( 0 );
}

static int
vips_embed_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsEmbed *embed = (VipsEmbed *) object;

	VipsRect want;

	if( VIPS_OBJECT_CLASS( vips_embed_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( embed->input ) || 
		vips_image_pio_output( conversion->output ) )
		return( -1 );
	if( embed->extend < 0 || embed->extend >= VIPS_EXTEND_LAST ) {
		vips_error( "VipsEmbed", "%s", _( "unknown VipsExtend" ) );
		return( -1 );
	}

	/* nip can generate this quite often ... just copy.
	 */
	if( embed->x == 0 && 
		embed->y == 0 && 
		embed->width == embed->input->Xsize && 
		embed->height == embed->input->Ysize )
		return( vips_image_write( embed->input, conversion->output ) );

	switch( embed->extend ) {
	case VIPS_EXTEND_REPEAT:
{
		/* Clock arithmetic: we want negative x/y to wrap around
		 * nicely.
		 */
		const int nx = embed->x < 0 ?
			-embed->x % embed->input->Xsize : 
			embed->input->Xsize - embed->x % embed->input->Xsize;
		const int ny = embed->y < 0 ?
			-embed->y % embed->input->Ysize : 
			embed->input->Ysize - embed->y % embed->input->Ysize;

		VipsImage *t[1];

		if( im_open_local_array( conversion->output, 
			t, 1, "embed-type2", "p" ) ||
			im_replicate( embed->input, t[0], 
				embed->width / embed->input->Xsize + 2, 
				embed->height / embed->input->Ysize + 2 ) ||
			im_extract_area( t[0], conversion->output, 
				nx, ny, embed->width, embed->height ) )
			return( -1 );
}
		break;

	case VIPS_EXTEND_MIRROR:
{
		/* As case 2, but the tiles are twice the size because of
		 * mirroring.
		 */
		const int w2 = embed->input->Xsize * 2;
		const int h2 = embed->input->Ysize * 2;

		const int nx = embed->x < 0 ? 
			-embed->x % w2 : w2 - embed->x % w2;
		const int ny = embed->y < 0 ? 
			-embed->y % h2 : h2 - embed->y % h2;

		VipsImage *t[7];

		if( im_open_local_array( conversion->output, 
			t, 7, "embed-type3", "p" ) ||
			/* Cache the edges of in, since we may well be reusing
			 * them repeatedly. Will only help for tiny borders
			 * (up to 20 pixels?), but that's our typical case
			 * with im_conv() etc.
			im_cache( in, t[0], IM__TILE_WIDTH, IM__TILE_HEIGHT,
				3 * (in->Xsize / IM__TILE_WIDTH + 1) +
				3 * (in->Ysize / IM__TILE_HEIGHT + 1) ) ||
			 */

			/* 

				FIXME ... alternatively, don't cache, hmm,
				need to time this for typical cases

			 */
			im_copy( embed->input, t[0] ) ||
			
			/* Make a 2x2 mirror tile.
			 */
			im_fliphor( t[0], t[1] ) ||
			im_lrjoin( t[0], t[1], t[2] ) ||
			im_flipver( t[2], t[3] ) ||
			im_tbjoin( t[2], t[3], t[4] ) ||

			/* Repeat, then cut out the centre.
			 */
			im_replicate( t[4], t[5], 
				embed->width / t[4]->Xsize + 2, 
				embed->height / t[4]->Ysize + 2 ) ||
			im_extract_area( t[5], t[6], nx, ny, 
				embed->width, embed->height ) ||

			/* Overwrite the centre with the input, much faster
			 * for centre pixels.
			 */
			im_insert_noexpand( t[6], embed->input, 
				conversion->output, embed->x, embed->y ) )
				return( -1 );
}
		break;

	case 0:
	case 1:
	case 4:
		if( vips_image_copy_fields( conversion->output, embed->input ) )
			return( -1 );

		conversion->output->Xsize = embed->width;
		conversion->output->Ysize = embed->height;

		vips_demand_hint( conversion->output, 
			VIPS_DEMAND_STYLE_SMALLTILE, embed->input, NULL );

		/* Whole output area.
		 */
		embed->rout.left = 0;
		embed->rout.top = 0;
		embed->rout.width = conversion->output->Xsize;
		embed->rout.height = conversion->output->Ysize;

		/* Rect occupied by image (can be clipped to nothing).
		 */
		want.left = embed->x;
		want.top = embed->y;
		want.width = embed->input->Xsize;
		want.height = embed->input->Ysize;
		im_rect_intersectrect( &want, &embed->rout, &embed->rsub );

		/* FIXME ... actually, it can't. embed_find_edge() will fail 
		 * if rsub is empty. Make this more general at some point 
		 * and remove this test.
		 */
		if( vips_rect_isempty( &embed->rsub ) ) {
			vips_error( "VipsEmbed", "%s", _( "bad dimensions" ) );
			return( -1 );
		}

		/* Edge rects of new pixels ... top, right, bottom, left. Order
		 * important. Can be empty.
		 */
		embed->border[0].left = embed->rsub.left;
		embed->border[0].top = 0;
		embed->border[0].width = embed->rsub.width;
		embed->border[0].height = embed->rsub.top;

		embed->border[1].left = VIPS_RECT_RIGHT( &embed->rsub );
		embed->border[1].top = embed->rsub.top;
		embed->border[1].width = conversion->output->Xsize - 
			VIPS_RECT_RIGHT( &embed->rsub );
		embed->border[1].height = embed->rsub.height;

		embed->border[2].left = embed->rsub.left;	
		embed->border[2].top = VIPS_RECT_BOTTOM( &embed->rsub );
		embed->border[2].width = embed->rsub.width;
		embed->border[2].height = conversion->output->Ysize - 
			VIPS_RECT_BOTTOM( &embed->rsub );

		embed->border[3].left = 0;	
		embed->border[3].top = embed->rsub.top;
		embed->border[3].width = embed->rsub.left;
		embed->border[3].height = embed->rsub.height;

		/* Corner rects. Top-left, top-right, bottom-right, 
		 * bottom-left. Order important.
		 */
		embed->border[4].left = 0;
		embed->border[4].top = 0;
		embed->border[4].width = embed->rsub.left;
		embed->border[4].height = embed->rsub.top;

		embed->border[5].left = VIPS_RECT_RIGHT( &embed->rsub );
		embed->border[5].top = 0;
		embed->border[5].width = conversion->output->Xsize - 
			VIPS_RECT_RIGHT( &embed->rsub );
		embed->border[5].height = embed->rsub.top;

		embed->border[6].left = VIPS_RECT_RIGHT( &embed->rsub );
		embed->border[6].top = VIPS_RECT_BOTTOM( &embed->rsub );
		embed->border[6].width = conversion->output->Xsize - 
			VIPS_RECT_RIGHT( &embed->rsub );
		embed->border[6].height = conversion->output->Ysize - 
			VIPS_RECT_BOTTOM( &embed->rsub );

		embed->border[7].left = 0;
		embed->border[7].top = VIPS_RECT_BOTTOM( &embed->rsub );
		embed->border[7].width = embed->rsub.left;
		embed->border[7].height = conversion->output->Ysize - 
			VIPS_RECT_BOTTOM( &embed->rsub );

		if( vips_image_generate( conversion->output,
			vips_start_one, vips_embed_gen, vips_stop_one, 
			embed->input, embed ) )
			return( -1 );

		break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}

static void
vips_embed_class_init( VipsEmbedClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_embed_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "embed";
	vobject_class->description = _( "embed an image in a larger image" );
	vobject_class->build = vips_embed_build;

	VIPS_ARG_IMAGE( class, "in", -1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsEmbed, input ) );

	VIPS_ARG_INT( class, "width", 2, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsEmbed, width ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "height", 3, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsEmbed, height ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "x", 4, 
		_( "x" ), 
		_( "Left edge of input in output" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsEmbed, x ),
		-1000000, 1000000, 0 );

	VIPS_ARG_INT( class, "y", 5, 
		_( "y" ), 
		_( "Top edge of input in output" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsEmbed, y ),
		-1000000, 1000000, 0 );

	VIPS_ARG_ENUM( class, "extend", 6, 
		_( "Extend" ), 
		_( "How to generate the extra pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsEmbed, extend ),
		VIPS_TYPE_EXTEND, VIPS_EXTEND_BLACK );
}

static void
vips_embed_init( VipsEmbed *embed )
{
	/* Init our instance fields.
	 */
}

int
vips_embed( VipsImage *in, VipsImage **out, 
	int x, int y, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "embed", ap, 
		in, out, x, y, width, height );
	va_end( ap );

	return( result );
}
