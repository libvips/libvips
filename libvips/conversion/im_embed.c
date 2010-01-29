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
#include <assert.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Per-call struct.
 */
typedef struct _Embed {
	IMAGE *in;
	IMAGE *out;
	int flag;
	int x, y, w, h;

	/* Geometry calculations. 
	 */
	Rect rout;		/* Whole output area */
	Rect rsub;		/* Rect occupied by image */

	/* The 8 border pieces. The 4 borders strictly up/down/left/right of
	 * the main image, and the 4 corner pieces.
	 */
	Rect border[8];
} Embed;

/* r is the bit we are trying to paint, guaranteed to be entirely within
 * border area i. Set out to be the edge of the image we need to paint the
 * pixels in r.
 */
static void
embed_find_edge( Embed *embed, Rect *r, int i, Rect *out )
{
	/* Expand the border by 1 pixel, intersect with the image area, and we
	 * get the edge. Usually too much though: eg. we could make the entire
	 * right edge.
	 */
	*out = embed->border[i];
	im_rect_marginadjust( out, 1 );
	im_rect_intersectrect( out, &embed->rsub, out );

	/* Usually too much though: eg. we could make the entire
	 * right edge. If we're strictly up/down/left/right of the image, we
	 * can trim.
	 */
	if( i == 0 || i == 2 ) {
		Rect extend;

		/* Above or below.
		 */
		extend = *r;
		extend.top = 0;
		extend.height = embed->h;
		im_rect_intersectrect( out, &extend, out );
	}
	if( i == 1 || i == 3 ) {
		Rect extend;

		/* Left or right.
		 */
		extend = *r;
		extend.left = 0;
		extend.width = embed->w;
		im_rect_intersectrect( out, &extend, out );
	}
}

/* Copy a single pixel sideways into a line of pixels.
 */
static void
embed_copy_pixel( Embed *embed, PEL *q, PEL *p, int n )
{
	const int bs = IM_IMAGE_SIZEOF_PEL( embed->in );

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
embed_paint_edge( Embed *embed, REGION *or, int i, Rect *r, PEL *p, int plsk )
{
	const int bs = IM_IMAGE_SIZEOF_PEL( embed->in );

	Rect todo;
	PEL *q;
	int y;

	/* Pixels left to paint.
	 */
	todo = *r;

	/* Corner pieces ... copy the single pixel to paint the top line of
	 * todo, then use the line copier below to paint the rest of it.
	 */
	if( i > 3 ) {
		q = (PEL *) IM_REGION_ADDR( or, todo.left, todo.top );
		embed_copy_pixel( embed, q, p, todo.width );

		p = q;
		todo.top += 1;
		todo.height -= 1;
	}

	if( i == 1 || i == 3 ) {
		/* Vertical line of pixels to copy.
		 */
		for( y = 0; y < todo.height; y++ ) {
			q = (PEL *) IM_REGION_ADDR( or, 
				todo.left, todo.top + y );
			embed_copy_pixel( embed, q, p, todo.width );
			p += plsk;
		}
	}
	else {
		/* Horizontal line of pixels to copy.
		 */
		for( y = 0; y < todo.height; y++ ) {
			q = (PEL *) IM_REGION_ADDR( or, 
				todo.left, todo.top + y );
			memcpy( q, p, bs * todo.width );
		}
	}
}

static int
embed_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	Embed *embed = (Embed *) b;
	Rect *r = &or->valid;

	Rect ovl;
	int i;
	PEL *p;
	int plsk;

	/* Entirely within the input image? Generate the subimage and copy
	 * pointers.
	 */
	if( im_rect_includesrect( &embed->rsub, r ) ) {
		Rect need;

		need = *r;
		need.left -= embed->x;
		need.top -= embed->y;
		if( im_prepare( ir, &need ) ||
			im_region_region( or, ir, r, need.left, need.top ) )
			return( -1 );

		return( 0 );
	}

	/* Does any of the input image appear in the area we have been asked 
	 * to make? Paste it in.
	 */
	im_rect_intersectrect( r, &embed->rsub, &ovl );
	if( !im_rect_isempty( &ovl ) ) {
		/* Paint the bits coming from the input image.
		 */
		ovl.left -= embed->x;
		ovl.top -= embed->y;
		if( im_prepare_to( ir, or, &ovl, 
			ovl.left + embed->x, ovl.top + embed->y ) )
			return( -1 );
		ovl.left += embed->x;
		ovl.top += embed->y;
	}

	switch( embed->flag ) {
	case 0:
	case 4:
		/* Paint the borders a solid value.
		 */
		for( i = 0; i < 8; i++ )
			im_region_paint( or, &embed->border[i], 
				embed->flag == 0 ? 0 : 255 );
		break;

	case 1:
		/* Extend the borders.
		 */
		for( i = 0; i < 8; i++ ) {
			Rect todo;
			Rect edge;

			im_rect_intersectrect( r, &embed->border[i], &todo );
			if( !im_rect_isempty( &todo ) ) {
				embed_find_edge( embed, &todo, i, &edge );

				/* Did we paint any of the input image? If we
				 * did, we can fetch the edge pixels from
				 * that.
				 */
				if( !im_rect_isempty( &ovl ) ) {
					p = (PEL *) IM_REGION_ADDR( or, 
						edge.left, edge.top );
					plsk = IM_REGION_LSKIP( or );
				}
				else {
					/* No pixels painted ... fetch
					 * directly from the input image.
					 */
					edge.left -= embed->x;
					edge.top -= embed->y;
					if( im_prepare( ir, &edge ) )
						return( -1 );
					p = (PEL *) IM_REGION_ADDR( ir,
						 edge.left, edge.top );
					plsk = IM_REGION_LSKIP( ir );
				}

				embed_paint_edge( embed, 
					or, i, &todo, p, plsk );
			}
		}

		break;

	default:	
		assert( 0 );
	}

	return( 0 );
}

static Embed *
embed_new( IMAGE *in, IMAGE *out, int flag, int x, int y, int w, int h )
{
	Embed *embed = IM_NEW( out, Embed );
	Rect want;

	/* Take a copy of args.
	 */
	embed->in = in;
	embed->out = out;
	embed->flag = flag;
	embed->x = x;
	embed->y = y;
	embed->w = w;
	embed->h = h;

	/* Whole output area.
	 */
	embed->rout.left = 0;
	embed->rout.top = 0;
	embed->rout.width = out->Xsize;
	embed->rout.height = out->Ysize;

	/* Rect occupied by image (can be clipped to nothing).
	 */
	want.left = x;
	want.top = y;
	want.width = in->Xsize;
	want.height = in->Ysize;
	im_rect_intersectrect( &want, &embed->rout, &embed->rsub );

	/* FIXME ... actually, it can't. embed_find_edge() will fail if rsub
	 * is empty. Make this more general at some point and remove this
	 * test.
	 */
	if( im_rect_isempty( &embed->rsub ) ) {
		im_error( "im_embed", "%s", _( "bad dimensions" ) );
		return( NULL );
	}

	/* Edge rects of new pixels ... top, right, bottom, left. Order
	 * important. Can be empty.
	 */
	embed->border[0].left = embed->rsub.left;
	embed->border[0].top = 0;
	embed->border[0].width = embed->rsub.width;
	embed->border[0].height = embed->rsub.top;

	embed->border[1].left = IM_RECT_RIGHT( &embed->rsub );
	embed->border[1].top = embed->rsub.top;
	embed->border[1].width = out->Xsize - IM_RECT_RIGHT( &embed->rsub );
	embed->border[1].height = embed->rsub.height;

	embed->border[2].left = embed->rsub.left;	
	embed->border[2].top = IM_RECT_BOTTOM( &embed->rsub );
	embed->border[2].width = embed->rsub.width;
	embed->border[2].height = out->Ysize - IM_RECT_BOTTOM( &embed->rsub );

	embed->border[3].left = 0;	
	embed->border[3].top = embed->rsub.top;
	embed->border[3].width = embed->rsub.left;
	embed->border[3].height = embed->rsub.height;

	/* Corner rects. Top-left, top-right, bottom-right, bottom-left. Order
	 * important.
	 */
	embed->border[4].left = 0;
	embed->border[4].top = 0;
	embed->border[4].width = embed->rsub.left;
	embed->border[4].height = embed->rsub.top;

	embed->border[5].left = IM_RECT_RIGHT( &embed->rsub );
	embed->border[5].top = 0;
	embed->border[5].width = out->Xsize - IM_RECT_RIGHT( &embed->rsub );
	embed->border[5].height = embed->rsub.top;

	embed->border[6].left = IM_RECT_RIGHT( &embed->rsub );
	embed->border[6].top = IM_RECT_BOTTOM( &embed->rsub );
	embed->border[6].width = out->Xsize - IM_RECT_RIGHT( &embed->rsub );
	embed->border[6].height = out->Ysize - IM_RECT_BOTTOM( &embed->rsub );

	embed->border[7].left = 0;
	embed->border[7].top = IM_RECT_BOTTOM( &embed->rsub );
	embed->border[7].width = embed->rsub.left;
	embed->border[7].height = out->Ysize - IM_RECT_BOTTOM( &embed->rsub );

	return( embed );
}

/* Do flag 0/4 (black/white) and 1 (extend).
 */
static int
embed( IMAGE *in, IMAGE *out, int flag, int x, int y, int w, int h )
{
	Embed *embed;

	if( im_cp_desc( out, in ) ) 
                return( -1 );
	out->Xsize = w;
	out->Ysize = h;

	if( !(embed = embed_new( in, out, flag, x, y, w, h )) ||
		im_demand_hint( out, IM_SMALLTILE, in, NULL ) ||
		im_generate( out, 
			im_start_one, embed_gen, im_stop_one,
			in, embed ) )
		return( -1 );

	return( 0 );
}

/**
 * im_embed:
 * @in: input image
 * @out: output image
 * @flag: how to generate the edge pixels
 * @x: place @in at this x position in @out
 * @y: place @in at this y position in @out
 * @w: @out should be this many pixels across
 * @h: @out should be this many pixels down
 *
 * The opposite of im_extract(): embed an image within a larger image. @flag
 * controls what appears in the new pels:
 * 
 * <tgroup cols='2' align='left' colsep='1' rowsep='1'>
 *   <tbody>
 *     <row>
 *       <entry>0</entry>
 *       <entry>black pels (all bytes == 0)</entry>
 *     </row>
 *     <row>
 *       <entry>1</entry>
 *       <entry>extend pels from image edge</entry>
 *     </row>
 *     <row>
 *       <entry>2</entry>
 *       <entry>repeat image</entry>
 *     </row>
 *     <row>
 *       <entry>3</entry>
 *       <entry>mirror image</entry>
 *     </row>
 *     <row>
 *       <entry>4</entry>
 *       <entry>white pels (all bytes == 255)</entry>
 *     </row>
 *   </tbody>
 * </tgroup>
 * 
 * Returns: 0 on success, -1 on error.
 */
int
im_embed( IMAGE *in, IMAGE *out, int flag, int x, int y, int w, int h )
{
	if( im_piocheck( in, out ) ||
		im_check_coding_known( "im_embed", in ) )
		return( -1 );
	if( flag < 0 || flag > 4 ) {
		im_error( "im_embed", "%s", _( "unknown flag" ) );
		return( -1 );
	}
	if( w <= 0 || h <= 0 ) {
		im_error( "im_embed", "%s", _( "bad dimensions" ) );
		return( -1 );
	}

	/* nip can generate this quite often ... just copy.
	 */
	if( x == 0 && y == 0 && w == in->Xsize && h == in->Ysize )
		return( im_copy( in, out ) );

	switch( flag ) {
	case 0:
	case 1:
	case 4:
		if( embed( in, out, flag, x, y, w, h ) )
			return( -1 );
		break;

	case 2:
{
		/* Clock arithmetic: we want negative x/y to wrap around
		 * nicely.
		 */
		const int nx = x < 0 ?
			-x % in->Xsize :
			in->Xsize - x % in->Xsize;
		const int ny = y < 0 ?
			-y % in->Ysize :
			in->Ysize - y % in->Ysize;

		IMAGE *t[1];

		if( im_open_local_array( out, t, 1, "embed-flag2", "p" ) ||
			im_replicate( in, t[0], 
				w / in->Xsize + 2, h / in->Ysize + 2 ) ||
			im_extract_area( t[0], out, nx, ny, w, h ) )
			return( -1 );
}
		break;

	case 3:
{
		/* As case 2, but the tiles are twice the size because of
		 * mirroring.
		 */
		const int w2 = in->Xsize * 2;
		const int h2 = in->Ysize * 2;

		const int nx = x < 0 ?  -x % w2 : w2 - x % w2;
		const int ny = y < 0 ?  -y % h2 : h2 - y % h2;

		IMAGE *t[7];

		if( im_open_local_array( out, t, 7, "embed-flag3", "p" ) ||
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
			im_copy( in, t[0] ) ||
			
			/* Make a 2x2 mirror tile.
			 */
			im_fliphor( t[0], t[1] ) ||
			im_lrjoin( t[0], t[1], t[2] ) ||
			im_flipver( t[2], t[3] ) ||
			im_tbjoin( t[2], t[3], t[4] ) ||

			/* Repeat, then cut out the centre.
			 */
			im_replicate( t[4], t[5], 
				w / t[4]->Xsize + 2, h / t[4]->Ysize + 2 ) ||
			im_extract_area( t[5], t[6], nx, ny, w, h ) ||

			/* Overwrite the centre with the input, much faster
			 * for centre pixels.
			 */
			im_insert_noexpand( t[6], in, out, x, y ) )
				return( -1 );
}
		break;

	default:
		assert( 0 );
	}

	out->Xoffset = x;
	out->Yoffset = y;

	return( 0 );
}
