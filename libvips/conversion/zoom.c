/* im_zoom
 *
 * Author: N. Martinez 1991
 * 6/6/94 JC
 *	- rewritten to ANSI-C
 *	- now works for any type, including IM_CODING_LABQ
 * 7/10/94 JC
 *	- new IM_ARRAY() macro
 * 26/1/96 JC
 *	- separate x and y zoom factors
 * 21/8/96 JC
 *	- partial, yuk! this is so complicated ...
 * 30/8/96 JC
 *	- sets demand_hint
 * 10/2/00 JC
 *	- check for integer overflow in zoom facs ... was happening with ip's 
 * 	  zoom on large images
 * 3/8/02 JC
 *	- fall back to im_copy() for x & y factors == 1
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 1/2/10
 * 	- gtkdoc
 * 1/6/13
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

/*
 * TODO:
 * Test for pixel size and use memcpy() on individual pixels once they reach
 * sizes of the order of tens of bytes. char-wise copy is quicker than 
 * memcpy() for smaller pixels.
 *
 * Also, I haven't tested it but int-wise copying may be faster still, as 
 * long as alignment permits it.
 *
 * tcv.  2006-09-01
 */

/* Turn on ADDR() range checks.
#define DEBUG 1
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <vips/vips.h>

#include "pconversion.h"

typedef struct _VipsZoom {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *in;

	int xfac;		/* Scale factors */
	int yfac;

} VipsZoom;

typedef VipsConversionClass VipsZoomClass;

G_DEFINE_TYPE( VipsZoom, vips_zoom, VIPS_TYPE_CONVERSION );

/* Paint the part of the region containing only whole pels.
 */
static void
vips_zoom_paint_whole( VipsRegion *or, VipsRegion *ir, VipsZoom *zoom,
	const int left, const int right, const int top, const int bottom )
{
	const int ps = VIPS_IMAGE_SIZEOF_PEL( ir->im );
	const int ls = VIPS_REGION_LSKIP( or );
	const int rs = ps * (right - left);

	/* Transform to ir coordinates.
	 */
	const int ileft = left / zoom->xfac;
	const int iright = right / zoom->xfac;
	const int itop = top / zoom->yfac;
	const int ibottom = bottom / zoom->yfac;

	int x, y, z, i;

	/* We know this!
	 */
	g_assert( right > left && bottom > top && 
		right % zoom->xfac == 0 &&
		left % zoom->xfac == 0 &&
		top % zoom->yfac == 0 &&
		bottom % zoom->yfac == 0 );

	/* Loop over input, as we know we are all whole.
	 */
	for( y = itop; y < ibottom; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir, ileft, y );
		VipsPel *q = VIPS_REGION_ADDR( or, left, y * zoom->yfac );
		VipsPel *r;

		/* Expand the first line of pels.
		 */
		r = q;
		for( x = ileft; x < iright; x++ ) {
			/* Copy each pel xfac times.
			 */
			for( z = 0; z < zoom->xfac; z++ ) {
				for( i = 0; i < ps; i++ )
					r[i] = p[i];

				r += ps;
			}

			p += ps;
		}

		/* Copy the expanded line yfac-1 times.
		 */
		r = q + ls;
		for( z = 1; z < zoom->yfac; z++ ) {
			memcpy( r, q, rs );
			r += ls;
		}
	}
}

/* Paint the part of the region containing only part-pels.
 */
static void
vips_zoom_paint_part( VipsRegion *or, VipsRegion *ir, VipsZoom *zoom,
	const int left, const int right, const int top, const int bottom )
{
	const int ps = VIPS_IMAGE_SIZEOF_PEL( ir->im );
	const int ls = VIPS_REGION_LSKIP( or );
	const int rs = ps * (right - left);

	/* Start position in input.
	 */
	const int ix = left / zoom->xfac;
	const int iy = top / zoom->yfac;

	/* Pels down to yfac boundary, pels down to bottom. Do the smallest of
	 * these for first y loop.
	 */
	const int ptbound = (iy + 1) * zoom->yfac - top;
	const int ptbot = bottom - top;

	int yt = VIPS_MIN( ptbound, ptbot );

	int x, y, z, i;

	/* Only know this.
	 */
	g_assert( right - left >= 0 && bottom - top >= 0 );

	/* Have to loop over output.
	 */
	for( y = top; y < bottom; ) {
		VipsPel *p = VIPS_REGION_ADDR( ir, ix, y / zoom->yfac );
		VipsPel *q = VIPS_REGION_ADDR( or, left, y );
		VipsPel *r;

		/* Output pels until we jump the input pointer.
		 */
		int xt = (ix + 1) * zoom->xfac - left;

		/* Loop for this output line.
		 */
		r = q;
		for( x = left; x < right; x++ ) {
			/* Copy 1 pel.
			 */
			for( i = 0; i < ps; i++ )
				r[i] = p[i];
			r += ps;

			/* Move input if on boundary.
			 */
			--xt;
			if( xt == 0 ) {
				xt = zoom->xfac;
				p += ps;
			}
		}

		/* Repeat that output line until the bottom of this pixel
		 * boundary, or we hit bottom.
		 */
		r = q + ls;
		for( z = 1; z < yt; z++ ) {
			memcpy( r, q, rs );
			r += ls;
		}

		/* Move y on by the number of lines we wrote.
		 */
		y += yt;

		/* Reset yt for next iteration.
		 */
		yt = zoom->yfac;
	}
}

/* Zoom a VipsRegion.
 */
static int
vips_zoom_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsZoom *zoom = (VipsZoom *) b;

	/* Output area we are building.
	 */
	const VipsRect *r = &or->valid;
	const int ri = VIPS_RECT_RIGHT( r );
	const int bo = VIPS_RECT_BOTTOM(r);

	VipsRect s;
	int left, right, top, bottom;
	int width, height;

	/* Area of input we need. We have to round out, as we may have
	 * part-pixels all around the edges.
	 */
	left = VIPS_ROUND_DOWN( r->left, zoom->xfac );
	right = VIPS_ROUND_UP( ri, zoom->xfac );
	top = VIPS_ROUND_DOWN( r->top, zoom->yfac );
	bottom = VIPS_ROUND_UP( bo, zoom->yfac );
	width = right - left;
	height = bottom - top;
	s.left = left / zoom->xfac;
	s.top = top / zoom->yfac;
	s.width = width / zoom->xfac;
	s.height = height / zoom->yfac;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );
	
	/* Find the part of the output (if any) which uses only whole pels.
	 */
	left = VIPS_ROUND_UP( r->left, zoom->xfac );
	right = VIPS_ROUND_DOWN( ri, zoom->xfac );
	top = VIPS_ROUND_UP( r->top, zoom->yfac );
	bottom = VIPS_ROUND_DOWN( bo, zoom->yfac );
	width = right - left;
	height = bottom - top;

	/* Stage 1: we just paint the whole pels in the centre of the region.
	 * As we know they are not clipped, we can do it quickly.
	 */
	if( width > 0 && height > 0 ) 
		vips_zoom_paint_whole( or, ir, zoom, left, right, top, bottom );

	/* Just fractional pixels left. Paint in the top, left, right and
	 * bottom parts.
	 */
	if( top - r->top > 0 ) 
		/* Some top pixels.
		 */
		vips_zoom_paint_part( or, ir, zoom, 
			r->left, ri, r->top, VIPS_MIN( top, bo ) );
	if( left - r->left > 0 && height > 0 )
		/* Left pixels.
		 */
		vips_zoom_paint_part( or, ir, zoom, 
			r->left, VIPS_MIN( left, ri ), top, bottom );
	if( ri - right > 0 && height > 0 )
		/* Right pixels.
		 */
		vips_zoom_paint_part( or, ir, zoom, 
			VIPS_MAX( right, r->left ), ri, top, bottom );
	if( bo - bottom > 0 && height >= 0 )
		/* Bottom pixels.
		 */
		vips_zoom_paint_part( or, ir, zoom, 
			r->left, ri, VIPS_MAX( bottom, r->top ), bo );

	return( 0 );
}

static int
vips_zoom_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsZoom *zoom = (VipsZoom *) object;

	if( VIPS_OBJECT_CLASS( vips_zoom_parent_class )->build( object ) )
		return( -1 );

	g_assert( zoom->xfac > 0 ); 
	g_assert( zoom->yfac > 0 ); 
	
	/* Make sure we won't get integer overflow.
	 */
	if( (double) zoom->in->Xsize * zoom->xfac > (double) INT_MAX / 2 || 
		(double) zoom->in->Ysize * zoom->yfac > (double) INT_MAX / 2 ) {
		vips_error( class->nickname, 
			"%s", _( "zoom factors too large" ) );
		return( -1 );
	}
	if( zoom->xfac == 1 && 
		zoom->yfac == 1 ) 
		return( vips_image_write( zoom->in, conversion->out ) );

	if( vips_image_pio_input( zoom->in ) || 
		vips_check_coding_known( class->nickname, zoom->in ) )  
		return( -1 );

	/* Set demand hints. THINSTRIP will prevent us from using
	 * vips_zoom_paint_whole() much ... so go for FATSTRIP.
	 */
	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_FATSTRIP, zoom->in, NULL ) )
		return( -1 );
	conversion->out->Xsize = zoom->in->Xsize * zoom->xfac;
	conversion->out->Ysize = zoom->in->Ysize * zoom->yfac;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_zoom_gen, vips_stop_one, 
		zoom->in, zoom ) )
		return( -1 );

	return( 0 );
}

static void
vips_zoom_class_init( VipsZoomClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "zoom";
	vobject_class->description = _( "zoom an image" );
	vobject_class->build = vips_zoom_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "input", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsZoom, in ) );

	VIPS_ARG_INT( class, "xfac", 2, 
		_( "Xfac" ), 
		_( "Horizontal zoom factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsZoom, xfac ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "yfac", 3, 
		_( "Yfac" ), 
		_( "Vertical zoom factor" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsZoom, yfac ),
		1, VIPS_MAX_COORD, 1 );

}

static void
vips_zoom_init( VipsZoom *zoom )
{
}

/**
 * vips_zoom:
 * @in: input image
 * @out: output image
 * @xfac: horizontal scale factor
 * @yfac: vertical scale factor
 * @...: %NULL-terminated list of optional named arguments
 *
 * Zoom an image by repeating pixels. This is fast nearest-neighbour
 * zoom.
 *
 * See also: vips_affine(), vips_subsample().
 * 
 * Returns: 0 on success, -1 on error.
 */
int
vips_zoom( VipsImage *in, VipsImage **out, int xfac, int yfac, ... )
{
	va_list ap;
	int result;

	va_start( ap, yfac );
	result = vips_call_split( "zoom", ap, in, out, xfac, yfac );
	va_end( ap );

	return( result );
}
