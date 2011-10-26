/* flip left/right and up/down
 *
 * Copyright: 1990, N. Dessipris
 * Written on: 28/10/91
 * Updated on:
 * 19/7/93 JC
 *	- now allows IM_CODING_LABQ too
 *	- yuk! needs rewriting
 * 21/12/94 JC
 *	- rewritten
 * 14/4/04 
 *	- sets Xoffset / Yoffset
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 29/1/10
 * 	- cleanups
 * 	- gtkdoc
 * 17/10/11
 * 	- redone as a class
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

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "conversion.h"

/**
 * VipsFlip:
 * @in: input image
 * @output: output image
 * @direction: flip horizontally or vertically
 *
 * Flips an image left-right or up-down.
 *
 * See also: im_rot90().
 *
 * Returns: 0 on success, -1 on error
 */

typedef struct _VipsFlip {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *input;

	/* Swap bytes on the way through.
	 */
	VipsDirection direction;

} VipsFlip;

typedef VipsConversionClass VipsFlipClass;

G_DEFINE_TYPE( VipsFlip, vips_flip, VIPS_TYPE_CONVERSION );

static int
vips_flip_vertical_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &or->valid;
	VipsRect in;
	PEL *p, *q;
	int y;

	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );

	int ls;
	int psk, qsk;

	/* Transform to input coordinates.
	 */
	in = *r;
	in.top = ir->im->Ysize - bo;

	/* Ask for input we need.
	 */
	if( vips_region_prepare( ir, &in ) )
		return( -1 );

	/* Loop, copying and reversing lines.
	 */
	p = (PEL *) VIPS_REGION_ADDR( ir, le, in.top + in.height - 1 );
	q = (PEL *) VIPS_REGION_ADDR( or, le, to );
	psk = VIPS_REGION_LSKIP( ir );
	qsk = VIPS_REGION_LSKIP( or );
	ls = VIPS_REGION_SIZEOF_LINE( or );

	for( y = to; y < bo; y++ ) {
		memcpy( q, p, ls );

		p -= psk;
		q += qsk;
	}

	return( 0 );
}

static int
vips_flip_horizontal_gen( VipsRegion *or, void *seq, void *a, void *b, 
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &or->valid;
	VipsRect in;
	char *p, *q;
	int x, y, z;

	int le = r->left;
	int ri = VIPS_RECT_RIGHT(r);
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);

	int ps = VIPS_IMAGE_SIZEOF_PEL( ir->im );	/* sizeof pel */

	int hgt = ir->im->Xsize - r->width;

	int lastx;

	/* Transform to input coordinates.
	 */
	in = *r;
	in.left = hgt - r->left;

	/* Find x of final pixel in input area.
	 */
	lastx = VIPS_RECT_RIGHT( &in ) - 1;

	/* Ask for input we need.
	 */
	if( vips_region_prepare( ir, &in ) )
		return( -1 );

	/* Loop, copying and reversing lines.
	 */
	for( y = to; y < bo; y++ ) {
		p = VIPS_REGION_ADDR( ir, lastx, y );
		q = VIPS_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			/* Copy the pel.
			 */
			for( z = 0; z < ps; z++ )
				q[z] = p[z];

			/* Skip forwards in out, back in in.
			 */
			q += ps;
			p -= ps;
		}
	}

	return( 0 );
}

static int
vips_flip_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsFlip *flip = (VipsFlip *) object;

	VipsGenerateFn generate_fn;

	if( VIPS_OBJECT_CLASS( vips_flip_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( flip->input ) || 
		vips_image_pio_output( conversion->output ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->output, flip->input ) )
		return( -1 );
	vips_demand_hint( conversion->output, 
		VIPS_DEMAND_STYLE_THINSTRIP, flip->input, NULL );

	if( flip->direction == VIPS_DIRECTION_HORIZONTAL ) {
		generate_fn = vips_flip_horizontal_gen;
		conversion->output->Xoffset = flip->input->Xsize;
		conversion->output->Yoffset = 0;
	}
	else {
		generate_fn = vips_flip_vertical_gen;
		conversion->output->Xoffset = 0;
		conversion->output->Yoffset = flip->input->Ysize;
	}

	if( vips_image_generate( conversion->output,
		vips_start_one, generate_fn, vips_stop_one, 
		flip->input, flip ) )
		return( -1 );

	return( 0 );
}

static void
vips_flip_class_init( VipsFlipClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_flip_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "flip";
	vobject_class->description = _( "flip an image" );
	vobject_class->build = vips_flip_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFlip, input ) );

	VIPS_ARG_ENUM( class, "direction", 6, 
		_( "Direction" ), 
		_( "Direction to flip image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFlip, direction ),
		VIPS_TYPE_DIRECTION, VIPS_DIRECTION_HORIZONTAL ); 
}

static void
vips_flip_init( VipsFlip *flip )
{
}

int
vips_flip( VipsImage *in, VipsImage **out, VipsDirection direction, ... )
{
	va_list ap;
	int result;

	va_start( ap, direction );
	result = vips_call_split( "flip", ap, in, out, direction );
	va_end( ap );

	return( result );
}
