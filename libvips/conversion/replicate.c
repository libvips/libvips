/* replicate an image x times horizontally and vertically
 *
 * JC, 30 sep 03 
 *
 * 15/4/04
 *	- some optimisations for some cases
 * 1/2/10
 * 	- gtkdoc
 * 26/10/11
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

typedef struct _VipsReplicate {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *in;

	int across;
	int down;

} VipsReplicate;

typedef VipsConversionClass VipsReplicateClass;

G_DEFINE_TYPE( VipsReplicate, vips_replicate, VIPS_TYPE_CONVERSION );

static int
vips_replicate_gen( VipsRegion *or, void *seq, void *a, void *b, 
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsImage *in = (VipsImage *) a;
	VipsRect *r = &or->valid;
	int twidth = in->Xsize;
	int theight = in->Ysize;

	int x, y;
	VipsRect tile;

	/* Find top left of tiles we need.
	 */
	int xs = (r->left / twidth) * twidth;
	int ys = (r->top / theight) * theight;

	/* The tile enclosing the top-left corner of the requested area.
	 */
	tile.left = xs;
	tile.top = ys;
	tile.width = twidth;
	tile.height = theight;

	/* If the request fits inside a single tile, we can just pointer-copy.
	 */
	if( vips_rect_includesrect( &tile, r ) ) {
		VipsRect irect;

		/* Translate request to input space.
		 */
		irect = *r;
		irect.left -= xs;
		irect.top -= ys;
		if( vips_region_prepare( ir, &irect ) )
			return( -1 );

		if( vips_region_region( or, ir, r, irect.left, irect.top ) )
			return( -1 );

		return( 0 );
	}

	for( y = ys; y < VIPS_RECT_BOTTOM( r ); y += theight )
		for( x = xs; x < VIPS_RECT_RIGHT( r ); x += twidth ) {
			VipsRect paint;

			/* Whole tile at x, y
			 */
			tile.left = x;
			tile.top = y;
			tile.width = twidth;
			tile.height = theight;

			/* Which parts touch the area of the output we are
			 * building.
			 */
			vips_rect_intersectrect( &tile, r, &paint );

			/* Translate back to ir coordinates.
			 */
			paint.left -= x;
			paint.top -= y;

			g_assert( !vips_rect_isempty( &paint ) );

			/* Render into or.
			 */
			if( vips_region_prepare_to( ir, or, &paint,
				paint.left + x,
				paint.top + y ) )
				return( -1 );
		}

	return( 0 );
}

static int
vips_replicate_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsReplicate *replicate = (VipsReplicate *) object;

	if( VIPS_OBJECT_CLASS( vips_replicate_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( replicate->in ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->out, replicate->in ) )
		return( -1 );
	vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, replicate->in, NULL );

	conversion->out->Xsize *= replicate->across;
	conversion->out->Ysize *= replicate->down;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_replicate_gen, vips_stop_one, 
		replicate->in, replicate ) )
		return( -1 );

	return( 0 );
}

static void
vips_replicate_class_init( VipsReplicateClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_replicate_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "replicate";
	vobject_class->description = _( "replicate an image" );
	vobject_class->build = vips_replicate_build;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReplicate, in ) );

	VIPS_ARG_INT( class, "across", 4, 
		_( "Across" ), 
		_( "Repeat this many times horizontally" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReplicate, across ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "down", 5, 
		_( "Down" ), 
		_( "Repeat this many times vertically" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsReplicate, down ),
		1, 1000000, 1 );

}

static void
vips_replicate_init( VipsReplicate *replicate )
{
}

/**
 * vips_replicate:
 * @in: input image
 * @out: output image
 * @across: repeat input this many times across
 * @down: repeat input this many times down
 * @...: %NULL-terminated list of optional named arguments
 *
 * Repeats an image many times.
 *
 * See also: vips_extract().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_replicate( VipsImage *in, VipsImage **out, int across, int down, ... )
{
	va_list ap;
	int result;

	va_start( ap, down );
	result = vips_call_split( "replicate", ap, in, out, across, down );
	va_end( ap );

	return( result );
}
