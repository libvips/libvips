/* vips_transpose3d
 *
 * 30/4/18
 * 	- from grid.c 
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

#include "pconversion.h"

typedef struct _VipsTranspose3d {
	VipsConversion parent_instance;

	VipsImage *in;

	int page_height;

} VipsTranspose3d;

typedef VipsConversionClass VipsTranspose3dClass;

G_DEFINE_TYPE( VipsTranspose3d, vips_transpose3d, VIPS_TYPE_CONVERSION );

static int
vips_transpose3d_gen( VipsRegion *or, void *vseq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) vseq;
	VipsImage *in = (VipsImage *) a;
	VipsTranspose3d *transpose3d = (VipsTranspose3d *) b;
	VipsRect *r = &or->valid;

	int output_page_height = in->Ysize / transpose3d->page_height;

	int y;
	VipsRect tile;
	
	tile = *r;
	tile.height = 1;

	for( y = 0; y < r->height; y++ ) { 
		/* y in output.
		 */
		int yo = r->top + y;

		/* On output page.
		 */
		int yop = yo / output_page_height;

		/* Line on output page.
		 */
		int yol = yo % output_page_height;

		/* y of input page.
		 */
		int yip = yol * transpose3d->page_height;

		/* y of input line.
		 */
		int yi = yip + yop;

		tile.top = yi;

		/* Render into or.
		 */
		if( vips_region_prepare_to( ir, or, &tile, tile.left, yo ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_transpose3d_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsTranspose3d *transpose3d = (VipsTranspose3d *) object;

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_transpose3d_parent_class )->
		build( object ) )
		return( -1 );

	in = transpose3d->in;

	if( vips_check_coding_known( class->nickname, in ) ||
		vips_image_pio_input( in ) )
		return( -1 );

	if( !vips_object_argument_isset( object, "page_height" ) ) {
		if( vips_image_get_int( in, 
			VIPS_META_PAGE_HEIGHT, &transpose3d->page_height ) ) 
			return( -1 );
	}

	if( transpose3d->page_height <= 0 ||
		in->Ysize % transpose3d->page_height != 0 )  {
		vips_error( class->nickname, "%s", _( "bad page_height" ) );
		return( -1 );
	}

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, in, NULL ) )
		return( -1 );
	vips_image_set_int( conversion->out, 
		VIPS_META_PAGE_HEIGHT, in->Ysize / transpose3d->page_height );

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_transpose3d_gen, vips_stop_one, 
		in, transpose3d ) )
		return( -1 );

	return( 0 );
}

static void
vips_transpose3d_class_init( VipsTranspose3dClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "transpose3d";
	vobject_class->description = _( "transpose3d an image" );
	vobject_class->build = vips_transpose3d_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsTranspose3d, in ) );

	VIPS_ARG_INT( class, "page_height", 3, 
		_( "Page height" ), 
		_( "Height of each input page" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsTranspose3d, page_height ),
		0, 10000000, 0 );

}

static void
vips_transpose3d_init( VipsTranspose3d *transpose3d )
{
}

/**
 * vips_transpose3d: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @page_height: %gint, size of each input page
 *
 * Transpose a volumetric image. 
 *
 * Volumetric images are very tall, thin images, with the metadata item
 * #VIPS_META_PAGE_HEIGHT set to the height of each sub-image. 
 *
 * This operation swaps the two major dimensions, so that page N in the
 * output contains the Nth scanline, in order, from each input page.
 *
 * You can override the #VIPS_META_PAGE_HEIGHT metadata item with the optional
 * @page_height parameter. 
 *
 * #VIPS_META_PAGE_HEIGHT in the output image is the number of pages in the
 * input image. 
 *
 * See also: vips_grid().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_transpose3d( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "transpose3d", ap, in, out );
	va_end( ap );

	return( result );
}
