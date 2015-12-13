/* join an array of images together
 *
 * 11/12/15
 * 	- from join.c
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

#include "pconversion.h"

/* Round N down to P boundary. 
 */
#define ROUND_DOWN( N, P ) ((N) - ((N) % P)) 

/* Round N up to P boundary. 
 */
#define ROUND_UP( N, P ) (ROUND_DOWN( (N) + (P) - 1, (P) ))

typedef struct _VipsArrayjoin {
	VipsConversion parent_instance;

	/* Params.
	 */
	VipsArrayImage *in;
	int across;
	int shim;
	VipsArea *background;
	VipsAlign halign;
	VipsAlign valign;
	int hspacing;
	int vspacing;

	int down;
	VipsRect *rects;

} VipsArrayjoin;

typedef VipsConversionClass VipsArrayjoinClass;

G_DEFINE_TYPE( VipsArrayjoin, vips_arrayjoin, VIPS_TYPE_CONVERSION );

static int
vips_arrayjoin_gen( VipsRegion *or, void *seq, 
	void *a, void *b, gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsArrayjoin *join = (VipsArrayjoin *) b;
	VipsRect *r = &or->valid;
	int n = ((VipsArea *) join->in)->n;

	int i;

	/* Does this rect fit within one of our inputs? If it does, we
	 * can pass just the request on.
	 */
	for( i = 0; i < n; i++ ) 
		if( vips_rect_includesrect( &join->rects[i], r ) ) 
			return( vips__insert_just_one( or, ir[i],
				join->rects[i].left, join->rects[i].top ) ); 

	/* Output requires more than one input. Paste all touching inputs into
	 * the output.
	 */
	for( i = 0; i < n; i++ ) 
		if( vips__insert_paste_region( or, ir[i], &join->rects[i] ) )
			return( -1 );

	return( 0 );
}

static int
vips_arrayjoin_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsArrayjoin *join = (VipsArrayjoin *) object;

	VipsImage **in;
	int n;

	VipsImage **format;
	VipsImage **band;
	VipsImage **size;

	int hspacing;
	int vspacing;
	int output_width;
	int output_height;
	int i;

	if( VIPS_OBJECT_CLASS( vips_arrayjoin_parent_class )->build( object ) )
		return( -1 );

	in = vips_array_image_get( join->in, &n );

	/* Move all input images to a common format and number of bands.
	 */
	format = (VipsImage **) vips_object_local_array( object, n );
	if( vips__formatalike_vec( in, format, n ) )
		return( -1 );
	in = format;

	/* We have to include the number of bands in @background in our
	 * calculation.
	 */
	band = (VipsImage **) vips_object_local_array( object, n );
	if( vips__bandalike_vec( class->nickname, 
		in, band, n, join->background->n ) )
		return( -1 );
	in = band;

	/* Now sizealike: search for the largest image.
	 */
	hspacing = in[0]->Xsize;
	vspacing = in[0]->Ysize;
	for( i = 1; i < n; i++ ) {
		if( in[i]->Xsize > hspacing ) 
			hspacing = in[i]->Xsize;
		if( in[i]->Ysize > vspacing ) 
			vspacing = in[i]->Ysize;
	}

	if( !vips_object_argument_isset( object, "hspacing" ) ) 
		g_object_set( object, "hspacing", hspacing, NULL );
	if( !vips_object_argument_isset( object, "vspacing" ) ) 
		g_object_set( object, "vspacing", vspacing, NULL );

	hspacing = join->hspacing;
	vspacing = join->vspacing;

	if( !vips_object_argument_isset( object, "across" ) ) 
		g_object_set( object, "across", n, NULL );

	/* How many images down the grid?
	 */
	join->down = ROUND_UP( n, join->across ) / join->across;

	/* The output size.
	 */
	output_width = hspacing * join->across + 
		join->shim * (join->across - 1);
	output_height = vspacing * join->down + 
		join->shim * (join->down - 1);

	/* Make a rect for the position of each input.
	 */
	join->rects = VIPS_ARRAY( join, n, VipsRect ); 
	for( i = 0; i < n; i++ ) {
		int x = i % join->across;
		int y = i / join->across;

		join->rects[i].left = x * (hspacing + join->shim);
		join->rects[i].top = y * (vspacing + join->shim);
		join->rects[i].width = hspacing;
		join->rects[i].height = vspacing;

		/* In the centre of the array, we make width / height larger
		 * by shim.
		 */
		if( x != join->across - 1 )
			join->rects[i].width += join->shim;
		if( y != join->down - 1 )
			join->rects[i].height += join->shim;

		/* The right edge of the final image is stretched to the right
		 * to fill the whole row.
		 */
		if( i == n - 1 ) 
			join->rects[i].width = 
				output_width - join->rects[i].left;
	}

	/* Each image must be cropped and aligned within an @hspacing by
	 * @vspacing box.
	 */
	size = (VipsImage **) vips_object_local_array( object, n );
	for( i = 0; i < n; i++ ) {
		int left, top;
		int width, height;

		switch( join->halign ) {
		case VIPS_ALIGN_LOW:
			left = 0;
			break;

		case VIPS_ALIGN_CENTRE:
			left = (hspacing - in[i]->Xsize) / 2;
			break;

		case VIPS_ALIGN_HIGH:
			left = hspacing - in[i]->Xsize;
			break;

		default:
			g_assert( 0 );
			break;
		}

		switch( join->valign ) {
		case VIPS_ALIGN_LOW:
			top = 0;
			break;

		case VIPS_ALIGN_CENTRE:
			top = (vspacing - in[i]->Ysize) / 2;
			break;

		case VIPS_ALIGN_HIGH:
			top = vspacing - in[i]->Ysize;
			break;

		default:
			g_assert( 0 );
			break;
		}

		width = join->rects[i].width;
		height = join->rects[i].height;

		if( vips_embed( in[i], &size[i], left, top, width, height,
			"extend", VIPS_EXTEND_BACKGROUND,
			"background", join->background,
			NULL ) )
			return( -1 );
	}

	if( vips_image_pipeline_array( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, size ) )
		return( -1 );

	conversion->out->Xsize = output_width;
	conversion->out->Ysize = output_height;

	if( vips_image_generate( conversion->out,
		vips_start_many, vips_arrayjoin_gen, vips_stop_many, 
		size, join ) )
		return( -1 );

	return( 0 );
}

static void
vips_arrayjoin_class_init( VipsArrayjoinClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_arrayjoin_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "arrayjoin";
	vobject_class->description = _( "join an array of images" );
	vobject_class->build = vips_arrayjoin_build;

	VIPS_ARG_BOXED( class, "in", -1, 
		_( "Input" ), 
		_( "Array of input images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsArrayjoin, in ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_INT( class, "across", 4, 
		_( "Across" ), 
		_( "Number of images across grid" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsArrayjoin, across ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "shim", 5, 
		_( "Shim" ), 
		_( "Pixels between images" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsArrayjoin, shim ),
		0, 1000000, 0 );

	VIPS_ARG_BOXED( class, "background", 6, 
		_( "Background" ), 
		_( "Colour for new pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsArrayjoin, background ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_ENUM( class, "halign", 7, 
		_( "Horizontal align" ), 
		_( "Align on the left, centre or right" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsArrayjoin, halign ),
		VIPS_TYPE_ALIGN, VIPS_ALIGN_LOW ); 

	VIPS_ARG_ENUM( class, "valign", 8, 
		_( "Vertical align" ), 
		_( "Align on the top, centre or bottom" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsArrayjoin, valign ),
		VIPS_TYPE_ALIGN, VIPS_ALIGN_LOW ); 

	VIPS_ARG_INT( class, "hspacing", 9, 
		_( "Horizontal spacing" ), 
		_( "Horizontal spacing between images" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsArrayjoin, hspacing ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "vspacing", 10, 
		_( "Vertical spacing" ), 
		_( "Vertical spacing between images" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsArrayjoin, vspacing ),
		1, 1000000, 1 );

}

static void
vips_arrayjoin_init( VipsArrayjoin *join )
{
	/* Init our instance fields.
	 */
	join->background = 
		vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), 1 ); 
	((double *) (join->background->data))[0] = 0.0;
}

static int
vips_arrayjoinv( VipsImage **in, VipsImage **out, int n, va_list ap )
{
	VipsArrayImage *array; 
	int result;

	array = vips_array_image_new( in, n ); 
	result = vips_call_split( "arrayjoin", ap, array, out );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}

/**
 * vips_arrayjoin:
 * @in: (array length=n) (transfer none): array of input images
 * @out: output image
 * @n: number of input images
 *
 * Optional arguments:
 *
 * @across: number of images per row
 * @shim: space between images, in pixels
 * @background: background ink colour
 * @halign: low, centre or high alignment
 * @valign: low, centre or high alignment
 * @hspacing: horizontal distance between images
 * @vspacing: vertical distance between images
 *
 * Lay out the images in @in in a grid. The grid is @across images across and
 * however high is necessary to use up all of @in. Images are set down
 * left-to-right and top-to-bottom. @across defaults to @n.
 *
 * Each input image is placed with a box of size @hspacing by @vspacing
 * pixels and cropped. These default to the largest width and largest height 
 * of the input images. 
 *
 * Space between images is filled with @background. This defaults to 0
 * (black).
 *
 * Images are positioned within their @hspacing by @vspacing box at low, 
 * centre or high coordinate values, controlled by @halign and @valign. These
 * default to left-top. 
 *
 * Boxes are joined and separated by @shim pixels. This defaults to 0.
 *
 * If the number of bands in the input images differs, all but one of the 
 * images must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the n-band images are operated upon.
 *
 * The input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="libvips-arithmetic">arithmetic</link>).
 *
 * See also: vips_join(), vips_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_arrayjoin( VipsImage **in, VipsImage **out, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_arrayjoinv( in, out, n, ap );
	va_end( ap );

	return( result );
}
