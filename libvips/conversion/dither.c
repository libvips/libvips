/* find a dither
 *
 * 25/9/22
 *	- from cgifsave.c
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pconversion.h"
#include "../foreign/quantise.h"

typedef struct _VipsDither {
	VipsConversion parent_instance;

	VipsImage *in;
	VipsImage *palette;
	double dither;

        VipsQuantiseAttr *attr;
	VipsQuantiseImage *image;
        VipsQuantiseResult *result;

} VipsDither;

typedef VipsConversionClass VipsDitherClass;

G_DEFINE_TYPE( VipsDither, vips_dither, VIPS_TYPE_CONVERSION );

static void
vips_dither_dispose( GObject *gobject )
{
	VipsDither *dither = (VipsDither *) gobject;

        VIPS_FREEF( vips__quantise_result_destroy, dither->result );
	VIPS_FREEF( vips__quantise_image_destroy, dither->image );
	VIPS_FREEF( vips__quantise_attr_destroy, dither->attr );

	G_OBJECT_CLASS( vips_dither_parent_class )->dispose( gobject );
}

static int
vips_dither_to_rgba( VipsDither *dither, VipsImage *in, VipsImage **out )
{
        VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( dither );
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( dither ), 1 );

	VipsImage *rgba;

	rgba = in;

        if( vips_check_uncoded( class->nickname, rgba ) ||
                vips_check_format( class->nickname, rgba, VIPS_FORMAT_UCHAR ) ||
                vips_check_bands_atleast( class->nickname, rgba, 3 ) )
		return( -1 );

	if( rgba->Bands == 3 ) {
		if( vips_addalpha( rgba, &t[0], NULL ) ) 
			return( -1 );
		rgba = t[0];
	}
	else if( rgba->Bands > 4 ) {
		if( vips_extract_band( rgba, &t[0], 0, "n", 4, NULL ) )
			return( -1 );
		rgba = t[0];
	}

	g_object_ref( rgba );
	*out = rgba;

	return( 0 );
}

static int
vips_dither_build( VipsObject *object )
{
        VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsDither *dither = (VipsDither *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	VipsImage *in;
	VipsImage *palette;
	guint32 fake_image[257];
	int n_colours;

	if( VIPS_OBJECT_CLASS( vips_dither_parent_class )->build( object ) )
		return( -1 );

	in = dither->in;
	palette = dither->palette;

	/* The palette can't have more than 256 entries.
	 */
	if( palette->Xsize != 1 && 
		palette->Ysize != 1 ) {
		vips_error( class->nickname, "%s", 
			_( "palettes must have width or height 1" ) );
		return( -1 );
	}
	if( VIPS_IMAGE_N_PELS( palette ) > 256 ) {
		vips_error( class->nickname, "%s", 
			_( "palettes must have not have more than "
				"256 elements" ) );
		return( -1 );
	}
	n_colours = palette->Xsize * palette->Ysize;

        /* We only work for 8-bit RGBA images.
         */
	if( vips_dither_to_rgba( dither, in, &t[0] ) ||
		vips_dither_to_rgba( dither, palette, &t[1] ) )
		return( -1 );
	in = t[0];
	palette = t[1];

	/* We need the whole thing in memory.
	 */
	if( vips_image_wio_input( in ) ||
		vips_image_wio_input( palette ) )
		return( -1 );

        dither->attr = vips__quantise_attr_create();
	vips__quantise_set_max_colors( dither->attr, n_colours );
        vips__quantise_set_quality( dither->attr, 0, 100 );

	/* Make a fake image from the input palette and quantise that to get
	 * the context we use for dithering.
	 */
	memcpy( fake_image, VIPS_IMAGE_ADDR( palette, 0, 0 ), 
		n_colours * sizeof( int ) );
	dither->image = vips__quantise_image_create_rgba( dither->attr,
		fake_image, n_colours, 1, 0.0 );
	if( vips__quantise_image_quantize_fixed( dither->image, 
		dither->attr, &dither->result ) ) {
		vips_error( class->nickname,
			"%s", _( "quantisation failed" ) );
		return( -1 );
	}
	VIPS_FREEF( vips__quantise_image_destroy, dither->image );

{
	const VipsQuantisePalette *lp = 
		vips__quantise_get_palette( dither->result );

	for( int i = 0; i < lp->count; i++ )
		printf( "%d) r = %d, g = %d, b = %d, a = %d\n",
			i,
			lp->entries[i].r,
			lp->entries[i].g,
			lp->entries[i].b,
			lp->entries[i].a );
}

	/* The frame index buffer.
	 */
	vips_image_init_fields( conversion->out,
		in->Xsize, in->Ysize, 1, 
		VIPS_FORMAT_UCHAR, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );
	if( vips_image_write_prepare( conversion->out ) ) 
		return( -1 );
	dither->image = vips__quantise_image_create_rgba( dither->attr,
		VIPS_IMAGE_ADDR( in, 0, 0 ), in->Xsize, in->Ysize, 0.0 );

	/* Now dither!
	 */
	vips__quantise_set_dithering_level( dither->result, dither->dither );
	if( vips__quantise_write_remapped_image( dither->result, dither->image, 
		VIPS_IMAGE_ADDR( conversion->out, 0, 0 ), 
		VIPS_IMAGE_N_PELS( conversion->out ) ) ) {
		vips_error( class->nickname, "%s", _( "dither failed" ) );
		return( -1 );
	}

	return( 0 );
}

static void
vips_dither_class_init( VipsDitherClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->dispose = vips_dither_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "dither";
	vobject_class->description = _( "dither image into palette" );
	vobject_class->build = vips_dither_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDither, in ) );

	VIPS_ARG_IMAGE( class, "palette", 3, 
		_( "Palette" ), 
		_( "Palette image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsDither, palette ) );

	VIPS_ARG_DOUBLE( class, "dither", 10,
		_( "Dithering" ),
		_( "Amount of dithering" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsDither, dither ),
		0.0, 1.0, 1.0 );

}

static void
vips_dither_init( VipsDither *dither )
{
}

/**
 * vips_dither: (method)
 * @in: input image 
 * @out: (out): output image
 * @palette: (in): palette image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dither: %gdouble, dithering level
 *
 * Dither @in using @palette. 
 *
 * Use @dither to set the degree of Floyd-Steinberg dithering.
 *
 * See also: vips_palette().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_dither( VipsImage *in, VipsImage **out, VipsImage *palette, ... )
{
	va_list ap;
	int result;

	va_start( ap, palette );
	result = vips_call_split( "dither", ap, in, out, palette );
	va_end( ap );

	return( result );
}
