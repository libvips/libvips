/* find a palette
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

typedef struct _VipsPalette {
	VipsConversion parent_instance;

	VipsImage *in;
	int effort;
	int bitdepth;
} VipsPalette;

typedef VipsConversionClass VipsPaletteClass;

G_DEFINE_TYPE( VipsPalette, vips_palette, VIPS_TYPE_CONVERSION );

static int
vips_palette_write( VipsPalette *palette, VipsImage *out, 
	const VipsQuantisePalette *lp )
{
	VipsPel line[256 * 4];
	VipsPel *rgba;

	g_assert( lp->count <= 256 );

	rgba = line;
	for( int i = 0; i < lp->count; i++ ) {
		rgba[0] = lp->entries[i].r;
		rgba[1] = lp->entries[i].g;
		rgba[2] = lp->entries[i].b;
		rgba[3] = lp->entries[i].a;

		rgba += 4;
	}

	vips_image_init_fields( out,
		lp->count, 1, 4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 
		1.0, 1.0 );

	if( vips_image_write_line( out, 0, line ) )
		return( -1 ); 

	return( 0 );
}

static int
vips_palette_build( VipsObject *object )
{
        VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsPalette *palette = (VipsPalette *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	VipsImage *in;
        VipsQuantiseResult *result;
        VipsQuantiseAttr *attr;
	VipsQuantiseImage *image;

	if( VIPS_OBJECT_CLASS( vips_palette_parent_class )->
		build( object ) )
		return( -1 );

        /* We only work for 8-bit RGBA images.
         */
	in = palette->in;
        if( vips_check_uncoded( class->nickname, in ) ||
                vips_check_format( class->nickname, in, VIPS_FORMAT_UCHAR ) ||
                vips_check_bands_atleast( class->nickname, in, 3 ) )
		return( -1 );

	/* To RGBA.
	 */
	if( in->Bands == 3 ) {
		if( vips_addalpha( in, &t[0], NULL ) )
			return( -1 );
		in = t[0];
	}
	else if( in->Bands > 4 ) {
		if( vips_extract_band( in, &t[0], 0, "n", 4, NULL ) )
			return( -1 );
		in = t[0];
	}

	/* We need the whole thing in memory.
	 */
	if( vips_image_wio_input( in ) )
		return( -1 );

        attr = vips__quantise_attr_create();
	vips__quantise_set_max_colors( attr,
                VIPS_MIN( 255, 1 << palette->bitdepth ) );
        vips__quantise_set_quality( attr, 0, 100 );
        vips__quantise_set_speed( attr, 11 - palette->effort );

	image = vips__quantise_image_create_rgba( attr,
		VIPS_IMAGE_ADDR( in, 0, 0 ), in->Xsize, in->Ysize, 0.0 );

	result = NULL;
        if( vips__quantise_image_quantize_fixed( image, attr, &result ) ) {
		VIPS_FREEF( vips__quantise_image_destroy, image );
		VIPS_FREEF( vips__quantise_attr_destroy, attr );
                vips_error( class->nickname, "%s", _( "quantisation failed" ) );
                return( -1 );
        }

	if( vips_palette_write( palette, conversion->out, 
		vips__quantise_get_palette( result ) ) ) {
		VIPS_FREEF( vips__quantise_result_destroy, result );
		return( -1 );
	}

	VIPS_FREEF( vips__quantise_image_destroy, image );
        VIPS_FREEF( vips__quantise_attr_destroy, attr );

        VIPS_FREEF( vips__quantise_result_destroy, result );

	return( 0 );
}

static void
vips_palette_class_init( VipsPaletteClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "palette";
	vobject_class->description = _( "compute image palette" );
	vobject_class->build = vips_palette_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPalette, in ) );

	VIPS_ARG_INT( class, "effort", 11,
		_( "Effort" ),
		_( "Quantisation effort" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsPalette, effort ),
		1, 10, 7 );

	VIPS_ARG_INT( class, "bitdepth", 1,
		_( "Bit depth" ),
		_( "Compute an N bit palette" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsPalette, bitdepth ),
		0, 16, 8 );

}

static void
vips_palette_init( VipsPalette *palette )
{
}

/**
 * vips_palette: (method)
 * @in: input image 
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @effort: %gint, how much effort to spend on the search
 * * @bitdepth: %gint, bitdepth for generated palette
 *
 * Find the most common colours in an 8-bit RGB or RGBA image.
 *
 * Set @bitdepth to control the size of the computed palette. By default it
 * finds an 8-bit palette, or 256 colours. 
 *
 * Set @effort to control the CPU effort (1 is the fastest,
 * 10 is the slowest, 7 is the default).
 *
 * See also: vips_dither(), vips_maplut().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_palette( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "palette", ap, in, out );
	va_end( ap );

	return( result );
}
