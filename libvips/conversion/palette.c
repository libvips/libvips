/* find a palette
 *
 * 25/9/22
 * 	- from palette.c
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

typedef struct _VipsPalette {
	VipsConversion parent_instance;

	VipsImage *in;
	int bitdepth;
} VipsPalette;

typedef VipsConversionClass VipsPaletteClass;

G_DEFINE_TYPE( VipsPalette, vips_palette, VIPS_TYPE_CONVERSION );

static int
vips_palette_build( VipsObject *object )
{
        VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsPalette *palette = (VipsPalette *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

        VipsQuantiseResult *result;
        VipsQuantiseAttr *attr;

	if( VIPS_OBJECT_CLASS( vips_palette_parent_class )->
		build( object ) )
		return( -1 );

        /* We only work for 8-bit images.
         */
        if( vips_check_uncoded( class->nickname, conversion->in ) ||
                vips_check_format( class->nickname, 
                        conversion->in, VIPS_FORMAT_UCHAR ) )
		return( -1 );

        /* We need the whole thing in memory.
         */
        if( vips_image_wio_input( conversion->in ) )
		return( -1 );

        attr = vips__quantise_attr_create();
                vips__quantise_set_max_colors( cgif->attr,
                VIPS_MIN( 255, 1 << cgif->bitdepth ) );
        vips__quantise_set_quality( cgif->attr, 0, 100 );
        vips__quantise_set_speed( cgif->attr, 11 - cgif->effort );

        if( vips__quantise_image_quantize_fixed( conversion->in, cgif->attr,
                &result ) ) {
                vips_error( class->nickname, "%s", _( "quantisation failed" ) );
                return( -1 );
        }

        VIPS_FREEF( vips__quantise_result_destroy, result );
        VIPS_FREEF( vips__quantise_attr_destroy, attr );

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
 * Find the most common colours in an 8-bit image.
 *
 * Set @bitdepth to control the size of the computed palette. By default it
 * finds an 8-bit palette, or 256 colours. 
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
