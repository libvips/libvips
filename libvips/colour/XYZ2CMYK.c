/* Use lcms to move from XYZ to CMYK, if we can. This needs a working
 * vips_icc_export.
 *
 * 21/12/18
 *      - from CMYK2XYZ.c
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

#include <vips/vips.h>

#include <stdio.h>
#include <math.h>

#include <vips/internal.h>

#include "pcolour.h"
#include "profiles.h"

#ifdef HAVE_LCMS2

typedef struct _VipsXYZ2CMYK {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
} VipsXYZ2CMYK;

typedef VipsColourCodeClass VipsXYZ2CMYKClass;

G_DEFINE_TYPE( VipsXYZ2CMYK, vips_XYZ2CMYK, VIPS_TYPE_OPERATION );

/* Our actual processing, as a VipsColourTransformFn.
 */
static int
vips_XYZ2CMYK_process( VipsImage *in, VipsImage **out, ... )
{
	return( vips_icc_export( in, out,
		"pcs", VIPS_PCS_XYZ,
		NULL ) );
}

static int
vips_XYZ2CMYK_build( VipsObject *object )
{
	VipsXYZ2CMYK *XYZ2CMYK = (VipsXYZ2CMYK *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *out; 

	if( VIPS_OBJECT_CLASS( vips_XYZ2CMYK_parent_class )->build( object ) )
		return( -1 );

	out = vips_image_new();
	g_object_set( object, "out", out, NULL ); 

	if( vips_copy( XYZ2CMYK->in, &t[0], NULL ) ||
		vips_CMYK2XYZ_set_fallback_profile( t[0] ) ||
		vips__colourspace_process_n( "XYZ2CMYK", 
			t[0], &t[1], 3, vips_XYZ2CMYK_process ) ||
		vips_image_write( t[1], out ) )
		return( -1 );

	return( 0 );
}

static void
vips_XYZ2CMYK_class_init( VipsXYZ2CMYKClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "XYZ2CMYK";
	object_class->description = _( "transform XYZ to CMYK" );

	object_class->build = vips_XYZ2CMYK_build;
	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1,
		_( "Input" ),
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsXYZ2CMYK, in ) );

	VIPS_ARG_IMAGE( class, "out", 100,
		_( "Output" ),
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsXYZ2CMYK, out ) );
}

static void
vips_XYZ2CMYK_init( VipsXYZ2CMYK *XYZ2CMYK )
{
}

#else

typedef VipsColourCode VipsXYZ2CMYK;
typedef VipsColourCodeClass VipsXYZ2CMYKClass;

G_DEFINE_TYPE(VipsXYZ2CMYK, vips_XYZ2CMYK, VIPS_TYPE_COLOUR_CODE);

void
vips_XYZ2CMYK_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
    float *p = (float *) in[0];
    unsigned char *q = (unsigned char *) out;

    const float epsilon = 0.00001;

    int i;

    for (i = 0; i < width; i++) {
        float c, m, y, k;
        float r = p[0] / VIPS_D65_X0;
        float g = p[1] / VIPS_D65_Y0;
        float b = p[2] / VIPS_D65_Z0;

        if (r < epsilon && g < epsilon && b < epsilon)
            q[3] = 255.0;
        c = 255.0 - r;
        m = 255.0 - g;
        y = 255.0 - b;
        k = c;
        k = VIPS_MIN(k, VIPS_MIN(m, y));

        c = (c - k) / (255.0 - k) * 255.0;
        m = (m - k) / (255.0 - k) * 255.0;
        y = (y - k) / (255.0 - k) * 255.0;

        q[0] = (unsigned char) VIPS_CLIP(0, c, 255.0);
        q[1] = (unsigned char) VIPS_CLIP(0, m, 255.0);
        q[2] = (unsigned char) VIPS_CLIP(0, y, 255.0);
        q[3] = (unsigned char) VIPS_CLIP(0, k, 255.0);

        p += 3;
        q += 4;
    }
}

static void
vips_XYZ2CMYK_class_init( VipsXYZ2CMYKClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "XYZ2CMYK";
	object_class->description = _( "transform XYZ to CMYK" );
    
    colour_class->process_line = vips_XYZ2CMYK_line;
}

static void
vips_XYZ2CMYK_init( VipsXYZ2CMYK *XYZ2CMYK )
{
    VipsColour *colour = VIPS_COLOUR( XYZ2CMYK );
    VipsColourCode *code = VIPS_COLOUR_CODE( XYZ2CMYK );

    colour->interpretation = VIPS_INTERPRETATION_CMYK;
    colour->format = VIPS_FORMAT_UCHAR;
    colour->bands = 4;
    colour->input_bands = 3;

    code->input_coding = VIPS_CODING_NONE;
    code->input_format = VIPS_FORMAT_FLOAT;
    code->input_interpretation = VIPS_INTERPRETATION_XYZ;
}

#endif /*HAVE_LCMS2*/

/**
 * vips_XYZ2CMYK: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Turn XYZ to CMYK. If the image has an embedded ICC profile this will be
 * used for the conversion. If there is no embedded profile, a generic
 * fallback profile will be used. 
 *
 * Conversion is from D65 XYZ with relative intent. If you need more control 
 * over the process, use vips_icc_export() instead.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_XYZ2CMYK( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "XYZ2CMYK", ap, in, out );
	va_end( ap );

	return( result );
}
