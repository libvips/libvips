/* Use lcms to move from CMYK to XYZ, if we can. This needs a working
 * vips_icc_import.
 *
 * 21/12/18
 *      - from scRGB2XYZ.c
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

#include <vips/vips.h>

#include <stdio.h>
#include <math.h>

#include <vips/internal.h>

#include "profiles.h"
#include "pcolour.h"

#ifdef HAVE_LCMS2

typedef struct _VipsCMYK2XYZ {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
} VipsCMYK2XYZ;

typedef VipsColourCodeClass VipsCMYK2XYZClass;

G_DEFINE_TYPE( VipsCMYK2XYZ, vips_CMYK2XYZ, VIPS_TYPE_OPERATION );

/* Our actual processing, as a VipsColourTransformFn.
 */
static int
vips_CMYK2XYZ_process( VipsImage *in, VipsImage **out, ... )
{
	return( vips_icc_import( in, out,
		"embedded", TRUE,
		"pcs", VIPS_PCS_XYZ,
		NULL ) );
}

static int
vips_CMYK2XYZ_build( VipsObject *object )
{
	VipsCMYK2XYZ *CMYK2XYZ = (VipsCMYK2XYZ *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *out; 

	if( VIPS_OBJECT_CLASS( vips_CMYK2XYZ_parent_class )->build( object ) )
		return( -1 );

	out = vips_image_new();
	g_object_set( object, "out", out, NULL ); 

	if( vips_copy( CMYK2XYZ->in, &t[0], NULL ) ||
		vips__profile_set( t[0], "cmyk" ) ||
		vips__colourspace_process_n( "CMYK2XYZ", 
			t[0], &t[1], 4, vips_CMYK2XYZ_process ) ||
		vips_image_write( t[1], out ) )
		return( -1 );

	return( 0 );
}

static void
vips_CMYK2XYZ_class_init( VipsCMYK2XYZClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "CMYK2XYZ";
	object_class->description = _( "transform CMYK to XYZ" );

	object_class->build = vips_CMYK2XYZ_build;
	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1,
		_( "Input" ),
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCMYK2XYZ, in ) );

	VIPS_ARG_IMAGE( class, "out", 100,
		_( "Output" ),
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsCMYK2XYZ, out ) );
}

static void
vips_CMYK2XYZ_init( VipsCMYK2XYZ *CMYK2XYZ )
{
}

#else /*!HAVE_LCMS2*/

typedef VipsColourCode VipsCMYK2XYZ;
typedef VipsColourCodeClass VipsCMYK2XYZClass;

G_DEFINE_TYPE(VipsCMYK2XYZ, vips_CMYK2XYZ, VIPS_TYPE_COLOUR_CODE);

void
vips_CMYK2XYZ_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	unsigned char *p = (unsigned char *) in[0];
	float *q = (float *) out;

	int i;

	for( i = 0; i < width; i++ ) {
		float c = p[0] / 255.0;
		float m = p[1] / 255.0;
		float y = p[2] / 255.0;
		float k = p[3] / 255.0;

		float r = 1.0 - (c * (1.0 - k) + k);
		float g = 1.0 - (m * (1.0 - k) + k);
		float b = 1.0 - (y * (1.0 - k) + k);

		q[0] = VIPS_D65_X0 * r;
		q[1] = VIPS_D65_Y0 * g;
		q[2] = VIPS_D65_Z0 * b;

		p += 4;
		q += 3;
	}
}

static void
vips_CMYK2XYZ_class_init( VipsCMYK2XYZClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "CMYK2XYZ";
	object_class->description = _( "transform CMYK to XYZ" );
    
	colour_class->process_line = vips_CMYK2XYZ_line;
}

static void
vips_CMYK2XYZ_init( VipsCMYK2XYZ *CMYK2XYZ )
{
	VipsColour *colour = VIPS_COLOUR( CMYK2XYZ );
	VipsColourCode *code = VIPS_COLOUR_CODE( CMYK2XYZ );

	colour->interpretation = VIPS_INTERPRETATION_XYZ;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;
	colour->input_bands = 4;

	code->input_coding = VIPS_CODING_NONE;
	code->input_format = VIPS_FORMAT_UCHAR;
	code->input_interpretation = VIPS_INTERPRETATION_CMYK;
}

#endif /*HAVE_LCMS2*/

/**
 * vips_CMYK2XYZ: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Turn CMYK to XYZ. If the image has an embedded ICC profile this will be
 * used for the conversion. If there is no embedded profile, a generic
 * fallback profile will be used. 
 *
 * Conversion is to D65 XYZ with relative intent. If you need more control 
 * over the process, use vips_icc_import() instead.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_CMYK2XYZ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "CMYK2XYZ", ap, in, out );
	va_end( ap );

	return( result );
}
