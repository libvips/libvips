/* im_falsecolour
 *
 * 23/6/95 JC
 *	- rewritten for PIO
 *	- now walks edges of colour cube to get more saturated appearance
 * 21/8/05
 * 	- uses falsecolour scale from PET scanner
 * 7/4/06
 * 	- hmm, reversed scale
 * 29/1/10
 * 	- cleanups
 * 	- gtkdoc
 * 12/7/11
 * 	- force input to mono 8-bit for the user
 * 1/8/13
 * 	- redone as a class
 * 23/1/14	
 * 	- oops, was not auto-getting and casting the first band
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

#include <vips/vips.h>
#include <vips/internal.h>

#include "pconversion.h"

typedef struct _VipsFalsecolour {
	VipsConversion parent_instance;

	VipsImage *in;
} VipsFalsecolour;

typedef VipsConversionClass VipsFalsecolourClass;

G_DEFINE_TYPE( VipsFalsecolour, vips_falsecolour, VIPS_TYPE_CONVERSION );

/* Falsecolour scale nicked from a PET scan.
 */
static unsigned char vips_falsecolour_pet[][3] = {
	{ 12, 0, 25 },
	{ 17, 0, 34 },
	{ 20, 0, 41 },
	{ 22, 0, 45 },
	{ 23, 0, 47 },
	{ 27, 0, 55 },
	{ 12, 0, 25 },
	{ 5, 0, 11 },
	{ 5, 0, 11 },
	{ 5, 0, 11 },
	{ 1, 0, 4 },
	{ 1, 0, 4 },
	{ 6, 0, 13 },
	{ 15, 0, 30 },
	{ 19, 0, 40 },
	{ 23, 0, 48 },
	{ 28, 0, 57 },
	{ 36, 0, 74 },
	{ 42, 0, 84 },
	{ 46, 0, 93 },
	{ 51, 0, 102 },
	{ 59, 0, 118 },
	{ 65, 0, 130 },
	{ 69, 0, 138 },
	{ 72, 0, 146 },
	{ 81, 0, 163 },
	{ 47, 0, 95 },
	{ 12, 0, 28 },
	{ 64, 0, 144 },
	{ 61, 0, 146 },
	{ 55, 0, 140 },
	{ 52, 0, 137 },
	{ 47, 0, 132 },
	{ 43, 0, 128 },
	{ 38, 0, 123 },
	{ 30, 0, 115 },
	{ 26, 0, 111 },
	{ 23, 0, 108 },
	{ 17, 0, 102 },
	{ 9, 0, 94 },
	{ 6, 0, 91 },
	{ 2, 0, 87 },
	{ 0, 0, 88 },
	{ 0, 0, 100 },
	{ 0, 0, 104 },
	{ 0, 0, 108 },
	{ 0, 0, 113 },
	{ 0, 0, 121 },
	{ 0, 0, 125 },
	{ 0, 0, 129 },
	{ 0, 0, 133 },
	{ 0, 0, 141 },
	{ 0, 0, 146 },
	{ 0, 0, 150 },
	{ 0, 0, 155 },
	{ 0, 0, 162 },
	{ 0, 0, 167 },
	{ 0, 0, 173 },
	{ 0, 0, 180 },
	{ 0, 0, 188 },
	{ 0, 0, 193 },
	{ 0, 0, 197 },
	{ 0, 0, 201 },
	{ 0, 0, 209 },
	{ 0, 0, 214 },
	{ 0, 0, 218 },
	{ 0, 0, 222 },
	{ 0, 0, 230 },
	{ 0, 0, 235 },
	{ 0, 0, 239 },
	{ 0, 0, 243 },
	{ 0, 0, 247 },
	{ 0, 4, 251 },
	{ 0, 10, 255 },
	{ 0, 14, 255 },
	{ 0, 18, 255 },
	{ 0, 24, 255 },
	{ 0, 31, 255 },
	{ 0, 36, 255 },
	{ 0, 39, 255 },
	{ 0, 45, 255 },
	{ 0, 53, 255 },
	{ 0, 56, 255 },
	{ 0, 60, 255 },
	{ 0, 66, 255 },
	{ 0, 74, 255 },
	{ 0, 77, 255 },
	{ 0, 81, 255 },
	{ 0, 88, 251 },
	{ 0, 99, 239 },
	{ 0, 104, 234 },
	{ 0, 108, 230 },
	{ 0, 113, 225 },
	{ 0, 120, 218 },
	{ 0, 125, 213 },
	{ 0, 128, 210 },
	{ 0, 133, 205 },
	{ 0, 141, 197 },
	{ 0, 145, 193 },
	{ 0, 150, 188 },
	{ 0, 154, 184 },
	{ 0, 162, 176 },
	{ 0, 167, 172 },
	{ 0, 172, 170 },
	{ 0, 180, 170 },
	{ 0, 188, 170 },
	{ 0, 193, 170 },
	{ 0, 197, 170 },
	{ 0, 201, 170 },
	{ 0, 205, 170 },
	{ 0, 211, 170 },
	{ 0, 218, 170 },
	{ 0, 222, 170 },
	{ 0, 226, 170 },
	{ 0, 232, 170 },
	{ 0, 239, 170 },
	{ 0, 243, 170 },
	{ 0, 247, 170 },
	{ 0, 251, 161 },
	{ 0, 255, 147 },
	{ 0, 255, 139 },
	{ 0, 255, 131 },
	{ 0, 255, 120 },
	{ 0, 255, 105 },
	{ 0, 255, 97 },
	{ 0, 255, 89 },
	{ 0, 255, 78 },
	{ 0, 255, 63 },
	{ 0, 255, 55 },
	{ 0, 255, 47 },
	{ 0, 255, 37 },
	{ 0, 255, 21 },
	{ 0, 255, 13 },
	{ 0, 255, 5 },
	{ 2, 255, 2 },
	{ 13, 255, 13 },
	{ 18, 255, 18 },
	{ 23, 255, 23 },
	{ 27, 255, 27 },
	{ 35, 255, 35 },
	{ 40, 255, 40 },
	{ 43, 255, 43 },
	{ 48, 255, 48 },
	{ 55, 255, 55 },
	{ 60, 255, 60 },
	{ 64, 255, 64 },
	{ 69, 255, 69 },
	{ 72, 255, 72 },
	{ 79, 255, 79 },
	{ 90, 255, 82 },
	{ 106, 255, 74 },
	{ 113, 255, 70 },
	{ 126, 255, 63 },
	{ 140, 255, 56 },
	{ 147, 255, 53 },
	{ 155, 255, 48 },
	{ 168, 255, 42 },
	{ 181, 255, 36 },
	{ 189, 255, 31 },
	{ 197, 255, 27 },
	{ 209, 255, 21 },
	{ 224, 255, 14 },
	{ 231, 255, 10 },
	{ 239, 255, 7 },
	{ 247, 251, 3 },
	{ 255, 243, 0 },
	{ 255, 239, 0 },
	{ 255, 235, 0 },
	{ 255, 230, 0 },
	{ 255, 222, 0 },
	{ 255, 218, 0 },
	{ 255, 214, 0 },
	{ 255, 209, 0 },
	{ 255, 201, 0 },
	{ 255, 197, 0 },
	{ 255, 193, 0 },
	{ 255, 188, 0 },
	{ 255, 180, 0 },
	{ 255, 176, 0 },
	{ 255, 172, 0 },
	{ 255, 167, 0 },
	{ 255, 156, 0 },
	{ 255, 150, 0 },
	{ 255, 146, 0 },
	{ 255, 142, 0 },
	{ 255, 138, 0 },
	{ 255, 131, 0 },
	{ 255, 125, 0 },
	{ 255, 121, 0 },
	{ 255, 117, 0 },
	{ 255, 110, 0 },
	{ 255, 104, 0 },
	{ 255, 100, 0 },
	{ 255, 96, 0 },
	{ 255, 90, 0 },
	{ 255, 83, 0 },
	{ 255, 78, 0 },
	{ 255, 75, 0 },
	{ 255, 71, 0 },
	{ 255, 67, 0 },
	{ 255, 65, 0 },
	{ 255, 63, 0 },
	{ 255, 59, 0 },
	{ 255, 54, 0 },
	{ 255, 52, 0 },
	{ 255, 50, 0 },
	{ 255, 46, 0 },
	{ 255, 41, 0 },
	{ 255, 39, 0 },
	{ 255, 36, 0 },
	{ 255, 32, 0 },
	{ 255, 25, 0 },
	{ 255, 22, 0 },
	{ 255, 20, 0 },
	{ 255, 17, 0 },
	{ 255, 13, 0 },
	{ 255, 10, 0 },
	{ 255, 7, 0 },
	{ 255, 4, 0 },
	{ 255, 0, 0 },
	{ 252, 0, 0 },
	{ 251, 0, 0 },
	{ 249, 0, 0 },
	{ 248, 0, 0 },
	{ 244, 0, 0 },
	{ 242, 0, 0 },
	{ 240, 0, 0 },
	{ 237, 0, 0 },
	{ 234, 0, 0 },
	{ 231, 0, 0 },
	{ 229, 0, 0 },
	{ 228, 0, 0 },
	{ 225, 0, 0 },
	{ 222, 0, 0 },
	{ 221, 0, 0 },
	{ 219, 0, 0 },
	{ 216, 0, 0 },
	{ 213, 0, 0 },
	{ 212, 0, 0 },
	{ 210, 0, 0 },
	{ 207, 0, 0 },
	{ 204, 0, 0 },
	{ 201, 0, 0 },
	{ 199, 0, 0 },
	{ 196, 0, 0 },
	{ 193, 0, 0 },
	{ 192, 0, 0 },
	{ 190, 0, 0 },
	{ 188, 0, 0 },
	{ 184, 0, 0 },
	{ 183, 0, 0 },
	{ 181, 0, 0 },
	{ 179, 0, 0 },
	{ 175, 0, 0 },
	{ 174, 0, 0 },
	{ 174, 0, 0 }
};

static int
vips_falsecolour_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsFalsecolour *falsecolour = (VipsFalsecolour *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	if( VIPS_OBJECT_CLASS( vips_falsecolour_parent_class )->
		build( object ) )
		return( -1 );

	if( !(t[0] = vips_image_new_from_memory( 
		(void *) vips_falsecolour_pet, 
		sizeof( vips_falsecolour_pet ),
		1, VIPS_NUMBER( vips_falsecolour_pet ), 3, 
		VIPS_FORMAT_UCHAR )) )
		return( -1 );

	/* Force to mono 8-bit. Don't use vips_colourspace() to go to B_W, we
	 * want to work for images which aren't in a recognised space, like
	 * MULTIBAND.
	 */
	if( vips_image_decode( falsecolour->in, &t[1] ) ||
		vips_extract_band( t[1], &t[2], 0, NULL ) ||
		vips_cast( t[2], &t[3], VIPS_FORMAT_UCHAR, NULL ) ||
		vips_maplut( t[3], &t[4], t[0], NULL ) ||
		vips_image_write( t[4], conversion->out ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_falsecolour_class_init( VipsFalsecolourClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "falsecolour";
	vobject_class->description = _( "false colour an image" );
	vobject_class->build = vips_falsecolour_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "in" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFalsecolour, in ) );

}

static void
vips_falsecolour_init( VipsFalsecolour *falsecolour )
{
}

/**
 * vips_falsecolour:
 * @in: input image 
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Force @in to 1 band, 8-bit, then transform to 
 * a 3-band 8-bit image with a false colour
 * map. The map is supposed to make small differences in brightness more
 * obvious.
 *
 * See also: vips_maplut().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_falsecolour( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "falsecolour", ap, in, out );
	va_end( ap );

	return( result );
}
