/* autorot
 *
 * 19/10/14
 * 	- from jpegload
 * 12/4/16
 * 	- test and remove orientation from every ifd
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>

#include "pconversion.h"

typedef struct _VipsAutorot {
	VipsConversion parent_instance;

	VipsImage *in;

	VipsAngle angle;

} VipsAutorot;

typedef VipsConversionClass VipsAutorotClass;

G_DEFINE_TYPE( VipsAutorot, vips_autorot, VIPS_TYPE_CONVERSION );

/**
 * vips_autorot_get_angle:
 * @image: image to fetch orientation from
 *
 * Examine the metadata on @im and return the #VipsAngle to rotate by to turn
 * the image upright. 
 *
 * See also: vips_autorot(). 
 *
 * Returns: the #VipsAngle to rotate by to make the image upright.
 */
VipsAngle
vips_autorot_get_angle( VipsImage *im )
{
	int orientation;
	VipsAngle angle;

	if( vips_image_get_int( im, VIPS_META_ORIENTATION, &orientation ) )
		orientation = 1;

	switch( orientation ) {
	case 6:
		angle = VIPS_ANGLE_D90;
		break;

	case 8:
		angle = VIPS_ANGLE_D270;
		break;

	case 3:
		angle = VIPS_ANGLE_D180;
		break;

	default:
		/* Other values do rotate + mirror, don't bother handling them
		 * though, how common can mirroring be.
		 *
		 * See:
		 *
		 * http://www.80sidea.com/archives/2316
		 */
		angle = VIPS_ANGLE_D0;
		break;
	}

	return( angle ); 
}

static void *
vips_autorot_remove_angle_sub( VipsImage *image, 
	const char *field, GValue *value, void *my_data )
{
	if( vips_isprefix( "exif-", field ) &&
		vips_ispostfix( field, "-Orientation" ) ) {
#ifdef DEBUG
		printf( "vips_autorot_remove_angle: %s\n", field ); 
#endif /*DEBUG*/

		(void) vips_image_remove( image, field );
	}

	return( NULL );
}

/**
 * vips_autorot_remove_angle:
 * @im: image to remove orientation from
 *
 * Remove the orientation tag on @im. Also remove any exif orientation tags. 
 *
 * See also: vips_autorot_get_angle(). 
 */
void
vips_autorot_remove_angle( VipsImage *image )
{
	(void) vips_image_remove( image, VIPS_META_ORIENTATION ); 
	(void) vips_image_map( image, vips_autorot_remove_angle_sub, NULL );
}

static int
vips_autorot_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsAutorot *autorot = (VipsAutorot *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 1 );

	if( VIPS_OBJECT_CLASS( vips_autorot_parent_class )->build( object ) )
		return( -1 );

	g_object_set( object, 
		"angle", vips_autorot_get_angle( autorot->in ),
		NULL ); 
	if( vips_rot( autorot->in, &t[0], autorot->angle, NULL ) )
		return( -1 );
	vips_autorot_remove_angle( t[0] ); 
	if( vips_image_write( t[0], conversion->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_autorot_class_init( VipsAutorotClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "autorot";
	vobject_class->description = _( "autorotate image by exif tag" );
	vobject_class->build = vips_autorot_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsAutorot, in ) );

	VIPS_ARG_ENUM( class, "angle", 6, 
		_( "Angle" ), 
		_( "Angle image was rotated by" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsAutorot, angle ),
		VIPS_TYPE_ANGLE, VIPS_ANGLE_D0 ); 
}

static void
vips_autorot_init( VipsAutorot *autorot )
{
	autorot->angle = VIPS_ANGLE_D0;
}

/**
 * vips_autorot:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @angle: output #VipsAngle the image was rotated by
 *
 * Look at the exif tags and rotate the image to make it upright. The
 * orientation tag is removed from @out to prevent accidental double rotation. 
 *
 * Read @angle to find the amount the image was rotated by. 
 *
 * See also: vips_rot().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_autorot( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "autorot", ap, in, out );
	va_end( ap );

	return( result );
}

