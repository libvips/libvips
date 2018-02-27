/* Sobel edge detector
 * 
 * 2/2/18
 * 	- from vips_sobel()
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

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

/* TODO
 *	- check sobel speed with separated and non-sep masks
 *	- add an 8-bit sobel path, with offset 128 and code for abs() + abs()
 */

typedef struct _VipsSobel {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

} VipsSobel;

typedef VipsOperationClass VipsSobelClass;

G_DEFINE_TYPE( VipsSobel, vips_sobel, VIPS_TYPE_OPERATION );

static int
vips_sobel_build( VipsObject *object )
{
	VipsSobel *sobel = (VipsSobel *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 20 );

	t[1] = vips_image_new_matrixv( 1, 3, 1.0, 2.0, 1.0 );
	t[2] = vips_image_new_matrixv( 3, 1, 1.0, 0.0, -1.0 );
	if( vips_conv( sobel->in, &t[3], t[1], NULL ) ||
		vips_conv( t[3], &t[4], t[2], NULL ) ) 
		return( -1 );

	t[5] = vips_image_new_matrixv( 3, 1, 1.0, 2.0, 1.0 );
	t[6] = vips_image_new_matrixv( 1, 3, 1.0, 0.0, -1.0 );
	if( vips_conv( sobel->in, &t[7], t[5], NULL ) ||
		vips_conv( t[7], &t[8], t[6], NULL ) ) 
		return( -1 );

	if( vips_abs( t[4], &t[9], NULL ) ||
		vips_abs( t[8], &t[10], NULL ) ||
		vips_add( t[9], t[10], &t[11], NULL ) ||
		vips_cast( t[11], &t[12], sobel->in->BandFmt, NULL ) )
		return( -1 ); 

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( vips_image_write( t[12], sobel->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_sobel_class_init( VipsSobelClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "sobel";
	object_class->description = _( "Sobel edge detector" );
	object_class->build = vips_sobel_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSobel, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsSobel, out ) );

}

static void
vips_sobel_init( VipsSobel *sobel )
{
}

/**
 * vips_sobel: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Simple Sobel edge detector.
 *
 * See also: vips_canny().
 * 
 * Returns: 0 on success, -1 on error.
 */
int 
vips_sobel( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sobel", ap, in, out );  
	va_end( ap );

	return( result );
}
