/* 'lossless' 45 degree rot45ate ... odd-sized square images only
 *
 * Author: N. Dessipris (Copyright, N. Dessipris 1991)
 * Written on: 08/05/1991
 * Modified on: 28/05/1991
 * 12/10/95 JC
 *	- small revisions, needs rewriting really
 * 7/8/96 JC
 *	- absolutely foul desp code revised
 *	- many bugs and mem leaks fixed
 * 1/3/99 JC
 *	- oops, fns were not preserving scale and offset
 * 1/12/10
 * 	- allow any size mask for the 90 degree rot45ates by using im_rot4590().
 * 12/10/13
 * 	- redone as a class from im_offsets45()
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

typedef struct _VipsRot45 {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *in;

	/* Rotate by ...
	 */
	VipsAngle45 angle;

	/* Output memory buffer ... copy this to ->out.
	 */
	VipsImage *outbuf; 

} VipsRot45;

typedef VipsConversionClass VipsRot45Class;

G_DEFINE_TYPE( VipsRot45, vips_rot45, VIPS_TYPE_CONVERSION );


/* Creates the offsets to rotate by 45 degrees an odd size square mask 
 */
int *
im_offsets45( int size )
{
	int temp;
	int x, y;
	int size2 = size * size;
	int size_2 = size / 2;
	int *pnt, *cpnt1, *cpnt2;

	if( size%2 == 0 ) {
		im_error( "im_offsets45", "%s", _( "size not odd" ) );
		return( NULL );
	}
	if( !(pnt = IM_ARRAY( NULL, size2, int )) ) 
		return( NULL );

	/* point at the beginning and end of the buffer
	 */
	cpnt1 = pnt; cpnt2 = pnt + size2 - 1;

	for( y = 0; y < size_2; y++ ) {
		temp = (size_2 + y) * size;
		*cpnt1++ = temp; 
		*cpnt2-- = size2 - 1 - temp;

		for( x = 0; x < y; x++ ) {
			temp -= (size-1);
			*cpnt1++ = temp; 
			*cpnt2-- = size2 - 1 - temp;
		}

		for( x = 0; x < size_2 - y; x++ ) {
			temp -= size;
			*cpnt1++ = temp; 
			*cpnt2-- = size2 - 1 - temp;
		}

		for( x = 0; x < size_2 - y; x++ ) {
			temp++;
			*cpnt1++ = temp; 
			*cpnt2-- = size2 - 1 - temp;
		}

		for( x = 0; x < y; x++ ) {
			temp -= ( size - 1 );
			*cpnt1++ = temp; 
			*cpnt2-- = size2 - 1 - temp;
		}
	}

	/* the diagonal now 
	 */
	temp = size * (size - 1);
	cpnt1 = pnt + size_2 * size;
	for( x = 0; x < size; x++ ) {
		*cpnt1++ = temp; 
		temp -= (size-1);
	}

#ifdef PIM_RINT
	temp = 0;
	for( y = 0; y < size; y++ ) {
		for( x = 0; x < size; x++ ) {
			fprintf( stderr, "%4d", *(pnt+temp) );
			temp++;
		}
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n");
#endif

	return( pnt );
}

static void
vips_rot45_45( VipsRot45 *rot45 )
{
	int x, y, i;


}

static int
vips_rot45_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsRot45 *rot45 = (VipsRot *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 1 );

	if( VIPS_OBJECT_CLASS( vips_rot45_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_oddsquare( class->nickname, rot45->in ) )
		return( -1 ); 

	if( rot45->angle == VIPS_ANGLE45_0 )
		return( vips_image_write( rot45->in, conversion->out ) );

	if( vips_image_wio_input( rot45->in ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->out, rot45->in ) )
		return( -1 );

	switch( rot45->angle ) {
	case VIPS_ANGLE45_45:
		break;

	default:
		g_assert( 0 );

		/* Keep -Wall happy.
		 */
		return( 0 );
	}

	return( 0 );
}

static void
vips_rot45_class_init( VipsRot45Class *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_rot45_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "rot45";
	vobject_class->description = _( "rotate an image" );
	vobject_class->build = vips_rot45_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRot45, in ) );

	VIPS_ARG_ENUM( class, "angle", 6, 
		_( "Angle" ), 
		_( "Angle to rotate image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRot45, angle ),
		VIPS_TYPE_ANGLE45, VIPS_ANGLE_45 ); 
}

static void
vips_rot45_init( VipsRot45 *rot45 )
{
}

/**
 * vips_rot45:
 * @in: input image
 * @out: output image
 * @angle: rotation angle
 * @...: %NULL-terminated list of optional named arguments
 *
 * Rotate @in by a multiple of 45 degrees. Odd-length sides and square images
 * only. 
 *
 * See also: vips_rot().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_rot45( VipsImage *in, VipsImage **out, VipsAngle angle, ... )
{
	va_list ap;
	int result;

	va_start( ap, angle );
	result = vips_call_split( "rot45", ap, in, out, angle );
	va_end( ap );

	return( result );
}
