/* 'lossless' 45 degree rotate ... odd-sized square images only
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
 * 	- rewritten as a class 
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

} VipsRot45;

typedef VipsConversionClass VipsRot45Class;

G_DEFINE_TYPE( VipsRot45, vips_rot45, VIPS_TYPE_CONVERSION );

#define ASSIGN( Xout, Yout, Xin, Yin ) { \
	VipsPel *q = VIPS_IMAGE_ADDR( out, Xout, Yout ); \
	VipsPel *p = VIPS_IMAGE_ADDR( in, Xin, Yin ); \
	int b;\
	\
	for( b = 0; b < ps; b++ )\
		q[b] = p[b];\
}

#define POINT_TO_TEMP( q, Xin, Yin ) { \
	VipsPel *p = VIPS_IMAGE_ADDR( in, Xin, Yin ); \
	int b;\
	\
	for( b = 0; b < ps; b++ )\
		q[b] = p[b];\
}

#define TEMP_TO_POINT( Xout, Yout, p ) { \
	VipsPel *q = VIPS_IMAGE_ADDR( out, Xout, Yout ); \
	int b;\
	\
	for( b = 0; b < ps; b++ )\
		q[b] = p[b];\
}

/* This can work inplace, ie. in == out is allowed.
 */
static void
vips_rot45_rot45( VipsImage *out, VipsImage *in )
{
	size_t ps = VIPS_IMAGE_SIZEOF_PEL( in ); 
	VipsPel *temp = VIPS_ARRAY( in, ps, VipsPel ); 
	int size = in->Xsize; 
	int size_2 = size / 2;

	int x, y;

	g_assert( in->Xsize == in->Ysize ); 
	g_assert( out->Xsize == out->Ysize ); 
	g_assert( in->Xsize == out->Ssize ); 
	g_assert( in->Xsize % 2 == 0 );

	/* Split the square into 8 triangles. Loop over the top-left one,
	 * reflect into the others.
	 *
	 * 	1 1 2 2 3
	 * 	8 1 2 3 3
	 * 	8 8 x 4 4
	 * 	7 7 6 5 4
	 * 	7 6 6 5 5 
	 *
	 * do the centre separately.
	 */

	for( y = 0; y < size_2; y++ )  
		for( x = y; x < size_2; x++ ) {
			/* Save 1, it goes into 8 at the end.
			 */
			POINT_TO_TEMP( temp, x, y ); 

			/* Fill 1 from 2.
			 */
			ASSIGN( x, y, 
				(x - y) + size_2, y ); 

			/* 2 from 3.
			 */
			ASSIGN( (x - y) + size_2, y, 
				(size - 1) - y, x ); 

			/* 3 from 4.
			 */
			ASSIGN( (size - 1) - y, x, 
				(size - 1) - y, (x - y) + size_2 );

			/* 4 from 5.
			 */
			ASSIGN( (size - 1) - y, (x - y) + size_2, 
				(size - 1) - x, (size - 1) - y ); 

			/* 5 from 6. 
			 */
			ASSIGN( (size - 1) - x, (size - 1) - y,
				size_2 - (x - y), (size - 1) - y );

			/* 6 from 7. 
			 */
			ASSIGN( size_2 - (x - y), (size - 1) - y,
				y, (size - 1) - x ); 

			/* 7 from 8.
			 */
			ASSIGN( y, (size - 1) - x,
				y, size_2 - (x - y) );

			/* 8 from saved 1. 
			 */
			TEMP_TO_POINT( y, size_2 - (x - y), temp ); 
		}

	/* Centre.
	 */
	ASSIGN( size_2, size_2, size_2, size_2 ); 
}

static int
vips_rot45_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsRot45 *rot45 = (VipsRot45 *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 1 );

	VipsImage *from;

	if( VIPS_OBJECT_CLASS( vips_rot45_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_oddsquare( class->nickname, rot45->in ) )
		return( -1 ); 

	if( rot45->angle == VIPS_ANGLE45_0 )
		return( vips_image_write( rot45->in, conversion->out ) );

	if( vips_image_wio_input( rot45->in ) )
		return( -1 );

	t[0] = vips_image_new_buffer();
	if( vips_image_copy_fields( t[0], rot45->in ) ||
		vips_image_write_prepare( t[0] ) )
		return( -1 );

	from = rot45->in;

	switch( rot45->angle ) {
	case VIPS_ANGLE45_315:
		vips_rot45_rot45( t[0], from );
		from = t[0];
		
	case VIPS_ANGLE45_270:
		vips_rot45_rot45( t[0], from );
		from = t[0];

	case VIPS_ANGLE45_225:
		vips_rot45_rot45( t[0], from );
		from = t[0];

	case VIPS_ANGLE45_180:
		vips_rot45_rot45( t[0], from );
		from = t[0];

	case VIPS_ANGLE45_135:
		vips_rot45_rot45( t[0], from );
		from = t[0];

	case VIPS_ANGLE45_90:
		vips_rot45_rot45( t[0], from );
		from = t[0];

	case VIPS_ANGLE45_45:
		vips_rot45_rot45( t[0], from );
		from = t[0];
		break;

	default:
		g_assert( 0 );

		/* Keep -Wall happy.
		 */
		return( 0 );
	}

	if( vips_image_write( t[0], conversion->out ) )
		return( -1 );

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
		VIPS_TYPE_ANGLE45, VIPS_ANGLE45_45 ); 
}

static void
vips_rot45_init( VipsRot45 *rot45 )
{
	rot45->angle = VIPS_ANGLE45_45;
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
vips_rot45( VipsImage *in, VipsImage **out, VipsAngle45 angle, ... )
{
	va_list ap;
	int result;

	va_start( ap, angle );
	result = vips_call_split( "rot45", ap, in, out, angle );
	va_end( ap );

	return( result );
}
