/* base class for all create operations
 *
 * properties:
 * 	- single output image we build
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
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
#include <vips/internal.h>

#include "pcreate.h"
#include "point.h"
#include "pmask.h"

/** 
 * SECTION: create
 * @short_description: create #VipsImage in various ways
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These functions generate various test images. You can combine them with
 * the arithmetic and rotate functions to build more complicated images.
 *
 * The im_benchmark() operations are for testing the VIPS SMP system.
 */

G_DEFINE_ABSTRACT_TYPE( VipsCreate, vips_create, VIPS_TYPE_OPERATION );

static int
vips_create_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );

#ifdef DEBUG
	printf( "vips_create_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_object_set( create, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_create_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_create_class_init( VipsCreateClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "create";
	vobject_class->description = _( "create operations" );
	vobject_class->build = vips_create_build;

	VIPS_ARG_IMAGE( class, "out", 1, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsCreate, out ) );
}

static void
vips_create_init( VipsCreate *create )
{
}

void
vips_create_operation_init( void )
{
	extern GType vips_black_get_type( void ); 
	extern GType vips_gaussmat_get_type( void ); 
	extern GType vips_logmat_get_type( void ); 
	extern GType vips_gaussnoise_get_type( void ); 
#ifdef HAVE_PANGOFT2
	extern GType vips_text_get_type( void ); 
#endif /*HAVE_PANGOFT2*/
	extern GType vips_xyz_get_type( void ); 
	extern GType vips_eye_get_type( void ); 
	extern GType vips_grey_get_type( void ); 
	extern GType vips_zone_get_type( void ); 
	extern GType vips_sines_get_type( void ); 
	extern GType vips_buildlut_get_type( void ); 
	extern GType vips_invertlut_get_type( void ); 
	extern GType vips_tonelut_get_type( void ); 
	extern GType vips_identity_get_type( void ); 
	extern GType vips_mask_butterworth_ring_get_type( void ); 
	extern GType vips_mask_butterworth_band_get_type( void ); 
	extern GType vips_mask_gaussian_ring_get_type( void ); 
	extern GType vips_mask_gaussian_band_get_type( void ); 
	extern GType vips_mask_ideal_ring_get_type( void ); 
	extern GType vips_mask_ideal_band_get_type( void ); 

	vips_black_get_type();
	vips_gaussmat_get_type();
	vips_logmat_get_type();
	vips_gaussnoise_get_type(); 
#ifdef HAVE_PANGOFT2
	vips_text_get_type(); 
#endif /*HAVE_PANGOFT2*/
	vips_xyz_get_type(); 
	vips_eye_get_type(); 
	vips_grey_get_type(); 
	vips_zone_get_type(); 
	vips_sines_get_type(); 
	vips_buildlut_get_type(); 
	vips_invertlut_get_type(); 
	vips_tonelut_get_type(); 
	vips_identity_get_type(); 
	vips_mask_ideal_get_type(); 
	vips_mask_ideal_ring_get_type(); 
	vips_mask_ideal_band_get_type(); 
	vips_mask_butterworth_get_type(); 
	vips_mask_butterworth_ring_get_type(); 
	vips_mask_butterworth_band_get_type(); 
	vips_mask_gaussian_get_type(); 
	vips_mask_gaussian_ring_get_type(); 
	vips_mask_gaussian_band_get_type(); 
}

