/* base class for all resample operations
 *
 * properties:
 * 	- one in, one out
 * 	- not point-to-point
 * 	- size can change in any way
 * 	- bands, type, format etc. all fixed
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

#include "presample.h"

G_DEFINE_ABSTRACT_TYPE( VipsResample, vips_resample, VIPS_TYPE_OPERATION );

static int
vips_resample_build( VipsObject *object )
{
	VipsResample *resample = VIPS_RESAMPLE( object );

#ifdef DEBUG
	printf( "vips_resample_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_object_set( resample, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_resample_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_resample_class_init( VipsResampleClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "resample";
	vobject_class->description = _( "resample operations" );
	vobject_class->build = vips_resample_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsResample, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsResample, out ) );

}

static void
vips_resample_init( VipsResample *resample )
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_resample_operation_init( void )
{
	extern GType vips_shrink_get_type( void ); 
	extern GType vips_quadratic_get_type( void ); 
	extern GType vips_affine_get_type( void ); 
	extern GType vips_similarity_get_type( void ); 
	extern GType vips_resize_get_type( void ); 

	vips_shrink_get_type(); 
	vips_quadratic_get_type(); 
	vips_affine_get_type(); 
	vips_similarity_get_type(); 
	vips_resize_get_type(); 
}

