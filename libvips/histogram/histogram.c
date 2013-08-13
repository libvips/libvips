/* base class for all histogram operations
 *
 * properties:
 * 	- one input image
 * 	- one output image
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

#include "phistogram.h"

/**
 * SECTION: histogram
 * @short_description: find, manipulate and apply histograms and lookup tables
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 * Histograms and look-up tables are 1xn or nx1 images, where n is less than
 * 256 or less than 65536, corresponding to 8- and 16-bit unsigned int images. 
 * They are
 * tagged with a #VipsType of IM_TYPE_HISTOGRAM and usually displayed by
 * user-interfaces such as nip2 as plots rather than images.
 *
 * These functions can be broadly grouped as things to find or build 
 * histograms (im_histgr(), im_buildlut(), in_identity()), operations that 
 * manipulate histograms in some way (im_histcum(), im_histnorm()), operations
 * to apply histograms (im_maplut()), and a variety of utility 
 * operations.
 *
 * A final group of operations build tone curves. These are useful in
 * pre-press work for adjusting the appearance of images. They are designed
 * for CIELAB images, but might be useful elsewhere.
 */

G_DEFINE_ABSTRACT_TYPE( VipsHistogram, vips_histogram, VIPS_TYPE_OPERATION );

static int
vips_histogram_build( VipsObject *object )
{
	VipsHistogram *histogram = VIPS_HISTOGRAM( object );

#ifdef DEBUG
	printf( "vips_histogram_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_histogram_parent_class )->build( object ) )
		return( -1 );

	g_object_set( histogram, "out", vips_image_new(), NULL ); 

	return( 0 );
}

static void
vips_histogram_class_init( VipsHistogramClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "histogram";
	vobject_class->description = _( "histogram operations" );
	vobject_class->build = vips_histogram_build;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsHistogram, in ) );

	VIPS_ARG_IMAGE( class, "out", 1, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistogram, out ) );

}

static void
vips_histogram_init( VipsHistogram *histogram )
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_histogram_operation_init( void )
{
	extern GType vips_maplut_get_type( void ); 
	extern GType vips_hist_cum_get_type( void ); 

	vips_maplut_get_type(); 
	vips_hist_cum_get_type(); 
}
