/* base class for all conversion operations
 *
 * properties:
 * 	- single output image
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

#include "pconversion.h"

/** 
 * SECTION: conversion
 * @short_description: convert images in some way: change band format, change header, insert, extract, join
 * @see_also: <link linkend="libvips-resample">resample</link>
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations convert an image in some way. They can be split into a two
 * main groups.
 *
 * The first set of operations change an image's format in some way. You
 * can change the band format (for example, cast to 32-bit unsigned
 * int), form complex images from real images, convert images to
 * matrices and back, change header fields, and a few others.
 *
 * The second group move pixels about in some way. You can flip, rotate,
 * extract, insert and join pairs of images in various ways.
 *
 */

/** 
 * VipsAlign:
 * @VIPS_ALIGN_LOW: align low coordinate edge
 * @VIPS_ALIGN_CENTRE: align centre
 * @VIPS_ALIGN_HIGH: align high coordinate edge
 *
 * See vips_join() and so on.
 *
 * Operations like vips_join() need to be told whether to align images on the
 * low or high coordinate edge, or centre.
 *
 * See also: vips_join().
 */

/** 
 * VipsAngle:
 * @VIPS_ANGLE_D0: no rotate
 * @VIPS_ANGLE_D90: 90 degrees clockwise
 * @VIPS_ANGLE_D180: 180 degree rotate
 * @VIPS_ANGLE_D270: 90 degrees anti-clockwise
 *
 * See vips_rot() and so on.
 *
 * Fixed rotate angles.
 *
 * See also: vips_rot().
 */

/** 
 * VipsInteresting:
 * @VIPS_INTERESTING_NONE: do nothing
 * @VIPS_INTERESTING_CENTRE: just take the centre
 * @VIPS_INTERESTING_ENTROPY: use an entropy measure
 * @VIPS_INTERESTING_ATTENTION: look for features likely to draw human attention
 *
 * Pick the algorithm vips uses to decide image "interestingness". This is used
 * by vips_smartcrop(), for example, to decide what parts of the image to
 * keep. 
 *
 * See also: vips_smartcrop().
 */

/**
 * VipsAngle45:
 * @VIPS_ANGLE45_D0: no rotate
 * @VIPS_ANGLE45_D45: 45 degrees clockwise 
 * @VIPS_ANGLE45_D90: 90 degrees clockwise
 * @VIPS_ANGLE45_D135: 135 degrees clockwise
 * @VIPS_ANGLE45_D180: 180 degrees 
 * @VIPS_ANGLE45_D225: 135 degrees anti-clockwise
 * @VIPS_ANGLE45_D270: 90 degrees anti-clockwise
 * @VIPS_ANGLE45_D315: 45 degrees anti-clockwise
 *
 * See vips_rot45() and so on.
 *
 * Fixed rotate angles.
 *
 * See also: vips_rot45().
 */

/** 
 * VipsExtend:
 * @VIPS_EXTEND_BLACK: extend with black (all 0) pixels
 * @VIPS_EXTEND_COPY: copy the image edges
 * @VIPS_EXTEND_REPEAT: repeat the whole image
 * @VIPS_EXTEND_MIRROR: mirror the whole image
 * @VIPS_EXTEND_WHITE: extend with white (all bits set) pixels
 * @VIPS_EXTEND_BACKGROUND: extend with colour from the @background property
 *
 * See vips_embed(), vips_conv(), vips_affine() and so on.
 *
 * When the edges of an image are extended, you can specify
 * how you want the extension done. 
 *
 * #VIPS_EXTEND_BLACK --- new pixels are black, ie. all bits are zero. 
 *
 * #VIPS_EXTEND_COPY --- each new pixel takes the value of the nearest edge
 * pixel
 *
 * #VIPS_EXTEND_REPEAT --- the image is tiled to fill the new area
 *
 * #VIPS_EXTEND_MIRROR --- the image is reflected and tiled to reduce hash
 * edges
 *
 * #VIPS_EXTEND_WHITE --- new pixels are white, ie. all bits are set
 *
 * #VIPS_EXTEND_BACKGROUND --- colour set from the @background property
 *
 * We have to specify the exact value of each enum member since we have to 
 * keep these frozen for back compat with vips7.
 *
 * See also: vips_embed().
 */

/** 
 * VipsDirection:
 * @VIPS_DIRECTION_HORIZONTAL: left-right 
 * @VIPS_DIRECTION_VERTICAL: top-bottom
 *
 * See vips_flip(), vips_join() and so on.
 *
 * Operations like vips_flip() need to be told whether to flip left-right or
 * top-bottom. 
 *
 * See also: vips_flip(), vips_join().
 */

G_DEFINE_ABSTRACT_TYPE( VipsConversion, vips_conversion, VIPS_TYPE_OPERATION );

static int
vips_conversion_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );

#ifdef DEBUG
	printf( "vips_conversion_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_object_set( conversion, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_conversion_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_conversion_class_init( VipsConversionClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "conversion";
	vobject_class->description = _( "conversion operations" );
	vobject_class->build = vips_conversion_build;

	VIPS_ARG_IMAGE( class, "out", 1, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsConversion, out ) );
}

static void
vips_conversion_init( VipsConversion *conversion )
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_conversion_operation_init( void )
{
	extern GType vips_copy_get_type( void ); 
	extern GType vips_tile_cache_get_type( void ); 
	extern GType vips_line_cache_get_type( void ); 
	extern GType vips_sequential_get_type( void ); 
	extern GType vips_cache_get_type( void ); 
	extern GType vips_embed_get_type( void ); 
	extern GType vips_flip_get_type( void ); 
	extern GType vips_insert_get_type( void ); 
	extern GType vips_join_get_type( void ); 
	extern GType vips_arrayjoin_get_type( void ); 
	extern GType vips_extract_area_get_type( void ); 
	extern GType vips_crop_get_type( void ); 
	extern GType vips_smartcrop_get_type( void ); 
	extern GType vips_extract_band_get_type( void ); 
	extern GType vips_replicate_get_type( void ); 
	extern GType vips_cast_get_type( void ); 
	extern GType vips_bandjoin_get_type( void ); 
	extern GType vips_bandjoin_const_get_type( void ); 
	extern GType vips_bandrank_get_type( void ); 
	extern GType vips_black_get_type( void ); 
	extern GType vips_rot_get_type( void ); 
	extern GType vips_rot45_get_type( void ); 
	extern GType vips_autorot_get_type( void ); 
	extern GType vips_ifthenelse_get_type( void ); 
	extern GType vips_recomb_get_type( void ); 
	extern GType vips_bandmean_get_type( void ); 
	extern GType vips_bandfold_get_type( void ); 
	extern GType vips_bandunfold_get_type( void ); 
	extern GType vips_flatten_get_type( void ); 
	extern GType vips_premultiply_get_type( void ); 
	extern GType vips_unpremultiply_get_type( void ); 
	extern GType vips_bandbool_get_type( void ); 
	extern GType vips_gaussnoise_get_type( void ); 
	extern GType vips_grid_get_type( void ); 
	extern GType vips_scale_get_type( void ); 
	extern GType vips_wrap_get_type( void ); 
	extern GType vips_zoom_get_type( void ); 
	extern GType vips_subsample_get_type( void ); 
	extern GType vips_msb_get_type( void ); 
	extern GType vips_byteswap_get_type( void ); 
#ifdef HAVE_PANGOFT2
	extern GType vips_text_get_type( void ); 
#endif /*HAVE_PANGOFT2*/
	extern GType vips_xyz_get_type( void ); 
	extern GType vips_falsecolour_get_type( void ); 
	extern GType vips_gamma_get_type( void ); 

	vips_copy_get_type();
	vips_tile_cache_get_type(); 
	vips_line_cache_get_type(); 
	vips_sequential_get_type(); 
	vips_cache_get_type(); 
	vips_embed_get_type();
	vips_flip_get_type();
	vips_insert_get_type();
	vips_join_get_type();
	vips_arrayjoin_get_type();
	vips_extract_area_get_type();
	vips_crop_get_type();
	vips_smartcrop_get_type();
	vips_extract_band_get_type();
	vips_replicate_get_type();
	vips_cast_get_type();
	vips_bandjoin_get_type();
	vips_bandjoin_const_get_type();
	vips_bandrank_get_type();
	vips_black_get_type();
	vips_rot_get_type();
	vips_rot45_get_type();
	vips_autorot_get_type();
	vips_ifthenelse_get_type();
	vips_recomb_get_type(); 
	vips_bandmean_get_type(); 
	vips_bandfold_get_type(); 
	vips_bandunfold_get_type(); 
	vips_flatten_get_type(); 
	vips_premultiply_get_type(); 
	vips_unpremultiply_get_type(); 
	vips_bandbool_get_type(); 
	vips_gaussnoise_get_type(); 
	vips_grid_get_type(); 
	vips_scale_get_type(); 
	vips_wrap_get_type(); 
	vips_zoom_get_type(); 
	vips_subsample_get_type(); 
	vips_msb_get_type(); 
	vips_byteswap_get_type(); 
#ifdef HAVE_PANGOFT2
	vips_text_get_type(); 
#endif /*HAVE_PANGOFT2*/
	vips_xyz_get_type(); 
	vips_falsecolour_get_type(); 
	vips_gamma_get_type(); 
}
