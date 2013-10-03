/* simple wrapper over vips_similarity() to make scale / rotate easy from the
 * command-line
 *
 * 3/10/13
 * 	- from similarity.c
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

#include <math.h>

#include <vips/vips.h>

#include "presample.h"

typedef struct _VipsSimilarity {
	VipsResample parent_instance;

	double scale;
	double angle;
	VipsInterpolate *interpolate;
	double odx;
	double ody;
	double idx;
	double idy;

} VipsSimilarity;

typedef VipsResampleClass VipsSimilarityClass;

G_DEFINE_TYPE( VipsSimilarity, vips_similarity, VIPS_TYPE_RESAMPLE );

static int
vips_similarity_build( VipsObject *object )
{
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsSimilarity *similarity = (VipsSimilarity *) object;

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 4 );

	double a, b, c, d; 

	if( VIPS_OBJECT_CLASS( vips_similarity_parent_class )->build( object ) )
		return( -1 );

	a = similarity->scale * cos( VIPS_RAD( similarity->angle ) ); 
	b = sin( VIPS_RAD( similarity->angle ) );
	c = -b;
	d = a;

	if( vips_affine( resample->in, &t[0], a, b, c, d, 
		"interpolate", similarity->interpolate,
		"odx", similarity->odx,
		"ody", similarity->ody,
		"idx", similarity->idx,
		"idy", similarity->idy,
		NULL ) ||
		vips_image_write( t[0], resample->out ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_similarity_class_init( VipsSimilarityClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "similarity";
	vobject_class->description = _( "similarity transform of an image" );
	vobject_class->build = vips_similarity_build;

	VIPS_ARG_DOUBLE( class, "scale", 3, 
		_( "Scale" ), 
		_( "Scale by this factor" ), 
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarity, scale ),
		0, 10000000, 1 );

	VIPS_ARG_DOUBLE( class, "angle", 4, 
		_( "Angle" ), 
		_( "Rotate anticlockwise by this many degrees" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarity, angle ),
		-10000000, 10000000, 0 );

	VIPS_ARG_INTERPOLATE( class, "interpolate", 2, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsSimilarity, interpolate ) );

	VIPS_ARG_DOUBLE( class, "odx", 112, 
		_( "Output offset" ), 
		_( "Horizontal output displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarity, odx ),
		-10000000, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "ody", 113, 
		_( "Output offset" ), 
		_( "Vertical output displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarity, ody ),
		-10000000, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "idx", 114, 
		_( "Input offset" ), 
		_( "Horizontal input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarity, idx ),
		-10000000, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "idy", 115, 
		_( "Input offset" ), 
		_( "Vertical input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarity, idy ),
		-10000000, 10000000, 0 );
}

static void
vips_similarity_init( VipsSimilarity *similarity )
{
	similarity->scale = 1; 
}

/**
 * vips_similarity:
 * @in: input image
 * @out: output image
 *
 * Optional arguments:
 *
 * @scale: scale by this factor
 * @angle: rotate by this many degrees anticlockwise
 * @interpolate: interpolate pixels with this
 * @idx: input horizontal offset
 * @idy: input vertical offset
 * @odx: output horizontal offset
 * @ody: output vertical offset
 *
 * This operator calls vips_affine() for you, calculating the matrix for the
 * affine transform from @scale and @angle. Other parameters are passed on to
 * vips_affine() unaltered. 
 *
 * See also: vips_affine(), #VipsInterpolate.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_similarity( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "similarity", ap, in, out );
	va_end( ap );

	return( result );
}
