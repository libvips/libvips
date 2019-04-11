/* simple wrapper over vips_affine() to make scale / rotate easy from the
 * command-line
 *
 * 3/10/13
 * 	- from affine.c
 * 25/10/13
 * 	- oops, reverse rotation direction to match the convention used in the
 * 	  rest of vips
 * 13/8/14
 * 	- oops, missing scale from b, thanks Topochicho
 * 7/2/16
 * 	- use vips_reduce(), if we can
 * 17/11/17
 * `	- add optional "background" param
 * `	- don't use vips_reduce() since it has no "background" param
 * 10/3/18
 * 	- add vips_rotate() class for convenience
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
#include <string.h>

#include <vips/vips.h>

#include "presample.h"

typedef struct _VipsSimilarityBase {
	VipsResample parent_instance;

	double scale;
	double angle;
	VipsInterpolate *interpolate;
	VipsArrayDouble *background;
	double odx;
	double ody;
	double idx;
	double idy;

} VipsSimilarityBase;

typedef VipsResampleClass VipsSimilarityBaseClass;

G_DEFINE_ABSTRACT_TYPE( VipsSimilarityBase, vips_similarity_base, 
	VIPS_TYPE_RESAMPLE );

static int
vips_similarity_base_build( VipsObject *object )
{
	VipsResample *resample = VIPS_RESAMPLE( object );
	VipsSimilarityBase *base = (VipsSimilarityBase *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 4 );
	double a = base->scale * cos( VIPS_RAD( base->angle ) ); 
	double b = base->scale * -sin( VIPS_RAD( base->angle ) );
	double c = -b;
	double d = a;

	if( VIPS_OBJECT_CLASS( vips_similarity_base_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_affine( resample->in, &t[0], a, b, c, d, 
		"interpolate", base->interpolate,
		"odx", base->odx,
		"ody", base->ody,
		"idx", base->idx,
		"idy", base->idy,
		"background", base->background,
		NULL ) )
		return( -1 );

	if( vips_image_write( t[0], resample->out ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_similarity_base_class_init( VipsSimilarityBaseClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "similarity_base";
	vobject_class->description = _( "base similarity transform" );
	vobject_class->build = vips_similarity_base_build;

	VIPS_ARG_INTERPOLATE( class, "interpolate", 5, 
		_( "Interpolate" ), 
		_( "Interpolate pixels with this" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsSimilarityBase, interpolate ) );

	VIPS_ARG_BOXED( class, "background", 6, 
		_( "Background" ), 
		_( "Background value" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarityBase, background ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_DOUBLE( class, "odx", 112, 
		_( "Output offset" ), 
		_( "Horizontal output displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarityBase, odx ),
		-10000000, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "ody", 113, 
		_( "Output offset" ), 
		_( "Vertical output displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarityBase, ody ),
		-10000000, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "idx", 114, 
		_( "Input offset" ), 
		_( "Horizontal input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarityBase, idx ),
		-10000000, 10000000, 0 );

	VIPS_ARG_DOUBLE( class, "idy", 115, 
		_( "Input offset" ), 
		_( "Vertical input displacement" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSimilarityBase, idy ),
		-10000000, 10000000, 0 );

}

static void
vips_similarity_base_init( VipsSimilarityBase *base )
{
	base->scale = 1; 
	base->angle = 0; 
	base->interpolate = NULL; 
	base->odx = 0; 
	base->ody = 0; 
	base->idx = 0; 
	base->idy = 0; 
	base->background = vips_array_double_newv( 1, 0.0 );
}

typedef VipsSimilarityBase VipsSimilarity;
typedef VipsSimilarityBaseClass VipsSimilarityClass;

G_DEFINE_TYPE( VipsSimilarity, vips_similarity, 
	vips_similarity_base_get_type() );

static void
vips_similarity_class_init( VipsSimilarityClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "similarity";
	vobject_class->description = _( "similarity transform of an image" );

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

}

static void
vips_similarity_init( VipsSimilarity *similarity )
{
}

/**
 * vips_similarity: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @scale: %gdouble, scale by this factor
 * * @angle: %gdouble, rotate by this many degrees clockwise
 * * @interpolate: #VipsInterpolate, interpolate pixels with this
 * * @background: #VipsArrayDouble colour for new pixels 
 * * @idx: %gdouble, input horizontal offset
 * * @idy: %gdouble, input vertical offset
 * * @odx: %gdouble, output horizontal offset
 * * @ody: %gdouble, output vertical offset
 * * @ody: %gdouble, output vertical offset
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

typedef VipsSimilarityBase VipsRotate;
typedef VipsSimilarityBaseClass VipsRotateClass;

G_DEFINE_TYPE( VipsRotate, vips_rotate, vips_similarity_base_get_type() );

static void
vips_rotate_class_init( VipsRotateClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "rotate";
	vobject_class->description = 
		_( "rotate an image by a number of degrees" );

	VIPS_ARG_DOUBLE( class, "angle", 4, 
		_( "Angle" ), 
		_( "Rotate anticlockwise by this many degrees" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSimilarity, angle ),
		-10000000, 10000000, 0 );

}

static void
vips_rotate_init( VipsRotate *rotate )
{
}

/**
 * vips_rotate: (method)
 * @in: input image
 * @out: (out): output image
 * @angle: %gdouble, rotate by this many degrees clockwise
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @interpolate: #VipsInterpolate, interpolate pixels with this
 * * @background: #VipsArrayDouble colour for new pixels 
 * * @idx: %gdouble, input horizontal offset
 * * @idy: %gdouble, input vertical offset
 * * @odx: %gdouble, output horizontal offset
 * * @ody: %gdouble, output vertical offset
 * * @ody: %gdouble, output vertical offset
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
vips_rotate( VipsImage *in, VipsImage **out, double angle, ... )
{
	va_list ap;
	int result;

	va_start( ap, angle );
	result = vips_call_split( "rotate", ap, in, out, angle );
	va_end( ap );

	return( result );
}
