/* fractal surface
 *
 * Author: N. Dessipris
 * Written on: 10/09/1991
 * Modified on:
 * 20/9/95 JC
 *	 - modernised, a little
 * 7/2/10
 * 	- cleanups
 * 	- gtkdoc
 * 4/1/14
 * 	- redo as a class
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>

#include "pcreate.h"

typedef struct _VipsFractsurf {
	VipsCreate parent_instance;

	int width;
	int height;
	double fractal_dimension;

} VipsFractsurf;

typedef VipsCreateClass VipsFractsurfClass;

G_DEFINE_TYPE( VipsFractsurf, vips_fractsurf, VIPS_TYPE_CREATE );

static int
vips_fractsurf_build( VipsObject *object )
{
	VipsCreate *create = VIPS_CREATE( object );
	VipsFractsurf *fractsurf = (VipsFractsurf *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	if( VIPS_OBJECT_CLASS( vips_fractsurf_parent_class )->build( object ) )
		return( -1 );

	if( vips_gaussnoise( &t[0], 
		fractsurf->width, fractsurf->height, 0.0, 1.0, NULL ) || 
		vips_mask_fractal( &t[1], fractsurf->width, fractsurf->height, 
			fractsurf->fractal_dimension, NULL ) ||
		vips_freqmult( t[0], t[1], &t[2], NULL ) ||
		vips_image_write( t[2], create->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_fractsurf_class_init( VipsFractsurfClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "fractsurf";
	vobject_class->description = _( "make a fractal surface" );
	vobject_class->build = vips_fractsurf_build;

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFractsurf, width ),
		1, VIPS_MAX_COORD, 64 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFractsurf, height ),
		1, VIPS_MAX_COORD, 64 );

	VIPS_ARG_DOUBLE( class, "fractal_dimension", 8, 
		_( "Fractal dimension" ), 
		_( "Fractal dimension" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFractsurf, fractal_dimension ),
		2.0, 3.0, 2.5 );

}

static void
vips_fractsurf_init( VipsFractsurf *fractsurf )
{
	fractsurf->width = 64; 
	fractsurf->height = 64; 
	fractsurf->fractal_dimension = 2.5;
}

/**
 * vips_fractsurf:
 * @out: output image
 * @width: output width
 * @height: output height
 * @fractal_dimension: fractal dimension
 * @...: %NULL-terminated list of optional named arguments
 *
 * Generate an image of size @width by @height and fractal dimension 
 * @fractal_dimension. The dimension should be between 2 and 3.
 *
 * See also: vips_gaussnoise(), vips_mask_fractal().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_fractsurf( VipsImage **out, 
	int width, int height, double fractal_dimension, ... )
{
	va_list ap;
	int result;

	va_start( ap, fractal_dimension );
	result = vips_call_split( "fractsurf", ap, 
		out, width, height, fractal_dimension );
	va_end( ap );

	return( result );
}
