/* creates a fractal filter.
 *
 * 02/01/14
 * 	- from ideal.c
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
#include <math.h>

#include <vips/vips.h>

#include "pcreate.h"
#include "point.h"
#include "pmask.h"

typedef struct _VipsMaskFractal {
	VipsMask parent_instance;

	double fractal_dimension;

} VipsMaskFractal;

typedef VipsMaskClass VipsMaskFractalClass;

G_DEFINE_TYPE( VipsMaskFractal, vips_mask_fractal, 
	VIPS_TYPE_MASK );

static double
vips_mask_fractal_point( VipsMask *mask, double dx, double dy ) 
{
	VipsMaskFractal *fractal = (VipsMaskFractal *) mask;
	double fd = (fractal->fractal_dimension - 4.0) / 2.0;

	double d2 = dx * dx + dy * dy;

	return( pow( d2, fd ) ); 
}

static void
vips_mask_fractal_class_init( VipsMaskFractalClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsMaskClass *mask_class = VIPS_MASK_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "mask_fractal";
	vobject_class->description = _( "make fractal filter" );

	mask_class->point = vips_mask_fractal_point;

	VIPS_ARG_DOUBLE( class, "fractal_dimension", 8, 
		_( "Fractal dimension" ), 
		_( "Fractal dimension" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskFractal, fractal_dimension ),
		1.0, 1000000.0, 2.5 );

}

static void
vips_mask_fractal_init( VipsMaskFractal *fractal )
{
	fractal->fractal_dimension = 2.5;
}

/**
 * vips_mask_fractal:
 * @out: output image
 * @width: image size
 * @height: image size
 * @fractal_dimension: fractal dimension
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @nodc: don't set the DC pixel
 * @reject: invert the filter sense
 * @optical: coordinates in optical space
 * @uchar: output a uchar image
 *
 * This operation should be used to create fractal images by filtering the
 * power spectrum of Gaussian white noise. See vips_gaussnoise(). 
 *
 * See also: vips_mask_ideal().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_mask_fractal( VipsImage **out, int width, int height, 
	double fractal_dimension, ... )
{
	va_list ap;
	int result;

	va_start( ap, r );
	result = vips_call_split( "mask_fractal", ap, out, width, height, 
		fractal_dimension );
	va_end( ap );

	return( result );
}
