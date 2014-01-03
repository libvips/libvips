/* creates a gaussian filter.
 *
 * 02/01/14
 * 	- from gaussian.c
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

typedef struct _VipsMaskGaussianBand {
	VipsMask parent_instance;

	double frequency_cutoff_x;
	double frequency_cutoff_y;
	double r;
	double amplitude_cutoff;

} VipsMaskGaussianBand;

typedef VipsMaskClass VipsMaskGaussianBandClass;

G_DEFINE_TYPE( VipsMaskGaussianBand, vips_mask_gaussian_band, VIPS_TYPE_MASK );

static double
vips_mask_gaussian_band_point( VipsMask *mask, double dx, double dy ) 
{
	VipsMaskGaussianBand *gaussian_band = (VipsMaskGaussianBand *) mask;

	double fcx = gaussian_band->frequency_cutoff_x;
	double fcy = gaussian_band->frequency_cutoff_y;
	double r2 = gaussian_band->r * gaussian_band->r;
	double ac = gaussian_band->amplitude_cutoff;

	double cnst = log( ac ); 

	double d1 = (dx - fcx) * (dx - fcx) + (dy - fcy) * (dy - fcy);
	double d2 = (dx + fcx) * (dx + fcx) + (dy + fcy) * (dy + fcy);

	/* Normalise the amplitude at (fcx, fcy) to 1.0.
	 */
	double cnsta = 1.0 / (1.0 + 
		exp( cnst * 4.0 * (fcx * fcx + fcy * fcy) / r2 )); 

	return( cnsta * (exp( cnst * d1 / r2 ) + exp( cnst * d2 / r2 )) );
}

static void
vips_mask_gaussian_band_class_init( VipsMaskGaussianBandClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsMaskClass *mask_class = VIPS_MASK_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "mask_gaussian_band";
	vobject_class->description = _( "make a gaussian filter" );

	mask_class->point = vips_mask_gaussian_band_point;

	VIPS_ARG_DOUBLE( class, "frequency_cutoff_x", 7, 
		_( "Frequency cutoff x" ), 
		_( "Frequency cutoff x" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskGaussianBand, frequency_cutoff_x ),
		0.0, 1000000.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "frequency_cutoff_y", 8, 
		_( "Frequency cutoff y" ), 
		_( "Frequency cutoff y" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskGaussianBand, frequency_cutoff_y ),
		0.0, 1000000.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "r", 9, 
		_( "r" ), 
		_( "radius of circle" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskGaussianBand, r ),
		0.0, 1000000.0, 0.1 );

	VIPS_ARG_DOUBLE( class, "amplitude_cutoff", 10, 
		_( "Amplitude cutoff" ), 
		_( "Amplitude cutoff" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskGaussianBand, amplitude_cutoff ),
		0.0, 1.0, 0.5 );

}

static void
vips_mask_gaussian_band_init( VipsMaskGaussianBand *gaussian_band )
{
	gaussian_band->frequency_cutoff_x = 0.5;
	gaussian_band->frequency_cutoff_x = 0.5;
	gaussian_band->r = 0.1;
	gaussian_band->amplitude_cutoff = 0.5;
}

/**
 * vips_mask_gaussian_band:
 * @out: output image
 * @width: image size
 * @height: image size
 * @frequency_cutoff_x: band position 
 * @frequency_cutoff_y: band position
 * @r: band radius
 * @amplitude_cutoff: amplitude threshold
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @nodc: don't set the DC pixel
 * @reject: invert the filter sense
 * @optical: coordinates in optical space
 * @uchar: output a uchar image
 *
 * Make a gaussian band-pass or band-reject filter, that is, one with a 
 * variable, smooth transition positioned at @frequency_cutoff_x, 
 * @frequency_cutoff_y, of radius @r.
 *
 * See also: vips_mask_ideal(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_mask_gaussian_band( VipsImage **out, int width, int height, 
	double frequency_cutoff_x, double frequency_cutoff_y, double r, 
	double amplitude_cutoff, ... )
{
	va_list ap;
	int result;

	va_start( ap, amplitude_cutoff );
	result = vips_call_split( "mask_gaussian_band", ap, out, width, height, 
		frequency_cutoff_x, frequency_cutoff_y, r, 
		amplitude_cutoff );
	va_end( ap );

	return( result );
}
