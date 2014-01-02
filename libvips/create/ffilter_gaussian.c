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
#include "ffilter.h"

G_DEFINE_TYPE( VipsFfilterGaussian, vips_ffilter_gaussian, VIPS_TYPE_FFILTER );

static double
vips_ffilter_gaussian_point( VipsFfilter *ffilter, double dx, double dy ) 
{
	VipsFfilterGaussian *gaussian = (VipsFfilterGaussian *) ffilter;
	double fc = gaussian->frequency_cutoff;
	double ac = gaussian->amplitude_cutoff;

	double cnst = log( ac ); 
	double fc2 = fc * fc;
	double dist2 = (dx * dx + dy * dy) / fc2;

	return( exp( cnst * dist2 ) ); 
}

static void
vips_ffilter_gaussian_class_init( VipsFfilterGaussianClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsFfilterClass *ffilter_class = VIPS_FFILTER_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "ffilter_gaussian";
	vobject_class->description = _( "make a gaussian filter" );

	ffilter_class->point = vips_ffilter_gaussian_point;

	VIPS_ARG_DOUBLE( class, "frequency_cutoff", 7, 
		_( "Frequency cutoff" ), 
		_( "Frequency cutoff" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFfilterGaussian, frequency_cutoff ),
		0.0, 1000000.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "amplitude_cutoff", 8, 
		_( "Amplitude cutoff" ), 
		_( "Amplitude cutoff" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFfilterGaussian, amplitude_cutoff ),
		0.0, 1.0, 0.5 );

}

static void
vips_ffilter_gaussian_init( VipsFfilterGaussian *gaussian )
{
	gaussian->frequency_cutoff = 0.5;
	gaussian->amplitude_cutoff = 0.5;
}

/**
 * vips_ffilter_gaussian:
 * @out: output image
 * @width: image size
 * @height: image size
 * @frequency_cutoff: frequency threshold
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
 * Make a gaussian high- or low-pass filter, that is, one with a variable,
 * smooth transition positioned at @frequency_cutoff.
 *
 * For other arguments, see vips_ffilter_ideal().
 *
 * See also: vips_ffilter_butterworth(), vips_ffilter_ideal(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_ffilter_gaussian( VipsImage **out, int width, int height, 
	double frequency_cutoff, double amplitude_cutoff, ... )
{
	va_list ap;
	int result;

	va_start( ap, amplitude_cutoff );
	result = vips_call_split( "ffilter_gaussian", ap, out, width, height, 
		frequency_cutoff, amplitude_cutoff );
	va_end( ap );

	return( result );
}
