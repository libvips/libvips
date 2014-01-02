/* creates a gaussian_ring filter.
 *
 * 02/01/14
 * 	- from gaussian_ring.c
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

typedef struct _VipsFfilterGaussianRing {
	VipsFfilterGaussian parent_instance;

	double ringwidth;

} VipsFfilterGaussianRing;

typedef VipsFfilterGaussianClass VipsFfilterGaussianRingClass;

G_DEFINE_TYPE( VipsFfilterGaussianRing, vips_ffilter_gaussian_ring, 
	VIPS_TYPE_FFILTER_GAUSSIAN );

static double
vips_ffilter_gaussian_ring_point( VipsFfilter *ffilter, double dx, double dy ) 
{
	VipsFfilterGaussian *gaussian = (VipsFfilterGaussian *) ffilter;
	VipsFfilterGaussianRing *gaussian_ring = 
		(VipsFfilterGaussianRing *) ffilter;

	double fc = gaussian->frequency_cutoff;
	double ac = gaussian->amplitude_cutoff;
	double ringwidth = gaussian_ring->ringwidth;

	double df = ringwidth / 2.0;
	double df2 = df * df; 
	double cnst = log( ac ); 
	double dist = sqrt( dx * dx + dy * dy );

	return( exp( cnst * (dist - fc) * (dist - fc) / df2 ) ); 
}

static void
vips_ffilter_gaussian_ring_class_init( VipsFfilterGaussianRingClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsFfilterClass *ffilter_class = VIPS_FFILTER_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "ffilter_gaussian_ring";
	vobject_class->description = _( "make a gaussian ring filter" );

	ffilter_class->point = vips_ffilter_gaussian_ring_point;

	VIPS_ARG_DOUBLE( class, "ringwidth", 20, 
		_( "Ringwidth" ), 
		_( "Ringwidth" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFfilterGaussianRing, ringwidth ),
		0.0, 1000000.0, 0.5 );

}

static void
vips_ffilter_gaussian_ring_init( VipsFfilterGaussianRing *gaussian_ring )
{
	gaussian_ring->ringwidth = 0.5;
}

/**
 * vips_ffilter_gaussian_ring:
 * @out: output image
 * @width: image size
 * @height: image size
 * @frequency_cutoff: frequency threshold
 * @amplitude_cutoff: amplitude threshold
 * @ringwidth: ringwidth
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @nodc: don't set the DC pixel
 * @reject: invert the filter sense
 * @optical: coordinates in optical space
 * @uchar: output a uchar image
 *
 * Make a gaussian ring-pass or ring-reject filter, that is, one with a 
 * variable, smooth transition positioned at @frequency_cutoff of width
 * @ringwidth. 
 *
 * For other arguments, see vips_ffilter_ideal().
 *
 * See also: vips_ffilter_butterworth_ring(), vips_ffilter_ideal_ring(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_ffilter_gaussian_ring( VipsImage **out, int width, int height, 
	double frequency_cutoff, double amplitude_cutoff, double ringwidth, 
	... )
{
	va_list ap;
	int result;

	va_start( ap, ringwidth );
	result = vips_call_split( "ffilter_gaussian_ring", 
		ap, out, width, height, 
		frequency_cutoff, amplitude_cutoff, ringwidth );
	va_end( ap );

	return( result );
}
