/* creates an ideal filter.
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
#include "ffilter.h"

typedef struct _VipsFfilterIdealBand {
	VipsFfilter parent_instance;

	double frequency_cutoff_x;
	double frequency_cutoff_y;
	double r;

} VipsFfilterIdealBand;

typedef VipsFfilterClass VipsFfilterIdealBandClass;

G_DEFINE_TYPE( VipsFfilterIdealBand, vips_ffilter_ideal_band, 
	VIPS_TYPE_FFILTER );

static double
vips_ffilter_ideal_band_point( VipsFfilter *ffilter, double dx, double dy ) 
{
	VipsFfilterIdealBand *ideal_band = (VipsFfilterIdealBand *) ffilter;
	double fcx = ideal_band->frequency_cutoff_x;
	double fcy = ideal_band->frequency_cutoff_y;
	double r2 = ideal_band->r * ideal_band->r;

	double d1 = (dx - fcx) * (dx - fcx) + (dy - fcy) * (dy - fcy);
	double d2 = (dx + fcx) * (dx + fcx) + (dy + fcy) * (dy + fcy);

	return( d1 < r2 || d2 < r2 ? 1.0 : 0.0 ); 
}

static void
vips_ffilter_ideal_band_class_init( VipsFfilterIdealBandClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsFfilterClass *ffilter_class = VIPS_FFILTER_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "ffilter_ideal_band";
	vobject_class->description = _( "make an ideal band filter" );

	ffilter_class->point = vips_ffilter_ideal_band_point;

	VIPS_ARG_DOUBLE( class, "frequency_cutoff_x", 6, 
		_( "Frequency cutoff x" ), 
		_( "Frequency cutoff x" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFfilterIdealBand, frequency_cutoff_x ),
		0.0, 1000000.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "frequency_cutoff_y", 7, 
		_( "Frequency cutoff y" ), 
		_( "Frequency cutoff y" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFfilterIdealBand, frequency_cutoff_y ),
		0.0, 1000000.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "r", 8, 
		_( "r" ), 
		_( "radius of circle" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsFfilterIdealBand, r ),
		0.0, 1000000.0, 0.1 );

}

static void
vips_ffilter_ideal_band_init( VipsFfilterIdealBand *ideal_band )
{
	ideal_band->frequency_cutoff_x = 0.5;
	ideal_band->frequency_cutoff_y = 0.5;
	ideal_band->r = 0.1;
}

/**
 * vips_ffilter_ideal_band:
 * @out: output image
 * @width: image size
 * @height: image size
 * @frequency_cutoff_x: position of band
 * @frequency_cutoff_y: position of band
 * @r: size of band
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @nodc: don't set the DC pixel
 * @reject: invert the filter sense
 * @optical: coordinates in optical space
 * @uchar: output a uchar image
 *
 * Make an ideal band-pass or band-reject filter, that is, one with a 
 * sharp cutoff around the point @frequency_cutoff_x, @frequency_cutoff_y, 
 * of size @r. 
 *
 * See also: vips_ffilter_ideal().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_ffilter_ideal_band( VipsImage **out, int width, int height, 
	double frequency_cutoff_x, double frequency_cutoff_y, double r, ... )
{
	va_list ap;
	int result;

	va_start( ap, r );
	result = vips_call_split( "ffilter_ideal", ap, out, width, height, 
		frequency_cutoff_x, frequency_cutoff_y, r );
	va_end( ap );

	return( result );
}
