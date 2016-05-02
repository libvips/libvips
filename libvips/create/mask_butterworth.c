/* creates an butterworth filter.
 *
 * 02/01/14
 * 	- from butterworth.c
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

G_DEFINE_TYPE( VipsMaskButterworth, vips_mask_butterworth, 
	VIPS_TYPE_MASK );

static double
vips_mask_butterworth_point( VipsMask *mask, double dx, double dy ) 
{
	VipsMaskButterworth *butterworth = (VipsMaskButterworth *) mask;
	double order = butterworth->order;
	double fc = butterworth->frequency_cutoff;
	double ac = butterworth->amplitude_cutoff;

	double cnst = (1.0 / ac) - 1.0;
	double fc2 = fc * fc;
	double dist2 = fc2 / (dx * dx + dy * dy);

	return( 1.0 / (1.0 + cnst * pow( dist2, order )) ); 
}

static void
vips_mask_butterworth_class_init( VipsMaskButterworthClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsMaskClass *mask_class = VIPS_MASK_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "mask_butterworth";
	vobject_class->description = _( "make a butterworth filter" );

	mask_class->point = vips_mask_butterworth_point;

	VIPS_ARG_DOUBLE( class, "order", 6, 
		_( "Order" ), 
		_( "Filter order" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskButterworth, order ),
		1.0, 1000000.0, 1.0 );

	VIPS_ARG_DOUBLE( class, "frequency_cutoff", 7, 
		_( "Frequency cutoff" ), 
		_( "Frequency cutoff" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskButterworth, frequency_cutoff ),
		0.0, 1000000.0, 0.5 );

	VIPS_ARG_DOUBLE( class, "amplitude_cutoff", 8, 
		_( "Amplitude cutoff" ), 
		_( "Amplitude cutoff" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskButterworth, amplitude_cutoff ),
		0.0, 1.0, 0.5 );

}

static void
vips_mask_butterworth_init( VipsMaskButterworth *butterworth )
{
	butterworth->order = 1.0;
	butterworth->frequency_cutoff = 0.5;
	butterworth->amplitude_cutoff = 0.5;
}

/**
 * vips_mask_butterworth:
 * @out: output image
 * @width: image size
 * @height: image size
 * @order: filter order
 * @frequency_cutoff: frequency threshold
 * @amplitude_cutoff: amplitude threshold
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @nodc: don't set the DC pixel
 * * @reject: invert the filter sense
 * * @optical: coordinates in optical space
 * * @uchar: output a uchar image
 *
 * Make an butterworth high- or low-pass filter, that is, one with a variable,
 * smooth transition
 * positioned at @frequency_cutoff, where @frequency_cutoff is in
 * range 0 - 1. The shape of the curve is controlled by
 * @order --- higher values give a sharper transition. See Gonzalez and Wintz,
 * Digital Image Processing, 1987. 
 *
 * See also: vips_mask_ideal(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_mask_butterworth( VipsImage **out, int width, int height, 
	double order, double frequency_cutoff, double amplitude_cutoff, ... )
{
	va_list ap;
	int result;

	va_start( ap, amplitude_cutoff );
	result = vips_call_split( "mask_butterworth", ap, 
		out, width, height, 
		order, frequency_cutoff, amplitude_cutoff );
	va_end( ap );

	return( result );
}
