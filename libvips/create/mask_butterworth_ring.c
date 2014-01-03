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

typedef struct _VipsMaskButterworthRing {
	VipsMaskButterworth parent_instance;

	double ringwidth;

} VipsMaskButterworthRing;

typedef VipsMaskButterworthClass VipsMaskButterworthRingClass;

G_DEFINE_TYPE( VipsMaskButterworthRing, vips_mask_butterworth_ring, 
	VIPS_TYPE_MASK_BUTTERWORTH );

static double
vips_mask_butterworth_ring_point( VipsMask *mask, 
	double dx, double dy ) 
{
	VipsMaskButterworth *butterworth = 
		(VipsMaskButterworth *) mask;
	VipsMaskButterworthRing *butterworth_ring = 
		(VipsMaskButterworthRing *) mask;

	double order = butterworth->order;
	double fc = butterworth->frequency_cutoff;
	double ac = butterworth->amplitude_cutoff;
	double ringwidth = butterworth_ring->ringwidth;

	double df = ringwidth / 2.0;
	double cnst = (1.0 / ac) - 1.0;
	double df2 = df * df; 
	double dist = sqrt( dx * dx + dy * dy );

	return( 1.0 / (1.0 + cnst * pow( 
		(dist - fc) * (dist - fc) / df2, order )) ); 
}

static void
vips_mask_butterworth_ring_class_init( 
	VipsMaskButterworthRingClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsMaskClass *mask_class = VIPS_MASK_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "mask_butterworth_ring";
	vobject_class->description = _( "make a butterworth ring filter" );

	mask_class->point = vips_mask_butterworth_ring_point;

	VIPS_ARG_DOUBLE( class, "ringwidth", 20, 
		_( "Ringwidth" ), 
		_( "Ringwidth" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskButterworthRing, ringwidth ),
		0.0, 1000000.0, 0.1 );

}

static void
vips_mask_butterworth_ring_init( 
	VipsMaskButterworthRing *butterworth_ring )
{
	butterworth_ring->ringwidth = 0.1;
}

/**
 * vips_mask_butterworth_ring:
 * @out: output image
 * @width: image size
 * @height: image size
 * @order: filter order
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
 * Make a butterworth ring-pass or ring-reject filter, that is, one with a 
 * variable,
 * smooth transition
 * positioned at @frequency_cutoff of width @width, where @frequency_cutoff is 
 * in the range 0 - 1. The shape of the curve is controlled by
 * @order: higher values give a sharper transition. See Gonzalez and Wintz,
 * Digital Image Processing, 1987. 
 *
 * See also: vips_mask_ideal(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_mask_butterworth_ring( VipsImage **out, int width, int height, 
	double order, double frequency_cutoff, double amplitude_cutoff, 
	double ringwidth, ... )
{
	va_list ap;
	int result;

	va_start( ap, ringwidth );
	result = vips_call_split( "mask_butterworth_ring", ap, 
		out, width, height, 
		order, frequency_cutoff, amplitude_cutoff, ringwidth );
	va_end( ap );

	return( result );
}
