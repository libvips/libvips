/* creates an ideal ringpass filter.
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

typedef struct _VipsMaskIdealRing {
	VipsMaskIdeal parent_instance;

	double ringwidth;

} VipsMaskIdealRing;

typedef VipsMaskIdealClass VipsMaskIdealRingClass;

G_DEFINE_TYPE( VipsMaskIdealRing, vips_mask_ideal_ring, 
	VIPS_TYPE_MASK_IDEAL );

static double
vips_mask_ideal_ring_point( VipsMask *mask, double dx, double dy ) 
{
	VipsMaskIdeal *ideal = (VipsMaskIdeal *) mask;
	VipsMaskIdealRing *ideal_ring = (VipsMaskIdealRing *) mask;
	double fc = ideal->frequency_cutoff;
	double ringwidth = ideal_ring->ringwidth;

	double df = ringwidth / 2.0;
	double dist2 = dx * dx + dy * dy;
	double fc2_1 = (fc - df) * (fc - df);
	double fc2_2 = (fc + df) * (fc + df);

	return( dist2 > fc2_1 && dist2 < fc2_2 ? 1.0 : 0.0 ); 
}

static void
vips_mask_ideal_ring_class_init( VipsMaskIdealClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsMaskClass *mask_class = VIPS_MASK_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "mask_ideal_ring";
	vobject_class->description = _( "make an ideal ring filter" );

	mask_class->point = vips_mask_ideal_ring_point;

	VIPS_ARG_DOUBLE( class, "ringwidth", 20, 
		_( "Ringwidth" ), 
		_( "Ringwidth" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskIdealRing, ringwidth ),
		0.0, 1000000.0, 0.5 );

}

static void
vips_mask_ideal_ring_init( VipsMaskIdealRing *ideal_ring )
{
	ideal_ring->ringwidth = 0.5;
}

/**
 * vips_mask_ideal_ring:
 * @out: output image
 * @width: image size
 * @height: image size
 * @frequency_cutoff: threshold at which filter ends
 * @ringwidth: ring width
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @nodc: don't set the DC pixel
 * * @reject: invert the filter sense
 * * @optical: coordinates in optical space
 * * @uchar: output a uchar image
 *
 * Make an ideal ring-pass or ring-reject filter, that is, one with a sharp 
 * ring positioned at @frequency_cutoff of width @width, where 
 * @frequency_cutoff and @width are expressed as the range 0 - 1.
 *
 * See also: vips_mask_ideal(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_mask_ideal_ring( VipsImage **out, int width, int height, 
	double frequency_cutoff, double ringwidth, ... )
{
	va_list ap;
	int result;

	va_start( ap, ringwidth );
	result = vips_call_split( "mask_ideal_ring", ap, out, width, height, 
		frequency_cutoff, ringwidth );
	va_end( ap );

	return( result );
}
