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
#include "pmask.h"

G_DEFINE_TYPE( VipsMaskIdeal, vips_mask_ideal, VIPS_TYPE_MASK );

static double
vips_mask_ideal_point( VipsMask *mask, double dx, double dy ) 
{
	VipsMaskIdeal *ideal = (VipsMaskIdeal *) mask;
	double fc = ideal->frequency_cutoff;

	double dist2 = dx * dx + dy * dy;
	double fc2 = fc * fc;

	return( dist2 <= fc2 ? 0.0 : 1.0 ); 
}

static void
vips_mask_ideal_class_init( VipsMaskIdealClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsMaskClass *mask_class = VIPS_MASK_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "mask_ideal";
	vobject_class->description = _( "make an ideal filter" );

	mask_class->point = vips_mask_ideal_point;

	VIPS_ARG_DOUBLE( class, "frequency_cutoff", 6, 
		_( "Frequency cutoff" ), 
		_( "Frequency cutoff" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaskIdeal, frequency_cutoff ),
		0.0, 1000000.0, 0.5 );

}

static void
vips_mask_ideal_init( VipsMaskIdeal *ideal )
{
	ideal->frequency_cutoff = 0.5;
}

/**
 * vips_mask_ideal:
 * @out: output image
 * @width: image size
 * @height: image size
 * @frequency_cutoff: 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @nodc: don't set the DC pixel
 * @reject: invert the filter sense
 * @optical: coordinates in optical space
 * @uchar: output a uchar image
 *
 * Make an ideal high- or low-pass filter, that is, one with a sharp cutoff
 * positioned at @frequency_cutoff, where @frequency_cutoff is in
 * the range 0 - 1.
 *
 * This operation creates a one-band float image of the specified size. 
 * The image has
 * values in the range [0, 1] and is typically used for multiplying against 
 * frequency domain images to filter them.
 * Masks are created with the DC component at (0, 0). The DC pixel always
 * has the value 1.0.
 *
 * Set @nodc to not set the DC pixel. 
 *
 * Set @optical to position the DC component in the centre of the image. This
 * makes the mask suitable for multiplying against optical Fourier transforms. 
 * See vips_wrap(). 
 *
 * Set @reject to invert the sense of
 * the filter. For example, low-pass becomes low-reject. 
 *
 * Set @uchar to output an 8-bit unsigned char image rather than a
 * float image. In this case, pixels are in the range [0 - 255].
 *
 * See also: vips_mask_ideal(), vips_mask_ideal_ring(), 
 * vips_mask_ideal_band(), vips_mask_butterworth(), 
 * vips_mask_butterworth_ring(), vips_mask_butterworth_band(), 
 * vips_mask_gaussian(), vips_mask_gaussian_ring(), 
 * vips_mask_gaussian_band(). 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_mask_ideal( VipsImage **out, int width, int height, 
	double frequency_cutoff, ... )
{
	va_list ap;
	int result;

	va_start( ap, frequency_cutoff );
	result = vips_call_split( "mask_ideal", ap, out, width, height, 
		frequency_cutoff );
	va_end( ap );

	return( result );
}
