/* base class for frequency filter create operations
 *
 * 02/01/14
 * 	- from sines.c
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

G_DEFINE_ABSTRACT_TYPE( VipsMask, vips_mask, VIPS_TYPE_POINT );

static float
vips_mask_point( VipsPoint *point, int x, int y )
{
	VipsMask *mask = VIPS_MASK( point ); 
	VipsMaskClass *class = VIPS_MASK_GET_CLASS( point ); 
	int half_width = point->width / 2;
	int half_height = point->height / 2;

	double result;

	/* Move centre for an optical transform mask.
	 */
	if( !mask->optical ) {
		x = (x + half_width) % point->width;
		y = (y + half_height) % point->height;
	}

	x = x - half_width;
	y = y - half_height;

	if( !mask->nodc && 
		x == 0 &&
		y == 0 )
		/* DC component is always 1.
		 */
		result = 1.0;
	else {
		double dx, dy;

		dx = (double) x / half_width;
		dy = (double) y / half_height;

		result = class->point( mask, dx, dy );

		/* Invert filter sense for a highpass filter, or to swap
		 * band-pass for band-reject. 
		 */
		if( mask->reject )
			result = 1.0 - result;
	}

	return( result ); 
}

static void
vips_mask_class_init( VipsMaskClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsPointClass *point_class = VIPS_POINT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "mask";
	vobject_class->description = _( "base class for frequency filters" );

	point_class->point = vips_mask_point;
	point_class->min = 0.0; 
	point_class->max = 1.0; 
	point_class->interpretation = VIPS_INTERPRETATION_FOURIER;

	VIPS_ARG_BOOL( class, "optical", 5, 
		_( "Optical" ), 
		_( "Rotate quadrants to optical space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMask, optical ),
		FALSE ); 

	VIPS_ARG_BOOL( class, "reject", 5, 
		_( "Reject" ), 
		_( "Invert the sense of the filter" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMask, reject ),
		FALSE ); 

	VIPS_ARG_BOOL( class, "nodc", 5, 
		_( "Nodc" ), 
		_( "Remove DC component" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMask, nodc ),
		FALSE ); 

}

static void
vips_mask_init( VipsMask *mask )
{
}

