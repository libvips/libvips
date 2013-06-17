/* square zone plate of size
 *
 * N. Dessipris 01/02/1991
 *
 * 22/7/93 JC
 *	- externs removed
 *	- im_outcheck() added
 * 30/8/95 JC
 *	- modernized
 *	- memory leaks fixed
 *	- split into im_zone() and im_fzone()
 * 1/2/11
 * 	- gtk-doc
 * 13/6/13
 * 	- redo as a class
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

typedef VipsPoint VipsZone;
typedef VipsPointClass VipsZoneClass;

G_DEFINE_TYPE( VipsZone, vips_zone, VIPS_TYPE_POINT );

static float
vips_zone_point( VipsPoint *point, int x, int y ) 
{
	VipsZone *zone = (VipsZone *) point;

	int hwidth = point->width / 2;
	int hheight = point->height / 2;
	int h2 = (x - hwidth) * (x - hwidth);
	int v2 = (y - hheight) * (y - hheight);
	double c = VIPS_PI / zone->width;

	return( cos( c * (v2 + h2) ) );
}

static void
vips_zone_class_init( VipsZoneClass *class )
{
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsPointClass *point_class = VIPS_POINT_CLASS( class );

	vobject_class->nickname = "zone";
	vobject_class->description = _( "make a zone plate" );

	point_class->point = vips_zone_point;
}

static void
vips_zone_init( VipsZone *zone )
{
}

/**
 * vips_zone:
 * @out: output image
 * @xsize: image size
 * @ysize: image size
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @uchar: output a uchar image
 *
 * Create a one-band image of a zone plate. 
 *
 * Pixels are normally in [-1, +1], set @uchar to output [0, 255]. 
 *
 * See also: vips_eye(), vips_xyz().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_zone( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "zone", ap, out, width, height );
	va_end( ap );

	return( result );
}
