/* grey ramps
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/02/1990
 * Modified on:
 * 22/7/93 JC
 *	- im_outcheck() added
 *	- externs removed
 * 8/2/95 JC
 *	- ANSIfied
 *	- im_fgrey() made from im_grey()
 * 31/8/95 JC
 *	- now makes [0,1], rather than [0,256)
 *	- im_grey() now defined in terms of im_fgrey()
 * 2/3/98 JC
 *	- partialed
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

typedef VipsPoint VipsGrey;
typedef VipsPointClass VipsGreyClass;

G_DEFINE_TYPE( VipsGrey, vips_grey, VIPS_TYPE_POINT );

static float
vips_grey_point( VipsPoint *point, int x, int y ) 
{
	return( (double) x / (point->width - 1) );
}

static void
vips_grey_class_init( VipsGreyClass *class )
{
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsPointClass *point_class = VIPS_POINT_CLASS( class );

	vobject_class->nickname = "grey";
	vobject_class->description = _( "make a grey ramp image" );

	point_class->point = vips_grey_point;
}

static void
vips_grey_init( VipsGrey *grey )
{
}

/**
 * vips_grey:
 * @out: output image
 * @xsize: image size
 * @ysize: image size
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @uchar: output a uchar image
 *
 * Create a one-band float image with the left-most column zero and the
 * right-most 1. Intermediate pixels are a linear ramp.
 *
 * Set @uchar to output a uchar image with the leftmost pixel 0 and the
 * rightmost 255. 
 *
 * See also: vips_xyz(), vips_identity().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_grey( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "grey", ap, out, width, height );
	va_end( ap );

	return( result );
}
