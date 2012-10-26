/* im_dE_fromLab.c
 *
 * Modified:
 * 16/11/94 JC
 *	- partialed!
 * 31/10/09
 * 	- use im__colour_binary() 
 * 	- gtkdoc comment
 * 25/10/12
 * 	- redone as a class
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include "colour.h"

typedef struct _VipsdE76 {
	VipsColourDifference parent_instance;

} VipsdE76;

typedef VipsColourSpaceClass VipsdE76Class;

G_DEFINE_TYPE( VipsdE76, vips_dE76, VIPS_TYPE_COLOUR_DIFFERENCE );

/* Find the difference between two buffers of LAB data.
 */
static void
vips_dE76_line( VipsColour *colour, VipsPel *out, VipsPel **in, int width )
{
	float *p1 = (float *) in[0];
	float *p2 = (float *) in[1];
	float *q = (float *) out;

	int x;

	for( x = 0; x < width; x++ ) {
		q[x] = vips_pythagoras( 
			p1[0], p1[1], p1[2], p2[0], p2[1], p2[2] );

		p1 += 3;
		p2 += 3;
	}
}

static void
vips_dE76_class_init( VipsdE76Class *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	object_class->nickname = "dE76";
	object_class->description = _( "calculate dE76" );

	colour_class->process_line = vips_dE76_line;
}

static void
vips_dE76_init( VipsdE76 *dE76 )
{
	VipsColourDifference *difference = VIPS_COLOUR_DIFFERENCE( dE76 ); 

	difference->interpretation = VIPS_INTERPRETATION_LAB;
}

/**
 * vips_dE76:
 * @in: input image
 * @out: output image
 *
 * Calculate dE 76.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_dE76( VipsImage *left, VipsImage *right, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "dE76", ap, left, right, out );
	va_end( ap );

	return( result );
}
