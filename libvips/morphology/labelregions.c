/* labelregions.c
 *
 * 5/11/09
 *	- renamed from im_segment()
 * 11/2/14
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pmorphology.h"

typedef struct _VipsLabelregions {
	VipsMorphology parent_instance;

	VipsImage *mask;
	int segments; 
} VipsLabelregions;

typedef VipsMorphologyClass VipsLabelregionsClass;

G_DEFINE_TYPE( VipsLabelregions, vips_labelregions, VIPS_TYPE_MORPHOLOGY );

static int
vips_labelregions_build( VipsObject *object )
{
	VipsMorphology *morphology = VIPS_MORPHOLOGY( object );
	VipsLabelregions *labelregions = (VipsLabelregions *) object;
	VipsImage *in = morphology->in;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );

	int serial;
	int *m;
	int x, y;

	if( VIPS_OBJECT_CLASS( vips_labelregions_parent_class )->
		build( object ) )
		return( -1 );

	/* Create the zero mask image.
	 */
	if( vips_black( &t[0], in->Xsize, in->Ysize, NULL ) ||
		vips_cast( t[0], &t[1], VIPS_FORMAT_INT, NULL ) ) 
		return( -1 );

	/* Search the mask image, flooding as we find zero pixels.
	 */
	if( vips_image_inplace( t[1] ) )
		return( -1 );

	serial = 1;
	m = (int *) t[1]->data;
	for( y = 0; y < t[1]->Ysize; y++ ) {
		for( x = 0; x < t[1]->Xsize; x++ ) {
			if( !m[x] ) {
				/* Use a direct path for speed.
				 */
				if( vips__draw_flood_direct( t[1], in, 
					serial, x, y ) )
					return( -1 ); 

				serial += 1;
			}
		}

		m += t[1]->Xsize;
	}

	g_object_set( object,
		"mask", vips_image_new(),
		"segments", serial,
		NULL ); 

	if( vips_image_write( t[1], labelregions->mask ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_labelregions_class_init( VipsLabelregionsClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "labelregions";
	vobject_class->description = _( "label regions in an image" ); 
	vobject_class->build = vips_labelregions_build;

	VIPS_ARG_IMAGE( class, "mask", 2, 
		_( "Mask" ), 
		_( "Mask of region labels" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsLabelregions, mask ) ); 

	VIPS_ARG_INT( class, "segments", 3, 
		_( "Segments" ), 
		_( "Number of discrete contigious regions" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsLabelregions, segments ),
		0, 1000000000, 0 );

}

static void
vips_labelregions_init( VipsLabelregions *labelregions )
{
}

/**
 * vips_labelregions:
 * @test: image to test
 * @mask: write labelled regions here
 *
 * Optional arguments:
 *
 * @segments: return number of regions found here
 *
 * Repeatedly scans @test for regions of 4-connected pixels
 * with the same pixel value. Every time a region is discovered, those
 * pixels are marked in @mask with a unique serial number. Once all pixels
 * have been labelled, the operation returns, setting @segments to the number
 * of discrete regions which were detected.
 *
 * @mask is always a 1-band #VIPS_FORMAT_INT image of the same dimensions as
 * @test.
 *
 * This operation is useful for, for example, blob counting. You can use the
 * morphological operators to detect and isolate a series of objects, then use
 * vips_labelregions() to number them all.
 *
 * Use vips_hist_find_indexed() to (for example) find blob coordinates.
 *
 * See also: vips_hist_find_indexed().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_labelregions( VipsImage *in, VipsImage **mask, ... ) 
{
	va_list ap;
	int result;

	va_start( ap, mask );
	result = vips_call_split( "labelregions", ap, in, mask );
	va_end( ap );

	return( result );
}
