/* base class for all colour operations
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "colour.h"

G_DEFINE_ABSTRACT_TYPE( VipsColour, vips_colour, VIPS_TYPE_OPERATION );

static int
vips_colour_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsColour *colour = VIPS_COLOUR( b ); 
	VipsColourClass *class = VIPS_COLOUR_GET_CLASS( colour ); 
	Rect *r = &or->valid;

	VipsPel *p, *q;
	int y;

	if( vips_region_prepare( ir, r ) ) 
		return( -1 );
	p = (VipsPel *) VIPS_REGION_ADDR( ir, r->left, r->top );
	q = (VipsPel *) VIPS_REGION_ADDR( or, r->left, r->top );

	for( y = 0; y < r->height; y++ ) {
		class->process_line( colour, q, p, r->width );

		p += VIPS_REGION_LSKIP( ir );
		q += VIPS_REGION_LSKIP( or );
	}

	return( 0 );
}

static int
vips_colour_build( VipsObject *object )
{
	VipsColour *colour = VIPS_COLOUR( object );

	VipsImage **t;

#ifdef DEBUG
	printf( "vips_colour_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_colour_parent_class )->
		build( object ) ) 
		return( -1 );

	g_object_set( colour, "out", vips_image_new(), NULL ); 

	if( vips_image_pio_input( colour->in ) || 
		vips_check_bands_1or3( "VipsColour", colour->in ) ||
		vips_check_uncoded( "VipsColour", colour->in ) ) 
		return( -1 );

	t = (VipsImage **) vips_object_local_array( object, 5 );

	/* Always process float.
	 */
	if( vips_cast_float( colour->in, &t[0], NULL ) )
		return( -1 );

	/* If there are more than bands, process just the first three and
	 * reattach the rest after.
	 */
	if( t[0]->Bands > 3 ) {
		if( vips_extract_band( t[0], &t[1], 0, "n", 3, NULL ) ||
			vips_extract_band( t[0], &t[2], 0, 
				"n", t[0]->Bands - 3, NULL ) )
			return( -1 );

		if( vips_image_copy_fields( t[3], t[1] ) ) 
			return( -1 );
		vips_demand_hint( t[3], 
			VIPS_DEMAND_STYLE_THINSTRIP, t[1], NULL );

		if( vips_image_generate( t[3],
			vips_start_one, vips_colour_gen, vips_stop_one, 
			t[1], colour ) ) 
			return( -1 );

		if( vips_bandjoin2( t[3], t[2], &t[4], NULL ) ||
			vips_image_write( t[4], colour->out ) )
			return( -1 );
	}
	else {
		if( vips_image_copy_fields( colour->out, t[1] ) ) 
			return( -1 );
		vips_demand_hint( colour->out, 
			VIPS_DEMAND_STYLE_THINSTRIP, t[1], NULL );

		if( vips_image_generate( colour->out,
			vips_start_one, vips_colour_gen, vips_stop_one, 
			t[1], colour ) ) 
			return( -1 );
	}

	return( 0 );
}

static void
vips_colour_class_init( VipsColourClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "colour";
	vobject_class->description = _( "colour operations" );
	vobject_class->build = vips_colour_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsColour, in ) );

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsColour, out ) );
}

static void
vips_colour_init( VipsColour *colour )
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_colour_operation_init( void )
{
	extern GType vips_add_get_type( void ); 

	vips_add_get_type();
}
