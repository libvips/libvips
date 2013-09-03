/* a hist operation implemented as a unary processor
 *
 * properties:
 * 	- single hist to single hist
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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
#include <vips/internal.h>

#include "phistogram.h"
#include "hist_unary.h"

G_DEFINE_ABSTRACT_TYPE( VipsHistUnary, vips_hist_unary, VIPS_TYPE_HISTOGRAM );

static int
vips_hist_unary_build( VipsObject *object )
{
	VipsHistogram *histogram = VIPS_HISTOGRAM( object );
	VipsHistUnary *unary = VIPS_HIST_UNARY( object );

	histogram->n = 1;
	histogram->in = (VipsImage **) vips_object_local_array( object, 1 );
	histogram->in[0] = unary->in;

	if( histogram->in[0] )
		g_object_ref( histogram->in[0] );

	if( VIPS_OBJECT_CLASS( vips_hist_unary_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_hist_unary_class_init( VipsHistUnaryClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "hist_unary";
	vobject_class->description = _( "hist_unary operations" );
	vobject_class->build = vips_hist_unary_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistUnary, in ) );

}

static void
vips_hist_unary_init( VipsHistUnary *hist_unary )
{
}
