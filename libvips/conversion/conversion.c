/* base class for all conversion operations
 *
 * properties:
 * 	- unary, binary or binary with one arg a constant
 * 	- cast binary args to match
 * 	- not point-to-point
 * 	- format, bands etc. can all change
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

#include "conversion.h"

/* Properties.
 */
enum {
	PROP_OUTPUT = 1,
	PROP_LAST
}; 

G_DEFINE_ABSTRACT_TYPE( VipsConversion, vips_conversion, VIPS_TYPE_OPERATION );

static int
vips_conversion_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );

#ifdef DEBUG
	printf( "vips_conversion_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_object_set( conversion, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_conversion_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_conversion_class_init( VipsConversionClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	GParamSpec *pspec;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "conversion";
	vobject_class->description = _( "conversion operations" );
	vobject_class->build = vips_conversion_build;

	pspec = g_param_spec_object( "out", "Output", 
		_( "Output image" ),
		VIPS_TYPE_IMAGE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_OUTPUT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsConversion, output ) );
}

static void
vips_conversion_init( VipsConversion *conversion )
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_conversion_operation_init( void )
{
	extern GType vips_copy_get_type( void ); 

	vips_copy_get_type();
}

