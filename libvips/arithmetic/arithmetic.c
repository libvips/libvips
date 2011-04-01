/* base class for all arithmetic operations
 *
 * properties:
 * 	- unary, binary or binary with one arg a constant
 * 	- cast binary args to match
 * 	- output is large enough to hold output values (value preserving)
 * 	- point-to-point operations (ie. each pixel depends only on the
 * 	  corresponding pixel in the input)
 * 	- LUT-able: ie. arithmetic (image) can be exactly replaced by
 * 	  maplut (image, arithmetic (lut)) for 8/16 bit int images
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
#include <vips8/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "arithmetic.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Properties.
 */
enum {
	PROP_OUTPUT = 1,
	PROP_LAST
}; 

G_DEFINE_ABSTRACT_TYPE( VipsArithmetic, vips_arithmetic, VIPS_TYPE_OPERATION );

static int
vips_arithmetic_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC (object);

	if( VIPS_OBJECT_CLASS( vips_arithmetic_parent_class )->build( object ) )
		return( -1 );

	/* Should we _generate() here? We should keep the params in the object
	 * ready to be dropped in.
	 */

	return( 0 );
}

static void
vips_arithmetic_class_init( VipsArithmeticClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	GParamSpec *pspec;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->build = vips_arithmetic_build;

	pspec = g_param_spec_object( "output-image", 
		"Output", "Output image",
		VIPS_TYPE_IMAGE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_OUTPUT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsArithmetic, output ) );
}

static void
vips_arithmetic_init( VipsArithmetic *arithmetic )
{
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_arithmetic_operation_init( void )
{
	extern GType vips_add_get_type( void ); 

	vips_add_get_type();
}
