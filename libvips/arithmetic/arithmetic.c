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
 */
#define DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

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
	PROP_BOOLTEST = 2,
	PROP_IMTEST = 3,
	PROP_LAST
}; 

G_DEFINE_ABSTRACT_TYPE( VipsArithmetic, vips_arithmetic, VIPS_TYPE_OPERATION );

static int
vips_arithmetic_build( VipsObject *object )
{
	VipsArithmetic *arithmetic = VIPS_ARITHMETIC( object );

#ifdef DEBUG
	printf( "vips_arithmetic_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	g_object_set( arithmetic, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_arithmetic_parent_class )->build( object ) )
		return( -1 );

	/* Should we _generate() here? We should keep the params in the object
	 * ready to be dropped in.
	 *
	 * At the moment we _generate() separately in binary.c and unary.c.
	 */

#ifdef DEBUG
	printf( "vips_arithmetic_build: booltest = %d\n", 
		arithmetic->booltest );
	printf( "vips_arithmetic_build: imtest = %p\n", 
		arithmetic->imtest );
#endif /*DEBUG*/

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

	pspec = g_param_spec_object( "out", "Output", 
		_( "Output image" ),
		VIPS_TYPE_IMAGE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_OUTPUT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsArithmetic, output ) );

	pspec = g_param_spec_boolean( "booltest", "Bool test", 
		_( "Test optional boolean argument" ),
		FALSE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_BOOLTEST, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsArithmetic, booltest ) );

	pspec = g_param_spec_object( "imtest", "Image test", 
		_( "Test optional image argument" ),
		VIPS_TYPE_IMAGE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_IMTEST, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsArithmetic, imtest ) );

}

static void
vips_arithmetic_init( VipsArithmetic *arithmetic )
{
}

void 
vips_arithmetic_set_format_table( VipsArithmeticClass *class, 
	VipsBandFormat *format_table )
{
	int i;

	g_assert( !class->format_table );

	class->format_table = format_table;

	for( i = 0; i < VIPS_FORMAT_LAST; i++ ) {
		int isize = vips_format_sizeof( i );
		int osize = vips_format_sizeof( (int) format_table[i] );

		VipsVector *v;

		v = vips_vector_new( "arithmetic", osize );

		vips_vector_source_name( v, "s1", isize );
		vips_vector_source_name( v, "s2", isize );
		vips_vector_temporary( v, "t1", osize );
		vips_vector_temporary( v, "t2", osize );

		class->vectors[i] = v;
	}
}

/* Get the stub for this program ... use _get_vector() to get the compiled
 * code.
 */
VipsVector *
vips_arithmetic_get_program( VipsArithmeticClass *class, VipsBandFormat fmt )
{
	g_assert( (int) fmt >= 0 && (int) fmt < VIPS_FORMAT_LAST );
	g_assert( !class->vector_program[fmt] );

	class->vector_program[fmt] = TRUE;

	return( class->vectors[fmt] );
}

/* Get the compiled code for this type, if available.
 */
VipsVector *
vips_arithmetic_get_vector( VipsArithmeticClass *class, VipsBandFormat fmt )
{
	g_assert( fmt >= 0 && fmt < VIPS_FORMAT_LAST );

	if( !vips_vector_get_enabled() ||
		!class->vector_program[fmt] )
		return( NULL );

	return( class->vectors[fmt] );
}

void
vips_arithmetic_compile( VipsArithmeticClass *class ) 
{
	int i;

	g_assert( class->format_table );

	for( i = 0; i < VIPS_FORMAT_LAST; i++ ) 
		if( class->vector_program[i] &&
			!vips_vector_compile( class->vectors[i] ) )
			/* If compilation fails, turn off the vector for this
			 * type.
			 */
			class->vector_program[i] = FALSE;

#ifdef DEBUG
	printf( "vips_arithmetic_compile: " );
	for( i = 0; i < IM_BANDFMT_LAST; i++ ) 
		if( class->vector_program[i] )
			printf( "%s ", 
				VIPS_ENUM_NICK( VIPS_TYPE_BAND_FORMAT, i ) );
	printf( "\n" );
#endif /*DEBUG*/
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

