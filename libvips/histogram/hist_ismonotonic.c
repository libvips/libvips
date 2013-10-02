/* test for monotonicity
 *
 * Author: John Cupitt
 * Written on: 18/7/1995
 * 17/9/96 JC
 *	- restrictions on Ps, Pm, Ph relaxed
 *	- restrictions on S, M, H relaxed
 * 25/7/01 JC
 *	- patched for im_extract_band() change
 * 11/7/04
 *	- generalised to im_tone_build_range() ... so you can use it for any
 *	  image, not just LabS
 * 26/3/10
 * 	- cleanups
 * 	- gtkdoc
 * 20/9/13
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

typedef struct _VipsHistIsmonotonic { 
	VipsOperation parent_instance;

	VipsImage *in;

	gboolean monotonic;
} VipsHistIsmonotonic;

typedef VipsOperationClass VipsHistIsmonotonicClass;

G_DEFINE_TYPE( VipsHistIsmonotonic, vips_hist_ismonotonic, 
	VIPS_TYPE_OPERATION );

static int
vips_hist_ismonotonic_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsHistIsmonotonic *ismonotonic = (VipsHistIsmonotonic *) object; 
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	double m; 

	if( VIPS_OBJECT_CLASS( vips_hist_ismonotonic_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_check_hist( class->nickname, ismonotonic->in ) )
		return( -1 );

	if( ismonotonic->in->Xsize == 1 ) 
		t[0] = vips_image_new_matrixv( 1, 2, -1.0, 1.0 );
	else 
		t[0] = vips_image_new_matrixv( 2, 1, -1.0, 1.0 );
        vips_image_set_double( t[0], "offset", 128 );

	/* We want >=128 everywhere, ie. no -ve transitions.
	 */
	if( vips_conv( ismonotonic->in, &t[1], t[0], NULL ) ||
		vips_moreeq_const1( t[1], &t[2], 128, NULL ) ||
		vips_min( t[2], &m, NULL ) )
		return( -1 );

	g_object_set( ismonotonic, "monotonic", (int) m == 255, NULL ); 

	return( 0 );
}

static void
vips_hist_ismonotonic_class_init( VipsHistIsmonotonicClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hist_ismonotonic";
	object_class->description = _( "test for monotonicity" );
	object_class->build = vips_hist_ismonotonic_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input histogram image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistIsmonotonic, in ) );

	VIPS_ARG_BOOL( class, "monotonic", 2, 
		_( "Monotonic" ), 
		_( "true if in is monotonic" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistIsmonotonic, monotonic ),
		FALSE ); 

}

static void
vips_hist_ismonotonic_init( VipsHistIsmonotonic *ismonotonic )
{
}

/**
 * vips_hist_ismonotonic:
 * @in: lookup-table to test
 * @out: set non-zero if @in is monotonic 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Test @in for monotonicity. @out is set non-zero if @in is monotonic.
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_hist_ismonotonic( VipsImage *in, gboolean *monotonic, ... )
{
	va_list ap;
	int result;

	va_start( ap, monotonic );
	result = vips_call_split( "hist_ismonotonic", ap, in, monotonic );
	va_end( ap );

	return( result );
}
