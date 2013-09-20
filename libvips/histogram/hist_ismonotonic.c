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

	int *monotonic;
} VipsHistIsmonotonic;

typedef VipsOperationClass VipsHistIsmonotonicClass;

G_DEFINE_TYPE( VipsHistIsmonotonic, vips_hist_ismonotonic, VIPS_TYPE_OPERATION );

static int
vips_hist_ismonotonic_build( VipsObject *object )
{
	VipsHistIsmonotonic *ismonotonic = (VipsHistIsmonotonic *) object; 
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	if( VIPS_OBJECT_CLASS( vips_hist_ismonotonic_parent_class )->
		build( object ) )
		return( -1 );

	if( im_check_hist( "im_ismonotonic", lut ) ||
		im_open_local_array( lut, t, 2, "im_ismonotonic", "p" ) )
		return( -1 );

	if( lut->Xsize == 1 ) 
		mask = im_create_imaskv( "im_ismonotonic", 1, 2, -1, 1 );
	else 
		mask = im_create_imaskv( "im_ismonotonic", 2, 1, -1, 1 );
	if( !(mask = im_local_imask( lut, mask )) )
		return( -1 );
	mask->offset = 128;

	/* We want >=128 everywhere, ie. no -ve transitions.
	 */
	if( im_conv( lut, t[0], mask ) ||
		im_moreeqconst( t[0], t[1], 128 ) ||
		im_min( t[1], &m ) )
		return( -1 );

	*out = m;

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
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistIsmonotonic, in ) );

	VIPS_ARG_INT( class, "monotonic", 2, 
		_( "Monotonic" ), 
		_( "non-zero if in is monotonic" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistIsmonotonic, monotonic ),
		0, 1, 0 );

}

static void
vips_hist_ismonotonic_init( VipsHistIsmonotonic *ismonotonic )
{
}

/**
 * im_ismonotonic:
 * @lut: lookup-table to test
 * @out: set non-zero if @lut is monotonic 
 *
 * Test @lut for monotonicity. @out is set non-zero if @lut is monotonic.
 *
 * See also: im_tone_build_range().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_hist_ismonotonic( VipsImage *in, int *monotonic, ... )
{
	va_list ap;
	int result;

	va_start( ap, monotonic );
	result = vips_call_split( "hist_ismonotonic", ap, in, monotonic );
	va_end( ap );

	return( result );
}
