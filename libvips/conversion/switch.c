/* switch between an array of images
 *
 * 28/7/19
 * 	- from maplut.c
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsSwitch {
	VipsOperation parent_instance;

	VipsArrayImage *tests;
	VipsImage *out;

	int n;

} VipsSwitch;

typedef VipsOperationClass VipsSwitchClass;

G_DEFINE_TYPE( VipsSwitch, vips_switch, VIPS_TYPE_OPERATION );

static int 
vips_switch_gen( VipsRegion *or, void *seq, void *a, void *b, 
	gboolean *stop )
{
	VipsRegion **ar = (VipsRegion **) seq;
	VipsSwitch *swit = (VipsSwitch *) b;
	VipsRect *r = &or->valid;

	int x, y, i;
	VipsPel * restrict q;
	size_t qls;
	VipsPel * restrict p[256];
	size_t ls[256];

	if( vips_reorder_prepare_many( or->im, ar, r ) )
		return( -1 );

	g_assert( ar[0]->im->BandFmt == VIPS_FORMAT_UCHAR );
	g_assert( ar[0]->im->Bands == 1 );

	for( i = 0; i < swit->n; i++ ) {
		p[i] = VIPS_REGION_ADDR( ar[i], r->left, r->top );
		ls[i] = VIPS_REGION_LSKIP( ar[i] );
	}

	q = VIPS_REGION_ADDR( or, r->left, r->top );
	qls = VIPS_REGION_LSKIP( or );
	for( y = 0; y < r->height; y++ ) {
		for( x = 0; x < r->width; x++ ) {
			for( i = 0; i < swit->n; i++ )
				if( p[i][x] )
					break;

			q[x] = i;
		}

		q += qls;
		for( i = 0; i < swit->n; i++ ) 
			p[i] += ls[i];
	}

	return( 0 );
}

static int
vips_switch_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsSwitch *swit = (VipsSwitch *) object;

	VipsImage **tests;
	VipsImage **decode;
	VipsImage **format;
	VipsImage **band;
	VipsImage **size;
	int i;

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_switch_parent_class )->build( object ) )
		return( -1 );

	/* 255 rather than 256, since we want to reserve +1 as the no
	 * match value.
	 */
	tests = vips_area_get_data( &swit->tests->area, 
		NULL, &swit->n, NULL, NULL );
	if( swit->n > 255 ||
		swit->n < 1 ) {
		vips_error( class->nickname, "%s", _( "bad number of tests" ) );
		return( -1 );
	}

	decode = (VipsImage **) vips_object_local_array( object, swit->n );
	format = (VipsImage **) vips_object_local_array( object, swit->n );
	band = (VipsImage **) vips_object_local_array( object, swit->n + 1 );
	size = (VipsImage **) vips_object_local_array( object, swit->n + 1 );

	/* Decode RAD/LABQ etc.
	 */
	for( i = 0; i < swit->n; i++ )
		if( vips_image_decode( tests[i], &decode[i] ) )
			return( -1 );
	tests = decode;

	/* Must be uchar.
	 */
	for( i = 0; i < swit->n; i++ )
		if( vips_cast_uchar( tests[i], &format[i], NULL ) )
			return( -1 );
	tests = format;

	/* Images must match in size and bands.
	 */
	if( vips__bandalike_vec( class->nickname, tests, band, swit->n, 1 ) ||
		vips__sizealike_vec( band, size, swit->n ) ) 
		return( -1 );
	tests = size;

	if( tests[0]->Bands > 1 ) {
		vips_error( class->nickname, 
			"%s", _( "test images not 1-band" ) );
		return( -1 );
	}

	if( vips_image_pipeline_array( swit->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, tests ) )
		return( -1 );

	if( vips_image_generate( swit->out,
		vips_start_many, vips_switch_gen, vips_stop_many, 
		tests, swit ) )
		return( -1 );

	return( 0 );
}

static void
vips_switch_class_init( VipsSwitchClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "switch";
	object_class->description = 
		_( "find the index of the first non-zero pixel in tests" );
	object_class->build = vips_switch_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_BOXED( class, "tests", 1, 
		_( "Tests" ), 
		_( "Table of images to test" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSwitch, tests ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsSwitch, out ) );

}

static void
vips_switch_init( VipsSwitch *swit )
{
}

static int
vips_switchv( VipsImage **tests, VipsImage **out, int n, va_list ap )
{
	VipsArrayImage *tests_array; 
	int result;

	tests_array = vips_array_image_new( tests, n ); 
	result = vips_call_split( "switch", ap, tests_array, out );
	vips_area_unref( VIPS_AREA( tests_array ) );

	return( result );
}

/**
 * vips_switch:
 * @tests: (array length=n): test these images
 * @out: (out): output index image
 * @n: number of input images
 * @...: %NULL-terminated list of optional named arguments
 *
 * The @tests images are evaluated and at each point the index of the first 
 * non-zero value is written to @out. If all @tests are false, the value 
 * (@n + 1) is written. 
 *
 * Images in @tests must have one band. They are expanded to the
 * bounding box of the set of images in @tests, and that size is used for
 * @out. @tests can have up to 255 elements.  
 *
 * Combine with vips_case() to make an efficient multi-way vips_ifthenelse().
 *
 * See also: vips_maplut(), vips_case(), vips_ifthenelse().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_switch( VipsImage **tests, VipsImage **out, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_switchv( tests, out, n, ap );
	va_end( ap );

	return( result );
}

