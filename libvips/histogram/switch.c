/* use pixel values to switch between an array of images
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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsSwitch {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	VipsArrayImage *lut;
	int n;

} VipsSwitch;

typedef VipsOperationClass VipsSwitchClass;

G_DEFINE_TYPE( VipsSwitch, vips_switch, VIPS_TYPE_OPERATION );

/* Do a map.
 */
static int 
vips_switch_gen( VipsRegion *or, void *seq, void *a, void *b, 
	gboolean *stop )
{
	VipsRegion **ar = (VipsRegion **) seq;
	VipsSwitch *swit = (VipsSwitch *) b;
	VipsRect *r = &or->valid;
	VipsRegion *index = ar[swit->n];

	int x, y, i, j;
	VipsPel *ip;
	VipsPel *q;
	size_t ils;
	size_t qls;
	int hist[256];
	VipsPel *p[256];
	size_t ls[256];
	size_t ps;

	if( vips_region_prepare( index, r ) )
		return( -1 );

	g_assert( index->im->BandFmt == VIPS_FORMAT_UCHAR );
	g_assert( index->im->Bands == 1 );

	/* Histogram of input region, so we know which of our inputs we will
	 * need to prepare.
	 */
	memset( hist, 0, 256 * sizeof( int ) );
	ip = VIPS_REGION_ADDR( index, r->left, r->top );
	ils = VIPS_REGION_LSKIP( index );
	for( y = 0; y < r->height; y++ ) {
		for( x = 0; x < r->width; x++ )
			hist[ip[x]] += 1;

		ip += ils;
	}

	for( i = 0; i < 256; i++ ) 
		if( hist[i] ) {
			if( vips_region_prepare( ar[i], r ) )
				return( -1 );
			p[i] = VIPS_REGION_ADDR( ar[i], r->left, r->top );
			ls[i] = VIPS_REGION_LSKIP( ar[i] );
		}

	ip = VIPS_REGION_ADDR( index, r->left, r->top );
	q = VIPS_REGION_ADDR( or, r->left, r->top );
	qls = VIPS_REGION_LSKIP( or );
	ps = VIPS_IMAGE_SIZEOF_PEL( or->im );
	for( y = 0; y < r->height; y++ ) {
		i = 0;
		for( x = 0; x < r->width; x++ ) {
			int v = ip[x];

			for( j = 0; j < ps; j++ ) {
				q[i] = p[v][i];
				i += 1;
			}
		}

		ip += ils;
		q += qls;
		for( i = 0; i < 256; i++ ) 
			if( hist[i] ) 
				p[i] += ls[i];
	}

	return( 0 );
}

static int
vips_switch_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsSwitch *swit = (VipsSwitch *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;
	VipsImage **lut;
	VipsImage **decode;
	VipsImage **format;
	VipsImage **band;
	VipsImage **size;
	int i;

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_switch_parent_class )->build( object ) )
		return( -1 );

	in = swit->in;
	lut = vips_area_get_data( &swit->lut->area, 
		NULL, &swit->n, NULL, NULL );
	if( swit->n > 256 ) {
		vips_error( class->nickname, "%s", _( "LUT too large" ) );
		return( -1 );
	}
	if( in->Bands > 1 ) {
		vips_error( class->nickname, 
			"%s", _( "index image not 1-band" ) );
		return( -1 );
	}

	/* Cast @in to u8 to make the index image.
	 */
	if( vips_cast( in, &t[0], VIPS_FORMAT_UCHAR, NULL ) )
		return( -1 );
	in = t[0];

	decode = (VipsImage **) vips_object_local_array( object, swit->n );
	format = (VipsImage **) vips_object_local_array( object, swit->n );
	band = (VipsImage **) vips_object_local_array( object, swit->n + 1 );
	size = (VipsImage **) vips_object_local_array( object, swit->n + 1 );

	/* Decode RAD/LABQ etc.
	 */
	for( i = 0; i < swit->n; i++ )
		if( vips_image_decode( lut[i], &decode[i] ) )
			return( -1 );
	lut = decode;

	/* LUT images must match in format, size and bands.
	 *
	 * We want everything sized up to the size of the index image, so add
	 * that to the end of the set of images for sizealike.
	 */
	band[swit->n] = in;
	if( vips__formatalike_vec( lut, format, swit->n ) ||
		vips__bandalike_vec( class->nickname, 
			format, band, swit->n, 1 ) ||
		vips__sizealike_vec( band, size, swit->n + 1 ) ) 
		return( -1 );
	lut = size;

	swit->out->BandFmt = lut[0]->BandFmt;
	swit->out->Bands = lut[0]->Bands;
	swit->out->Type = lut[0]->Type;
	swit->out->Xsize = in->Xsize;
	swit->out->Ysize = in->Ysize;

	if( vips_image_pipeline_array( swit->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, lut ) )
		return( -1 );

	if( vips_image_generate( swit->out,
		vips_start_many, vips_switch_gen, vips_stop_many, 
		lut, swit ) )
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
		_( "use pixel values to switch between a set of images" );
	object_class->build = vips_switch_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSwitch, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsSwitch, out ) );

	VIPS_ARG_BOXED( class, "lut", 3, 
		_( "LUT" ), 
		_( "Look-up table of images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSwitch, lut ),
		VIPS_TYPE_ARRAY_IMAGE );

}

static void
vips_switch_init( VipsSwitch *swit )
{
}

static int
vips_switchv( VipsImage *in, VipsImage **out, VipsImage **lut, int n, 
	va_list ap )
{
	VipsArrayImage *array; 
	int result;

	array = vips_array_image_new( lut, n ); 
	result = vips_call_split( "switch", ap, in, out, array );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}

/**
 * vips_switch: (method)
 * @in: input image
 * @out: (out): output image
 * @lut: (array length=n): LUT of input images
 * @n: number of input images
 * @...: %NULL-terminated list of optional named arguments
 *
 * Use pixel values to switch between an array of images.
 *
 * Each value in @in is used to select an image from @lut, and the
 * corresponding pixel is copied to the output.
 *
 * @in must have one band. @lut can have up to 256 elements. Values in @in
 * greater than or equal to @n use the final image in @lut. The images in @lut
 * must have either one band or the same number of bands. The output image is
 * the same size as @in. Images in @lut are expanded to the smallest common
 * format and number of bands.
 *
 * See also: vips_maplut().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_switch( VipsImage *in, VipsImage **out, VipsImage **lut, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_switchv( in, out, lut, n, ap );
	va_end( ap );

	return( result );
}

