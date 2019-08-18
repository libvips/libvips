/* use pixel values to pick cases from an array of images
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

typedef struct _VipsCase {
	VipsOperation parent_instance;

	VipsImage *index;
	VipsArrayImage *cases;
	VipsImage *out;
	int n;

} VipsCase;

typedef VipsOperationClass VipsCaseClass;

G_DEFINE_TYPE( VipsCase, vips_case, VIPS_TYPE_OPERATION );

static int 
vips_case_gen( VipsRegion *or, void *seq, void *a, void *b, 
	gboolean *stop )
{
	VipsRegion **ar = (VipsRegion **) seq;
	VipsCase *cas = (VipsCase *) b;
	VipsRect *r = &or->valid;
	VipsRegion *index = ar[cas->n];

	int x, y, i;
	VipsPel * restrict ip;
	VipsPel * restrict q;
	size_t ils;
	size_t qls;
	int hist[256];
	VipsPel * restrict p[256];
	size_t ls[256];
	size_t ps;

	if( vips_region_prepare( index, r ) )
		return( -1 );

	g_assert( index->im->BandFmt == VIPS_FORMAT_UCHAR );
	g_assert( index->im->Bands == 1 );

	/* Histogram of index region, so we know which of our inputs we will
	 * need to prepare.
	 */
	memset( hist, 0, cas->n * sizeof( int ) );
	ip = VIPS_REGION_ADDR( index, r->left, r->top );
	ils = VIPS_REGION_LSKIP( index );
	for( y = 0; y < r->height; y++ ) {
		for( x = 0; x < r->width; x++ ) {
			int v = VIPS_MIN( ip[x], cas->n - 1 );

			hist[v] += 1;
		}

		ip += ils;
	}

	for( i = 0; i < cas->n; i++ ) 
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
		int k;

		k = 0;
		for( x = 0; x < r->width; x++ ) {
			int v = VIPS_MIN( ip[x], cas->n - 1 );
			VipsPel * restrict pv = p[v];

			int j;

			for( j = 0; j < ps; j++ ) {
				q[k] = pv[k];
				k += 1;
			}
		}

		ip += ils;
		q += qls;
		for( i = 0; i < cas->n; i++ ) 
			if( hist[i] ) 
				p[i] += ls[i];
	}

	return( 0 );
}

static int
vips_case_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsCase *cas = (VipsCase *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *index;
	VipsImage **cases;
	VipsImage **decode;
	VipsImage **format;
	VipsImage **band;
	VipsImage **size;
	int i;

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_case_parent_class )->build( object ) )
		return( -1 );

	index = cas->index;
	cases = vips_area_get_data( &cas->cases->area, 
		NULL, &cas->n, NULL, NULL );
	if( cas->n > 256 ||
		cas->n < 1 ) {
		vips_error( class->nickname, "%s", _( "bad number of cases" ) );
		return( -1 );
	}
	if( index->Bands > 1 ) {
		vips_error( class->nickname, 
			"%s", _( "index image not 1-band" ) );
		return( -1 );
	}

	/* Cast @index to u8 to make the index image.
	 */
	if( vips_cast( index, &t[0], VIPS_FORMAT_UCHAR, NULL ) )
		return( -1 );
	index = t[0];

	decode = (VipsImage **) vips_object_local_array( object, cas->n );
	format = (VipsImage **) vips_object_local_array( object, cas->n );
	band = (VipsImage **) vips_object_local_array( object, cas->n + 1 );
	size = (VipsImage **) vips_object_local_array( object, cas->n + 1 );

	/* Decode RAD/LABQ etc.
	 */
	for( i = 0; i < cas->n; i++ )
		if( vips_image_decode( cases[i], &decode[i] ) )
			return( -1 );
	cases = decode;

	/* case images must match in format, size and bands.
	 *
	 * We want everything sized up to the size of the index image, so add
	 * that to the end of the set of images for sizealike.
	 */
	band[cas->n] = index;
	g_object_ref( index ); 
	if( vips__formatalike_vec( cases, format, cas->n ) ||
		vips__bandalike_vec( class->nickname, 
			format, band, cas->n, 1 ) ||
		vips__sizealike_vec( band, size, cas->n + 1 ) ) 
		return( -1 );
	cases = size;

	if( vips_image_pipeline_array( cas->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, cases ) )
		return( -1 );

	cas->out->BandFmt = cases[0]->BandFmt;
	cas->out->Bands = cases[0]->Bands;
	cas->out->Type = cases[0]->Type;

	if( vips_image_generate( cas->out,
		vips_start_many, vips_case_gen, vips_stop_many, 
		cases, cas ) )
		return( -1 );

	return( 0 );
}

static void
vips_case_class_init( VipsCaseClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "case";
	object_class->description = 
		_( "use pixel values to pick cases from an array of images" );
	object_class->build = vips_case_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "index", 1, 
		_( "index" ), 
		_( "Index image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCase, index ) );

	VIPS_ARG_BOXED( class, "cases", 2, 
		_( "cases" ), 
		_( "Array of case images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCase, cases ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_IMAGE( class, "out", 3, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsCase, out ) );

}

static void
vips_case_init( VipsCase *cas )
{
}

static int
vips_casev( VipsImage *index, VipsImage **cases, VipsImage **out, int n, 
	va_list ap )
{
	VipsArrayImage *array; 
	int result;

	array = vips_array_image_new( cases, n ); 
	result = vips_call_split( "case", ap, index, array, out );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}

/**
 * vips_case: (method)
 * @index: index image
 * @cases: (array length=n): array of case images
 * @out: (out): output image
 * @n: number of case images
 * @...: %NULL-terminated list of optional named arguments
 *
 * Use values in @index to select pixels from @cases.
 *
 * @index must have one band. @cases can have up to 256 elements. Values in
 * @index greater than or equal to @n use the final image in @cases. The 
 * images in @cases must have either one band or the same number of bands. 
 * The output image is the same size as @index. Images in @cases are 
 * expanded to the smallest common format and number of bands.
 *
 * Combine this with vips_switch() to make something like a case statement or
 * a multi-way vips_ifthenelse().
 *
 * See also: vips_maplut(), vips_switch(), vips_ifthenelse().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_case( VipsImage *index, VipsImage **cases, VipsImage **out, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_casev( index, cases, out, n, ap );
	va_end( ap );

	return( result );
}

