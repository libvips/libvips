/* use pixel values to select between an array of images
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

typedef struct _VipsSelect {
	VipsOperation parent_instance;

	VipsArrayImage *tests;
	VipsArrayImage *cases;
	VipsImage *out;

	int n;

} VipsSelect;

typedef VipsOperationClass VipsSelectClass;

G_DEFINE_TYPE( VipsSelect, vips_select, VIPS_TYPE_OPERATION );

/* Our sequence value.
 */
typedef struct _VipsSelectSeq {
	VipsSelect *select;

	/* Set of input regions.
	 */
	VipsRegion **tests;
	VipsRegion **cases;

} VipsSelectSeq;

int
vips_select_stop( void *vseq, void *a, void *b )
{
	VipsSelectSeq *seq = (VipsSelectSeq *) vseq;

	if( seq->tests ) {
		vips_stop_many( (void *) seq->tests, NULL, NULL );
		seq->tests = NULL;
	}
	if( seq->cases ) {
		vips_stop_many( (void *) seq->cases, NULL, NULL );
		seq->cases = NULL;
	}
	VIPS_FREE( seq );

	return( 0 ):
}

static void *
vips_select_start( VipsImage *out, void *a, void *b )
{
	VipsImage **in = (VipsImage **) a;
	VipsSelect *select = (VipsSelect *) b;

	VipsSelectSeq *seq;
	int i, n;

	if( !(seq = VIPS_NEW( NULL, VipsSelectSeq )) )
		return( NULL );

	seq->select = select;
	seq->tests = NULL;
	seq->cases = NULL;

	seq->tests = vips_start_many( NULL, (void *) select->tests, NULL );
	seq->cases = vips_start_many( NULL, (void *) select->cases, NULL );
	if( !seq->tests ||
		!seq->cases ) {
		vips_select_stop( (void *) seq, NULL, NULL  );
		return( NULL );
	}

	return( seq );
}

/* Do a map.
 */
static int 
vips_select_gen( VipsRegion *or, void *vseq, void *a, void *b, 
	gboolean *stop )
{
	VipsSelectSeq *seq = (VipsSelectSeq *) vseq;
	VipsSelect *select = seq->select;
	VipsRect *r = &or->valid;

	int x, y, i, j;
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
			VipsPel * restrict pv = p[ip[x]];

			for( j = 0; j < ps; j++ ) {
				q[i] = pv[i];
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
vips_select_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsSelect *swit = (VipsSelect *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;
	VipsImage **lut;
	VipsImage **decode;
	VipsImage **format;
	VipsImage **band;
	VipsImage **size;
	int i;

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_select_parent_class )->build( object ) )
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
	g_object_ref( in ); 
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
		vips_start_many, vips_select_gen, vips_stop_many, 
		lut, swit ) )
		return( -1 );

	return( 0 );
}

static void
vips_select_class_init( VipsSelectClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "select";
	object_class->description = 
		_( "test images pick pixels from a set of case images" );
	object_class->build = vips_select_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_BOXED( class, "tests", 1, 
		_( "Tests" ), 
		_( "Table of images to test" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSelect, tests ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_BOXED( class, "cases", 2, 
		_( "Cases" ), 
		_( "Table of image cases" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSelect, cases ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_IMAGE( class, "out", 3, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsSelect, out ) );

}

static void
vips_select_init( VipsSelect *swit )
{
}

static int
vips_selectv( VipsImage **tests, VipsImage **cases, VipsImage **out, int n, 
	va_list ap )
{
	VipsArrayImage *tests_array; 
	VipsArrayImage *cases_array; 
	int result;

	tests_array = vips_array_image_new( tests n ); 
	cases_array = vips_array_image_new( selects, n ); 
	result = vips_call_split( "select", ap, 
		tests_array, cases_array, out );
	vips_area_unref( VIPS_AREA( tests_array ) );
	vips_area_unref( VIPS_AREA( cases_array ) );

	return( result );
}

/**
 * vips_select: (method)
 * @tests: (array length=n): test these images
 * @cases: (array length=n): to pick between these images 
 * @out: (out): output image
 * @n: number of input images
 * @...: %NULL-terminated list of optional named arguments
 *
 * The @tests images are evaluated and the index of the first non-zero value 
 * in @tests is used to pick a pixel from @cases. If all @tests are false, the
 * pixel from the final image is @cases is used.
 *
 * Images in @tests images must have one uchar band. @cases and @tests can 
 * have up to 256 elements. The images in @tests and @cases
 * must have either one band or the same number of bands. The output image is
 * the same size as @tests. Images in @cases are expanded to the smallest 
 * common format and number of bands.
 *
 * See also: vips_maplut().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_select( VipsImage **tests, VipsImage **cases, VipsImage **out, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_selectv( tests, cases, out, n, ap );
	va_end( ap );

	return( result );
}

