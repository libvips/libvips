/* compose a set of images together with porter-duff operators
 *
 * 25/9/17
 * 	- from bandjoin.c
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

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

/**
 * VipsBlendMode:
 * VIPS_BLEND_MODE_OVER: 
 *
 * The various Porter-Duff blend modes. See vips_composite(), for example. 
 */

/* References:
 *
 * @gasi's composite example https://gist.github.com/jcupitt/abacc012e2991f332e8b
 *
 * https://en.wikipedia.org/wiki/Alpha_compositing
 */

typedef struct _VipsComposite {
	VipsConversion parent_instance;

	/* The input images.
	 */
	VipsArrayImage *in;

	/* For N input images, N - 1 blend modes.
	 */
	VipsArrayInt *mode;

	/* Compositing space. This defaults to RGB, or B_W if we only have
	 * G and GA inputs.
	 */
	VipsInterpretation compositing_space;

	/* The number of inputs. This can be less than the number of images in
	 * @in.
	 */
	int n;
} VipsComposite;

typedef VipsConversionClass VipsCompositeClass;

G_DEFINE_TYPE( VipsComposite, vips_composite, VIPS_TYPE_CONVERSION );

#define COMPOSE_INT( TYPE ) { \
	TYPE
}


static void
vips_composite_process_line( VipsComposite *composite, VipsBandFormat format,
	VipsPel *q, VipsPel **p, int width )
{
	int n = composite->n;
	int i;

	switch( format ) {
	case VIPS_FORMAT_UCHAR:
		COMPOSE_INT( unsigned char );
		break;

	case VIPS_FORMAT_CHAR:
		COMPOSE_INT( unsigned char );
		break;

	case VIPS_FORMAT_USHORT:
	case VIPS_FORMAT_SHORT:
	case VIPS_FORMAT_UINT:
	case VIPS_FORMAT_INT:
	case VIPS_FORMAT_FLOAT:
	case VIPS_FORMAT_DOUBLE:
		g_assert_not_reached();
		break;

	case VIPS_FORMAT_COMPLEX:
	case VIPS_FORMAT_DPCOMPLEX:
	default:
		return;
	}
}

static int
vips_composite_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsComposite *composite = (VipsComposite *) b;
	VipsRect *r = &or->valid;

	VipsPel *p[MAX_INPUT_IMAGES], *q;
	int y, i;

	if( vips_reorder_prepare_many( or->im, ir, r ) )
		return( -1 );
	for( i = 0; i < bandary->n; i++ ) 
		p[i] = VIPS_REGION_ADDR( ir[i], r->left, r->top );
	p[i] = NULL;
	q = VIPS_REGION_ADDR( or, r->left, r->top );

	VIPS_GATE_START( "vips_composite_gen: work" ); 

	for( y = 0; y < r->height; y++ ) {
		vips_composite_process_line( composite, ir[0]->im->BandFmt, 
			q, p, r->width );

		for( i = 0; i < bandary->n; i++ )
			p[i] += VIPS_REGION_LSKIP( ir[i] );
		q += VIPS_REGION_LSKIP( or );
	}

	VIPS_GATE_STOP( "vips_composite_gen: work" ); 

	return( 0 );
}

static int
vips_composite_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBandary *bandary = (VipsBandary *) object;
	VipsComposite *composite = (VipsComposite *) object;

	int i;
	VipsImage **in;
	VipsImage **decode;
	VipsImage **compositing;
	VipsImage **format;
	VipsImage **size;
	VipsImage **ready;
	VipsInterpretation compositing_space;
	int max_bands;
	VipsInterpretation max_interpretation;

	if( VIPS_OBJECT_CLASS( vips_composite_parent_class )->build( object ) )
		return( -1 );

	composite->n = composite->in->area->n;

	in = (VipsImage **) composite->in->data;
	decode = (VipsImage **) vips_object_local_array( object, composite->n );
	for( i = 0; i < composite->n; i++ )
		if( vips_image_decode( in[i], &decode[i] ) )
			return( -1 );
	in = decode;

	/* Are any of the images missing alpha? The first missing alpha is
	 * given a solid 255 and becomes the background image, shortening n.
	 */
	for( i = 0; i < composite->n; i++ )
		if( !vips_image_hasalpha( in[i] ) ) { 
			VipsImage *x;

			if( vips_bandjoin( in[i], &x, 255 ) )
				return( -1 );
			g_object_unref( in[i] );
			in[i] = x;
			composite->n = i + 1;
			break;
		}

	/* Transform to compositing space. It defaults to sRGB or B_W. 
	 */
	if( !vips_object_argument_isset( object, "compositing_space" ) ) {
		gboolean all_grey;

		all_grey = TRUE;
		for( i = 0; i < composite->n; i++ ) 
			if( in[i]->Bands > 2 ) {
				all_grey = FALSE;
				break;
			}

		composite->compositing_space = all_grey ? 
			VIPS_INTERPRETATION_B_W : VIPS_INTERPRETATION_sRGB;
	}

	compositing = (VipsImage **) 
		vips_object_local_array( object, composite->n );
	for( i = 0; i < composite->n; i++ )
		if( vips_colourspace( in[i], &compositing[i], 
			composite->compositing_space, NULL ) )
			return( -1 );
	in = compositing;

	/* Transform the input images to match in size and format.
	 */
	format = (VipsImage **) vips_object_local_array( object, composite->n );
	size = (VipsImage **) vips_object_local_array( object, composite->n );
	if( vips__formatalike_vec( decode, format, composite->n ) ||
		vips__sizealike_vec( format, size, composite->n ) )
		return( -1 );
	in = size;

	/* Check that they all now match in bands. This can fail for some
	 * inputs.
	 */
	for( i = 1; i < composite->n; i++ )
		if( in[i]->Bands != in[0]->Bands ) {
			vips_error( class->nickname, 
				_( "image %d does not have %d bands" ), 
				i, in[0]->Bands ); 
			return( -1 );
		}

	if( vips_image_pipeline_array( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in ) )
		return( -1 );

	if( vips_image_generate( conversion->out,
		vips_start_many, vips_composite_gen, vips_stop_many, 
		in, composite ) )
		return( -1 );

	return( 0 );
}

static void
vips_composite_class_init( VipsCompositeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_composite_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "composite";
	vobject_class->description = _( "blend an array of images according to an array of blend modes" );
	vobject_class->build = vips_composite_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_BOXED( class, "in", 0, 
		_( "Inputs" ), 
		_( "Array of input images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComposite, in ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_BOXED( class, "mode", 1, 
		_( "Blend modes" ), 
		_( "Array of VipsBlendMode to join with" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComposite, mode ),
		VIPS_TYPE_ARRAY_INT );

	VIPS_ARG_ENUM( class, "compositing_space", 10, 
		_( "Interpretation" ), 
		_( "Pixel interpretation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsComposite, compositing_space ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_sRGB ); 

}

static void
vips_composite_init( VipsComposite *composite )
{
	composite->compositing_space = VIPS_INTERPRETATION_sRGB;
}

static int
vips_compositev( VipsImage **in, VipsImage **out, int n, va_list ap )
{
	VipsArrayImage *array; 
	int result;

	array = vips_array_image_new( in, n ); 
	result = vips_call_split( "composite", ap, array, out );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}

/**
 * vips_composite:
 * @in: (array length=n) (transfer none): array of input images
 * @out: output image
 * @n: number of input images
 * @...: %NULL-terminated list of optional named arguments
 *
 * Join a set of images together, bandwise. 
 *
 * If the images
 * have n and m bands, then the output image will have n + m
 * bands, with the first n coming from the first image and the last m
 * from the second. 
 *
 * If the images differ in size, the smaller images are enlarged to match the
 * larger by adding zero pixels along the bottom and right.
 *
 * The input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="libvips-arithmetic">arithmetic</link>).
 *
 * See also: vips_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_composite( VipsImage **in, VipsImage **out, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_compositev( in, out, n, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_composite2:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Join a pair of images together, bandwise. See vips_composite().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_composite2( VipsImage *in1, VipsImage *in2, VipsImage **out, ... )
{
	va_list ap;
	int result;
	VipsImage *in[2];

	in[0] = in1;
	in[1] = in2;

	va_start( ap, out );
	result = vips_compositev( in, out, 2, ap );
	va_end( ap );

	return( result );
}
