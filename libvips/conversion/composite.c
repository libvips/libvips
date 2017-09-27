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

#include "pconversion.h"

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

/* Maximum number of image bands. 
 */
#define MAX_BANDS (64)

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
 *
 * composite -compose over PNG_transparency_demonstration_1.png \
 * 	Opera-icon-high-res.png x.png
 *
 * vips composite "PNG_transparency_demonstration_1.png \
 * 	Opera-icon-high-res.png" x.png 0
 *
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

	/* Set if the input images have already been premultiplied.
	 */
	gboolean premultiplied;

	/* The number of inputs. This can be less than the number of images in
	 * @in.
	 */
	int n;

	/* The number of bands we are blending.
	 */
	int bands;

} VipsComposite;

typedef VipsConversionClass VipsCompositeClass;

G_DEFINE_TYPE( VipsComposite, vips_composite, VIPS_TYPE_CONVERSION );

#define BLEND( OUT, AOUT, SRC1, A1, SRC2, A2 ) { \
	if( AOUT == 0 ) \
		OUT = 0; \
	else \
		switch( mode ) { \
		case VIPS_BLEND_MODE_OVER: \
			OUT = (SRC1 + SRC2 * (1 - A1)) / AOUT; \
			break; \
		\
		default: \
			 g_assert_not_reached(); \
		} \
}

#define COMBINE( TYPE ) { \
	TYPE **tp = (TYPE **) p; \
	TYPE *tq = (TYPE *) q; \
	\
	for( x = 0; x < width; x++ ) { \
		int o = x * (bands + 1); \
		\
		for( b = 0; b < bands; b++ ) \
			pixel[b] = tp[n - 1][o + b]; \
		alpha = tp[n - 1][o + bands] / 255.0; \
		\
		for( i = n - 2; i >= 0; i-- ) { \
			TYPE *src1 = tp[i] + o; \
			double a1 = src1[bands] / 255.0; \
			double aout = a1 + alpha * (1 - a1); \
			VipsBlendMode mode = ((VipsBlendMode *) \
				composite->mode->area.data)[i]; \
			\
			for( b = 0; b < bands; b++ ) \
				BLEND( pixel[b], aout, \
					src1[b], a1, pixel[b], alpha ); \
			\
			alpha = aout; \
		} \
		\
		for( b = 0; b < bands; b++ ) \
			tq[o + b] = pixel[b]; \
		tq[o + bands] = alpha * 255; \
	} \
}

static void
vips_composite_process_line( VipsComposite *composite, VipsBandFormat format,
	VipsPel *q, VipsPel **p, int width )
{
	int n = composite->n;
	int bands = composite->bands;

	double pixel[MAX_BANDS];
	double alpha;
	int x, i, b;

	switch( format ) {
	case VIPS_FORMAT_UCHAR:
		COMBINE( unsigned char );
		break;

	case VIPS_FORMAT_CHAR:
		COMBINE( signed char );
		break;

	case VIPS_FORMAT_USHORT:
		COMBINE( unsigned short );
		break;

	case VIPS_FORMAT_SHORT:
		COMBINE( signed short );
		break;

	case VIPS_FORMAT_UINT:
		COMBINE( unsigned int );
		break;

	case VIPS_FORMAT_INT:
		COMBINE( signed int );
		break;

	case VIPS_FORMAT_FLOAT:
		COMBINE( float );
		break;

	case VIPS_FORMAT_DOUBLE:
		COMBINE( double );
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
	for( i = 0; i < composite->n; i++ ) 
		p[i] = VIPS_REGION_ADDR( ir[i], r->left, r->top );
	p[i] = NULL;
	q = VIPS_REGION_ADDR( or, r->left, r->top );

	VIPS_GATE_START( "vips_composite_gen: work" ); 

	for( y = 0; y < r->height; y++ ) {
		vips_composite_process_line( composite, ir[0]->im->BandFmt, 
			q, p, r->width );

		for( i = 0; i < composite->n; i++ )
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
	VipsComposite *composite = (VipsComposite *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

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
	VipsBlendMode *mode;
	VipsImage *out;

	if( VIPS_OBJECT_CLASS( vips_composite_parent_class )->build( object ) )
		return( -1 );

	composite->n = composite->in->area.n;

	if( composite->n <= 0 ) { 
		vips_error( class->nickname, "%s", _( "no input images" ) ); 
		return( -1 );
	}
	if( composite->mode->area.n != composite->n - 1 ) {
		vips_error( class->nickname, 
			_( "for %d input images there must be %d blend modes" ),
			composite->n, composite->n - 1 ); 
		return( -1 );
	}
	mode = (VipsBlendMode *) composite->mode->area.data;
	for( i = 0; i < composite->n - 1; i++ ) {
		if( mode[i] < 0 || 
			mode[i] >= VIPS_BLEND_MODE_LAST ) {
			vips_error( class->nickname, 
				_( "blend mode index %d (%d) invalid" ),
				i, mode[i] ); 
			return( -1 );
		}
	}

	in = (VipsImage **) composite->in->area.data;

	/* Premultiply alpha, if it hasn't been.
	 */
	if( !composite->premultiplied ) { 
		VipsImage **premultiply = (VipsImage **) 
			vips_object_local_array( object, composite->n );

		for( i = 0; i < composite->n; i++ )
			if( vips_premultiply( in[i], &premultiply[i], NULL ) )
				return( -1 );
		in = premultiply;
	}

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

			if( vips_bandjoin_const1( in[i], &x, 255, NULL ) )
				return( -1 );
			g_object_unref( in[i] );
			in[i] = x;
			composite->n = i + 1;
			break;
		}

	if( composite->n > MAX_INPUT_IMAGES ) {
		vips_error( class->nickname, 
			"%s", _( "too many input images" ) ); 
		return( -1 );
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

	if( in[0]->Bands > MAX_BANDS ) {
		vips_error( class->nickname, 
			"%s", _( "too many input bands" ) ); 
		return( -1 );
	}

	composite->bands = in[0]->Bands - 1;

	t[0] = vips_image_new();
	out = t[0];

	if( vips_image_pipeline_array( out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in ) )
		return( -1 );

	if( vips_image_generate( out,
		vips_start_many, vips_composite_gen, vips_stop_many, 
		in, composite ) )
		return( -1 );

	/* And unpremultiply alpha, if we need to.
	 */
	if( !composite->premultiplied ) { 
		if( vips_unpremultiply( out, &t[1], NULL ) )
			return( -1 );
		out = t[1];
	}

	if( vips_image_write( out, conversion->out ) )
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

	VIPS_ARG_BOXED( class, "mode", 3, 
		_( "Blend modes" ), 
		_( "Array of VipsBlendMode to join with" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsComposite, mode ),
		VIPS_TYPE_ARRAY_INT );

	VIPS_ARG_ENUM( class, "compositing_space", 10, 
		_( "Compositing space" ), 
		_( "Composite images in this colour space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsComposite, compositing_space ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_sRGB ); 

	VIPS_ARG_BOOL( class, "premultiplied", 11, 
		_( "Premultiplied" ), 
		_( "Images have premultiplied alpha" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsComposite, premultiplied ),
		FALSE ); 

}

static void
vips_composite_init( VipsComposite *composite )
{
	composite->compositing_space = VIPS_INTERPRETATION_sRGB;
}

static int
vips_compositev( VipsImage **in, VipsImage **out, int n, int *mode, va_list ap )
{
	VipsArrayImage *image_array; 
	VipsArrayInt *mode_array; 
	int result;

	image_array = vips_array_image_new( in, n ); 
	mode_array = vips_array_int_new( mode, n - 1 ); 
	result = vips_call_split( "composite", ap, 
		image_array, out, mode_array );
	vips_area_unref( VIPS_AREA( image_array ) );
	vips_area_unref( VIPS_AREA( mode_array ) );

	return( result );
}

/**
 * vips_composite:
 * @in: (array length=n) (transfer none): array of input images
 * @out: output image
 * @n: number of input images
 * @mode: array of (@n - 1) #VipsBlendMode
 * @...: %NULL-terminated list of optional named arguments
 *
 * Composite an array of images together. 
 *
 * See also: vips_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_composite( VipsImage **in, VipsImage **out, int n, int *mode, ... )
{
	va_list ap;
	int result;

	va_start( ap, mode );
	result = vips_compositev( in, out, n, mode, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_composite2:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 * @mode: composite with this blend mode
 * @...: %NULL-terminated list of optional named arguments
 *
 * Composite a pair of images together. See vips_composite().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_composite2( VipsImage *in1, VipsImage *in2, VipsImage **out, 
	VipsBlendMode mode1, ... )
{
	va_list ap;
	int result;
	VipsImage *in[2];
	int mode[1];

	in[0] = in1;
	in[1] = in2;
	mode[0] = mode1;

	va_start( ap, mode1 );
	result = vips_compositev( in, out, 2, mode, ap );
	va_end( ap );

	return( result );
}
