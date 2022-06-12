/* quantise an image
 *
 * 20/6/18 
 * 	  - from vipspng.c
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
#define DEBUG
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <vips/vips.h>

#include "quantise.h"

#ifdef HAVE_QUANTIZATION

#ifdef HAVE_IMAGEQUANT

VipsQuantiseAttr *
vips__quantise_attr_create()
{
	return liq_attr_create();
}

VipsQuantiseError
vips__quantise_set_max_colors( VipsQuantiseAttr *attr, int colors )
{
	return liq_set_max_colors( attr, colors );
}

VipsQuantiseError
vips__quantise_set_quality( VipsQuantiseAttr *attr, int minimum, int maximum )
{
	return liq_set_quality( attr, minimum, maximum );
}

VipsQuantiseError
vips__quantise_set_speed( VipsQuantiseAttr *attr, int speed )
{
	return liq_set_speed( attr, speed );
}

VipsQuantiseImage *
vips__quantise_image_create_rgba( const VipsQuantiseAttr *attr,
	const void *bitmap, int width, int height, double gamma )
{
	return liq_image_create_rgba( attr, bitmap, width, height, gamma );
}

VipsQuantiseError
vips__quantise_image_quantize( VipsQuantiseImage *const input_image,
	VipsQuantiseAttr *const options, VipsQuantiseResult **result_output )
{
	return liq_image_quantize( input_image, options, result_output );
}

/* Like vips__quantise_image_quantize(), but make a fixed palette that won't
 * get remapped during dithering.
 */
VipsQuantiseError
vips__quantise_image_quantize_fixed( VipsQuantiseImage *const input_image,
	VipsQuantiseAttr *const options, VipsQuantiseResult **result_output )
{
	int i;
	liq_result *result;
	const liq_palette *palette;
	liq_error err;
	liq_image *fake_image;
	char fake_image_pixels[4] = { 0 };

	/* First, quantize the image and get its palette.
	 */
	err = liq_image_quantize( input_image, options, &result );
	if( err != LIQ_OK )
		return err;

	palette = liq_get_palette( result );

	/* Now, we need a fake 1 pixel image that will be quantized on the
	 * next step. Its pixel color doesn't matter since we'll add all the
	 * colors from the palette further.
	 */
	fake_image = 
		liq_image_create_rgba( options, fake_image_pixels, 1, 1, 0 );
	if( !fake_image ) {
		liq_result_destroy( result );
		return LIQ_OUT_OF_MEMORY;
	}

	/* Add all the colors from the palette as fixed colors to the fake
	 * image. Since the fixed colors number is the same as required colors
	 * number, no new colors will be added.
	 */
	for( i = 0; i < palette->count; i++ )
		liq_image_add_fixed_color( fake_image, palette->entries[i] );

	liq_result_destroy( result );

	/* Finally, quantize the fake image with fixed colors to make a 
	 * VipsQuantiseResult with a fixed palette.
	 */
	err = liq_image_quantize( fake_image, options, result_output );

	liq_image_destroy( fake_image );

	return err;
}

VipsQuantiseError
vips__quantise_set_dithering_level( VipsQuantiseResult *res,
	float dither_level )
{
	return liq_set_dithering_level( res, dither_level );
}

const VipsQuantisePalette *
vips__quantise_get_palette( VipsQuantiseResult *result )
{
	return liq_get_palette( result );
}

VipsQuantiseError
vips__quantise_write_remapped_image( VipsQuantiseResult *result,
	VipsQuantiseImage *input_image, void *buffer, size_t buffer_size )
{
	return liq_write_remapped_image(
		result, input_image, buffer, buffer_size );
}

void
vips__quantise_result_destroy( VipsQuantiseResult *result )
{
	liq_result_destroy( result );
}

void
vips__quantise_image_destroy( VipsQuantiseImage *img )
{
	liq_image_destroy( img );
}

void
vips__quantise_attr_destroy( VipsQuantiseAttr *attr )
{
	liq_attr_destroy( attr );
}

#elif defined(HAVE_QUANTIZR) /*!HAVE_IMAGEQUANT*/

VipsQuantiseAttr *
vips__quantise_attr_create()
{
	return quantizr_new_options();
}

VipsQuantiseError
vips__quantise_set_max_colors( VipsQuantiseAttr *attr, int colors )
{
	return quantizr_set_max_colors( attr, colors );
}

VipsQuantiseError
vips__quantise_set_quality( VipsQuantiseAttr *attr, int minimum, int maximum )
{
	/* Not supported by quantizr
	 */
	return 0;
}

VipsQuantiseError
vips__quantise_set_speed( VipsQuantiseAttr *attr, int speed )
{
	/* Not supported by quantizr
	 */
	return 0;
}

VipsQuantiseImage *
vips__quantise_image_create_rgba( const VipsQuantiseAttr *attr,
	const void *bitmap, int width, int height, double gamma )
{
	/* attr and gamma ununused by quantizr
	 */
	return quantizr_create_image_rgba(
		(unsigned char *) bitmap, width, height );
}

VipsQuantiseError
vips__quantise_image_quantize( VipsQuantiseImage *const input_image,
	VipsQuantiseAttr *const options, VipsQuantiseResult **result_output )
{
	*result_output = quantizr_quantize( input_image, options );
	return 0;
}

VipsQuantiseError
vips__quantise_image_quantize_fixed( VipsQuantiseImage *const input_image,
	VipsQuantiseAttr *const options, VipsQuantiseResult **result_output )
{
	/* Quantizr doesn't change the palette during remapping, so we don't
	 * need a special implementation for this
	 */
	return vips__quantise_image_quantize( input_image, options,
		result_output );
}

VipsQuantiseError
vips__quantise_set_dithering_level( VipsQuantiseResult *res,
	float dither_level )
{
	return quantizr_set_dithering_level( res, dither_level );
}

const VipsQuantisePalette *
vips__quantise_get_palette( VipsQuantiseResult *result )
{
	return quantizr_get_palette( result );
}

VipsQuantiseError
vips__quantise_write_remapped_image( VipsQuantiseResult *result,
	VipsQuantiseImage *input_image, void *buffer, size_t buffer_size )
{
	return quantizr_remap( result, input_image, buffer, buffer_size );
}

void
vips__quantise_result_destroy( VipsQuantiseResult *result )
{
	quantizr_free_result( result );
}

void
vips__quantise_image_destroy( VipsQuantiseImage *img )
{
	quantizr_free_image( img );
}

void
vips__quantise_attr_destroy( VipsQuantiseAttr *attr )
{
	quantizr_free_options( attr );
}

#endif /*HAVE_IMAGEQUANT*/

/* Track during a quantisation.
 */
typedef struct _Quantise {
	VipsImage *in;
	VipsImage **index_out;
	VipsImage **palette_out;
	int colours;
	int Q;
	double dither;
	int effort;

	VipsQuantiseAttr *attr;
	VipsQuantiseImage *input_image;
	VipsQuantiseResult *quantisation_result;
	VipsImage *t[5];
} Quantise;

static void
vips__quantise_free( Quantise *quantise )
{
	int i;

	VIPS_FREEF( vips__quantise_result_destroy, quantise->quantisation_result );
	VIPS_FREEF( vips__quantise_image_destroy, quantise->input_image );
	VIPS_FREEF( vips__quantise_attr_destroy, quantise->attr );

	for( i = 0; i < VIPS_NUMBER( quantise->t ); i++ )
		VIPS_UNREF( quantise->t[i] ); 

	VIPS_FREE( quantise );
}

static Quantise *
vips__quantise_new( VipsImage *in, 
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither, int effort )
{
	Quantise *quantise;
	int i;

	quantise = VIPS_NEW( NULL, Quantise );
	quantise->in = in;
	quantise->index_out = index_out;
	quantise->palette_out = palette_out;
	quantise->colours = colours;
	quantise->Q = Q;
	quantise->dither = dither;
	quantise->effort = effort;
	for( i = 0; i < VIPS_NUMBER( quantise->t ); i++ )
		quantise->t[i] = NULL; 

	return( quantise ); 
}

int
vips__quantise_image( VipsImage *in, 
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither, int effort,
	gboolean threshold_alpha )
{
	Quantise *quantise;
	VipsImage *index;
	VipsImage *palette;
	const VipsQuantisePalette *lp;
	gint64 i;
	VipsPel * restrict p;
	gboolean added_alpha;

	quantise = vips__quantise_new( in, index_out, palette_out, 
		colours, Q, dither, effort );

	/* Ensure input is sRGB. 
	 */
	if( in->Type != VIPS_INTERPRETATION_sRGB ) {
		if( vips_colourspace( in, &quantise->t[0], 
			VIPS_INTERPRETATION_sRGB, NULL ) ) {
			vips__quantise_free( quantise ); 
			return( -1 );
		}
		in = quantise->t[0];
	}

	/* Add alpha channel if missing. 
	 */
	added_alpha = FALSE;
	if( !vips_image_hasalpha( in ) ) {
		if( vips_bandjoin_const1( in, &quantise->t[1], 255, NULL ) ) {
			vips__quantise_free( quantise ); 
			return( -1 );
		}
		added_alpha = TRUE;
		in = quantise->t[1];
	}

	if( !(quantise->t[2] = vips_image_copy_memory( in )) ) {
		vips__quantise_free( quantise ); 
		return( -1 );
	}
	in = quantise->t[2];

	/* Threshold alpha channel.
	 */
	if( threshold_alpha && 
		!added_alpha ) {
		const guint64 n_pels = VIPS_IMAGE_N_PELS( in );

		p = VIPS_IMAGE_ADDR( in, 0, 0 );
		for( i = 0; i < n_pels; i++ ) {
			p[3] = p[3] > 128 ? 255 : 0;
			p += 4;
		}
	}

	quantise->attr = vips__quantise_attr_create();
	vips__quantise_set_max_colors( quantise->attr, colours );
	vips__quantise_set_quality( quantise->attr, 0, Q );
	vips__quantise_set_speed( quantise->attr, 11 - effort );

	quantise->input_image = vips__quantise_image_create_rgba( quantise->attr,
		VIPS_IMAGE_ADDR( in, 0, 0 ), in->Xsize, in->Ysize, 0 );

	if( vips__quantise_image_quantize( quantise->input_image, quantise->attr,
		&quantise->quantisation_result ) ) {
		vips_error( "quantise", "%s", _( "quantisation failed" ) );
		vips__quantise_free( quantise ); 
		return( -1 );
	}

	vips__quantise_set_dithering_level( quantise->quantisation_result, dither );

	index = quantise->t[3] = vips_image_new_memory();
	vips_image_init_fields( index, 
		in->Xsize, in->Ysize, 1, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );

	if( vips_image_write_prepare( index ) ) {
		vips__quantise_free( quantise ); 
		return( -1 );
	}

	if( vips__quantise_write_remapped_image( quantise->quantisation_result,
		quantise->input_image,
		VIPS_IMAGE_ADDR( index, 0, 0 ), VIPS_IMAGE_N_PELS( index ) ) ) {
		vips_error( "quantise", "%s", _( "quantisation failed" ) );
		vips__quantise_free( quantise ); 
		return( -1 );
	}

	lp = vips__quantise_get_palette( quantise->quantisation_result );

	palette = quantise->t[4] = vips_image_new_memory();
	vips_image_init_fields( palette, lp->count, 1, 4,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );

	if( vips_image_write_prepare( palette ) ) {
		vips__quantise_free( quantise ); 
		return( -1 );
	}

	p = VIPS_IMAGE_ADDR( palette, 0, 0 );
	for( i = 0; i < lp->count; i++ ) {
		p[0] = lp->entries[i].r;
		p[1] = lp->entries[i].g;
		p[2] = lp->entries[i].b;
		p[3] = lp->entries[i].a;

		p += 4;
	}

	*index_out = index;
	g_object_ref( index );
	*palette_out = palette;
	g_object_ref( palette );

	vips__quantise_free( quantise ); 

	return( 0 );
}

#else /*!HAVE_QUANTIZATION*/

int
vips__quantise_image( VipsImage *in, 
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither, int effort,
	gboolean threshold_alpha )
{
	vips_error( "vips__quantise_image", 
		"%s", _( "libvips not built with quantisation support" ) ); 

	return( -1 );
}

#endif /*HAVE_QUANTIZATION*/

