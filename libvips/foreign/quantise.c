/* quantise an image with libimagequant
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
#include <vips/intl.h>

#include <vips/vips.h>

#ifdef HAVE_IMAGEQUANT

#include "pforeign.h"

#include <libimagequant.h>

/* Track during a quantisation.
 */
typedef struct _Quantise {
	VipsImage *in;
       	VipsImage **index_out;
       	VipsImage **palette_out;
        int colours;
       	int Q;
       	double dither;

	liq_attr *attr;
	liq_image *input_image;
	liq_result *quantisation_result;
	VipsImage *t[5];
} Quantise;

static void
vips__quantise_free( Quantise *quantise )
{
	int i;

	VIPS_FREEF( liq_result_destroy, quantise->quantisation_result );
	VIPS_FREEF( liq_image_destroy, quantise->input_image );
	VIPS_FREEF( liq_attr_destroy, quantise->attr );

	for( i = 0; i < VIPS_NUMBER( quantise->t ); i++ )
		VIPS_UNREF( quantise->t[i] ); 

	VIPS_FREE( quantise );
}

static Quantise *
vips__quantise_new( VipsImage *in, 
	VipsImage **index_out, VipsImage **palette_out,
        int colours, int Q, double dither )
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
	for( i = 0; i < VIPS_NUMBER( quantise->t ); i++ )
		quantise->t[i] = NULL; 

	return( quantise ); 
}

int
vips__quantise_image( VipsImage *in, 
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither )
{
	Quantise *quantise;
	VipsImage *index;
	VipsImage *palette;
	const liq_palette *lp;
	int i;

	quantise = vips__quantise_new( in, index_out, palette_out, 
		colours, Q, dither );

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
	if( !vips_image_hasalpha( in ) ) {
		if( vips_bandjoin_const1( in, &quantise->t[1], 255, NULL ) ) {
			vips__quantise_free( quantise ); 
			return( -1 );
		}
		in = quantise->t[1];
	}

	if( !(quantise->t[2] = vips_image_copy_memory( in )) ) {
		vips__quantise_free( quantise ); 
		return( -1 );
	}
	in = quantise->t[2];

	quantise->attr = liq_attr_create();
	liq_set_max_colors( quantise->attr, colours );
	liq_set_quality( quantise->attr, 0, Q );

	quantise->input_image = liq_image_create_rgba( quantise->attr,
		VIPS_IMAGE_ADDR( in, 0, 0 ), in->Xsize, in->Ysize, 0 );

	if( liq_image_quantize( quantise->input_image, quantise->attr, 
		&quantise->quantisation_result ) ) {
		vips_error( "vips2png", "%s", _( "quantisation failed" ) );
		vips__quantise_free( quantise ); 
		return( -1 );
	}

	liq_set_dithering_level( quantise->quantisation_result, dither );

	index = quantise->t[3] = vips_image_new_memory();
	vips_image_init_fields( index, 
		in->Xsize, in->Ysize, 1, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );

	if( vips_image_write_prepare( index ) ) {
		vips__quantise_free( quantise ); 
		return( -1 );
	}

	if( liq_write_remapped_image( quantise->quantisation_result, 
		quantise->input_image,
		VIPS_IMAGE_ADDR( index, 0, 0 ), VIPS_IMAGE_N_PELS( index ) ) ) {
		vips_error( "vips2png", "%s", _( "quantisation failed" ) );
		vips__quantise_free( quantise ); 
		return( -1 );
	}

	lp = liq_get_palette( quantise->quantisation_result );

	palette = quantise->t[4] = vips_image_new_memory();
	vips_image_init_fields( palette, lp->count, 1, 4,
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB,
		1.0, 1.0 );

	if( vips_image_write_prepare( palette ) ) {
		vips__quantise_free( quantise ); 
		return( -1 );
	}

	for( i = 0; i < lp->count; i++ ) {
		unsigned char *p = VIPS_IMAGE_ADDR( palette, i, 0 );

		p[0] = lp->entries[i].r;
		p[1] = lp->entries[i].g;
		p[2] = lp->entries[i].b;
		p[3] = lp->entries[i].a;
	}

	*index_out = index;
	g_object_ref( index );
	*palette_out = palette;
	g_object_ref( palette );

	vips__quantise_free( quantise ); 

	return( 0 );
}

#else /*!HAVE_IMAGEQUANT*/

int
vips__quantise_image( VipsImage *in, 
	VipsImage **index_out, VipsImage **palette_out,
	int colours, int Q, double dither )
{
  vips_error( "vips__quantise_image", 
      "%s", _( "libvips not built with quantisation support" ) ); 

  return( -1 );
}

#endif /*HAVE_IMAGEQUANT*/

