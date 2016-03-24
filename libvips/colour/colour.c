/* base class for all colour operations
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pcolour.h"

/**
 * SECTION: colour
 * @short_description: colour operators
 * @stability: Stable
 * @see_also: <link linkend="libvips-arithmetic">arithmetic</link>
 * @include: vips/vips.h
 *
 * These operators let you transform coordinates and images between colour 
 * spaces, calculate colour differences, and move 
 * to and from device spaces.
 *
 * All operations process colour from the first few bands and pass other bands
 * through unaltered. This means you can operate on images with alpha channels
 * safely. If you move to or from 16-bit RGB, any alpha channels are rescaled
 * for you.
 *
 * Radiance images have four 8-bits bands and store 8 bits of R, G and B and
 * another 8 bits of exponent, common to all channels. They are widely used in
 * the HDR imaging community.
 *
 * The colour functions can be divided into three main groups. First, 
 * functions to transform images between the different colour spaces supported 
 * by VIPS: #VIPS_INTERPRETATION_sRGB, #VIPS_INTERPRETATION_scRGB,  
 * #VIPS_INTERPRETATION_B_W,
 * #VIPS_INTERPRETATION_XYZ, #VIPS_INTERPRETATION_YXY,  
 * #VIPS_INTERPRETATION_LAB, 
 * #VIPS_INTERPRETATION_LCH, and
 * #VIPS_INTERPRETATION_CMC.
 *
 * There are also a set of minor colourspaces which are one of the above in a
 * slightly different format:
 * #VIPS_INTERPRETATION_LAB, #VIPS_INTERPRETATION_LABQ, 
 * #VIPS_INTERPRETATION_LABS, #VIPS_INTERPRETATION_LCH, 
 * #VIPS_INTERPRETATION_RGB16, and #VIPS_INTERPRETATION_GREY16.
 *
 * Use vips_colourspace() to move an image to a
 * target colourspace using the best sequence of colour transform operations. 
 *
 * Secondly, there are a set of operations for 
 * calculating colour difference metrics. Finally, VIPS wraps LittleCMS and
 * uses it to provide a set of operations for reading and writing images with
 * ICC profiles.
 *
 * This figure shows how the VIPS colour spaces interconvert:
 *
 * <para>
 *   <inlinegraphic fileref="interconvert.png" format="PNG" />
 * </para>
 *
 * The colour spaces supported by VIPS are:
 *
 * * #VIPS_INTERPRETATION_LAB -- CIELAB '76 colourspace with a D65 white. This 
 *   uses three floats for each band, and bands have the obvious range. 
 *
 *   There are two
 *   variants, #VIPS_INTERPRETATION_LABQ and #VIPS_INTERPRETATION_LABS, which
 *   use ints to store values. These are less precise, but can be quicker to
 *   store and process. 
 *
 *   #VIPS_INTERPRETATION_LCH is the same, but with a*b* as polar coordinates.
 *   Hue is expressed in degrees.
 *
 * * #VIPS_INTERPRETATION_XYZ -- CIE XYZ. This uses three floats.
 *   See #VIPS_D75_X0 and friends for values for the ranges
 *   under various illuminants.
 *
 *   #VIPS_INTERPRETATION_YXY is the same, but with little x and y. 
 *
 * * #VIPS_INTERPRETATION_scRGB -- a linear colourspace with the sRGB
 *   primaries. This is useful if you need linear light and don't care
 *   much what the primaries are. 
 *
 *   Linearization is performed with the usual sRGB equations, see below.
 *
 * * #VIPS_INTERPRETATION_sRGB -- the standard sRGB colourspace, see: 
 *   [wikipedia sRGB](http://en.wikipedia.org/wiki/SRGB).
 *
 *   This uses three 8-bit values for each of RGB. 
 *
 *   #VIPS_INTERPRETATION_RGB16 is the same, but using three 16-bit values for
 *   RGB.
 *
 *   #VIPS_INTERPRETATION_HSV is sRGB, but in polar coordinates.
 *   #VIPS_INTERPRETATION_LCH is much better, only use HSV if you have to. 
 *
 * * #VIPS_INTERPRETATION_B_W -- a monochrome image, roughly G from sRGB.
 *   The grey value is
 *   calculated in #VIPS_INTERPRETATION_scRGB space with the usual 0.2, 0.7, 0.1
 *   RGB ratios.
 *
 *   #VIPS_INTERPRETATION_GREY16 is the same, but using 16-bits.
 *
 * * #VIPS_INTERPRETATION_CMC -- a colour space based on the CMC(1:1) 
 *   colour difference measurement. This is a highly uniform colour space, 
 *   much better than CIELAB for expressing small differences. 
 *
 *   The CMC colourspace is described in "Uniform Colour Space Based on the
 *   CMC(l:c) Colour-difference Formula", M R Luo and B Rigg, Journal of the
 *   Society of Dyers and Colourists, vol 102, 1986. Distances in this 
 *   colourspace approximate, within 10% or so, differences in the CMC(l:c)
 *   colour difference formula.
 *
 *   You can calculate metrics like CMC(2:1) by scaling the spaces before
 *   finding differences. 
 * 
 */

/* Areas under curves for Dxx. 2 degree observer.
 */

/**
 * VIPS_D93_X0:
 *
 * Areas under curves for D93, 2 degree observer.
 */

/**
 * VIPS_D75_X0:
 *
 * Areas under curves for D75, 2 degree observer.
 */

/**
 * VIPS_D65_X0:
 *
 * Areas under curves for D65, 2 degree observer.
 */

/**
 * VIPS_D55_X0:
 *
 * Areas under curves for D55, 2 degree observer.
 */

/**
 * VIPS_D50_X0:
 *
 * Areas under curves for D50, 2 degree observer.
 */

/**
 * VIPS_A_X0:
 *
 * Areas under curves for illuminant A (2856K), 2 degree observer.
 */

/**
 * VIPS_B_X0:
 *
 * Areas under curves for illuminant B (4874K), 2 degree observer.
 */

/**
 * VIPS_C_X0:
 *
 * Areas under curves for illuminant C (6774K), 2 degree observer.
 */

/**
 * VIPS_E_X0:
 *
 * Areas under curves for equal energy illuminant E.
 */

/**
 * VIPS_D3250_X0:
 *
 * Areas under curves for black body at 3250K, 2 degree observer.
 */

G_DEFINE_ABSTRACT_TYPE( VipsColour, vips_colour, VIPS_TYPE_OPERATION );

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

static int
vips_colour_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsColour *colour = VIPS_COLOUR( b ); 
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( colour ); 
	VipsColourClass *class = VIPS_COLOUR_GET_CLASS( colour ); 
	VipsRect *r = &or->valid;

	int i, y;
	VipsPel *p[MAX_INPUT_IMAGES], *q;

	for( i = 0; ir[i]; i++ ) 
		if( vips_region_prepare( ir[i], r ) ) 
			return( -1 );

	VIPS_GATE_START( "vips_colour_gen: work" ); 

	for( y = 0; y < r->height; y++ ) {
		for( i = 0; ir[i]; i++ )
			p[i] = VIPS_REGION_ADDR( ir[i], r->left, r->top + y );
		p[i] = NULL;
		q = VIPS_REGION_ADDR( or, r->left, r->top + y );

		class->process_line( colour, q, p, r->width );
	}

	VIPS_GATE_STOP( "vips_colour_gen: work" ); 

	VIPS_COUNT_PIXELS( or, object_class->nickname ); 

	return( 0 );
}

static int
vips_colour_attach_profile( VipsImage *im, const char *filename )
{
	char *data;
	size_t data_length;

	if( !(data = vips__file_read_name( filename, VIPS_ICC_DIR, 
		&data_length )) ) 
		return( -1 );
	vips_image_set_blob( im, VIPS_META_ICC_NAME, 
		(VipsCallbackFn) g_free, data, data_length );

	return( 0 );
}

static int
vips_colour_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsColour *colour = VIPS_COLOUR( object );

	VipsImage **in;
	VipsImage **extra_bands; 
	VipsImage *out;

	int i;

#ifdef DEBUG
	printf( "vips_colour_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_colour_parent_class )->
		build( object ) ) 
		return( -1 );

	if( colour->n > MAX_INPUT_IMAGES ) {
		vips_error( class->nickname,
			"%s", _( "too many input images" ) );
		return( -1 );
	}
	for( i = 0; i < colour->n; i++ )
		if( vips_image_pio_input( colour->in[i] ) )
			return( -1 );

	/* colour->in[] must be NULL-terminated, we can use it as an arg to
	 * vips_start_many().
	 */
	g_assert( !colour->in[colour->n] ); 

	in = colour->in;
	extra_bands = (VipsImage **) 
		vips_object_local_array( object, colour->n );

	/* If there are more than @input_bands bands, we detach and reattach
	 * after processing.
	 */
	if( colour->input_bands > 0 ) {
		VipsImage **new_in = (VipsImage **) 
			vips_object_local_array( object, colour->n );

		for( i = 0; i < colour->n; i++ ) {
			if( vips_check_bands_atleast( class->nickname, 
				in[i], colour->input_bands ) )
				return( -1 ); 

			if( in[i]->Bands > colour->input_bands ) {
				if( vips_extract_band( in[i], &new_in[i], 0, 
					"n", colour->input_bands, 
					NULL ) )
					return( -1 ); 
			}
			else {
				new_in[i] = in[i];
				g_object_ref( new_in[i] ); 
			}

			if( in[i]->Bands > colour->input_bands ) 
				if( vips_extract_band( in[i], &extra_bands[i], 
					colour->input_bands, 
					"n", in[i]->Bands - 
						colour->input_bands, 
					NULL ) )
					return( -1 );
		}

		in = new_in;
	}

	out = vips_image_new();
	if( vips_image_pipeline_array( out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in ) ) {
		g_object_unref( out );
		return( -1 );
	}
	out->Coding = colour->coding;
	out->Type = colour->interpretation;
	out->BandFmt = colour->format;
	out->Bands = colour->bands;

	if( colour->profile_filename ) 
		if( vips_colour_attach_profile( out, 
			colour->profile_filename ) ) {
			g_object_unref( out );
			return( -1 );
		}

	if( vips_image_generate( out,
		vips_start_many, vips_colour_gen, vips_stop_many, 
		in, colour ) ) {
		g_object_unref( out );
		return( -1 );
	}

	/* Reattach higher bands, if necessary. If we have more than one input
	 * image, just use the first extra bands. 
	 */
	for( i = 0; i < colour->n; i++ ) 
		if( extra_bands[i] ) {
			VipsImage *t1, *t2;

			/* We can't just reattach the extra bands: they might
			 * be float (for example) and we might be trying to
			 * make a short image. Cast extra to match the body of
			 * the image.
			 */

			if( vips_cast( extra_bands[i], &t1, out->BandFmt,
				NULL ) ) {
				g_object_unref( out );
				return( -1 );
			}

			if( vips_bandjoin2( out, t1, &t2,
				NULL ) ) {
				g_object_unref( t1 );
				g_object_unref( out );
				return( -1 );
			}
			g_object_unref( out );
			g_object_unref( t1 );
			out = t2;

			break;
		}

	g_object_set( colour, "out", out, NULL ); 

	return( 0 );
}

static void
vips_colour_class_init( VipsColourClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "colour";
	vobject_class->description = _( "color operations" );
	vobject_class->build = vips_colour_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsColour, out ) );
}

static void
vips_colour_init( VipsColour *colour )
{
	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_sRGB;
	colour->format = VIPS_FORMAT_UCHAR;
	colour->bands = 3;
	colour->input_bands = -1;
}

G_DEFINE_ABSTRACT_TYPE( VipsColourTransform, vips_colour_transform, 
	VIPS_TYPE_COLOUR );

static int
vips_colour_transform_build( VipsObject *object )
{
	VipsColour *colour = VIPS_COLOUR( object );
	VipsColourTransform *transform = VIPS_COLOUR_TRANSFORM( object );
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 1 );

	/* We only process float.
	 */
	if( transform->in &&
		transform->in->BandFmt != VIPS_FORMAT_FLOAT ) { 
		if( vips_cast_float( transform->in, &t[0], NULL ) )
			return( -1 );
	}
	else {
		t[0] = transform->in;
		g_object_ref( t[0] ); 
	}

	/* We always do 3 bands -> 3 bands. 
	 */
	colour->input_bands = 3;

	colour->n = 1;
	colour->in = t;

	if( VIPS_OBJECT_CLASS( vips_colour_transform_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_colour_transform_class_init( VipsColourTransformClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "space";
	vobject_class->description = _( "color space transformations" );
	vobject_class->build = vips_colour_transform_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsColourTransform, in ) );
}

static void
vips_colour_transform_init( VipsColourTransform *space )
{
	VipsColour *colour = (VipsColour *) space; 

	/* What we write. interpretation should be overwritten in subclass
	 * builds.
	 */
	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_LAB;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 3;
}

G_DEFINE_ABSTRACT_TYPE( VipsColourCode, vips_colour_code, VIPS_TYPE_COLOUR );

static int
vips_colour_code_build( VipsObject *object )
{
	VipsColour *colour = VIPS_COLOUR( object );
	VipsColourCode *code = VIPS_COLOUR_CODE( object );
	VipsColourCodeClass *class = VIPS_COLOUR_CODE_GET_CLASS( object ); 
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 6 );

	VipsImage *in;

	in = code->in;

	/* If this is a LABQ and the coder wants uncoded, unpack.
	 */
	if( in && 
		in->Coding == VIPS_CODING_LABQ &&
		code->input_coding == VIPS_CODING_NONE ) {
		if( vips_LabQ2Lab( in, &t[0], NULL ) )
			return( -1 );
		in = t[0];
	}

	if( in && 
		vips_check_coding( VIPS_OBJECT_CLASS( class )->nickname,
			in, code->input_coding ) )
		return( -1 );

	if( in &&
		code->input_coding == VIPS_CODING_NONE &&
		code->input_format != VIPS_FORMAT_NOTSET &&
		in->BandFmt != code->input_format ) { 
		if( vips_cast( in, &t[3], code->input_format, NULL ) )
			return( -1 );
		in = t[3];
	}

	if( in &&
		code->input_coding == VIPS_CODING_NONE &&
		code->input_interpretation != VIPS_INTERPRETATION_ERROR &&
		in->Type != code->input_interpretation ) { 
		if( vips_colourspace( in, &t[4], 
			code->input_interpretation, NULL ) )
			return( -1 );
		in = t[4];
	}

	colour->n = 1;
	colour->in = VIPS_ARRAY( object, 2, VipsImage * );
	colour->in[0] = in;
	colour->in[1] = NULL;

	if( VIPS_OBJECT_CLASS( vips_colour_code_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_colour_code_class_init( VipsColourCodeClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "code";
	vobject_class->description = _( "change color coding" );
	vobject_class->build = vips_colour_code_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsColourCode, in ) );
}

static void
vips_colour_code_init( VipsColourCode *code )
{
	code->input_coding = VIPS_CODING_NONE;
	code->input_interpretation = VIPS_INTERPRETATION_ERROR;
	code->input_format = VIPS_FORMAT_NOTSET;
}

G_DEFINE_ABSTRACT_TYPE( VipsColourDifference, vips_colour_difference, 
	VIPS_TYPE_COLOUR );

static int
vips_colour_difference_build( VipsObject *object )
{
	VipsColour *colour = VIPS_COLOUR( object );
	VipsColourDifference *difference = VIPS_COLOUR_DIFFERENCE( object );

	VipsImage **t;
	VipsImage *left;
	VipsImage *right;

	t = (VipsImage **) vips_object_local_array( object, 12 );

	left = difference->left;
	right = difference->right;

	if( left ) {
		if( vips_image_decode( left, &t[0] ) )
			return( -1 );
		left = t[0];
	}

	if( right ) {
		if( vips_image_decode( right, &t[1] ) )
			return( -1 );
		right = t[1];
	}

	/* Detach and reattach any extra bands. 
	 */
	colour->input_bands = 3;

	if( left &&
		left->Type != difference->interpretation ) {
		if( vips_colourspace( left, &t[6], 
			difference->interpretation, NULL ) )
			return( -1 );
		left = t[6];
	}

	if( right &&
		right->Type != difference->interpretation ) { 
		if( vips_colourspace( right, &t[7], 
			difference->interpretation, NULL ) )
			return( -1 );
		right = t[7];
	}

	/* We only process float.
	 */
	if( left &&
		left->BandFmt != VIPS_FORMAT_FLOAT ) { 
		if( vips_cast_float( left, &t[8], NULL ) )
			return( -1 );
		left = t[8];
	}

	if( right &&
		right->BandFmt != VIPS_FORMAT_FLOAT ) { 
		if( vips_cast_float( right, &t[9], NULL ) )
			return( -1 );
		right = t[9];
	}

	if( vips__sizealike( left, right, &t[10], &t[11] ) )
		return( -1 );
	left = t[10];
	right = t[11];

	colour->n = 2;
	colour->in = VIPS_ARRAY( object, 3, VipsImage * );
	colour->in[0] = left;
	colour->in[1] = right;
	colour->in[2] = NULL;

	if( VIPS_OBJECT_CLASS( vips_colour_difference_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_colour_difference_class_init( VipsColourDifferenceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "difference";
	vobject_class->description = _( "calculate color difference" );
	vobject_class->build = vips_colour_difference_build;

	VIPS_ARG_IMAGE( class, "left", 1, 
		_( "Left" ), 
		_( "Left-hand input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsColourDifference, left ) );

	VIPS_ARG_IMAGE( class, "right", 2, 
		_( "Right" ), 
		_( "Right-hand input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsColourDifference, right ) );

}

static void
vips_colour_difference_init( VipsColourDifference *difference )
{
	VipsColour *colour = VIPS_COLOUR( difference );

	colour->coding = VIPS_CODING_NONE;
	colour->interpretation = VIPS_INTERPRETATION_B_W;
	colour->format = VIPS_FORMAT_FLOAT;
	colour->bands = 1;
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_colour_operation_init( void )
{
	extern GType vips_colourspace_get_type( void ); 
	extern GType vips_Lab2XYZ_get_type( void ); 
	extern GType vips_XYZ2Lab_get_type( void ); 
	extern GType vips_Lab2LCh_get_type( void ); 
	extern GType vips_LCh2Lab_get_type( void ); 
	extern GType vips_LCh2CMC_get_type( void ); 
	extern GType vips_CMC2LCh_get_type( void ); 
	extern GType vips_Yxy2XYZ_get_type( void ); 
	extern GType vips_XYZ2Yxy_get_type( void ); 
	extern GType vips_LabQ2Lab_get_type( void ); 
	extern GType vips_Lab2LabQ_get_type( void ); 
	extern GType vips_LabQ2LabS_get_type( void ); 
	extern GType vips_LabS2LabQ_get_type( void ); 
	extern GType vips_LabS2Lab_get_type( void ); 
	extern GType vips_Lab2LabS_get_type( void ); 
	extern GType vips_rad2float_get_type( void ); 
	extern GType vips_float2rad_get_type( void ); 
	extern GType vips_LabQ2sRGB_get_type( void ); 
	extern GType vips_XYZ2sRGB_get_type( void ); 
	extern GType vips_sRGB2scRGB_get_type( void ); 
	extern GType vips_sRGB2HSV_get_type( void ); 
	extern GType vips_HSV2sRGB_get_type( void ); 
	extern GType vips_scRGB2XYZ_get_type( void ); 
	extern GType vips_scRGB2BW_get_type( void ); 
	extern GType vips_XYZ2scRGB_get_type( void ); 
	extern GType vips_scRGB2sRGB_get_type( void ); 
#if defined(HAVE_LCMS) || defined(HAVE_LCMS2)
	extern GType vips_icc_import_get_type( void ); 
	extern GType vips_icc_export_get_type( void ); 
	extern GType vips_icc_transform_get_type( void ); 
#endif
	extern GType vips_dE76_get_type( void ); 
	extern GType vips_dE00_get_type( void ); 
	extern GType vips_dECMC_get_type( void ); 

	vips_colourspace_get_type();
	vips_Lab2XYZ_get_type();
	vips_XYZ2Lab_get_type();
	vips_Lab2LCh_get_type();
	vips_LCh2Lab_get_type();
	vips_LCh2CMC_get_type();
	vips_CMC2LCh_get_type();
	vips_XYZ2Yxy_get_type();
	vips_Yxy2XYZ_get_type();
	vips_LabQ2Lab_get_type();
	vips_Lab2LabQ_get_type();
	vips_LabQ2LabS_get_type();
	vips_LabS2LabQ_get_type();
	vips_LabS2Lab_get_type();
	vips_Lab2LabS_get_type();
	vips_rad2float_get_type();
	vips_float2rad_get_type();
	vips_LabQ2sRGB_get_type();
	vips_sRGB2scRGB_get_type();
	vips_scRGB2XYZ_get_type();
	vips_scRGB2BW_get_type();
	vips_sRGB2HSV_get_type(); 
	vips_HSV2sRGB_get_type(); 
	vips_XYZ2scRGB_get_type();
	vips_scRGB2sRGB_get_type();
#if defined(HAVE_LCMS) || defined(HAVE_LCMS2)
	vips_icc_import_get_type();
	vips_icc_export_get_type();
	vips_icc_transform_get_type();
#endif
	vips_dE76_get_type(); 
	vips_dE00_get_type(); 
	vips_dECMC_get_type(); 
}
