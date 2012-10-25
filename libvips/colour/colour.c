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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include "colour.h"

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
	VipsColourClass *class = VIPS_COLOUR_GET_CLASS( colour ); 
	Rect *r = &or->valid;

	VipsPel *p[MAX_INPUT_IMAGES], *q;
	int i, y;

	/* Prepare all input regions and make buffer pointers.
	 */
	for( i = 0; ir[i]; i++ ) {
		if( vips_region_prepare( ir[i], r ) ) 
			return( -1 );
		p[i] = (VipsPel *) VIPS_REGION_ADDR( ir[i], r->left, r->top );
	}
	p[i] = NULL;
	q = (VipsPel *) VIPS_REGION_ADDR( or, r->left, r->top );

	for( y = 0; y < r->height; y++ ) {
		class->process_line( colour, q, p, r->width );

		for( i = 0; ir[i]; i++ )
			p[i] += VIPS_REGION_LSKIP( ir[i] );
		q += VIPS_REGION_LSKIP( or );
	}

	return( 0 );
}

static int
vips_colour_attach_profile( VipsImage *im, const char *filename )
{
	char *data;
	unsigned int data_length;

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

	int i;

#ifdef DEBUG
	printf( "vips_colour_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_colour_parent_class )->
		build( object ) ) 
		return( -1 );

	g_object_set( colour, "out", vips_image_new(), NULL ); 

	if( colour->n > MAX_INPUT_IMAGES ) {
		vips_error( class->nickname,
			"%s", _( "too many input images" ) );
		return( -1 );
	}
	for( i = 0; i < colour->n; i++ )
		if( vips_image_pio_input( colour->in[i] ) )
			return( -1 );

	if( vips_image_copy_fields_array( colour->out, colour->in ) ) 
		return( -1 );
        vips_demand_hint_array( colour->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, colour->in );
	colour->out->Coding = colour->coding;
	colour->out->Type = colour->interpretation;
	colour->out->BandFmt = colour->format;
	colour->out->Bands = colour->bands;

	if( colour->profile_filename ) 
		if( vips_colour_attach_profile( colour->out, 
			colour->profile_filename ) )
			return( -1 );

	if( vips_image_generate( colour->out,
		vips_start_many, vips_colour_gen, vips_stop_many, 
		colour->in, colour ) ) 
		return( -1 );

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
	vobject_class->description = _( "colour operations" );
	vobject_class->build = vips_colour_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

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
}

G_DEFINE_ABSTRACT_TYPE( VipsColourSpace, vips_colour_space, VIPS_TYPE_COLOUR );

static int
vips_colour_space_build( VipsObject *object )
{
	VipsColour *colour = VIPS_COLOUR( object );
	VipsColourSpace *space = VIPS_COLOUR_SPACE( object );

	VipsImage **t;
	VipsImage *in;
	VipsImage *extra;

	t = (VipsImage **) vips_object_local_array( object, 4 );

	in = space->in;
	extra = NULL;

	/* We only process float.
	 */
	if( vips_cast_float( in, &t[0], NULL ) )
		return( -1 );
	in = t[0];

	/* If there are more than n bands, process just the first three and
	 * reattach the rest after. This lets us handle RGBA etc. 
	 */
	if( in->Bands > 3 ) {
		if( vips_extract_band( in, &t[1], 0, "n", 3, NULL ) ||
			vips_extract_band( in, &t[2], 3, 
				"n", in->Bands - 3, NULL ) )
			return( -1 );

		in = t[1];
		extra = t[2];
	}
	else if( vips_check_bands_atleast( 
		VIPS_OBJECT_GET_CLASS( object )->nickname, in, 3 ) )
		return( -1 );

	colour->n = 1;
	colour->in = (VipsImage **) vips_object_local_array( object, 1 );
	colour->in[0] = in;
	if( colour->in[0] )
		g_object_ref( colour->in[0] );

	if( VIPS_OBJECT_CLASS( vips_colour_space_parent_class )->
		build( object ) )
		return( -1 );

	/* Reattach higher bands, if necessary.
	 */
	if( extra ) {
		VipsImage *x;

		if( vips_bandjoin2( colour->out, extra, &x, NULL ) )
			return( -1 );

		VIPS_UNREF( colour->out );

		colour->out = x;
	}

	return( 0 );
}

static void
vips_colour_space_class_init( VipsColourSpaceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "space";
	vobject_class->description = _( "colour space transformations" );
	vobject_class->build = vips_colour_space_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsColourSpace, in ) );
}

static void
vips_colour_space_init( VipsColourSpace *space )
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

	VipsImage **t;
	VipsImage *in;
	VipsImage *extra;

	t = (VipsImage **) vips_object_local_array( object, 4 );

	in = code->in;
	extra = NULL;

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

	/* Extra band processing. don't do automatic detach/reattach if either
	 * input or output will be coded.
	 */
	if( in &&
		code->input_coding == VIPS_CODING_NONE &&
		colour->coding == VIPS_CODING_NONE &&
		code->input_bands > 0 ) { 
		if( in->Bands > code->input_bands ) { 
			if( vips_extract_band( in, &t[1], 0, 
				"n", code->input_bands, NULL ) )
				return( -1 );
			if( vips_extract_band( in, &t[2], code->input_bands, 
				"n", in->Bands - code->input_bands, 
				NULL ) )
				return( -1 );
			in = t[1];
			extra = t[2];
		}
		else if( vips_check_bands_atleast( 
			VIPS_OBJECT_CLASS( class )->nickname,
			in, code->input_bands ) )
			return( -1 );
	}

	if( in &&
		code->input_coding == VIPS_CODING_NONE &&
		code->input_format != VIPS_FORMAT_NOTSET ) {
		if( vips_cast( in, &t[3], code->input_format, NULL ) )
			return( -1 );
		in = t[3];
	}

	colour->n = 1;
	colour->in = (VipsImage **) vips_object_local_array( object, 1 );
	colour->in[0] = in;
	if( colour->in[0] )
		g_object_ref( colour->in[0] );

	if( VIPS_OBJECT_CLASS( vips_colour_space_parent_class )->
		build( object ) )
		return( -1 );

	/* Reattach higher bands, if necessary.
	 */
	if( extra ) {
		VipsImage *x;

		if( vips_bandjoin2( colour->out, extra, &x, NULL ) )
			return( -1 );

		VIPS_UNREF( colour->out );

		colour->out = x;
	}

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
	vobject_class->description = _( "change colour coding" );
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
}

G_DEFINE_ABSTRACT_TYPE( VipsColourDifference, vips_colour_difference, 
	VIPS_TYPE_COLOUR );

static int
vips_colour_difference_build( VipsObject *object )
{
	VipsColour *colour = VIPS_COLOUR( object );
	VipsColourDifference *difference = VIPS_COLOUR_DIFFERENCE( object );
	VipsColourDifferenceClass *class = 
		VIPS_COLOUR_DIFFERENCE_GET_CLASS( object ); 

	VipsImage **t;
	VipsImage *left;
	VipsImage *right;
	VipsImage *extra;

	t = (VipsImage **) vips_object_local_array( object, 10 );

	left = difference->left;
	right = difference->right;
	extra = NULL;

	/* Unpack LABQ images, 
	 */
	if( left && 
		left->Coding == VIPS_CODING_LABQ ) { 
		if( vips_LabQ2Lab( left, &t[0], NULL ) )
			return( -1 );
		left = t[0];
	}
	if( right && 
		right->Coding == VIPS_CODING_LABQ ) { 
		if( vips_LabQ2Lab( right, &t[1], NULL ) )
			return( -1 );
		right = t[1];
	}

	if( left && 
		vips_check_uncoded( VIPS_OBJECT_CLASS( class )->nickname,
			left ) )
		return( -1 );
	if( right && 
		vips_check_uncoded( VIPS_OBJECT_CLASS( class )->nickname,
			right ) )
		return( -1 );

	/* Detach and reattach extra bands, if any. If both left and right
	 * have extra bands, give up.
	 */
	if( left &&
		left->Bands > 3 &&
		right &&
		right->Bands > 3 ) {
		vips_error( VIPS_OBJECT_CLASS( class )->nickname,
			"%s", "both images have extra bands" );
		return( -1 );
	}

	if( left &&
		left->Bands > 3 ) {
		if( vips_extract_band( left, &t[2], 0, 
			"n", 3, 
			NULL ) )
			return( -1 );
		if( vips_extract_band( left, &t[3], 3, 
			"n", left->Bands - 3, 
			NULL ) )
			return( -1 );
		left = t[2];
		extra = t[3];
	}

	if( right &&
		right->Bands > 3 ) {
		if( vips_extract_band( right, &t[4], 0, 
			"n", 3, 
			NULL ) )
			return( -1 );
		if( vips_extract_band( right, &t[5], 3, 
			"n", right->Bands - 3, 
			NULL ) )
			return( -1 );
		right = t[4];
		extra = t[5];
	}

	if( vips_check_bands_atleast( VIPS_OBJECT_CLASS( class )->nickname,
		left, 3 ) )
		return( -1 );
	if( vips_check_bands_atleast( VIPS_OBJECT_CLASS( class )->nickname,
		right, 3 ) )
		return( -1 );

	if( vips_colour_convert( left, &t[6], 
		difference->interpretation, NULL ) )
		return( -1 );
	left = t[6];
	if( vips_colour_convert( right, &t[7], 
		difference->interpretation, NULL ) )
		return( -1 );
	right = t[7];

	/* We only process float.
	 */
	if( vips_cast_float( left, &t[8], NULL ) )
		return( -1 );
	left = t[8];
	if( vips_cast_float( right, &t[9], NULL ) )
		return( -1 );
	right = t[9];

	colour->n = 2;
	colour->in = (VipsImage **) vips_object_local_array( object, 2 );
	colour->in[0] = left;
	colour->in[1] = right;
	if( colour->in[0] )
		g_object_ref( colour->in[0] );
	if( colour->in[1] )
		g_object_ref( colour->in[1] );

	if( VIPS_OBJECT_CLASS( vips_colour_space_parent_class )->
		build( object ) )
		return( -1 );

	/* Reattach higher bands, if necessary.
	 */
	if( extra ) {
		VipsImage *x;

		if( vips_bandjoin2( colour->out, extra, &x, NULL ) )
			return( -1 );

		VIPS_UNREF( colour->out );

		colour->out = x;
	}

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
	vobject_class->description = _( "calculate colour difference" );
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
}


/* A colour-transforming function.
 */
typedef int (*VipsColourTransformFn)( VipsImage *in, VipsImage **out, ... );

/* Maximum number of steps we allow in a route. 10 steps should be enough 
 * for anyone. 
 */
#define MAX_STEPS (10)

/* A route between two colour spaces.
 *
 * 10 steps should be enough for anyone. 
 */
typedef struct _VipsColourRoute {
	VipsInterpretation from;
	VipsInterpretation to;
	VipsColourTransformFn route[MAX_STEPS + 1];
} VipsColourRoute;

/* Some defines to save typing. These are the colour spaces we support
 * conversions between.
 */
#define XYZ VIPS_INTERPRETATION_XYZ
#define LAB VIPS_INTERPRETATION_LAB
#define LABQ VIPS_INTERPRETATION_LABQ
#define LCH VIPS_INTERPRETATION_LCH
#define UCS VIPS_INTERPRETATION_UCS
#define LABS VIPS_INTERPRETATION_LABS
#define sRGB VIPS_INTERPRETATION_sRGB
#define YXY VIPS_INTERPRETATION_YXY

/* All the routes we know about.
 */
static VipsColourRoute vips_colour_routes[] = {
	{ XYZ, LAB, { vips_XYZ2Lab, NULL } },
	{ XYZ, LABQ, { vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ XYZ, LCH, { vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ XYZ, UCS, { vips_XYZ2Lab, vips_Lab2LCh, vips_LCh2UCS, NULL } },
	{ XYZ, LABS, { vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ XYZ, sRGB, { vips_XYZ2sRGB, NULL } },
	{ XYZ, YXY, { vips_XYZ2Yxy, NULL } },

	{ LAB, XYZ, { vips_Lab2XYZ, NULL } },
	{ LAB, LABQ, { vips_Lab2LabQ, NULL } },
	{ LAB, LCH, { vips_Lab2LCh, NULL } },
	{ LAB, UCS, { vips_Lab2LCh, vips_LCh2UCS, NULL } },
	{ LAB, LABS, { vips_Lab2LabS, NULL } },
	{ LAB, sRGB, { vips_Lab2XYZ, vips_XYZ2sRGB, NULL } },
	{ LAB, YXY, { vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ LABQ, XYZ, { vips_LabQ2Lab, vips_Lab2XYZ, NULL } },
	{ LABQ, LAB, { vips_LabQ2Lab, NULL } },
	{ LABQ, LCH, { vips_LabQ2Lab, vips_Lab2LCh, NULL } },
	{ LABQ, UCS, { vips_LabQ2Lab, vips_Lab2LCh, vips_LCh2UCS, NULL } },
	{ LABQ, LABS, { vips_LabQ2LabS, NULL } },
	{ LABQ, sRGB, { vips_LabQ2sRGB, NULL } },
	{ LABQ, YXY, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ LCH, XYZ, { vips_LCh2Lab, vips_Lab2XYZ, NULL } },
	{ LCH, LAB, { vips_LCh2Lab, NULL } },
	{ LCH, LABQ, { vips_LCh2Lab, vips_Lab2LabQ, NULL } },
	{ LCH, UCS, { vips_LCh2UCS, NULL } },
	{ LCH, LABS, { vips_LCh2Lab, vips_Lab2LabS, NULL } },
	{ LCH, sRGB, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2sRGB, NULL } },
	{ LCH, YXY, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ UCS, XYZ, { vips_UCS2LCh, vips_LCh2Lab, vips_Lab2XYZ, NULL } },
	{ UCS, LAB, { vips_UCS2LCh, vips_LCh2Lab, NULL } },
	{ UCS, LABQ, { vips_UCS2LCh, vips_LCh2Lab, vips_Lab2LabQ, NULL } },
	{ UCS, LCH, { vips_UCS2LCh, NULL } },
	{ UCS, LABS, { vips_UCS2LCh, vips_LCh2Lab, vips_Lab2LabS, NULL } },
	{ UCS, sRGB, { vips_UCS2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2sRGB, NULL } },
	{ UCS, YXY, { vips_UCS2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2Yxy, NULL } },

	{ LABS, XYZ, { vips_LabS2Lab, vips_Lab2XYZ, NULL } },
	{ LABS, LAB, { vips_LabS2Lab, NULL } },
	{ LABS, LABQ, { vips_LabS2LabQ, NULL } },
	{ LABS, LCH, { vips_LabS2Lab, vips_Lab2LCh, NULL } },
	{ LABS, UCS, { vips_LabS2Lab, vips_Lab2LCh, vips_LCh2UCS, NULL } },
	{ LABS, sRGB, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2sRGB, NULL } },
	{ LABS, YXY, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ sRGB, XYZ, { vips_sRGB2XYZ, NULL } },
	{ sRGB, LAB, { vips_sRGB2XYZ, vips_XYZ2Lab, NULL } },
	{ sRGB, LABQ, { vips_sRGB2XYZ, vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ sRGB, LCH, { vips_sRGB2XYZ, vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ sRGB, UCS, { vips_sRGB2XYZ, vips_XYZ2Lab, vips_Lab2LCh, 
		vips_LCh2UCS, NULL } },
	{ sRGB, LABS, { vips_sRGB2XYZ, vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ sRGB, YXY, { vips_sRGB2XYZ, vips_XYZ2Yxy, NULL } },

	{ YXY, XYZ, { vips_Yxy2XYZ, NULL } },
	{ YXY, LAB, { vips_Yxy2XYZ, vips_XYZ2Lab, NULL } },
	{ YXY, LABQ, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ YXY, LCH, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ YXY, UCS, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LCh, 
		vips_LCh2UCS, NULL } },
	{ YXY, LABS, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ YXY, sRGB, { vips_Yxy2XYZ, vips_XYZ2sRGB, NULL } },
};

typedef struct _VipsColourConvert {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	VipsInterpretation space;
} VipsColourConvert;

typedef VipsOperationClass VipsColourConvertClass;

G_DEFINE_TYPE( VipsColourConvert, vips_colour_convert, VIPS_TYPE_OPERATION );

static int
vips_colour_convert_build( VipsObject *object )
{
	VipsColourConvert *convert = (VipsColourConvert *) object; 

	int i, j;
	VipsImage *x;
	VipsImage **t;

	t = (VipsImage **) vips_object_local_array( object, MAX_STEPS );

	/* Verify that all input args have been set.
	 */
	if( VIPS_OBJECT_CLASS( vips_colour_convert_parent_class )->
		build( object ) )
		return( -1 );

	/* No conversion necessary.
	 */
	if( convert->in->Type == convert->space ) {
		g_object_set( convert, "out", vips_image_new(), NULL ); 

		return( vips_image_write( convert->in, convert->out ) );
	}

	x = convert->in;

	for( i = 0; i < VIPS_NUMBER( vips_colour_routes ); i++ )
		if( vips_colour_routes[i].from == x->Type &&
			vips_colour_routes[i].to == convert->space )
			break;
	if( i == VIPS_NUMBER( vips_colour_routes ) ) {
		vips_error( "vips_colour_convert", 
			_( "no known route between '%s' and '%s'" ),
			vips_enum_nick( VIPS_TYPE_INTERPRETATION, x->Type ),
			vips_enum_nick( VIPS_TYPE_INTERPRETATION, 
				convert->space ) );
		return( -1 );
	}

	for( j = 0; vips_colour_routes[i].route[j]; j++ ) {
		if( vips_colour_routes[i].route[j]( x, &t[j], NULL ) ) 
			return( -1 );
		x = t[j];
	}

	g_object_set( convert, "out", vips_image_new(), NULL ); 
	if( vips_image_write( x, convert->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_colour_convert_class_init( VipsColourConvertClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "colour_convert";
	vobject_class->description = _( "convert to a new colourspace" );
	vobject_class->build = vips_colour_convert_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsColourConvert, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsColourConvert, out ) );

	VIPS_ARG_ENUM( class, "space", 6, 
		_( "Space" ), 
		_( "Destination colour space" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsColourConvert, space ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_sRGB );
}

static void
vips_colour_convert_init( VipsColourConvert *convert )
{
}

/**
 * vips_colour_convert:
 * @in: input image
 * @out: output image
 * @space: convert to this colour space
 *
 * This convenience function looks at the interpretation field of @in and runs
 * a set of colourspace conversion functions to move it to @space. 
 *
 * For example, given an image tagged as #VIPS_INTERPRETATION_YXY, running
 * vips_colour_convert() with @space set to #VIPS_INTERPRETATION_LAB will
 * convert with vips_Yxy2XYZ() and vips_XYZ2Lab().
 */
int
vips_colour_convert( VipsImage *in, VipsImage **out, 
	VipsInterpretation space, ... )
{
	va_list ap;
	int result;

	va_start( ap, space );
	result = vips_call_split( "colour_convert", ap, in, out, space );
	va_end( ap );

	return( result );
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_colour_operation_init( void )
{
	extern GType vips_Lab2XYZ_get_type( void ); 
	extern GType vips_XYZ2Lab_get_type( void ); 
	extern GType vips_Lab2LCh_get_type( void ); 
	extern GType vips_LCh2Lab_get_type( void ); 
	extern GType vips_LCh2UCS_get_type( void ); 
	extern GType vips_UCS2LCh_get_type( void ); 
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
	extern GType vips_sRGB2XYZ_get_type( void ); 
#if defined(HAVE_LCMS) || defined(HAVE_LCMS2)
	extern GType vips_icc_import_get_type( void ); 
	extern GType vips_icc_export_get_type( void ); 
	extern GType vips_icc_transform_get_type( void ); 
#endif

	vips_colour_convert_get_type();
	vips_Lab2XYZ_get_type();
	vips_XYZ2Lab_get_type();
	vips_Lab2LCh_get_type();
	vips_LCh2Lab_get_type();
	vips_LCh2UCS_get_type();
	vips_UCS2LCh_get_type();
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
	vips_XYZ2sRGB_get_type();
	vips_sRGB2XYZ_get_type();
#if defined(HAVE_LCMS) || defined(HAVE_LCMS2)
	vips_icc_import_get_type();
	vips_icc_export_get_type();
	vips_icc_transform_get_type();
#endif
}
