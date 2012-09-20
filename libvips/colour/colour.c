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
vips_colour_build( VipsObject *object )
{
	VipsColour *colour = VIPS_COLOUR( object );
	VipsColourClass *class = VIPS_COLOUR_GET_CLASS( colour ); 

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
		vips_error( "VipsColour",
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
	colour->out->Coding = class->coding;
	colour->out->Type = class->interpretation;
	colour->out->BandFmt = class->format;
	colour->out->Bands = class->bands;

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

	class->coding = VIPS_CODING_NONE;
	class->interpretation = VIPS_INTERPRETATION_sRGB;
	class->format = VIPS_FORMAT_UCHAR;
	class->bands = 3;

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsColour, out ) );
}

static void
vips_colour_init( VipsColour *colour )
{
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
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "space";
	vobject_class->description = _( "colour space transformations" );
	vobject_class->build = vips_colour_space_build;

	colour_class->coding = VIPS_CODING_NONE;
	colour_class->interpretation = VIPS_INTERPRETATION_sRGB;
	colour_class->format = VIPS_FORMAT_FLOAT;
	colour_class->bands = 3;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsColourSpace, in ) );
}

static void
vips_colour_space_init( VipsColourSpace *space )
{
}

G_DEFINE_ABSTRACT_TYPE( VipsColourCode, vips_colour_code, VIPS_TYPE_COLOUR );

static int
vips_colour_code_build( VipsObject *object )
{
	VipsColour *colour = VIPS_COLOUR( object );
	VipsColourCode *code = VIPS_COLOUR_CODE( object );
	VipsColourCodeClass *class = VIPS_COLOUR_CODE_GET_CLASS( object ); 
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class ); 

	VipsImage **t;
	VipsImage *in;
	VipsImage *extra;

	t = (VipsImage **) vips_object_local_array( object, 4 );

	in = code->in;
	extra = NULL;

	if( in && 
		vips_check_coding( VIPS_OBJECT_CLASS( class )->nickname,
			in, class->input_coding ) )
		return( -1 );

	/* Extra band processing. don't do automatic detach/reattach if either
	 * input or output will be coded.
	 */
	if( in &&
		class->input_coding == VIPS_CODING_NONE &&
		colour_class->coding == VIPS_CODING_NONE &&
		class->input_bands > 0 ) { 
		if( in->Bands > class->input_bands ) { 
			if( vips_extract_band( in, &t[1], 0, 
				"n", class->input_bands, NULL ) )
				return( -1 );
			if( vips_extract_band( in, &t[2], class->input_bands, 
				"n", in->Bands - class->input_bands, 
				NULL ) )
				return( -1 );
			in = t[1];
			extra = t[2];
		}
		else if( vips_check_bands_atleast( 
			VIPS_OBJECT_CLASS( class )->nickname,
			in, class->input_bands ) )
			return( -1 );
	}

	if( in &&
		class->input_coding == VIPS_CODING_NONE &&
		class->input_format != VIPS_FORMAT_NOTSET ) {
		if( vips_cast( in, &t[3], class->input_format, NULL ) )
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

	class->input_coding = VIPS_CODING_ERROR;

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
	extern GType vips_LabS2Lab_get_type( void ); 
	extern GType vips_Lab2LabS_get_type( void ); 
	extern GType vips_rad2float_get_type( void ); 
	extern GType vips_float2rad_get_type( void ); 

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
	vips_LabS2Lab_get_type();
	vips_Lab2LabS_get_type();
	vips_rad2float_get_type();
	vips_float2rad_get_type();
}
