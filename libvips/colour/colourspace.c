/* convert between colourspaces
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
#include <vips/internal.h>

#include "colour.h"

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
#define CMC VIPS_INTERPRETATION_CMC
#define LABS VIPS_INTERPRETATION_LABS
#define sRGB VIPS_INTERPRETATION_sRGB
#define YXY VIPS_INTERPRETATION_YXY

/* All the routes we know about.
 */
static VipsColourRoute vips_colour_routes[] = {
	{ XYZ, LAB, { vips_XYZ2Lab, NULL } },
	{ XYZ, LABQ, { vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ XYZ, LCH, { vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ XYZ, CMC, { vips_XYZ2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ XYZ, LABS, { vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ XYZ, sRGB, { vips_XYZ2sRGB, NULL } },
	{ XYZ, YXY, { vips_XYZ2Yxy, NULL } },

	{ LAB, XYZ, { vips_Lab2XYZ, NULL } },
	{ LAB, LABQ, { vips_Lab2LabQ, NULL } },
	{ LAB, LCH, { vips_Lab2LCh, NULL } },
	{ LAB, CMC, { vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ LAB, LABS, { vips_Lab2LabS, NULL } },
	{ LAB, sRGB, { vips_Lab2XYZ, vips_XYZ2sRGB, NULL } },
	{ LAB, YXY, { vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ LABQ, XYZ, { vips_LabQ2Lab, vips_Lab2XYZ, NULL } },
	{ LABQ, LAB, { vips_LabQ2Lab, NULL } },
	{ LABQ, LCH, { vips_LabQ2Lab, vips_Lab2LCh, NULL } },
	{ LABQ, CMC, { vips_LabQ2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ LABQ, LABS, { vips_LabQ2LabS, NULL } },
	{ LABQ, sRGB, { vips_LabQ2sRGB, NULL } },
	{ LABQ, YXY, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ LCH, XYZ, { vips_LCh2Lab, vips_Lab2XYZ, NULL } },
	{ LCH, LAB, { vips_LCh2Lab, NULL } },
	{ LCH, LABQ, { vips_LCh2Lab, vips_Lab2LabQ, NULL } },
	{ LCH, CMC, { vips_LCh2CMC, NULL } },
	{ LCH, LABS, { vips_LCh2Lab, vips_Lab2LabS, NULL } },
	{ LCH, sRGB, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2sRGB, NULL } },
	{ LCH, YXY, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ CMC, XYZ, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, NULL } },
	{ CMC, LAB, { vips_CMC2LCh, vips_LCh2Lab, NULL } },
	{ CMC, LABQ, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2LabQ, NULL } },
	{ CMC, LCH, { vips_CMC2LCh, NULL } },
	{ CMC, LABS, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2LabS, NULL } },
	{ CMC, sRGB, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2sRGB, NULL } },
	{ CMC, YXY, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2Yxy, NULL } },

	{ LABS, XYZ, { vips_LabS2Lab, vips_Lab2XYZ, NULL } },
	{ LABS, LAB, { vips_LabS2Lab, NULL } },
	{ LABS, LABQ, { vips_LabS2LabQ, NULL } },
	{ LABS, LCH, { vips_LabS2Lab, vips_Lab2LCh, NULL } },
	{ LABS, CMC, { vips_LabS2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ LABS, sRGB, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2sRGB, NULL } },
	{ LABS, YXY, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ sRGB, XYZ, { vips_sRGB2XYZ, NULL } },
	{ sRGB, LAB, { vips_sRGB2XYZ, vips_XYZ2Lab, NULL } },
	{ sRGB, LABQ, { vips_sRGB2XYZ, vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ sRGB, LCH, { vips_sRGB2XYZ, vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ sRGB, CMC, { vips_sRGB2XYZ, vips_XYZ2Lab, vips_Lab2LCh, 
		vips_LCh2CMC, NULL } },
	{ sRGB, LABS, { vips_sRGB2XYZ, vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ sRGB, YXY, { vips_sRGB2XYZ, vips_XYZ2Yxy, NULL } },

	{ YXY, XYZ, { vips_Yxy2XYZ, NULL } },
	{ YXY, LAB, { vips_Yxy2XYZ, vips_XYZ2Lab, NULL } },
	{ YXY, LABQ, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ YXY, LCH, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ YXY, CMC, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LCh, 
		vips_LCh2CMC, NULL } },
	{ YXY, LABS, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ YXY, sRGB, { vips_Yxy2XYZ, vips_XYZ2sRGB, NULL } },
};

/* Is an image in a supported colourspace.
 */

/**
 * vips_colourspace_issupported:
 * @in: input image
 *
 * Test if @image is in a colourspace that vips_colourspace() can process. For
 * example, #VIPS_INTERPRETATION_RGB images are not in a well-defined 
 * colourspace, but #VIPS_INTERPRETATION_sRGB ones are.
 *
 * Returns: %TRUE if @image is in a supported colourspace.
 */
gboolean
vips_colourspace_issupported( const VipsImage *image )
{
	VipsInterpretation interpretation = 
		vips_image_guess_interpretation( image );
	int i;

	for( i = 0; i < VIPS_NUMBER( vips_colour_routes ); i++ )
		if( vips_colour_routes[i].from == interpretation )
			return( TRUE );

	return( FALSE );
}


typedef struct _VipsColourspace {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	VipsInterpretation space;
} VipsColourspace;

typedef VipsOperationClass VipsColourspaceClass;

G_DEFINE_TYPE( VipsColourspace, vips_colourspace, VIPS_TYPE_OPERATION );

static int
vips_colourspace_build( VipsObject *object )
{
	VipsColourspace *colourspace = (VipsColourspace *) object; 

	int i, j;
	VipsImage *x;
	VipsImage **t;

	VipsInterpretation interpretation;

	t = (VipsImage **) vips_object_local_array( object, MAX_STEPS );

	/* Verify that all input args have been set.
	 */
	if( VIPS_OBJECT_CLASS( vips_colourspace_parent_class )->
		build( object ) )
		return( -1 );

	interpretation = vips_image_guess_interpretation( colourspace->in );

	/* No conversion necessary.
	 */
	if( interpretation == colourspace->space ) {
		g_object_set( colourspace, "out", vips_image_new(), NULL ); 

		return( vips_image_write( colourspace->in, colourspace->out ) );
	}

	x = colourspace->in;

	for( i = 0; i < VIPS_NUMBER( vips_colour_routes ); i++ )
		if( vips_colour_routes[i].from == interpretation &&
			vips_colour_routes[i].to == colourspace->space )
			break;
	if( i == VIPS_NUMBER( vips_colour_routes ) ) {
		vips_error( "vips_colourspace", 
			_( "no known route between '%s' and '%s'" ),
			vips_enum_nick( VIPS_TYPE_INTERPRETATION, 
				interpretation ),
			vips_enum_nick( VIPS_TYPE_INTERPRETATION, 
				colourspace->space ) );
		return( -1 );
	}

	for( j = 0; vips_colour_routes[i].route[j]; j++ ) {
		if( vips_colour_routes[i].route[j]( x, &t[j], NULL ) ) 
			return( -1 );
		x = t[j];
	}

	g_object_set( colourspace, "out", vips_image_new(), NULL ); 
	if( vips_image_write( x, colourspace->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_colourspace_class_init( VipsColourspaceClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "colourspace";
	vobject_class->description = _( "convert to a new colourspace" );
	vobject_class->build = vips_colourspace_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsColourspace, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsColourspace, out ) );

	VIPS_ARG_ENUM( class, "space", 6, 
		_( "Space" ), 
		_( "Destination colour space" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsColourspace, space ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_sRGB );
}

static void
vips_colourspace_init( VipsColourspace *colourspace )
{
}

/**
 * vips_colourspace:
 * @in: input image
 * @out: output image
 * @space: convert to this colour space
 *
 * This operation looks at the interpretation field of @in and runs
 * a set of colourspace conversion functions to move it to @space. 
 *
 * For example, given an image tagged as #VIPS_INTERPRETATION_YXY, running
 * vips_colourspace() with @space set to #VIPS_INTERPRETATION_LAB will
 * convert with vips_Yxy2XYZ() and vips_XYZ2Lab().
 *
 * See also: vips_colourspace_issupported(),
 * vips_image_guess_interpretation().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_colourspace( VipsImage *in, VipsImage **out, 
	VipsInterpretation space, ... )
{
	va_list ap;
	int result;

	va_start( ap, space );
	result = vips_call_split( "colourspace", ap, in, out, space );
	va_end( ap );

	return( result );
}
