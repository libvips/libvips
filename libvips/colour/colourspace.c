/* convert between colourspaces
 *
 * 6/11/12
 * 	- add RGB16 as a destination
 * 12/1/14
 * 	- add B_W as a source / dest
 * 	- add GREY16 as a source / dest
 * 	- add RGB16 as a source
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

static int
vips_scRGB2RGB16( VipsImage *in, VipsImage **out, ... )
{
	return( vips_scRGB2sRGB( in, out, "depth", 16, NULL ) );
}

static int
vips_sRGB2BW( VipsImage *in, VipsImage **out, ... )
{
	if( vips_extract_band( in, out, 1, NULL ) )
		return( -1 );
	(*out)->Type = VIPS_INTERPRETATION_B_W;

	return( 0 ); 
}

static int
vips_BW2sRGB( VipsImage *in, VipsImage **out, ... )
{
	VipsImage *t[3];

	t[0] = in;
	t[1] = in;
	t[2] = in;

	if( vips_bandjoin( t, out, 3, NULL ) )
		return( -1 );
	(*out)->Type = VIPS_INTERPRETATION_sRGB;

	return( 0 );
}

static int
vips_RGB162GREY16( VipsImage *in, VipsImage **out, ... )
{
	if( vips_extract_band( in, out, 1, NULL ) )
		return( -1 );
	(*out)->Type = VIPS_INTERPRETATION_GREY16;

	return( 0 ); 
}

static int
vips_GREY162RGB16( VipsImage *in, VipsImage **out, ... )
{
	VipsImage *t[3];

	t[0] = in;
	t[1] = in;
	t[2] = in;

	if( vips_bandjoin( t, out, 3, NULL ) )
		return( -1 );
	(*out)->Type = VIPS_INTERPRETATION_RGB16;

	return( 0 );
}

/* A colour-transforming function.
 */
typedef int (*VipsColourTransformFn)( VipsImage *in, VipsImage **out, ... );

/* Maximum number of steps we allow in a route. 10 steps should be enough 
 * for anyone. 
 */
#define MAX_STEPS (10)

/* A route between two colour spaces.
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
#define scRGB VIPS_INTERPRETATION_scRGB
#define sRGB VIPS_INTERPRETATION_sRGB
#define RGB16 VIPS_INTERPRETATION_RGB16
#define GREY16 VIPS_INTERPRETATION_GREY16
#define YXY VIPS_INTERPRETATION_YXY
#define BW VIPS_INTERPRETATION_B_W

/* All the routes we know about.
 */
static VipsColourRoute vips_colour_routes[] = {
	{ XYZ, LAB, { vips_XYZ2Lab, NULL } },
	{ XYZ, LABQ, { vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ XYZ, LCH, { vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ XYZ, CMC, { vips_XYZ2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ XYZ, LABS, { vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ XYZ, scRGB, { vips_XYZ2scRGB, NULL } },
	{ XYZ, sRGB, { vips_XYZ2scRGB, vips_scRGB2sRGB, NULL } },
	{ XYZ, BW, { vips_XYZ2scRGB, vips_scRGB2sRGB, vips_sRGB2BW, NULL } },
	{ XYZ, RGB16, { vips_XYZ2scRGB, vips_scRGB2RGB16, NULL } },
	{ XYZ, GREY16, { vips_XYZ2scRGB, vips_scRGB2RGB16, 
		vips_RGB162GREY16, NULL } },
	{ XYZ, YXY, { vips_XYZ2Yxy, NULL } },

	{ LAB, XYZ, { vips_Lab2XYZ, NULL } },
	{ LAB, LABQ, { vips_Lab2LabQ, NULL } },
	{ LAB, LCH, { vips_Lab2LCh, NULL } },
	{ LAB, CMC, { vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ LAB, LABS, { vips_Lab2LabS, NULL } },
	{ LAB, scRGB, { vips_Lab2XYZ, vips_XYZ2scRGB, NULL } },
	{ LAB, sRGB, { vips_Lab2XYZ, vips_XYZ2scRGB, vips_scRGB2sRGB, NULL } },
	{ LAB, BW, { vips_Lab2XYZ, vips_XYZ2scRGB, vips_scRGB2sRGB, 
		vips_sRGB2BW, NULL } },
	{ LAB, RGB16, { vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ LAB, GREY16, { vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, vips_RGB162GREY16, NULL } },
	{ LAB, YXY, { vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ LABQ, XYZ, { vips_LabQ2Lab, vips_Lab2XYZ, NULL } },
	{ LABQ, LAB, { vips_LabQ2Lab, NULL } },
	{ LABQ, LCH, { vips_LabQ2Lab, vips_Lab2LCh, NULL } },
	{ LABQ, CMC, { vips_LabQ2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ LABQ, LABS, { vips_LabQ2LabS, NULL } },
	{ LABQ, scRGB, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2scRGB } },
	{ LABQ, sRGB, { vips_LabQ2sRGB, NULL } },
	{ LABQ, BW, { vips_LabQ2sRGB, vips_sRGB2BW, NULL } },
	{ LABQ, RGB16, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ LABQ, GREY16, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, vips_RGB162GREY16, NULL } },
	{ LABQ, YXY, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ LCH, XYZ, { vips_LCh2Lab, vips_Lab2XYZ, NULL } },
	{ LCH, LAB, { vips_LCh2Lab, NULL } },
	{ LCH, LABQ, { vips_LCh2Lab, vips_Lab2LabQ, NULL } },
	{ LCH, CMC, { vips_LCh2CMC, NULL } },
	{ LCH, LABS, { vips_LCh2Lab, vips_Lab2LabS, NULL } },
	{ LCH, scRGB, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, NULL } },
	{ LCH, sRGB, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2sRGB, NULL } },
	{ LCH, BW, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2sRGB, vips_sRGB2BW, NULL } },
	{ LCH, RGB16, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ LCH, GREY16, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, vips_RGB162GREY16, NULL } },
	{ LCH, YXY, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ CMC, XYZ, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, NULL } },
	{ CMC, LAB, { vips_CMC2LCh, vips_LCh2Lab, NULL } },
	{ CMC, LABQ, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2LabQ, NULL } },
	{ CMC, LCH, { vips_CMC2LCh, NULL } },
	{ CMC, LABS, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2LabS, NULL } },
	{ CMC, scRGB, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2scRGB, NULL } },
	{ CMC, sRGB, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2scRGB, vips_scRGB2sRGB, NULL } },
	{ CMC, BW, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2scRGB, vips_scRGB2sRGB, vips_sRGB2BW, NULL } },
	{ CMC, RGB16, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2scRGB, vips_scRGB2RGB16, NULL } },
	{ CMC, GREY16, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2scRGB, vips_scRGB2RGB16, vips_RGB162GREY16, NULL } },
	{ CMC, YXY, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2Yxy, NULL } },

	{ LABS, XYZ, { vips_LabS2Lab, vips_Lab2XYZ, NULL } },
	{ LABS, LAB, { vips_LabS2Lab, NULL } },
	{ LABS, LABQ, { vips_LabS2LabQ, NULL } },
	{ LABS, LCH, { vips_LabS2Lab, vips_Lab2LCh, NULL } },
	{ LABS, CMC, { vips_LabS2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ LABS, scRGB, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, NULL } },
	{ LABS, sRGB, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2sRGB, NULL } },
	{ LABS, BW, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2sRGB, vips_sRGB2BW, NULL } },
	{ LABS, RGB16, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ LABS, GREY16, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, vips_RGB162GREY16, NULL } },
	{ LABS, YXY, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ scRGB, XYZ, { vips_scRGB2XYZ, NULL } },
	{ scRGB, LAB, { vips_scRGB2XYZ, vips_XYZ2Lab, NULL } },
	{ scRGB, LABQ, { vips_scRGB2XYZ, vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ scRGB, LCH, { vips_scRGB2XYZ, vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ scRGB, CMC, { vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ scRGB, sRGB, { vips_scRGB2sRGB, NULL } },
	{ scRGB, BW, { vips_scRGB2sRGB, vips_sRGB2BW, NULL } },
	{ scRGB, LABS, { vips_scRGB2XYZ, vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ scRGB, RGB16, { vips_scRGB2RGB16, NULL } },
	{ scRGB, GREY16, { vips_scRGB2RGB16, vips_RGB162GREY16, NULL } },
	{ scRGB, YXY, { vips_scRGB2XYZ, vips_XYZ2Yxy, NULL } },

	{ sRGB, XYZ, { vips_sRGB2scRGB, vips_scRGB2XYZ, NULL } },
	{ sRGB, LAB, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, NULL } },
	{ sRGB, LABQ, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LabQ, NULL } },
	{ sRGB, LCH, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LCh, NULL } },
	{ sRGB, CMC, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ sRGB, scRGB, { vips_sRGB2scRGB, NULL } },
	{ sRGB, BW, { vips_sRGB2BW, NULL } },
	{ sRGB, LABS, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LabS, NULL } },
	{ sRGB, RGB16, { vips_sRGB2scRGB, vips_scRGB2RGB16, NULL } },
	{ sRGB, GREY16, { vips_sRGB2scRGB, vips_scRGB2RGB16, 
		vips_RGB162GREY16, NULL } },
	{ sRGB, YXY, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Yxy, NULL } },

	{ RGB16, XYZ, { vips_sRGB2scRGB, vips_scRGB2XYZ, NULL } },
	{ RGB16, LAB, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, NULL } },
	{ RGB16, LABQ, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LabQ, NULL } },
	{ RGB16, LCH, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LCh, NULL } },
	{ RGB16, CMC, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ RGB16, scRGB, { vips_sRGB2scRGB, NULL } },
	{ RGB16, sRGB, { vips_sRGB2scRGB, vips_scRGB2sRGB, NULL } },
	{ RGB16, BW, { vips_sRGB2scRGB, vips_scRGB2sRGB, vips_sRGB2BW, NULL } },
	{ RGB16, LABS, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LabS, NULL } },
	{ RGB16, GREY16, { vips_RGB162GREY16, NULL } },
	{ RGB16, YXY, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Yxy, NULL } },

	{ GREY16, XYZ, { vips_GREY162RGB16, vips_sRGB2scRGB, 
		vips_scRGB2XYZ, NULL } },
	{ GREY16, LAB, { vips_GREY162RGB16, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, NULL } },
	{ GREY16, LABQ, { vips_GREY162RGB16, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ GREY16, LCH, { vips_GREY162RGB16, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ GREY16, CMC, { vips_GREY162RGB16, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ GREY16, scRGB, { vips_GREY162RGB16, vips_sRGB2scRGB, NULL } },
	{ GREY16, sRGB, { vips_GREY162RGB16, vips_sRGB2scRGB, 
		vips_scRGB2sRGB, NULL } },
	{ GREY16, BW, { vips_GREY162RGB16, vips_sRGB2scRGB, vips_scRGB2sRGB, 
		vips_sRGB2BW, NULL } },
	{ GREY16, LABS, { vips_GREY162RGB16, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ GREY16, RGB16, { vips_GREY162RGB16, NULL } },
	{ GREY16, YXY, { vips_GREY162RGB16, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Yxy, NULL } },

	{ BW, XYZ, { vips_BW2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, NULL } },
	{ BW, LAB, { vips_BW2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, NULL } },
	{ BW, LABQ, { vips_BW2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ BW, LCH, { vips_BW2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ BW, CMC, { vips_BW2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ BW, scRGB, { vips_BW2sRGB, vips_sRGB2scRGB, NULL } },
	{ BW, sRGB, { vips_BW2sRGB, NULL } },
	{ BW, LABS, { vips_BW2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ BW, RGB16, { vips_BW2sRGB, vips_sRGB2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ BW, GREY16, { vips_BW2sRGB, vips_sRGB2scRGB, 
		vips_scRGB2RGB16, vips_RGB162GREY16, NULL } },
	{ BW, YXY, { vips_BW2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Yxy, NULL } },

	{ YXY, XYZ, { vips_Yxy2XYZ, NULL } },
	{ YXY, LAB, { vips_Yxy2XYZ, vips_XYZ2Lab, NULL } },
	{ YXY, LABQ, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ YXY, LCH, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ YXY, CMC, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LCh, 
		vips_LCh2CMC, NULL } },
	{ YXY, LABS, { vips_Yxy2XYZ, vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ YXY, scRGB, { vips_Yxy2XYZ, vips_XYZ2scRGB, NULL } },
	{ YXY, sRGB, { vips_Yxy2XYZ, vips_XYZ2scRGB, vips_scRGB2sRGB, NULL } },
	{ YXY, BW, { vips_Yxy2XYZ, vips_XYZ2scRGB, vips_scRGB2sRGB, 
		vips_sRGB2BW, NULL } },
	{ YXY, RGB16, { vips_Yxy2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ YXY, GREY16, { vips_Yxy2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, vips_RGB162GREY16, NULL } }
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
	VipsInterpretation interpretation;
	int i;

	/* Treat RGB and RGB16 as sRGB. If you want some other treatment,
	 * you'll need to use the icc funcs.
	 *
	 * sRGB2XYZ can handle 8 and 16-bit images. 
	 */
	interpretation = vips_image_guess_interpretation( image );
	if( interpretation == VIPS_INTERPRETATION_RGB || 
		interpretation == VIPS_INTERPRETATION_RGB16 )
		interpretation = VIPS_INTERPRETATION_sRGB;

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

	/* Treat RGB and RGB16 as sRGB. If you want some other treatment,
	 * you'll need to use the icc funcs.
	 *
	 * sRGB2XYZ can handle 8 and 16-bit images. 
	 */
	if( interpretation == VIPS_INTERPRETATION_RGB || 
		interpretation == VIPS_INTERPRETATION_RGB16 )
		interpretation = VIPS_INTERPRETATION_sRGB;

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
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "colourspace";
	vobject_class->description = _( "convert to a new colourspace" );
	vobject_class->build = vips_colourspace_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

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
