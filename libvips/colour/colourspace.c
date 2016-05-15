/* convert between colourspaces
 *
 * 6/11/12
 * 	- add RGB16 as a destination
 * 12/1/14
 * 	- add B_W as a source / dest
 * 	- add GREY16 as a source / dest
 * 	- add RGB16 as a source
 * 19/1/14
 * 	- auto-decode RAD images
 * 3/2/14
 * 	- add "source_space", overrides source space guess
 * 8/5/14
 * 	- oops, don't treat RGB16 as sRGB
 * 9/9/14	
 * 	- mono <-> rgb converters were not handling extra bands, thanks James
 * 4/2/15
 * 	- much faster RGB16->sRGB path
 * 17/4/15
 * 	- better conversion to greyscale, see 
 * 	  https://github.com/lovell/sharp/issues/193
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

/* A colour-transforming function.
 */
typedef int (*VipsColourTransformFn)( VipsImage *in, VipsImage **out, ... );

static int
vips_scRGB2RGB16( VipsImage *in, VipsImage **out, ... )
{
	return( vips_scRGB2sRGB( in, out, "depth", 16, NULL ) );
}

static int
vips_scRGB2BW16( VipsImage *in, VipsImage **out, ... )
{
	return( vips_scRGB2BW16( in, out, "depth", 16, NULL ) );
}

/* Do these two with a simple cast ... since we're just cast shifting, we can
 * short-circuit the extra band processing.
 */

static int
vips_RGB162sRGB( VipsImage *in, VipsImage **out, ... )
{
	if( vips_cast( in, out, VIPS_FORMAT_UCHAR,
		"shift", TRUE,
		NULL ) )
		return( -1 );
	(*out)->Type = VIPS_INTERPRETATION_sRGB;

	return( 0 ); 
}

static int
vips_sRGB2RGB16( VipsImage *in, VipsImage **out, ... )
{
	if( vips_cast( in, out, VIPS_FORMAT_USHORT,
		"shift", TRUE,
		NULL ) )
		return( -1 );
	(*out)->Type = VIPS_INTERPRETATION_RGB16;

	return( 0 ); 
}

/* Process the first @n bands with @fn, detach and reattach remaining bands.
 */
static int
vips_process_n( const char *domain, VipsImage *in, VipsImage **out, 
	int n, VipsColourTransformFn fn )
{
	if( in->Bands > n ) {
		VipsImage *scope = vips_image_new();
		VipsImage **t = (VipsImage **) 
			vips_object_local_array( VIPS_OBJECT( scope ), 4 );

		if( vips_extract_band( in, &t[0], 0,
			"n", n, 
			NULL ) ||
			vips_extract_band( in, &t[1], n,
				"n", in->Bands - n, 
				NULL ) ||
			fn( t[0], &t[2], NULL ) ||
			vips_cast( t[1], &t[3], t[2]->BandFmt, 
				NULL ) ||
			vips_bandjoin2( t[2], t[3], out, NULL ) ) {
			g_object_unref( scope );
			return( -1 );
		}

		g_object_unref( scope );
	}
	else if( in->Bands == n ) {
		if( fn( in, out, NULL ) )
			return( -1 );
	}
	else {
		vips_error( domain, "%s", _( "too few bands for operation" ) ); 
		return( -1 );
	}

	return( 0 );
}

static int
vips_BW2sRGB_op( VipsImage *in, VipsImage **out, ... )
{
	VipsImage *t[3];

	t[0] = in;
	t[1] = in;
	t[2] = in;
	if( vips_bandjoin( t, out, 3, NULL ) )
		return( -1 );

	return( 0 );
}

static int
vips_BW2sRGB( VipsImage *in, VipsImage **out, ... )
{
	if( vips_process_n( "BW2sRGB", in, out, 1, vips_BW2sRGB_op ) )
		return( -1 );
	(*out)->Type = VIPS_INTERPRETATION_sRGB;

	return( 0 );
}

static int
vips_GREY162RGB16( VipsImage *in, VipsImage **out, ... )
{
	if( vips_process_n( "GREY162RGB16", in, out, 1, vips_BW2sRGB_op ) )
		return( -1 );
	(*out)->Type = VIPS_INTERPRETATION_RGB16;

	return( 0 );
}

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
#define HSV VIPS_INTERPRETATION_HSV
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
	{ XYZ, HSV, { vips_XYZ2scRGB, vips_scRGB2sRGB, vips_sRGB2HSV, NULL } },
	{ XYZ, BW, { vips_XYZ2scRGB, vips_scRGB2BW, NULL } },
	{ XYZ, RGB16, { vips_XYZ2scRGB, vips_scRGB2RGB16, NULL } },
	{ XYZ, GREY16, { vips_XYZ2scRGB, vips_scRGB2BW16, NULL } },
	{ XYZ, YXY, { vips_XYZ2Yxy, NULL } },

	{ LAB, XYZ, { vips_Lab2XYZ, NULL } },
	{ LAB, LABQ, { vips_Lab2LabQ, NULL } },
	{ LAB, LCH, { vips_Lab2LCh, NULL } },
	{ LAB, CMC, { vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ LAB, LABS, { vips_Lab2LabS, NULL } },
	{ LAB, scRGB, { vips_Lab2XYZ, vips_XYZ2scRGB, NULL } },
	{ LAB, sRGB, { vips_Lab2XYZ, vips_XYZ2scRGB, vips_scRGB2sRGB, NULL } },
	{ LAB, HSV, { vips_Lab2XYZ, vips_XYZ2scRGB, vips_scRGB2sRGB, vips_sRGB2HSV, NULL } },
	{ LAB, BW, { vips_Lab2XYZ, vips_XYZ2scRGB, vips_scRGB2BW, NULL } },
	{ LAB, RGB16, { vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ LAB, GREY16, { vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2BW16, NULL } },
	{ LAB, YXY, { vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ LABQ, XYZ, { vips_LabQ2Lab, vips_Lab2XYZ, NULL } },
	{ LABQ, LAB, { vips_LabQ2Lab, NULL } },
	{ LABQ, LCH, { vips_LabQ2Lab, vips_Lab2LCh, NULL } },
	{ LABQ, CMC, { vips_LabQ2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ LABQ, LABS, { vips_LabQ2LabS, NULL } },
	{ LABQ, scRGB, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2scRGB } },
	{ LABQ, sRGB, { vips_LabQ2sRGB, NULL } },
	{ LABQ, HSV, { vips_LabQ2sRGB, vips_sRGB2HSV, NULL } },
	{ LABQ, BW, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2BW, NULL } },
	{ LABQ, RGB16, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ LABQ, GREY16, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2BW16, NULL } },
	{ LABQ, YXY, { vips_LabQ2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ LCH, XYZ, { vips_LCh2Lab, vips_Lab2XYZ, NULL } },
	{ LCH, LAB, { vips_LCh2Lab, NULL } },
	{ LCH, LABQ, { vips_LCh2Lab, vips_Lab2LabQ, NULL } },
	{ LCH, CMC, { vips_LCh2CMC, NULL } },
	{ LCH, LABS, { vips_LCh2Lab, vips_Lab2LabS, NULL } },
	{ LCH, scRGB, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, NULL } },
	{ LCH, sRGB, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2sRGB, NULL } },
	{ LCH, HSV, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2sRGB, vips_sRGB2HSV, NULL } },
	{ LCH, BW, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2BW, NULL } },
	{ LCH, RGB16, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ LCH, GREY16, { vips_LCh2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2BW16, NULL } },
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
	{ CMC, HSV, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2scRGB, vips_scRGB2sRGB, vips_sRGB2HSV, NULL } },
	{ CMC, BW, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2scRGB, vips_scRGB2BW, NULL } },
	{ CMC, RGB16, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2scRGB, vips_scRGB2RGB16, NULL } },
	{ CMC, GREY16, { vips_CMC2LCh, vips_LCh2Lab, vips_Lab2XYZ, 
		vips_XYZ2scRGB, vips_scRGB2BW16, NULL } },
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
	{ LABS, HSV, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2sRGB, vips_sRGB2HSV, NULL } },
	{ LABS, BW, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2BW, NULL } },
	{ LABS, RGB16, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ LABS, GREY16, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2BW16, NULL } },
	{ LABS, YXY, { vips_LabS2Lab, vips_Lab2XYZ, vips_XYZ2Yxy, NULL } },

	{ scRGB, XYZ, { vips_scRGB2XYZ, NULL } },
	{ scRGB, LAB, { vips_scRGB2XYZ, vips_XYZ2Lab, NULL } },
	{ scRGB, LABQ, { vips_scRGB2XYZ, vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ scRGB, LCH, { vips_scRGB2XYZ, vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ scRGB, CMC, { vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ scRGB, sRGB, { vips_scRGB2sRGB, NULL } },
	{ scRGB, HSV, { vips_scRGB2sRGB, vips_sRGB2HSV, NULL } },
	{ scRGB, BW, { vips_scRGB2BW, NULL } },
	{ scRGB, LABS, { vips_scRGB2XYZ, vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ scRGB, RGB16, { vips_scRGB2RGB16, NULL } },
	{ scRGB, GREY16, { vips_scRGB2BW16, NULL } },
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
	{ sRGB, HSV, { vips_sRGB2HSV, NULL } },
	{ sRGB, BW, { vips_sRGB2scRGB, vips_scRGB2BW, NULL } },
	{ sRGB, LABS, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LabS, NULL } },
	{ sRGB, RGB16, { vips_sRGB2RGB16, NULL } },
	{ sRGB, GREY16, { vips_sRGB2scRGB, vips_scRGB2BW16, NULL } },
	{ sRGB, YXY, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Yxy, NULL } },

	{ HSV, XYZ, { vips_HSV2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, NULL } },
	{ HSV, LAB, { vips_HSV2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, NULL } },
	{ HSV, LABQ, { vips_HSV2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LabQ, NULL } },
	{ HSV, LCH, { vips_HSV2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LCh, NULL } },
	{ HSV, CMC, { vips_HSV2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ HSV, scRGB, { vips_HSV2sRGB, vips_sRGB2scRGB, NULL } },
	{ HSV, sRGB, { vips_HSV2sRGB, NULL } },
	{ HSV, BW, { vips_HSV2sRGB, vips_sRGB2scRGB, vips_scRGB2BW, NULL } },
	{ HSV, LABS, { vips_HSV2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ HSV, RGB16, { vips_HSV2sRGB, vips_sRGB2RGB16, NULL } },
	{ HSV, GREY16, { vips_HSV2sRGB, vips_sRGB2scRGB, 
		vips_scRGB2BW16, NULL } },
	{ HSV, YXY, { vips_HSV2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Yxy, NULL } },

	{ RGB16, XYZ, { vips_sRGB2scRGB, vips_scRGB2XYZ, NULL } },
	{ RGB16, LAB, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, NULL } },
	{ RGB16, LABQ, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LabQ, NULL } },
	{ RGB16, LCH, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LCh, NULL } },
	{ RGB16, CMC, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LCh, vips_LCh2CMC, NULL } },
	{ RGB16, scRGB, { vips_sRGB2scRGB, NULL } },
	{ RGB16, sRGB, { vips_RGB162sRGB, NULL } },
	{ RGB16, HSV, { vips_RGB162sRGB, vips_sRGB2HSV, NULL } },
	{ RGB16, BW, { vips_sRGB2scRGB, vips_scRGB2BW, NULL } },
	{ RGB16, LABS, { vips_sRGB2scRGB, vips_scRGB2XYZ, vips_XYZ2Lab, 
		vips_Lab2LabS, NULL } },
	{ RGB16, GREY16, { vips_sRGB2scRGB, vips_scRGB2BW16, NULL } },
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
	{ GREY16, sRGB, { vips_GREY162RGB16, vips_RGB162sRGB, NULL } },
	{ GREY16, HSV, { vips_GREY162RGB16, vips_RGB162sRGB, vips_sRGB2HSV, NULL } },
	{ GREY16, BW, { vips_GREY162RGB16, vips_sRGB2scRGB, 
		vips_scRGB2BW, NULL } },
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
	{ BW, HSV, { vips_BW2sRGB, vips_sRGB2HSV, NULL } },
	{ BW, LABS, { vips_BW2sRGB, vips_sRGB2scRGB, vips_scRGB2XYZ, 
		vips_XYZ2Lab, vips_Lab2LabS, NULL } },
	{ BW, RGB16, { vips_BW2sRGB, vips_sRGB2RGB16, NULL } },
	{ BW, GREY16, { vips_BW2sRGB, vips_sRGB2scRGB, 
		vips_scRGB2BW16, NULL } },
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
	{ YXY, HSV, { vips_Yxy2XYZ, vips_XYZ2scRGB, vips_scRGB2sRGB, vips_sRGB2HSV, NULL } },
	{ YXY, BW, { vips_Yxy2XYZ, vips_XYZ2scRGB, vips_scRGB2BW, NULL } },
	{ YXY, RGB16, { vips_Yxy2XYZ, vips_XYZ2scRGB, 
		vips_scRGB2RGB16, NULL } },
	{ YXY, GREY16, { vips_Yxy2XYZ, vips_XYZ2scRGB, vips_scRGB2BW16, NULL } }

};

/* Is an image in a supported colourspace.
 */

/**
 * vips_colourspace_issupported:
 * @image: input image
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

	/* Treat RGB as sRGB. If you want some other treatment,
	 * you'll need to use the icc funcs.
	 */
	interpretation = vips_image_guess_interpretation( image );
	if( interpretation == VIPS_INTERPRETATION_RGB )
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
	VipsInterpretation source_space;
} VipsColourspace;

typedef VipsOperationClass VipsColourspaceClass;

G_DEFINE_TYPE( VipsColourspace, vips_colourspace, VIPS_TYPE_OPERATION );

static int
vips_colourspace_build( VipsObject *object )
{
	VipsColourspace *colourspace = (VipsColourspace *) object; 

	int i, j;
	VipsImage *x;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( object, 1 );
	VipsImage **pipe = (VipsImage **) 
		vips_object_local_array( object, MAX_STEPS );

	VipsInterpretation interpretation;

	/* Verify that all input args have been set.
	 */
	if( VIPS_OBJECT_CLASS( vips_colourspace_parent_class )->
		build( object ) )
		return( -1 );

	x = colourspace->in;

	/* Unpack radiance-coded images. We can't use interpretation for this,
	 * since rad images can be scRGB or XYZ.
	 */
	if( x->Coding == VIPS_CODING_RAD ) {
		if( vips_rad2float( x, &t[0], NULL ) )
			return( -1 );
		x = t[0]; 
	}

	if( vips_object_argument_isset( object, "source_space" ) )
		interpretation = colourspace->source_space;
	else
		interpretation = vips_image_guess_interpretation( x );

	/* Treat RGB as sRGB. If you want some other treatment,
	 * you'll need to use the icc funcs.
	 */
	if( interpretation == VIPS_INTERPRETATION_RGB )
		interpretation = VIPS_INTERPRETATION_sRGB;

	/* No conversion necessary.
	 */
	if( interpretation == colourspace->space ) {
		g_object_set( colourspace, "out", vips_image_new(), NULL ); 

		return( vips_image_write( colourspace->in, colourspace->out ) );
	}

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
		if( vips_colour_routes[i].route[j]( x, &pipe[j], NULL ) ) 
			return( -1 );
		x = pipe[j];
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
	vobject_class->description = _( "convert to a new colorspace" );
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
		_( "Destination color space" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsColourspace, space ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_sRGB );

	VIPS_ARG_ENUM( class, "source-space", 6, 
		_( "Source space" ), 
		_( "Source color space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsColourspace, source_space ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_sRGB );

}

static void
vips_colourspace_init( VipsColourspace *colourspace )
{
	colourspace->source_space = VIPS_INTERPRETATION_sRGB;
}

/**
 * vips_colourspace:
 * @in: input image
 * @out: output image
 * @space: convert to this colour space
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @source_space: input colour space
 *
 * This operation looks at the interpretation field of @in (or uses
 * @source_space, if set) and runs
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
