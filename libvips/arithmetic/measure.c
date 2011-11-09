/* im_measure.c
 *
 * Modified: 
 * 19/8/94 JC
 *	- now uses doubles for addressing
 *	- could miss by up to h pixels previously!
 *	- ANSIfied
 *	- now issues warning if any deviations are greater than 20% of the
 *	  mean
 * 31/10/95 JC
 *	- more careful about warning for averages <0, or averages near zero
 *	- can get these cases with im_measure() of IM_TYPE_LAB images
 * 28/10/02 JC
 *	- number bands from zero in error messages
 * 7/7/04
 *	- works on labq
 * 18/8/08
 * 	- add gtkdoc comments
 * 	- remove deprecated im_extract()
 * 30/11/09
 * 	- changes for im_extract() broke averaging
 * 9/11/11
 * 	- redo as a class
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
 */
#define VIPS_DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "statistic.h"

/**
 * VipsMeasure:
 * @im: image to measure
 * @out: array of measurements
 * @left: area of image containing chart
 * @top: area of image containing chart
 * @width: area of image containing chart
 * @height: area of image containing chart
 * @h: patches across chart
 * @v: patches down chart
 *
 * Analyse a grid of colour patches, producing an array of patch averages.
 * The mask has a row for each measured patch and a column for each image
 * band. The operations issues a warning if any patch has a deviation more 
 * than 20% of
 * the mean. Only the central 50% of each patch is averaged. 
 *
 * See also: #VipsAvg, #VipsDeviate.
 */

typedef struct _VipsStats {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	int left;
	int top;
	int width;
	int height;
	int h;
	int v;
} VipsMeasure;

typedef VipsOperationClass VipsMeasureClass;

G_DEFINE_TYPE( VipsMeasure, vips_measure, VIPS_TYPE_OPERATION );

/* Address a double in our array image.
 */
#define ARY( im, x, y ) ((double *) VIPS_IMAGE_ADDR( im, x, y ))

static int
vips_measure_build( VipsObject *object )
{
	VipsMeasure *measure = (VipsMeasure *) object;

	if( measure->in &&
		vips_argument_get_assigned( object, "h" ) &&
		vips_argument_get_assigned( object, "v" ) ) {
		int bands = vips_image_get_bands( measure->in );

		if( vips_check_noncomplex( "VipsMeasure", measure->in ) )
			return( -1 );

		g_object_set( object, 
			"out", vips_image_new_array( bands, 
				measure->h * measure->v ),
			NULL );
	}

	if( VIPS_OBJECT_CLASS( vips_measure_parent_class )->build( object ) )
		return( -1 );

	need labq2lab on labq images

	or maybe stats/avg/dev should do this?

	they could handle rad etc as well ... add it to statistics.c

	need to keep the whole of im_measure() in deprecated, we've removed 
	the 'measure these patch numbers' feature

	maybe remove the noncomplex check?

	parent->build() only checks that inputs have been set, I think, we 
	don't actually need to set out before calling it

	where else do we set out before build? verify

	/* How large are the patches we are to measure?
	 */
	double pw = (double) width / (double) u;
	double ph = (double) height / (double) v;

	/* Set up sub to be the size we need for a patch.
	 */
	w = (pw + 1) / 2;
	h = (ph + 1) / 2;

	/* Loop through sel, picking out areas to measure.
	 */
	for( j = 0, patch = 0; patch < nsel; patch++ ) {
		/* Sanity check. Is the patch number sensible?
		 */
		if( sel[patch] <= 0 || sel[patch] > u * v ) {
			im_error( "im_measure", 
				_( "patch %d is out of range" ),
				sel[patch] );
			return( 1 );
		}

		/* Patch coordinates.
		 */
		m = (sel[patch] - 1) % u;  
		n = (sel[patch] - 1) / u;

		/* Move sub to correct position.
		 */
		x = left + m * pw + (pw + 2) / 4;
		y = top + n * ph + (ph + 2) / 4;

		/* Loop through bands.
		 */
		for( i = 0; i < im->Bands; i++, j++ ) {
			/* Make temp buffer to extract to.
			 */
			if( !(tmp = im_open( "patch", "t" )) ) 
				return( -1 );
			
			/* Extract and measure.
			 */
			if( im_extract_areabands( im, tmp, x, y, w, h, i, 1 ) ||
				im_avg( tmp, &avg ) ||
				im_deviate( tmp, &dev ) ) {
				im_close( tmp );
				return( -1 );
			}
			im_close( tmp );

			/* Is the deviation large compared with the average?
			 * This could be a clue that our parameters have
			 * caused us to miss the patch. Look out for averages
			 * <0, or averages near zero (can get these if use
			 * im_measure() on IM_TYPE_LAB images).
			 */
			if( dev * 5 > fabs( avg ) && fabs( avg ) > 3 )
				im_warn( "im_measure",
					_( "patch %d, band %d: "
						"avg = %g, sdev = %g" ), 
					patch, i, avg, dev );

			/* Save results.
			 */
			coeff[j] = avg;
		}
	}

	return( 0 );
}

/* xy range we sanity check on ... just to stop crazy numbers from 1/0 etc.
 * causing g_assert() failures later.
 */
#define RANGE (100000000)

static void
vips_measure_class_init( VipsMeasureClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "measure";
	object_class->description = 
		_( "measure a set of patches on a colour chart" );
	object_class->build = vips_measure_build;

	VIPS_ARG_IMAGE( class, "in", 1,
		_( "in" ), 
		_( "Image to measure" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsJoin, in1 ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output array of statistics" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMeasure, out ) );

	VIPS_ARG_INT( class, "h", 5, 
		_( "Across" ), 
		_( "Number of patches across chart" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, h ),
		1, RANGE, 1 );

	VIPS_ARG_INT( class, "v", 6, 
		_( "Down" ), 
		_( "Number of patches down chart" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, v ),
		1, RANGE, 1 );

	VIPS_ARG_INT( class, "left", 10, 
		_( "Left" ), 
		_( "Left edge of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, left ),
		0, RANGE, 0 );

	VIPS_ARG_INT( class, "top", 11, 
		_( "Top" ), 
		_( "Top edge of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, top ),
		0, RANGE, 0 );

	VIPS_ARG_INT( class, "width", 12, 
		_( "Width" ), 
		_( "Width of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, width ),
		1, RANGE, 1 );

	VIPS_ARG_INT( class, "height", 13, 
		_( "Height" ), 
		_( "Height of extract area" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMeasure, height ),
		1, RANGE, 1 );

}

static void
vips_measure_init( VipsMeasure *measure )
{
}

int
vips_measure( VipsImage *in, VipsImage **out, int h, int v, ... )
{
	va_list ap;
	int result;

	va_start( ap, v );
	result = vips_call_split( "measure", ap, in, out, h, v );
	va_end( ap );

	return( result );
}
