/* Function dispatch tables for mosaicing.
 *
 * J. Cupitt, 23/2/95
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/transform.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* affinei args
 */
static im_arg_desc affinei_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INTERPOLATE( "interpolate" ),
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_DOUBLE( "c" ),
	IM_INPUT_DOUBLE( "d" ),
	IM_INPUT_DOUBLE( "dx" ),
	IM_INPUT_DOUBLE( "dy" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_INT( "w" ),
	IM_INPUT_INT( "h" )
};

/* Call im_affinei via arg vector.
 */
static int
affinei_vec( im_object *argv )
{
	VipsInterpolate *interpolate = VIPS_INTERPOLATE( argv[2] );
	double a = *((double *) argv[3]);
	double b = *((double *) argv[4]);
	double c = *((double *) argv[5]);
	double d = *((double *) argv[6]);
	double dx = *((double *) argv[7]);
	double dy = *((double *) argv[8]);
	int x = *((int *) argv[9]);
	int y = *((int *) argv[10]);
	int w = *((int *) argv[11]);
	int h = *((int *) argv[12]);

	return( im_affinei( argv[0], argv[1], interpolate, 
		a, b, c, d, dx, dy, x, y, w, h ) );
}

/* Description of im_affinei.
 */ 
static im_function affinei_desc = {
	"im_affinei", 			/* Name */
	"affine transform",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	affinei_vec, 			/* Dispatch function */
	IM_NUMBER( affinei_args ),	/* Size of arg list */
	affinei_args 			/* Arg list */
};

/* affinei_all args
 */
static im_arg_desc affinei_all_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INTERPOLATE( "interpolate" ),
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_DOUBLE( "c" ),
	IM_INPUT_DOUBLE( "d" ),
	IM_INPUT_DOUBLE( "dx" ),
	IM_INPUT_DOUBLE( "dy" )
};

/* Call im_affinei_all via arg vector.
 */
static int
affinei_all_vec( im_object *argv )
{
	VipsInterpolate *interpolate = VIPS_INTERPOLATE( argv[2] );
	double a = *((double *) argv[3]);
	double b = *((double *) argv[4]);
	double c = *((double *) argv[5]);
	double d = *((double *) argv[6]);
	double dx = *((double *) argv[7]);
	double dy = *((double *) argv[8]);

	return( im_affinei_all( argv[0], argv[1], interpolate, 
		a, b, c, d, dx, dy ) );
}

/* Description of im_affinei_all.
 */ 
static im_function affinei_all_desc = {
	"im_affinei_all", 		/* Name */
	"affine transform of whole image",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	affinei_all_vec, 		/* Dispatch function */
	IM_NUMBER( affinei_all_args ),	/* Size of arg list */
	affinei_all_args 		/* Arg list */
};

/* Package up all these functions.
 */
static im_function *resample_list[] = {
	&affinei_desc,
	&affinei_all_desc,
};

/* Package of functions.
 */
im_package im__resample = {
	"resample",
	IM_NUMBER( resample_list ),
	resample_list
};
