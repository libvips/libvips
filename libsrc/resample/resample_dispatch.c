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

/* affine args
 */
static im_arg_desc affine_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
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

/* Call im_affine via arg vector.
 */
static int
affine_vec( im_object *argv )
{
	double a = *((double *) argv[2]);
	double b = *((double *) argv[3]);
	double c = *((double *) argv[4]);
	double d = *((double *) argv[5]);
	double dx = *((double *) argv[6]);
	double dy = *((double *) argv[7]);
	int x = *((int *) argv[8]);
	int y = *((int *) argv[9]);
	int w = *((int *) argv[10]);
	int h = *((int *) argv[11]);

	return( im_affine( argv[0], argv[1], a, b, c, d, dx, dy, x, y, w, h ) );
}

/* Description of im_affine.
 */ 
static im_function affine_desc = {
	"im_affine", 			/* Name */
	"affine transform",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	affine_vec, 			/* Dispatch function */
	IM_NUMBER( affine_args ), 		/* Size of arg list */
	affine_args 			/* Arg list */
};

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

/* similarity args
 */
static im_arg_desc similarity_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_DOUBLE( "dx" ),
	IM_INPUT_DOUBLE( "dy" )
};

/* Call im_similarity via arg vector.
 */
static int
similarity_vec( im_object *argv )
{
	double a = *((double *) argv[2]);
	double b = *((double *) argv[3]);
	double dx = *((double *) argv[4]);
	double dy = *((double *) argv[5]);

	return( im_similarity( argv[0], argv[1], a, b, dx, dy ) );
}

/* Description of im_similarity.
 */ 
static im_function similarity_desc = {
	"im_similarity", 		/* Name */
	"similarity transformation",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	similarity_vec, 		/* Dispatch function */
	IM_NUMBER( similarity_args ), 	/* Size of arg list */
	similarity_args 		/* Arg list */
};

/* similarity_area args
 */
static im_arg_desc similarity_area_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_DOUBLE( "dx" ),
	IM_INPUT_DOUBLE( "dy" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_INT( "w" ),
	IM_INPUT_INT( "h" )
};

/* Call im_similarity_area via arg vector.
 */
static int
similarity_area_vec( im_object *argv )
{
	double a = *((double *) argv[2]);
	double b = *((double *) argv[3]);
	double dx = *((double *) argv[4]);
	double dy = *((double *) argv[5]);
	int x = *((int *) argv[6]);
	int y = *((int *) argv[7]);
	int w = *((int *) argv[8]);
	int h = *((int *) argv[9]);

	return( im_similarity_area( argv[0], argv[1], a, b, dx, dy,
		x, y, w, h ) );
}

/* Description of im_similarity_area.
 */ 
static im_function similarity_area_desc = {
	"im_similarity_area", 		/* Name */
	"output area xywh of similarity transformation",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	similarity_area_vec, 		/* Dispatch function */
	IM_NUMBER( similarity_area_args ), /* Size of arg list */
	similarity_area_args 		/* Arg list */
};

/* Package up all these functions.
 */
static im_function *resample_list[] = {
	&affine_desc,
	&affinei_desc,
	&affinei_all_desc,
	&similarity_area_desc,
	&similarity_desc
};

/* Package of functions.
 */
im_package im__resample = {
	"resample",
	IM_NUMBER( resample_list ),
	resample_list
};
