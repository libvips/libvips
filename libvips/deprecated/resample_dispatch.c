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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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

/** 
 * SECTION: resample
 * @short_description: shrink, expand, rotate with a choice of interpolators
 * @stability: Stable
 * @include: vips/vips.h
 *
 * Resample an image in various ways, using a #VipsInterpolate to generate
 * intermediate values.
 */

/* Args to im_rightshift_size.
 */
static im_arg_desc rightshift_size_args[] = {
  IM_INPUT_IMAGE ("in"),
  IM_OUTPUT_IMAGE ("out"),
  IM_INPUT_INT ("xshift"),
  IM_INPUT_INT ("yshift"),
  IM_INPUT_INT ("band_fmt")
};

/* Call im_rightshift_size via arg vector.
 */
static int
rightshift_size_vec (im_object * argv)
{
  IMAGE *in = (IMAGE *) argv[0];
  IMAGE *out = (IMAGE *) argv[1];
  int *xshift = (int *) argv[2];
  int *yshift = (int *) argv[3];
  int *band_fmt = (int *) argv[4];

  return im_rightshift_size (in, out, *xshift, *yshift, *band_fmt );
}

/* Description of im_rightshift_size.
 */
static im_function rightshift_size_desc = {
  "im_rightshift_size",		/* Name */
  "decrease size by a power-of-two factor",
  IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
  rightshift_size_vec,		/* Dispatch function */
  IM_NUMBER (rightshift_size_args),	/* Size of arg list */
  rightshift_size_args		/* Arg list */
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

/* Args for im_shrink.
 */
static im_arg_desc shrink_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "xfac" ),
	IM_INPUT_DOUBLE( "yfac" )
};

/* Call im_shrink via arg vector.
 */
static int
shrink_vec( im_object *argv )
{
	double xshrink = *((double *) argv[2]);
	double yshrink = *((double *) argv[3]);

	return( im_shrink( argv[0], argv[1], xshrink, yshrink ) );
}

/* Description of im_shrink.
 */ 
static im_function shrink_desc = {
	"im_shrink",	 		/* Name */
	"shrink image by xfac, yfac times",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	shrink_vec, 			/* Dispatch function */
	IM_NUMBER( shrink_args ), 		/* Size of arg list */
	shrink_args 			/* Arg list */
};

/* Args to im_stretch3.
 */
static im_arg_desc stretch3_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "xdisp" ),
	IM_INPUT_DOUBLE( "ydisp" )
};

/* Call im_stretch3 via arg vector.
 */
static int
stretch3_vec( im_object *argv )
{
	double xdisp = *((int *) argv[2]);
	double ydisp = *((int *) argv[3]);

	return( im_stretch3( argv[0], argv[1], xdisp, ydisp ) );
}

/* Description of im_stretch3.
 */ 
static im_function stretch3_desc = {
	"im_stretch3",	 		/* Name */
	"stretch 3%, sub-pixel displace by xdisp/ydisp",
	IM_FN_PIO,			/* Flags */
	stretch3_vec, 			/* Dispatch function */
	IM_NUMBER( stretch3_args ), 	/* Size of arg list */
	stretch3_args 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *resample_list[] = {
	&rightshift_size_desc,
	&shrink_desc,
	&stretch3_desc,
	&affinei_desc,
	&affinei_all_desc
};

/* Package of functions.
 */
im_package im__resample = {
	"resample",
	IM_NUMBER( resample_list ),
	resample_list
};
