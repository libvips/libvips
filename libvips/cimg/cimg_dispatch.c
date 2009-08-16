/* Function dispatch tables for cimg wrappers.
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

static int
greyc_vec( im_object *argv )
{
        IMAGE *src = (IMAGE *) argv[0];
        IMAGE *dst = (IMAGE *) argv[1];

        int iterations = *((int *) argv[2]); 
	double amplitude = *((double *) argv[3]);   
	double sharpness = *((double *) argv[4]); 
	double anisotropy = *((double *) argv[5]); 
	double alpha = *((double *) argv[6]); 
	double sigma = *((double *) argv[7]);
	double dl = *((double *) argv[8]); 
	double da = *((double *) argv[9]); 
	double gauss_prec = *((double *) argv[10]); 
	int interpolation = *((int *) argv[11]); 
	int fast_approx = *((int *) argv[12]); 

        if( im_greyc_mask( src, dst, NULL,
		iterations,
		amplitude, sharpness, anisotropy,
		alpha, sigma, 
		dl, da, gauss_prec, 
		interpolation, fast_approx ) )
		return( -1 );

        return( 0 );
}

static im_arg_desc greyc_arg_types[] = {
        IM_INPUT_IMAGE( "src" ),
        IM_OUTPUT_IMAGE( "dst" ),
        IM_INPUT_INT( "iterations" ),
	IM_INPUT_DOUBLE( "amplitude" ),
	IM_INPUT_DOUBLE( "sharpness" ),
	IM_INPUT_DOUBLE( "anisotropy" ),
	IM_INPUT_DOUBLE( "alpha" ),
	IM_INPUT_DOUBLE( "sigma" ),
	IM_INPUT_DOUBLE( "dl" ),
	IM_INPUT_DOUBLE( "da" ),
	IM_INPUT_DOUBLE( "gauss_prec" ),
	IM_INPUT_INT( "interpolation" ),
	IM_INPUT_INT( "fast_approx" )
};

static im_function greyc_desc = {
        "im_greyc", 			/* Name */
        "noise-removing filter",      	/* Description */
        (im_fn_flags) (IM_FN_TRANSFORM | IM_FN_PIO),/* Flags */
        greyc_vec,           		/* Dispatch function */
        IM_NUMBER( greyc_arg_types ),	/* Size of arg list */
        greyc_arg_types       		/* Arg list */
};

static int
greyc_mask_vec( im_object *argv )
{
        IMAGE *src = (IMAGE *) argv[0];
        IMAGE *dst = (IMAGE *) argv[1];
        IMAGE *mask = (IMAGE *) argv[2];

        int iterations = *((int *) argv[3]); 
	double amplitude = *((double *) argv[4]);   
	double sharpness = *((double *) argv[5]); 
	double anisotropy = *((double *) argv[6]); 
	double alpha = *((double *) argv[7]); 
	double sigma = *((double *) argv[8]);
	double dl = *((double *) argv[9]); 
	double da = *((double *) argv[10]); 
	double gauss_prec = *((double *) argv[11]); 
	int interpolation = *((int *) argv[12]); 
	int fast_approx = *((int *) argv[13]); 

        if( im_greyc_mask( src, dst, mask,
		iterations,
		amplitude, sharpness, anisotropy,
		alpha, sigma, 
		dl, da, gauss_prec, 
		interpolation, fast_approx ) )
		return( -1 );

        return( 0 );
}

static im_arg_desc greyc_mask_arg_types[] = {
        IM_INPUT_IMAGE( "src" ),
        IM_OUTPUT_IMAGE( "dst" ),
        IM_INPUT_IMAGE( "mask" ),
        IM_INPUT_INT( "iterations" ),
	IM_INPUT_DOUBLE( "amplitude" ),
	IM_INPUT_DOUBLE( "sharpness" ),
	IM_INPUT_DOUBLE( "anisotropy" ),
	IM_INPUT_DOUBLE( "alpha" ),
	IM_INPUT_DOUBLE( "sigma" ),
	IM_INPUT_DOUBLE( "dl" ),
	IM_INPUT_DOUBLE( "da" ),
	IM_INPUT_DOUBLE( "gauss_prec" ),
	IM_INPUT_INT( "interpolation" ),
	IM_INPUT_INT( "fast_approx" )
};

static im_function greyc_mask_desc = {
        "im_greyc_mask",     		/* Name */
        "noise-removing filter, with a mask", /* Description */
        (im_fn_flags) (IM_FN_TRANSFORM | IM_FN_PIO),/* Flags */
        greyc_mask_vec,           	/* Dispatch function */
        IM_NUMBER( greyc_mask_arg_types ),/* Size of arg list */
        greyc_mask_arg_types       	/* Arg list */
};

static im_function *function_list[] = {
	&greyc_desc,
	&greyc_mask_desc
};

/* Package of functions.
 */
im_package im__cimg = {
	"cimg",
	IM_NUMBER( function_list ),
	function_list
};
