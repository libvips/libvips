/* VIPS function dispatch tables for morphology.
 *
 * J. Cupitt, 19/9/95
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

/** 
 * SECTION: morphology
 * @short_description: morphological operators, rank filters and related image 
 * analysis
 * @see_also: <link linkend="libvips-boolean">boolean</link>
 * @stability: Stable
 * @include: vips/vips.h
 *
 * Erode, dilate, rank, count lines, number regions, etc.
 */

/* Args to im_profile.
 */
static im_arg_desc profile_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "direction" )
};

/* Call im_profile via arg vector.
 */
static int
profile_vec( im_object *argv )
{
	int dir = *((int *) argv[2]);

	return( im_profile( argv[0], argv[1], dir ) );
}

/* Description of im_profile.
 */ 
static im_function profile_desc = {
	"im_profile",	 		/* Name */
	"find first horizontal/vertical edge",	/* Descr. */
	IM_FN_TRANSFORM,		/* Flags */
	profile_vec, 			/* Dispatch function */
	IM_NUMBER( profile_args ), 	/* Size of arg list */
	profile_args 			/* Arg list */
};

/* Args to im_erode.
 */
static im_arg_desc erode_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_IMASK( "mask" )
};

/* Call im_dilate via arg vector.
 */
static int
dilate_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_dilate( argv[0], argv[1], mo->mask ) );
}

/* Description of im_dilate.
 */ 
static im_function dilate_desc = {
	"im_dilate",	 		/* Name */
	"dilate image with mask, adding a black border",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	dilate_vec, 			/* Dispatch function */
	IM_NUMBER( erode_args ), 		/* Size of arg list */
	erode_args 			/* Arg list */
};

/* Call im_dilate_raw via arg vector.
 */
static int
dilate_raw_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_dilate_raw( argv[0], argv[1], mo->mask ) );
}

/* Description of im_dilate_raw.
 */ 
static im_function dilate_raw_desc = {
	"im_dilate_raw",	 	/* Name */
	"dilate image with mask",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	dilate_raw_vec, 		/* Dispatch function */
	IM_NUMBER( erode_args ), 		/* Size of arg list */
	erode_args 			/* Arg list */
};

/* Call im_erode via arg vector.
 */
static int
erode_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_erode( argv[0], argv[1], mo->mask ) );
}

/* Description of im_erode.
 */ 
static im_function erode_desc = {
	"im_erode",	 		/* Name */
	"erode image with mask, adding a black border",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	erode_vec, 			/* Dispatch function */
	IM_NUMBER( erode_args ), 		/* Size of arg list */
	erode_args 			/* Arg list */
};

/* Call im_erode_raw via arg vector.
 */
static int
erode_raw_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_erode_raw( argv[0], argv[1], mo->mask ) );
}

/* Description of im_erode_raw.
 */ 
static im_function erode_raw_desc = {
	"im_erode_raw",	 		/* Name */
	"erode image with mask",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	erode_raw_vec, 			/* Dispatch function */
	IM_NUMBER( erode_args ), 		/* Size of arg list */
	erode_args 			/* Arg list */
};

/* Args to im_cntlines.
 */
static im_arg_desc cntlines_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_DOUBLE( "nlines" ),
	IM_INPUT_INT( "direction" )
};

/* Call im_cntlines via arg vector.
 */
static int
cntlines_vec( im_object *argv )
{
	double *out = (double *) argv[1];
	int dir = *((int *) argv[2]);

	return( im_cntlines( argv[0], out, dir ) );
}

/* Description of im_cntlines.
 */ 
static im_function cntlines_desc = {
	"im_cntlines",	 		/* Name */
	"count horizontal or vertical lines",
	0,				/* Flags */
	cntlines_vec, 			/* Dispatch function */
	IM_NUMBER( cntlines_args ), 	/* Size of arg list */
	cntlines_args 			/* Arg list */
};

/* Args to im_rank.
 */
static im_arg_desc rank_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "xsize" ),
	IM_INPUT_INT( "ysize" ),
	IM_INPUT_INT( "n" )
};

/* Call im_rank via arg vector.
 */
static int
rank_vec( im_object *argv )
{
	int xsize = *((int *) argv[2]);
	int ysize = *((int *) argv[3]);
	int n = *((int *) argv[4]);

	return( im_rank( argv[0], argv[1], xsize, ysize, n ) );
}

/* Description of im_rank.
 */ 
static im_function rank_desc = {
	"im_rank",	 		/* Name */
	"rank filter nth element of xsize/ysize window",
	IM_FN_PIO,			/* Flags */
	rank_vec, 			/* Dispatch function */
	IM_NUMBER( rank_args ), 		/* Size of arg list */
	rank_args 			/* Arg list */
};

/* Args for im_zerox.
 */
static im_arg_desc zerox_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "flag" )
};

/* Call im_zerox via arg vector.
 */
static int
zerox_vec( im_object *argv )
{
	int flag = *((int *) argv[2]);

	return( im_zerox( argv[0], argv[1], flag ) );
}

/* Description of im_zerox.
 */ 
static im_function zerox_desc = {
	"im_zerox",	 		/* Name */
	"find +ve or -ve zero crossings in image",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	zerox_vec, 			/* Dispatch function */
	IM_NUMBER( zerox_args ), 		/* Size of arg list */
	zerox_args 			/* Arg list */
};

static im_arg_desc maxvalue_args[] = {
	IM_INPUT_IMAGEVEC( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

static int
maxvalue_vec( im_object *argv )
{
	im_imagevec_object *iv = (im_imagevec_object *) argv[0];

	return( im_maxvalue( iv->vec, argv[1], iv->n ) );
}

static im_function maxvalue_desc = {
	"im_maxvalue", 			/* Name */
	"point-wise maximum value",	/* Description */
	IM_FN_PIO,			/* Flags */
	maxvalue_vec, 			/* Dispatch function */
	IM_NUMBER( maxvalue_args ), 	/* Size of arg list */
	maxvalue_args 			/* Arg list */
};

static im_arg_desc rank_image_args[] = {
	IM_INPUT_IMAGEVEC( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "index" )
};

static int
rank_image_vec( im_object *argv )
{
	im_imagevec_object *iv = (im_imagevec_object *) argv[0];
	int index = *((int *) argv[2]);

	return( im_rank_image( iv->vec, argv[1], iv->n, index ) );
}

static im_function rank_image_desc = {
	"im_rank_image", 		/* Name */
	"point-wise pixel rank",	/* Description */
	IM_FN_PIO,			/* Flags */
	rank_image_vec, 		/* Dispatch function */
	IM_NUMBER( rank_image_args ), 	/* Size of arg list */
	rank_image_args 		/* Arg list */
};

/* Call im_rank_raw via arg vector.
 */
static int
rank_raw_vec( im_object *argv )
{
	int xsize = *((int *) argv[2]);
	int ysize = *((int *) argv[3]);
	int n = *((int *) argv[4]);

	return( im_rank_raw( argv[0], argv[1], xsize, ysize, n ) );
}

/* Description of im_rank_raw.
 */ 
static im_function rank_raw_desc = {
	"im_rank_raw",	 		/* Name */
	"rank filter nth element of xsize/ysize window, no border",
	IM_FN_PIO,			/* Flags */
	rank_raw_vec, 			/* Dispatch function */
	IM_NUMBER( rank_args ), 		/* Size of arg list */
	rank_args 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *morph_list[] = {
	&cntlines_desc,
	&dilate_desc,
	&rank_desc,
	&rank_image_desc,
	&maxvalue_desc,
	&zerox_desc,
	&rank_raw_desc,
	&dilate_raw_desc,
	&erode_desc,
	&erode_raw_desc,
	&profile_desc
};

/* Package of functions.
 */
im_package im__morphology = {
	"morphology",
	IM_NUMBER( morph_list ),
	morph_list
};
