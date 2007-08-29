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

/* Package up all these functions.
 */
static im_function *morph_list[] = {
	&cntlines_desc,
	&dilate_desc,
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
