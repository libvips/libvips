/* Function dispatch tables for deprecated operations.
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
#include <vips/deprecated.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/** 
 * SECTION: deprecated
 * @short_description: various deprecated operations which remain for
 * compatibility
 *
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations are left-overs from earlier versions of VIPS which are
 * kept for compatibility.
 */

/* Two images in, one out.
 */
static im_arg_desc two_in_one_out[] = {
	IM_INPUT_IMAGE( "in1" ),
	IM_INPUT_IMAGE( "in2" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_cmulnorm via arg vector.
 */
static int
cmulnorm_vec( im_object *argv )
{
	return( im_cmulnorm( argv[0], argv[1], argv[2] ) );
}

/* Description of im_cmulnorm.
 */ 
static im_function cmulnorm_desc = {
	"im_cmulnorm", 			/* Name */
	N_( "multiply two complex images, normalising output" ),
	IM_FN_PIO,			/* Flags */
	cmulnorm_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Four images in, one out.
 */
static im_arg_desc fav4_args[] = {
	IM_INPUT_IMAGE( "in1" ),
	IM_INPUT_IMAGE( "in2" ),
	IM_INPUT_IMAGE( "in3" ),
	IM_INPUT_IMAGE( "in4" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_fav4 via arg vector.
 */
static int
fav4_vec( im_object *argv )
{
	IMAGE *buf[4];

	buf[0] = argv[0];
	buf[1] = argv[1];
	buf[2] = argv[2];
	buf[3] = argv[3];

	return( im_fav4( &buf[0], argv[4] ) );
}

/* Description of im_fav4.
 */ 
static im_function fav4_desc = {
	"im_fav4", 			/* Name */
	N_( "average of 4 images" ),
	0,				/* Flags */
	fav4_vec, 			/* Dispatch function */
	IM_NUMBER( fav4_args ), 	/* Size of arg list */
	fav4_args 			/* Arg list */
};

/* Args for im_gadd().
 */
static im_arg_desc gadd_args[] = {
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_IMAGE( "in1" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_IMAGE( "in2" ),
	IM_INPUT_DOUBLE( "c" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_gadd() via arg vector.
 */
static int
gadd_vec( im_object *argv )
{
	double a = *((double *) argv[0]);
	double b = *((double *) argv[2]);
	double c = *((double *) argv[4]);

	return( im_gadd( a, argv[1], b, argv[3], c, argv[5] ) );
}

/* Description of im_gadd().
 */ 
static im_function gadd_desc = {
	"im_gadd", 			/* Name */
	N_( "calculate a*in1 + b*in2 + c = outfile" ),
	0,				/* Flags */
	gadd_vec, 			/* Dispatch function */
	IM_NUMBER( gadd_args ), 	/* Size of arg list */
	gadd_args 			/* Arg list */
};

/* Args for im_litecor().
 */
static im_arg_desc litecor_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_IMAGE( "white" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "clip" ),
	IM_INPUT_DOUBLE( "factor" )
};

/* Call im_litecor() via arg vector.
 */
static int
litecor_vec( im_object *argv )
{
	int clip = *((int *) argv[3]);
	double factor = *((double *) argv[4]);

	return( im_litecor( argv[0], argv[1], argv[2], clip, factor ) );
}

/* Description of im_litecor().
 */ 
static im_function litecor_desc = {
	"im_litecor", 			/* Name */
	N_( "calculate max(white)*factor*(in/white), if clip == 1" ),
	0,				/* Flags */
	litecor_vec, 			/* Dispatch function */
	IM_NUMBER( litecor_args ), 	/* Size of arg list */
	litecor_args 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *deprecated_list[] = {
	&cmulnorm_desc,
	&fav4_desc,
	&gadd_desc,
	&litecor_desc
};

/* Package of functions.
 */
im_package im__deprecated = {
	"deprecated",
	IM_NUMBER( deprecated_list ),
	deprecated_list
};
