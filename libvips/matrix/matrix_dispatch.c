/* VIPS function dispatch tables for matricies.
 *
 * J. Cupitt, 14/2/95.
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

/* One matrix in, one out.
 */
static im_arg_desc one_in_one_out[] = {
	IM_INPUT_DMASK( "in" ),
	IM_OUTPUT_DMASK( "out" )
};

/* Two matricies in, one out.
 */
static im_arg_desc two_in_one_out[] = {
	IM_INPUT_DMASK( "in1" ),
	IM_INPUT_DMASK( "in2" ),
	IM_OUTPUT_DMASK( "out" )
};

/* Call im_matinv via arg vector.
 */
static int
matinv_vec( im_object *argv )
{
	im_mask_object *in = argv[0];
	im_mask_object *out = argv[1];

	if( !(out->mask = 
		im_matinv( in->mask, out->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_matinv.
 */ 
static im_function matinv_desc = {
	"im_matinv",	 		/* Name */
	"invert matrix",
	0,				/* Flags */
	matinv_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_mattrn via arg vector.
 */
static int
mattrn_vec( im_object *argv )
{
	im_mask_object *in = argv[0];
	im_mask_object *out = argv[1];

	if( !(out->mask = 
		im_mattrn( in->mask, out->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_mattrn.
 */ 
static im_function mattrn_desc = {
	"im_mattrn",	 		/* Name */
	"transpose matrix",
	0,				/* Flags */
	mattrn_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_matcat via arg vector.
 */
static int
matcat_vec( im_object *argv )
{
	im_mask_object *in1 = argv[0];
	im_mask_object *in2 = argv[1];
	im_mask_object *out = argv[2];

	if( !(out->mask = 
		im_matcat( in1->mask, in2->mask, out->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_matcat.
 */ 
static im_function matcat_desc = {
	"im_matcat",	 		/* Name */
	"append matrix in2 to the end of matrix in1",
	0,				/* Flags */
	matcat_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_matmul via arg vector.
 */
static int
matmul_vec( im_object *argv )
{
	im_mask_object *in1 = argv[0];
	im_mask_object *in2 = argv[1];
	im_mask_object *out = argv[2];

	if( !(out->mask = 
		im_matmul( in1->mask, in2->mask, out->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_matmul.
 */ 
static im_function matmul_desc = {
	"im_matmul",	 		/* Name */
	"multiply matrix in1 by matrix in2",
	0,				/* Flags */
	matmul_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *matrix_list[] = {
	&matcat_desc,
	&matinv_desc,
	&matmul_desc,
	&mattrn_desc
};

/* Package of functions.
 */
im_package im__matrix = {
	"matrix",
	IM_NUMBER( matrix_list ),
	matrix_list
};
