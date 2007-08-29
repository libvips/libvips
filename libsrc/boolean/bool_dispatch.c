/* VIPS function dispatch tables for conversion.
 *
 * J. Cupitt, 8/4/93.
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

/* Two images in, one out.
 */
static im_arg_desc two_in_one_out[] = {
	IM_INPUT_IMAGE( "in1" ),
	IM_INPUT_IMAGE( "in2" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* One image plus one constant in, one image out.
 */
static im_arg_desc const_in_one_out[] = {
	IM_INPUT_IMAGE( "in1" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "c" )
};

/* One image plus doublevec in, one image out.
 */
static im_arg_desc vec_in_one_out[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLEVEC( "vec" )
};

/* Call im_and via arg vector.
 */
static int
and_vec( im_object *argv )
{
	return( im_andimage( argv[0], argv[1], argv[2] ) );
}

/* Description of im_and.
 */ 
static im_function and_desc = {
	"im_andimage", 			/* Name */
	"bitwise and of two images",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	and_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_andconst via arg vector.
 */
static int
andconst_vec( im_object *argv )
{
	int c = *((int *) argv[2]);

	return( im_andconst( argv[0], argv[1], c ) );
}

/* Description of im_andconst.
 */ 
static im_function andconst_desc = {
	"im_andimageconst", 			/* Name */
	"bitwise and of an image with a constant",
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	andconst_vec, 			/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_and_vec via arg vector.
 */
static int
and_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_and_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_andconst.
 */ 
static im_function and_vec_desc = {
	"im_andimage_vec", 		/* Name */
	"bitwise and of an image with a vector constant",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	and_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out 			/* Arg list */
};

/* Call im_or via arg vector.
 */
static int
or_vec( im_object *argv )
{
	return( im_orimage( argv[0], argv[1], argv[2] ) );
}

/* Description of im_or.
 */ 
static im_function or_desc = {
	"im_orimage", 			/* Name */
	"bitwise or of two images",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	or_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_orconst via arg vector.
 */
static int
orconst_vec( im_object *argv )
{
	int c = *((int *) argv[2]);

	return( im_orconst( argv[0], argv[1], c ) );
}

/* Description of im_orconst.
 */ 
static im_function orconst_desc = {
	"im_orimageconst", 			/* Name */
	"bitwise or of an image with a constant",
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	orconst_vec, 			/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_or_vec via arg vector.
 */
static int
or_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_or_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_orconst.
 */ 
static im_function or_vec_desc = {
	"im_orimage_vec", 		/* Name */
	"bitwise or of an image with a vector constant",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	or_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out 			/* Arg list */
};

/* Call im_eor via arg vector.
 */
static int
eor_vec( im_object *argv )
{
	return( im_eorimage( argv[0], argv[1], argv[2] ) );
}

/* Description of im_eor.
 */ 
static im_function eor_desc = {
	"im_eorimage", 			/* Name */
	"bitwise eor of two images",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	eor_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_eorconst via arg vector.
 */
static int
eorconst_vec( im_object *argv )
{
	int c = *((int *) argv[2]);

	return( im_eorconst( argv[0], argv[1], c ) );
}

/* Description of im_eorconst.
 */ 
static im_function eorconst_desc = {
	"im_eorimageconst", 			/* Name */
	"bitwise eor of an image with a constant",
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	eorconst_vec, 			/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_eor_vec via arg vector.
 */
static int
eor_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_eor_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_eorconst.
 */ 
static im_function eor_vec_desc = {
	"im_eorimage_vec", 		/* Name */
	"bitwise eor of an image with a vector constant",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	eor_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out 			/* Arg list */
};

/* Call im_shiftleft via arg vector.
 */
static int
shiftleft_vec( im_object *argv )
{
	int n = *((int *) argv[2]);

	return( im_shiftleft( argv[0], argv[1], n ) );
}

/* Description of im_shiftleft.
 */ 
static im_function shiftleft_desc = {
	"im_shiftleft", 		/* Name */
	"shift integer image n bits to left",
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	shiftleft_vec, 			/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_shiftright via arg vector.
 */
static int
shiftright_vec( im_object *argv )
{
	int n = *((int *) argv[2]);

	return( im_shiftright( argv[0], argv[1], n ) );
}

/* Description of im_shiftright.
 */ 
static im_function shiftright_desc = {
	"im_shiftright", 		/* Name */
	"shift integer image n bits to right",
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	shiftright_vec, 		/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Package up all these functions.
 */
static im_function *bool_list[] = {
	&and_desc,
	&andconst_desc,
	&and_vec_desc,
	&or_desc,
	&orconst_desc,
	&or_vec_desc,
	&eor_desc,
	&eorconst_desc,
	&eor_vec_desc,
	&shiftleft_desc,
	&shiftright_desc
};

/* Package of functions.
 */
im_package im__boolean = {
	"boolean",
	IM_NUMBER( bool_list ),
	bool_list
};
