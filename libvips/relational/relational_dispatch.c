/* VIPS function dispatch tables for relational.
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/** 
 * SECTION: relational
 * @short_description: relational comparisons between pairs of images and 
 * images and constants
 * @see_also: <link linkend="libvips-arithmetic">arithmetic</link>
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations perform comparison operations, such as equals, on
 * every pixel in an image or pair of images. 
 * All will work with 
 * images of any type or any mixture of types of any size and of any number 
 * of bands.
 *
 * For binary operations, if the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together and then
 * the two n-band images are operated upon.
 *
 * In the same way, for operations that take an array constant, such as 
 * im_equal_vec(), you can mix single-element arrays or single-band images
 * freely.
 *
 * The output type is always unsigned char, 
 * with 255 for every band element for which the condition 
 * is true, and 0 for every other element.
 * For complex images, the operations calculate and compare the modulus.
 *
 * For binary operations on pairs of images, the images must match in size.
 */

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
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "c" )
};

/* One image plus doublevec in, one image out.
 */
static im_arg_desc vec_in_one_out[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLEVEC( "vec" )
};

/* Call im_equal via arg vector.
 */
static int
equal_vec( im_object *argv )
{
	return( im_equal( argv[0], argv[1], argv[2] ) );
}

/* Description of im_equal.
 */ 
static im_function equal_desc = {
	"im_equal", 			/* Name */
	"two images equal in value",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	equal_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_equalconst via arg vector.
 */
static int
equalconst_vec( im_object *argv )
{
	double c = *((double *) argv[2]);

	return( im_equalconst( argv[0], argv[1], c ) );
}

/* Description of im_equalconst.
 */ 
static im_function equalconst_desc = {
	"im_equalconst", 		/* Name */
	"image equals const",		/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	equalconst_vec, 		/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_equal_vec via arg vector.
 */
static int
equal_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_equal_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_equal_vec.
 */ 
static im_function equal_vec_desc = {
	"im_equal_vec", 		/* Name */
	"image equals doublevec",		/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	equal_vec_vec, 			/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out 			/* Arg list */
};

/* Call im_notequal via arg vector.
 */
static int
notequal_vec( im_object *argv )
{
	return( im_notequal( argv[0], argv[1], argv[2] ) );
}

/* Description of im_notequal.
 */ 
static im_function notequal_desc = {
	"im_notequal", 			/* Name */
	"two images not equal in value",/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	notequal_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_notequalconst via arg vector.
 */
static int
notequalconst_vec( im_object *argv )
{
	double c = *((double *) argv[2]);

	return( im_notequalconst( argv[0], argv[1], c ) );
}

/* Description of im_notequalconst.
 */ 
static im_function notequalconst_desc = {
	"im_notequalconst", 		/* Name */
	"image does not equal const",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	notequalconst_vec, 		/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_notequal_vec via arg vector.
 */
static int
notequal_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_notequal_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_notequal_vec.
 */ 
static im_function notequal_vec_desc = {
	"im_notequal_vec", 		/* Name */
	"image does not equal doublevec",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	notequal_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out 			/* Arg list */
};

/* Call im_less via arg vector.
 */
static int
less_vec( im_object *argv )
{
	return( im_less( argv[0], argv[1], argv[2] ) );
}

/* Description of im_less.
 */ 
static im_function less_desc = {
	"im_less", 			/* Name */
	"in1 less than in2 in value",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	less_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_lessconst via arg vector.
 */
static int
lessconst_vec( im_object *argv )
{
	double c = *((double *) argv[2]);

	return( im_lessconst( argv[0], argv[1], c ) );
}

/* Description of im_lessconst.
 */ 
static im_function lessconst_desc = {
	"im_lessconst", 		/* Name */
	"in less than const",		/* Description */
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	lessconst_vec, 			/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out		/* Arg list */
};

/* Call im_less_vec via arg vector.
 */
static int
less_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_less_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_less_vec.
 */ 
static im_function less_vec_desc = {
	"im_less_vec", 			/* Name */
	"in less than doublevec",		/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	less_vec_vec, 			/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out			/* Arg list */
};

/* Call im_more via arg vector.
 */
static int
more_vec( im_object *argv )
{
	return( im_more( argv[0], argv[1], argv[2] ) );
}

/* Description of im_more.
 */ 
static im_function more_desc = {
	"im_more", 			/* Name */
	"in1 more than in2 in value",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	more_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_moreconst via arg vector.
 */
static int
moreconst_vec( im_object *argv )
{
	double c = *((double *) argv[2]);

	return( im_moreconst( argv[0], argv[1], c ) );
}

/* Description of im_moreconst.
 */ 
static im_function moreconst_desc = {
	"im_moreconst", 		/* Name */
	"in more than const",		/* Description */
	IM_FN_PTOP | IM_FN_PIO,			/* Flags */
	moreconst_vec, 			/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out		/* Arg list */
};

/* Call im_more_vec via arg vector.
 */
static int
more_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_more_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_more_vec.
 */ 
static im_function more_vec_desc = {
	"im_more_vec", 			/* Name */
	"in more than doublevec",		/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	more_vec_vec, 			/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out			/* Arg list */
};

/* Call im_moreeq via arg vector.
 */
static int
moreeq_vec( im_object *argv )
{
	return( im_moreeq( argv[0], argv[1], argv[2] ) );
}

/* Description of im_moreeq.
 */ 
static im_function moreeq_desc = {
	"im_moreeq", 			/* Name */
	"in1 more than or equal to in2 in value",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	moreeq_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_moreeqconst via arg vector.
 */
static int
moreeqconst_vec( im_object *argv )
{
	double c = *((double *) argv[2]);

	return( im_moreeqconst( argv[0], argv[1], c ) );
}

/* Description of im_moreeqconst.
 */ 
static im_function moreeqconst_desc = {
	"im_moreeqconst", 		/* Name */
	"in more than or equal to const",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	moreeqconst_vec, 		/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out		/* Arg list */
};

/* Call im_moreeq_vec via arg vector.
 */
static int
moreeq_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_moreeq_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_moreeq_vec.
 */ 
static im_function moreeq_vec_desc = {
	"im_moreeq_vec", 		/* Name */
	"in more than or equal to doublevec",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	moreeq_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out			/* Arg list */
};

/* Call im_lesseq via arg vector.
 */
static int
lesseq_vec( im_object *argv )
{
	return( im_lesseq( argv[0], argv[1], argv[2] ) );
}

/* Description of im_lesseq.
 */ 
static im_function lesseq_desc = {
	"im_lesseq", 			/* Name */
	"in1 less than or equal to in2 in value",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	lesseq_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_lesseqconst via arg vector.
 */
static int
lesseqconst_vec( im_object *argv )
{
	double c = *((double *) argv[2]);

	return( im_lesseqconst( argv[0], argv[1], c ) );
}

/* Description of im_lesseqconst.
 */ 
static im_function lesseqconst_desc = {
	"im_lesseqconst", 		/* Name */
	"in less than or equal to const",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	lesseqconst_vec, 		/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out		/* Arg list */
};

/* Call im_lesseq_vec via arg vector.
 */
static int
lesseq_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_lesseq_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_lesseq_vec.
 */ 
static im_function lesseq_vec_desc = {
	"im_lesseq_vec", 		/* Name */
	"in less than or equal to doublevec",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	lesseq_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out			/* Arg list */
};

/* If-then-else args.
 */
static im_arg_desc ifthenelse_args[] = {
	IM_INPUT_IMAGE( "cond" ),
	IM_INPUT_IMAGE( "in1" ),
	IM_INPUT_IMAGE( "in2" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_blend via arg vector.
 */
static int
blend_vec( im_object *argv )
{
	return( im_blend( argv[0], argv[1], argv[2], argv[3] ) );
}

/* Description of im_blend.
 */ 
static im_function blend_desc = {
	"im_blend", 			/* Name */
	"use cond image to blend between images in1 and in2",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	blend_vec,			/* Dispatch function */
	IM_NUMBER( ifthenelse_args ), 	/* Size of arg list */
	ifthenelse_args 		/* Arg list */
};

/* Call im_ifthenelse via arg vector.
 */
static int
ifthenelse_vec( im_object *argv )
{
	return( im_ifthenelse( argv[0], argv[1], argv[2], argv[3] ) );
}

/* Description of im_ifthenelse.
 */ 
static im_function ifthenelse_desc = {
	"im_ifthenelse", 		/* Name */
	"use cond image to choose pels from image in1 or in2",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	ifthenelse_vec,			/* Dispatch function */
	IM_NUMBER( ifthenelse_args ), 	/* Size of arg list */
	ifthenelse_args 		/* Arg list */
};

/* Package up all these functions.
 */
static im_function *relational_list[] = {
	&blend_desc,
	&equal_desc,
	&equal_vec_desc,
	&equalconst_desc,
	&ifthenelse_desc,
	&less_desc,
	&less_vec_desc,
	&lessconst_desc,
	&lesseq_desc,
	&lesseq_vec_desc,
	&lesseqconst_desc,
	&more_desc,
	&more_vec_desc,
	&moreconst_desc,
	&moreeq_desc,
	&moreeq_vec_desc,
	&moreeqconst_desc,
	&notequal_desc,
	&notequal_vec_desc,
	&notequalconst_desc
};

/* Package of functions.
 */
im_package im__relational = {
	"relational",
	IM_NUMBER( relational_list ),
	relational_list
};
