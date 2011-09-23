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

/** 
 * SECTION: boolean
 * @short_description: boolean algebra on images, bitshifts
 * @see_also: <link linkend="libvips-arithmetic">arithmetic</link>
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations perform boolean operations, such as bitwise-and, on
 * every pixel in an image or pair of images. 
 * They are useful for combining the results of
 * the relational and morphological functions.
 * All will work with 
 * images of any type or any mixture of types, of any size and of any number 
 * of bands.
 *
 * For binary operations, if the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together and then
 * the two n-band images are operated upon.
 *
 * In the same way, for operations that take an array constant, such as 
 * im_andimage_vec(), you can mix single-element arrays or single-band images
 * freely.
 *
 * If the images differ in size, the smaller image is enlarged to match the
 * larger by adding zero pixels along the bottom and right.
 *
 * The output type is the same as the input type for integer types. Float and
 * complex types are cast to signed int.
 *
 * You might think im_andimage() would be called "im_and", but that causes
 * problems when we try and make a C++ binding and drop the "im_" prefix.
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

/* Call im_andimage via arg vector.
 */
static int
andimage_vec( im_object *argv )
{
	return( im_andimage( argv[0], argv[1], argv[2] ) );
}

/* Description of im_andimage.
 */ 
static im_function andimage_desc = {
	"im_andimage", 			/* Name */
	"bitwise and of two images",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	andimage_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_andimageconst via arg vector.
 */
static int
andimageconst_vec( im_object *argv )
{
	int c = *((int *) argv[2]);

	return( im_andimageconst( argv[0], argv[1], c ) );
}

/* Description of im_andconst.
 */ 
static im_function andimageconst_desc = {
	"im_andimageconst", 		/* Name */
	"bitwise and of an image with a constant",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	andimageconst_vec, 		/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_andimage_vec via arg vector.
 */
static int
andimage_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_andimage_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_andimageconst.
 */ 
static im_function andimage_vec_desc = {
	"im_andimage_vec", 		/* Name */
	"bitwise and of an image with a vector constant",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	andimage_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out 			/* Arg list */
};

/* Call im_orimage via arg vector.
 */
static int
orimage_vec( im_object *argv )
{
	return( im_orimage( argv[0], argv[1], argv[2] ) );
}

/* Description of im_orimage.
 */ 
static im_function orimage_desc = {
	"im_orimage", 			/* Name */
	"bitwise or of two images",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	orimage_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_orimageconst via arg vector.
 */
static int
orimageconst_vec( im_object *argv )
{
	int c = *((int *) argv[2]);

	return( im_orimageconst( argv[0], argv[1], c ) );
}

/* Description of im_orimageconst.
 */ 
static im_function orimageconst_desc = {
	"im_orimageconst", 		/* Name */
	"bitwise or of an image with a constant",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	orimageconst_vec, 		/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_orimage_vec via arg vector.
 */
static int
orimage_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_orimage_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_orimage_vec.
 */ 
static im_function orimage_vec_desc = {
	"im_orimage_vec", 		/* Name */
	"bitwise or of an image with a vector constant",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	orimage_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out 			/* Arg list */
};

/* Call im_eorimage via arg vector.
 */
static int
eorimage_vec( im_object *argv )
{
	return( im_eorimage( argv[0], argv[1], argv[2] ) );
}

/* Description of im_eorimage.
 */ 
static im_function eorimage_desc = {
	"im_eorimage", 			/* Name */
	"bitwise eor of two images",	/* Description */
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	eorimage_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_eorimageconst via arg vector.
 */
static int
eorimageconst_vec( im_object *argv )
{
	int c = *((int *) argv[2]);

	return( im_eorimageconst( argv[0], argv[1], c ) );
}

/* Description of im_eorimageconst.
 */ 
static im_function eorimageconst_desc = {
	"im_eorimageconst", 		/* Name */
	"bitwise eor of an image with a constant",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	eorimageconst_vec, 		/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_eorimage_vec via arg vector.
 */
static int
eorimage_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_eorimage_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_eorimage_vec.
 */ 
static im_function eorimage_vec_desc = {
	"im_eorimage_vec", 		/* Name */
	"bitwise eor of an image with a vector constant",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	eorimage_vec_vec, 		/* Dispatch function */
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
	"shift image n bits to left",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	shiftleft_vec, 			/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_shiftleft_vec via arg vector.
 */
static int
shiftleft_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_shiftleft_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_shiftleft_vec.
 */ 
static im_function shiftleft_vec_desc = {
	"im_shiftleft_vec", 		/* Name */
	"shift image array bits to left",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	shiftleft_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out 			/* Arg list */
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
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	shiftright_vec, 		/* Dispatch function */
	IM_NUMBER( const_in_one_out ), 	/* Size of arg list */
	const_in_one_out 		/* Arg list */
};

/* Call im_shiftright_vec via arg vector.
 */
static int
shiftright_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_shiftright_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_shiftright_vec.
 */ 
static im_function shiftright_vec_desc = {
	"im_shiftright_vec", 		/* Name */
	"shift image array bits to right",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	shiftright_vec_vec, 		/* Dispatch function */
	IM_NUMBER( vec_in_one_out ), 	/* Size of arg list */
	vec_in_one_out 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *bool_list[] = {
	&andimage_desc,
	&andimageconst_desc,
	&andimage_vec_desc,
	&orimage_desc,
	&orimageconst_desc,
	&orimage_vec_desc,
	&eorimage_desc,
	&eorimageconst_desc,
	&eorimage_vec_desc,
	&shiftleft_vec_desc,
	&shiftleft_desc,
	&shiftright_vec_desc,
	&shiftright_desc
};

/* Package of functions.
 */
im_package im__boolean = {
	"boolean",
	IM_NUMBER( bool_list ),
	bool_list
};
