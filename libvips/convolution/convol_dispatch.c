/* VIPS function dispatch tables for convolution.
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

/* One image in, one out.
 */
static im_arg_desc one_in_one_out[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Two images in, one out.
 */
static im_arg_desc two_in_one_out[] = {
	IM_INPUT_IMAGE( "in1" ),
	IM_INPUT_IMAGE( "in2" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Args to im_contrast_surface.
 */
static im_arg_desc contrast_surface_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "half_win_size" ),
	IM_INPUT_INT( "spacing" )
};

/* Call im_contrast_surface via arg vector.
 */
static int
contrast_surface_vec( im_object *argv )
{
	int half_win_size = *((int *) argv[2]);
	int spacing = *((int *) argv[3]);

	return( im_contrast_surface( argv[0], argv[1], 
		half_win_size, spacing ) );
}

/* Description of im_contrast_surface.
 */ 
static im_function contrast_surface_desc = {
	"im_contrast_surface",	 	/* Name */
	"find high-contrast points in an image",
	IM_FN_PIO,			/* Flags */
	contrast_surface_vec, 		/* Dispatch function */
	IM_NUMBER( contrast_surface_args ),/* Size of arg list */
	contrast_surface_args 		/* Arg list */
};

/* Args to im_contrast_surface_raw.
 */
static im_arg_desc contrast_surface_raw_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "half_win_size" ),
	IM_INPUT_INT( "spacing" )
};

/* Call im_contrast_surface_raw via arg vector.
 */
static int
contrast_surface_raw_vec( im_object *argv )
{
	int half_win_size = *((int *) argv[2]);
	int spacing = *((int *) argv[3]);

	return( im_contrast_surface_raw( argv[0], argv[1], 
		half_win_size, spacing ) );
}

/* Description of im_contrast_surface_raw.
 */ 
static im_function contrast_surface_raw_desc = {
	"im_contrast_surface_raw",	/* Name */
	"find high-contrast points in an image",
	IM_FN_PIO,			/* Flags */
	contrast_surface_raw_vec, 	/* Dispatch function */
	IM_NUMBER( contrast_surface_raw_args ),/* Size of arg list */
	contrast_surface_raw_args 	/* Arg list */
};

/* Args to im_sharpen.
 */
static im_arg_desc sharpen_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "mask_size" ),
	IM_INPUT_DOUBLE( "x1" ),
	IM_INPUT_DOUBLE( "y2" ),
	IM_INPUT_DOUBLE( "y3" ),
	IM_INPUT_DOUBLE( "m1" ),
	IM_INPUT_DOUBLE( "m2" )
};

/* Call im_sharpen via arg vector.
 */
static int
sharpen_vec( im_object *argv )
{
	int mask_size = *((int *) argv[2]);
	double x1 = *((double *) argv[3]);
	double x2 = *((double *) argv[4]);
	double x3 = *((double *) argv[5]);
	double m1 = *((double *) argv[6]);
	double m2 = *((double *) argv[7]);

	return( im_sharpen( argv[0], argv[1], mask_size, x1, x2, x3, m1, m2 ) );
}

/* Description of im_sharpen.
 */ 
static im_function sharpen_desc = {
	"im_sharpen",	 		/* Name */
	"sharpen high frequencies of L channel of LabQ",
	IM_FN_PIO,			/* Flags */
	sharpen_vec, 			/* Dispatch function */
	IM_NUMBER( sharpen_args ), 	/* Size of arg list */
	sharpen_args 			/* Arg list */
};

/* Args to im_addgnoise.
 */
static im_arg_desc addgnoise_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "sigma" )
};

/* Call im_addgnoise via arg vector.
 */
static int
addgnoise_vec( im_object *argv )
{
	double sigma = *((double *) argv[2]);

	return( im_addgnoise( argv[0], argv[1], sigma ) );
}

/* Description of im_addgnoise.
 */ 
static im_function addgnoise_desc = {
	"im_addgnoise", 		/* Name */
	"add gaussian noise with mean 0 and std. dev. sigma",
	IM_FN_PIO,			/* Flags */
	addgnoise_vec, 			/* Dispatch function */
	IM_NUMBER( addgnoise_args ), 	/* Size of arg list */
	addgnoise_args 			/* Arg list */
};

/* Args for convolver with imask.
 */
static im_arg_desc conv_imask[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_IMASK( "matrix" )
};

/* Args for convolver with dmask.
 */
static im_arg_desc conv_dmask[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DMASK( "matrix" )
};

/* Call im_compass via arg vector.
 */
static int
compass_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_compass( argv[0], argv[1], mo->mask ) );
}

/* Description of im_compass.
 */ 
static im_function compass_desc = {
	"im_compass", 			/* Name */
	"convolve with 8-way rotating integer mask",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	compass_vec, 			/* Dispatch function */
	IM_NUMBER( conv_imask ), 		/* Size of arg list */
	conv_imask 			/* Arg list */
};

/* Call im_conv via arg vector.
 */
static int
conv_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_conv( argv[0], argv[1], mo->mask ) );
}

/* Description of im_conv.
 */ 
static im_function conv_desc = {
	"im_conv", 			/* Name */
	"convolve",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	conv_vec, 			/* Dispatch function */
	IM_NUMBER( conv_imask ), 		/* Size of arg list */
	conv_imask 			/* Arg list */
};

/* Call im_conv_raw via arg vector.
 */
static int
conv_raw_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_conv_raw( argv[0], argv[1], mo->mask ) );
}

/* Description of im_conv_raw.
 */ 
static im_function conv_raw_desc = {
	"im_conv_raw", 			/* Name */
	"convolve, no border",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	conv_raw_vec, 			/* Dispatch function */
	IM_NUMBER( conv_imask ), 		/* Size of arg list */
	conv_imask 			/* Arg list */
};

/* Call im_convf via arg vector.
 */
static int
convf_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_convf( argv[0], argv[1], mo->mask ) );
}

/* Description of im_convf.
 */ 
static im_function convf_desc = {
	"im_convf", 			/* Name */
	"convolve, with DOUBLEMASK",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	convf_vec, 			/* Dispatch function */
	IM_NUMBER( conv_dmask ), 		/* Size of arg list */
	conv_dmask 			/* Arg list */
};

/* Call im_convf_raw via arg vector.
 */
static int
convf_raw_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_convf_raw( argv[0], argv[1], mo->mask ) );
}

/* Description of im_convf_raw.
 */ 
static im_function convf_raw_desc = {
	"im_convf_raw", 			/* Name */
	"convolve, with DOUBLEMASK, no border",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	convf_raw_vec, 			/* Dispatch function */
	IM_NUMBER( conv_dmask ), 		/* Size of arg list */
	conv_dmask 			/* Arg list */
};

/* Call im_convsep via arg vector.
 */
static int
convsep_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_convsep( argv[0], argv[1], mo->mask ) );
}

/* Description of im_convsep.
 */ 
static im_function convsep_desc = {
	"im_convsep", 			/* Name */
	"seperable convolution",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	convsep_vec, 			/* Dispatch function */
	IM_NUMBER( conv_imask ), 		/* Size of arg list */
	conv_imask 			/* Arg list */
};

/* Call im_convsep_raw via arg vector.
 */
static int
convsep_raw_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_convsep_raw( argv[0], argv[1], mo->mask ) );
}

/* Description of im_convsep_raw.
 */ 
static im_function convsep_raw_desc = {
	"im_convsep_raw", 			/* Name */
	"seperable convolution, no border",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	convsep_raw_vec, 		/* Dispatch function */
	IM_NUMBER( conv_imask ), 		/* Size of arg list */
	conv_imask 			/* Arg list */
};

/* Call im_convsepf via arg vector.
 */
static int
convsepf_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_convsepf( argv[0], argv[1], mo->mask ) );
}

/* Description of im_convsepf.
 */ 
static im_function convsepf_desc = {
	"im_convsepf", 			/* Name */
	"seperable convolution, with DOUBLEMASK",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	convsepf_vec, 			/* Dispatch function */
	IM_NUMBER( conv_dmask ), 		/* Size of arg list */
	conv_dmask 			/* Arg list */
};

/* Call im_convsepf_raw via arg vector.
 */
static int
convsepf_raw_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_convsepf_raw( argv[0], argv[1], mo->mask ) );
}

/* Description of im_convsepf_raw.
 */ 
static im_function convsepf_raw_desc = {
	"im_convsepf_raw", 		/* Name */
	"seperable convolution, with DOUBLEMASK, no border",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	convsepf_raw_vec, 		/* Dispatch function */
	IM_NUMBER( conv_dmask ), 		/* Size of arg list */
	conv_dmask 			/* Arg list */
};

/* Args for im_convsub.
 */
static im_arg_desc convsub_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_IMASK( "matrix" ),
	IM_INPUT_INT( "xskip" ),
	IM_INPUT_INT( "yskip" )
};

/* Call im_convsub via arg vector.
 */
static int
convsub_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];
	int xskip = *((int *) argv[3]);
	int yskip = *((int *) argv[4]);

	return( im_convsub( argv[0], argv[1], mo->mask, xskip, yskip ) );
}

/* Description of im_convsub.
 */ 
static im_function convsub_desc = {
	"im_convsub", 			/* Name */
	"convolve uchar to uchar, sub-sampling by xskip, yskip",
	IM_FN_TRANSFORM,		/* Flags */
	convsub_vec, 			/* Dispatch function */
	IM_NUMBER( convsub_args ),		/* Size of arg list */
	convsub_args 			/* Arg list */
};

/* Call im_fastcor via arg vector.
 */
static int
fastcor_vec( im_object *argv )
{
	return( im_fastcor( argv[0], argv[1], argv[2] ) );
}

/* Description of im_fastcor.
 */ 
static im_function fastcor_desc = {
	"im_fastcor", 			/* Name */
	"fast correlate in2 within in1",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	fastcor_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ),	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_fastcor_raw via arg vector.
 */
static int
fastcor_raw_vec( im_object *argv )
{
	return( im_fastcor_raw( argv[0], argv[1], argv[2] ) );
}

/* Description of im_fastcor_raw.
 */ 
static im_function fastcor_raw_desc = {
	"im_fastcor_raw", 		/* Name */
	"fast correlate in2 within in1, no border",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	fastcor_raw_vec,		/* Dispatch function */
	IM_NUMBER( two_in_one_out ),	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Args for im_gaussnoise.
 */
static im_arg_desc gaussnoise_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "xsize" ),
	IM_INPUT_INT( "ysize" ),
	IM_INPUT_DOUBLE( "mean" ),
	IM_INPUT_DOUBLE( "sigma" )
};

/* Call im_gaussnoise via arg vector.
 */
static int
gaussnoise_vec( im_object *argv )
{
	int xsize = *((int *) argv[1]);
	int ysize = *((int *) argv[2]);
	double mean = *((double *) argv[3]);
	double sigma = *((double *) argv[4]);

	if( im_gaussnoise( argv[0], xsize, ysize, mean, sigma ) )
		return( -1 );
	
	return( 0 );
}

/* Description of im_gaussnoise.
 */ 
static im_function gaussnoise_desc = {
	"im_gaussnoise", 		/* Name */
	"generate image of gaussian noise with specified statistics",
	IM_FN_PIO,			/* Flags */
	gaussnoise_vec, 		/* Dispatch function */
	IM_NUMBER( gaussnoise_args ), 	/* Size of arg list */
	gaussnoise_args 		/* Arg list */
};

/* Call im_grad_x via arg vector.
 */
static int
grad_x_vec( im_object *argv )
{
	return( im_grad_x( argv[0], argv[1] ) );
}

/* Description of im_grad_x.
 */ 
static im_function grad_x_desc = {
	"im_grad_x",	 		/* Name */
	"horizontal difference image",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	grad_x_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_grad_y via arg vector.
 */
static int
grad_y_vec( im_object *argv )
{
	return( im_grad_y( argv[0], argv[1] ) );
}

/* Description of im_grad_y.
 */ 
static im_function grad_y_desc = {
	"im_grad_y",	 		/* Name */
	"vertical difference image",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	grad_y_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_gradcor via arg vector.
 */
static int
gradcor_vec( im_object *argv )
{
	return( im_gradcor( argv[0], argv[1], argv[2] ) );
}

/* Description of im_gradcor.
 */ 
static im_function gradcor_desc = {
	"im_gradcor",	 		/* Name */
	"non-normalised correlation of gradient of in2 within in1",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	gradcor_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_gradcor_raw via arg vector.
 */
static int
gradcor_raw_vec( im_object *argv )
{
	return( im_gradcor_raw( argv[0], argv[1], argv[2] ) );
}

/* Description of im_gradcor_raw.
 */ 
static im_function gradcor_raw_desc = {
	"im_gradcor_raw",	 		/* Name */
	"non-normalised correlation of gradient of in2 within in1, no padding",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	gradcor_raw_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_gradient via arg vector.
 */
static int
gradient_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_gradient( argv[0], argv[1], mo->mask ) );
}

/* Description of im_gradient.
 */ 
static im_function gradient_desc = {
	"im_gradient", 			/* Name */
	"convolve with 2-way rotating mask",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	gradient_vec, 			/* Dispatch function */
	IM_NUMBER( conv_imask ), 		/* Size of arg list */
	conv_imask 			/* Arg list */
};

/* Call im_lindetect via arg vector.
 */
static int
lindetect_vec( im_object *argv )
{
	im_mask_object *mo = argv[2];

	return( im_lindetect( argv[0], argv[1], mo->mask ) );
}

/* Description of im_lindetect.
 */ 
static im_function lindetect_desc = {
	"im_lindetect", 		/* Name */
	"convolve with 4-way rotating mask",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	lindetect_vec, 			/* Dispatch function */
	IM_NUMBER( conv_imask ), 		/* Size of arg list */
	conv_imask 			/* Arg list */
};

/* Call im_spcor via arg vector.
 */
static int
spcor_vec( im_object *argv )
{
	return( im_spcor( argv[0], argv[1], argv[2] ) );
}

/* Description of im_spcor.
 */ 
static im_function spcor_desc = {
	"im_spcor",	 		/* Name */
	"normalised correlation of in2 within in1",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	spcor_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_spcor_raw via arg vector.
 */
static int
spcor_raw_vec( im_object *argv )
{
	return( im_spcor_raw( argv[0], argv[1], argv[2] ) );
}

/* Description of im_spcor_raw.
 */ 
static im_function spcor_raw_desc = {
	"im_spcor_raw",	 		/* Name */
	"normalised correlation of in2 within in1, no black padding",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	spcor_raw_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *convol_list[] = {
	&addgnoise_desc,
	&compass_desc,
	&contrast_surface_desc,
	&contrast_surface_raw_desc,
	&conv_desc,
	&convf_desc,
	&convf_raw_desc,
	&conv_raw_desc,
	&convsep_desc,
	&convsepf_desc,
	&convsepf_raw_desc,
	&convsep_raw_desc,
	&convsub_desc,
	&fastcor_desc,
	&fastcor_raw_desc,
	&gaussnoise_desc,
        &gradcor_desc,
        &gradcor_raw_desc,
	&gradient_desc,
        &grad_x_desc,
        &grad_y_desc,
	&lindetect_desc,
	&sharpen_desc,
	&spcor_desc,
	&spcor_raw_desc
};

/* Package of functions.
 */
im_package im__convolution = {
	"convolution",
	IM_NUMBER( convol_list ),
	convol_list
};
