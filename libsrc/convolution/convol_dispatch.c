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

/* Args for im_read_dmask()
 */
static im_arg_desc read_dmask_args[] = {
	IM_INPUT_STRING( "filename" ),
	IM_OUTPUT_DMASK( "mask" )
};

/* Call im_read_dmask via arg vector.
 */
static int
read_dmask_vec( im_object *argv )
{
	im_mask_object *mo = argv[1];

	if( !(mo->mask = im_read_dmask( argv[0] )) )
		return( -1 );

	return( 0 );
}

/* Description of im_read_dmask().
 */ 
static im_function read_dmask_desc = {
	"im_read_dmask",		/* Name */
	"read matrix of double from file",
	0,				/* Flags */
	read_dmask_vec, 		/* Dispatch function */
	IM_NUMBER( read_dmask_args ),	/* Size of arg list */
	read_dmask_args 		/* Arg list */
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

/* Args for im_gauss_dmask.
 */
static im_arg_desc gauss_dmask_args[] = {
	IM_OUTPUT_DMASK( "mask" ),
	IM_INPUT_DOUBLE( "sigma" ),
	IM_INPUT_DOUBLE( "min_amp" )
};

/* Call im_gauss_dmask via arg vector.
 */
static int
gauss_dmask_vec( im_object *argv )
{
	im_mask_object *mo = argv[0];
	double sigma = *((double *) argv[1]);
	double min_amp = *((double *) argv[2]);

	if( !(mo->mask = 
		im_gauss_dmask( mo->name, sigma, min_amp )) )
		return( -1 );
	
	return( 0 );
}

/* Description of im_gauss_dmask.
 */ 
static im_function gauss_dmask_desc = {
	"im_gauss_dmask", 		/* Name */
	"generate gaussian DOUBLEMASK",
	0,				/* Flags */
	gauss_dmask_vec, 		/* Dispatch function */
	IM_NUMBER( gauss_dmask_args ), 	/* Size of arg list */
	gauss_dmask_args 		/* Arg list */
};

/* Args for im_gauss_imask.
 */
static im_arg_desc gauss_imask_args[] = {
	IM_OUTPUT_IMASK( "mask" ),
	IM_INPUT_DOUBLE( "sigma" ),
	IM_INPUT_DOUBLE( "min_amp" )
};

/* Call im_gauss_imask via arg vector.
 */
static int
gauss_imask_vec( im_object *argv )
{
	im_mask_object *mo = argv[0];
	double sigma = *((double *) argv[1]);
	double min_amp = *((double *) argv[2]);

	if( !(mo->mask = 
		im_gauss_imask( mo->name, sigma, min_amp )) )
		return( -1 );
	
	return( 0 );
}

/* Description of im_gauss_imask.
 */ 
static im_function gauss_imask_desc = {
	"im_gauss_imask", 		/* Name */
	"generate gaussian INTMASK",
	0,				/* Flags */
	gauss_imask_vec, 		/* Dispatch function */
	IM_NUMBER( gauss_imask_args ), 	/* Size of arg list */
	gauss_imask_args 		/* Arg list */
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

/* Args for im_log_imask.
 */
static im_arg_desc log_imask_args[] = {
	IM_OUTPUT_IMASK( "mask" ),
	IM_INPUT_DOUBLE( "sigma" ),
	IM_INPUT_DOUBLE( "min_amp" )
};

/* Call im_log_imask via arg vector.
 */
static int
log_imask_vec( im_object *argv )
{
	im_mask_object *mo = argv[0];
	double sigma = *((double *) argv[1]);
	double min_amp = *((double *) argv[2]);

	if( !(mo->mask = 
		im_log_imask( mo->name, sigma, min_amp )) )
		return( -1 );

	return( 0 );
}

/* Description of im_log_imask.
 */ 
static im_function log_imask_desc = {
	"im_log_imask", 		/* Name */
	"generate laplacian of gaussian INTMASK",
	0,				/* Flags */
	log_imask_vec, 			/* Dispatch function */
	IM_NUMBER( log_imask_args ), 	/* Size of arg list */
	log_imask_args 			/* Arg list */
};

/* Args for im_log_dmask.
 */
static im_arg_desc log_dmask_args[] = {
	IM_OUTPUT_DMASK( "maskfile" ),
	IM_INPUT_DOUBLE( "sigma" ),
	IM_INPUT_DOUBLE( "min_amp" )
};

/* Call im_log_dmask via arg vector.
 */
static int
log_dmask_vec( im_object *argv )
{
	im_mask_object *mo = argv[0];
	double sigma = *((double *) argv[1]);
	double min_amp = *((double *) argv[2]);

	if( !(mo->mask = 
		im_log_dmask( mo->name, sigma, min_amp )) )
		return( -1 );

	return( 0 );
}

/* Description of im_log_dmask.
 */ 
static im_function log_dmask_desc = {
	"im_log_dmask", 		/* Name */
	"generate laplacian of gaussian DOUBLEMASK",
	0,				/* Flags */
	log_dmask_vec, 			/* Dispatch function */
	IM_NUMBER( log_dmask_args ), 	/* Size of arg list */
	log_dmask_args 			/* Arg list */
};

/* Args for im_resize_linear.
 */
static im_arg_desc resize_linear_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "X" ),
	IM_INPUT_INT( "Y" )
};

/* Call im_resize_linear via arg vector.
 */
static int
resize_linear_vec( im_object *argv )
{
	int X = *((int *) argv[2]);
	int Y = *((int *) argv[3]);

	return( im_resize_linear( argv[0], argv[1], X, Y ) );
}

/* Description of im_resize_linear.
 */ 
static im_function resize_linear_desc = {
	"im_resize_linear",	 	/* Name */
	"resize to X by Y pixels with linear interpolation",
	0,				/* Flags */
	resize_linear_vec, 		/* Dispatch function */
	IM_NUMBER( resize_linear_args ), 	/* Size of arg list */
	resize_linear_args 		/* Arg list */
};

/* Args for im_mpercent.
 */
static im_arg_desc mpercent_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_DOUBLE( "percent" ),
	IM_OUTPUT_INT( "thresh" )
};

/* Call im_mpercent via arg vector.
 */
static int
mpercent_vec( im_object *argv )
{
	double percent = *((double *) argv[1]);

	return( im_mpercent( argv[0], percent, argv[2] ) );
}

/* Description of im_mpercent.
 */ 
static im_function mpercent_desc = {
	"im_mpercent",	 		/* Name */
	"find threshold above which there are percent values",
	0,				/* Flags */
	mpercent_vec, 			/* Dispatch function */
	IM_NUMBER( mpercent_args ), 	/* Size of arg list */
	mpercent_args 			/* Arg list */
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

/* Args for im_embed.
 */
static im_arg_desc embed_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "type" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_INT( "w" ),
	IM_INPUT_INT( "h" )
};

/* Call im_embed via arg vector.
 */
static int
embed_vec( im_object *argv )
{
	int type = *((int *) argv[2]);
	int x = *((int *) argv[3]);
	int y = *((int *) argv[4]);
	int w = *((int *) argv[5]);
	int h = *((int *) argv[6]);

	return( im_embed( argv[0], argv[1], type, x, y, w, h ) );
}

/* Description of im_embed.
 */ 
static im_function embed_desc = {
	"im_embed",	 		/* Name */
	"embed in within a set of borders", 
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	embed_vec, 			/* Dispatch function */
	IM_NUMBER( embed_args ), 		/* Size of arg list */
	embed_args 			/* Arg list */
};

/* Mask functions!
 */
static im_arg_desc imask_args[] = {
	IM_INPUT_IMASK( "in" ),
	IM_OUTPUT_IMASK( "out" )
};

static im_arg_desc dmask_args[] = {
	IM_INPUT_DMASK( "in" ),
	IM_OUTPUT_DMASK( "out" )
};

/* Call im_rotate_imask45 via arg vector.
 */
static int
rotate_imask45_vec( im_object *argv )
{
	im_mask_object *min = argv[0];
	im_mask_object *mout = argv[1];

	if( !(mout->mask = im_rotate_imask45( min->mask, mout->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_rotate_imask45.
 */ 
static im_function rotate_imask45_desc = {
	"im_rotate_imask45",	 	/* Name */
	"rotate INTMASK clockwise by 45 degrees",
	0,				/* Flags */
	rotate_imask45_vec, 		/* Dispatch function */
	IM_NUMBER( imask_args ), 		/* Size of arg list */
	imask_args 			/* Arg list */
};

/* Call im_rotate_imask90 via arg vector.
 */
static int
rotate_imask90_vec( im_object *argv )
{
	im_mask_object *min = argv[0];
	im_mask_object *mout = argv[1];

	if( !(mout->mask = im_rotate_imask90( min->mask, mout->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_rotate_imask90.
 */ 
static im_function rotate_imask90_desc = {
	"im_rotate_imask90",	 	/* Name */
	"rotate INTMASK clockwise by 90 degrees",
	0,				/* Flags */
	rotate_imask90_vec, 		/* Dispatch function */
	IM_NUMBER( imask_args ), 		/* Size of arg list */
	imask_args 			/* Arg list */
};

/* Call im_rotate_dmask45 via arg vector.
 */
static int
rotate_dmask45_vec( im_object *argv )
{
	im_mask_object *min = argv[0];
	im_mask_object *mout = argv[1];

	if( !(mout->mask = im_rotate_dmask45( min->mask, mout->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_rotate_dmask45.
 */ 
static im_function rotate_dmask45_desc = {
	"im_rotate_dmask45",	 	/* Name */
	"rotate DOUBLEMASK clockwise by 45 degrees",
	0,				/* Flags */
	rotate_dmask45_vec, 		/* Dispatch function */
	IM_NUMBER( dmask_args ), 		/* Size of arg list */
	dmask_args 			/* Arg list */
};

/* Call im_rotate_dmask90 via arg vector.
 */
static int
rotate_dmask90_vec( im_object *argv )
{
	im_mask_object *min = argv[0];
	im_mask_object *mout = argv[1];

	if( !(mout->mask = im_rotate_dmask90( min->mask, mout->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_rotate_dmask90.
 */ 
static im_function rotate_dmask90_desc = {
	"im_rotate_dmask90",	 	/* Name */
	"rotate DOUBLEMASK clockwise by 90 degrees",
	0,				/* Flags */
	rotate_dmask90_vec, 		/* Dispatch function */
	IM_NUMBER( dmask_args ), 		/* Size of arg list */
	dmask_args 			/* Arg list */
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

static int
imask_xsize_vec( im_object *argv )
{
  *( (int*) argv[1] )= ( (INTMASK*) ( ( (im_mask_object*) argv[0] )-> mask ) )-> xsize;
  return 0;
}

static int
imask_ysize_vec( im_object *argv )
{
  *( (int*) argv[1] )= ( (INTMASK*) ( ( (im_mask_object*) argv[0] )-> mask ) )-> ysize;
  return 0;
}

static int
dmask_xsize_vec( im_object *argv )
{
  *( (int*) argv[1] )= ( (DOUBLEMASK*) ( ( (im_mask_object*) argv[0] )-> mask ) )-> xsize;
  return 0;
}

static int
dmask_ysize_vec( im_object *argv )
{
  *( (int*) argv[1] )= ( (DOUBLEMASK*) ( ( (im_mask_object*) argv[0] )-> mask ) )-> ysize;
  return 0;
}

static im_arg_desc imask_size_args[] = {
	IM_INPUT_IMASK( "mask" ),
	IM_OUTPUT_INT( "size" )
};

static im_arg_desc dmask_size_args[] = {
	IM_INPUT_DMASK( "mask" ),
	IM_OUTPUT_INT( "size" )
};

static im_function imask_xsize_desc = {
	"im_imask_xsize",	 	/* Name */
	"horizontal size of an intmask",	/* Description */
	0,				/* Flags */
	imask_xsize_vec,		/* Dispatch function */
	IM_NUMBER( imask_size_args ),	/* Size of arg list */
	imask_size_args			/* Arg list */
};

static im_function imask_ysize_desc = {
	"im_imask_ysize",	 	/* Name */
	"vertical size of an intmask",	/* Description */
	0,				/* Flags */
	imask_ysize_vec,		/* Dispatch function */
	IM_NUMBER( imask_size_args ),	/* Size of arg list */
	imask_size_args			/* Arg list */
};

static im_function dmask_xsize_desc = {
	"im_dmask_xsize",	 	/* Name */
	"horizontal size of a doublemask",	/* Description */
	0,				/* Flags */
	dmask_xsize_vec,		/* Dispatch function */
	IM_NUMBER( dmask_size_args ),	/* Size of arg list */
	dmask_size_args			/* Arg list */
};

static im_function dmask_ysize_desc = {
	"im_dmask_ysize",	 	/* Name */
	"vertical size of a doublemask",	/* Description */
	0,				/* Flags */
	dmask_ysize_vec,		/* Dispatch function */
	IM_NUMBER( dmask_size_args ),	/* Size of arg list */
	dmask_size_args			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *convol_list[] = {
	&addgnoise_desc,
	&compass_desc,
	&contrast_surface_desc,
	&contrast_surface_raw_desc,
	&conv_desc,
	&conv_raw_desc,
	&convf_desc,
	&convf_raw_desc,
	&convsep_desc,
	&convsep_raw_desc,
	&convsepf_desc,
	&convsepf_raw_desc,
	&convsub_desc,
        &dmask_xsize_desc,
        &dmask_ysize_desc,
	&embed_desc,
	&fastcor_desc,
	&fastcor_raw_desc,
	&gauss_dmask_desc,
	&gauss_imask_desc,
	&gaussnoise_desc,
        &grad_x_desc,
        &grad_y_desc,
        &gradcor_desc,
        &gradcor_raw_desc,
	&gradient_desc,
        &imask_xsize_desc,
        &imask_ysize_desc,
	&rank_image_desc,
	&lindetect_desc,
	&log_dmask_desc,
	&log_imask_desc,
	&maxvalue_desc,
	&mpercent_desc,
	&rank_desc,
	&rank_raw_desc,
	&read_dmask_desc,
	&resize_linear_desc,
	&rotate_dmask45_desc,
	&rotate_dmask90_desc,
	&rotate_imask45_desc,
	&rotate_imask90_desc,
	&sharpen_desc,
	&shrink_desc,
	&spcor_desc,
	&spcor_raw_desc,
	&stretch3_desc,
	&zerox_desc
};

/* Package of functions.
 */
im_package im__convolution = {
	"convolution",
	IM_NUMBER( convol_list ),
	convol_list
};
