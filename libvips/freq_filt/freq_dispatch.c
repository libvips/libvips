/* Function dispatch tables for freq_filt.
 *
 * J. Cupitt, 23/2/95
 * 22/4/97 JC
 *	- oops, im_freqflt() was wrong
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
#include <stdarg.h>

#include <vips/vips.h>
#include <vips/fmask.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: freq_filt
 * @short_description: fourier transforms and frequency-domin filters
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 * To and from Fourier space, filter in Fourier space, convert Fourier-space
 * images to a displayable form.
 */

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

/* Args to im_create_fmask().
 */
static im_arg_desc create_fmask_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" ),
	IM_INPUT_INT( "type" ),
	IM_INPUT_DOUBLE( "p1" ),
	IM_INPUT_DOUBLE( "p2" ),
	IM_INPUT_DOUBLE( "p3" ),
	IM_INPUT_DOUBLE( "p4" ),
	IM_INPUT_DOUBLE( "p5" )
};

/* Call im_create_fmask via arg vector.
 */
static int
create_fmask_vec( im_object *argv )
{
	int width = *((int *) argv[1]);
	int height = *((int *) argv[2]);
	int type = *((int *) argv[3]);
	double p1 = *((double *) argv[4]);
	double p2 = *((double *) argv[5]);
	double p3 = *((double *) argv[6]);
	double p4 = *((double *) argv[7]);
	double p5 = *((double *) argv[8]);

	return( im_create_fmask( argv[0], width, height,
		type, p1, p2, p3, p4, p5 ) );
}

/* Description of im_create_fmask.
 */ 
static im_function create_fmask_desc = {
	"im_create_fmask", 		/* Name */
	"create frequency domain filter mask",
	0,				/* Flags */
	create_fmask_vec, 		/* Dispatch function */
	IM_NUMBER( create_fmask_args ), 	/* Size of arg list */
	create_fmask_args 		/* Arg list */
};

/* Args to im_flt_image_freq().
 */
static im_arg_desc flt_image_freq_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "type" ),
	IM_INPUT_DOUBLE( "p1" ),
	IM_INPUT_DOUBLE( "p2" ),
	IM_INPUT_DOUBLE( "p3" ),
	IM_INPUT_DOUBLE( "p4" ),
	IM_INPUT_DOUBLE( "p5" )
};

/* Call im_flt_image_freq via arg vector.
 */
static int
flt_image_freq_vec( im_object *argv )
{
	int type = *((int *) argv[2]);
	double p1 = *((double *) argv[3]);
	double p2 = *((double *) argv[4]);
	double p3 = *((double *) argv[5]);
	double p4 = *((double *) argv[6]);
	double p5 = *((double *) argv[7]);

	return( im_flt_image_freq( argv[0], argv[1], 
		type, p1, p2, p3, p4, p5 ) );
}

/* Description of im_flt_image_freq.
 */ 
static im_function flt_image_freq_desc = {
	"im_flt_image_freq", 		/* Name */
	"frequency domain filter image",
	0,				/* Flags */
	flt_image_freq_vec, 		/* Dispatch function */
	IM_NUMBER( flt_image_freq_args ), 	/* Size of arg list */
	flt_image_freq_args 		/* Arg list */
};

/* Args to im_fractsurf().
 */
static im_arg_desc fractsurf_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "size" ),
	IM_INPUT_DOUBLE( "dimension" )
};

/* Call im_fractsurf via arg vector.
 */
static int
fractsurf_vec( im_object *argv )
{
	int size = *((int *) argv[1]);
	double dim = *((double *) argv[2]);

	return( im_fractsurf( argv[0], size, dim ) );
}

/* Description of im_fractsurf.
 */ 
static im_function fractsurf_desc = {
	"im_fractsurf", 			/* Name */
	"generate a fractal surface of given dimension",
	IM_FN_TRANSFORM,		/* Flags */
	fractsurf_vec, 			/* Dispatch function */
	IM_NUMBER( fractsurf_args ), 	/* Size of arg list */
	fractsurf_args 			/* Arg list */
};

/* Args to im_freqflt().
 */
static im_arg_desc freqflt_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_IMAGE( "mask" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_freqflt via arg vector.
 */
static int
freqflt_vec( im_object *argv )
{
	return( im_freqflt( argv[0], argv[1], argv[2] ) );
}

/* Description of im_freqflt.
 */ 
static im_function freqflt_desc = {
	"im_freqflt", 			/* Name */
	"frequency-domain filter of in with mask",
	IM_FN_TRANSFORM,		/* Flags */
	freqflt_vec, 			/* Dispatch function */
	IM_NUMBER( freqflt_args ), 	/* Size of arg list */
	freqflt_args 			/* Arg list */
};

/* Call im_disp_ps via arg vector.
 */
static int
disp_ps_vec( im_object *argv )
{
	return( im_disp_ps( argv[0], argv[1] ) );
}

/* Description of im_disp_ps.
 */ 
static im_function disp_ps_desc = {
	"im_disp_ps", 			/* Name */
	"make displayable power spectrum",
	IM_FN_TRANSFORM,		/* Flags */
	disp_ps_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_rotquad via arg vector.
 */
static int
rotquad_vec( im_object *argv )
{
	return( im_rotquad( argv[0], argv[1] ) );
}

/* Description of im_rotquad.
 */ 
static im_function rotquad_desc = {
	"im_rotquad", 			/* Name */
	"rotate image quadrants to move origin to centre",
	IM_FN_TRANSFORM,		/* Flags */
	rotquad_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_fwfft via arg vector.
 */
static int
fwfft_vec( im_object *argv )
{
	return( im_fwfft( argv[0], argv[1] ) );
}

/* Description of im_fwfft.
 */ 
static im_function fwfft_desc = {
	"im_fwfft", 			/* Name */
	"forward fast-fourier transform",
	IM_FN_TRANSFORM,		/* Flags */
	fwfft_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_invfft via arg vector.
 */
static int
invfft_vec( im_object *argv )
{
	return( im_invfft( argv[0], argv[1] ) );
}

/* Description of im_invfft.
 */ 
static im_function invfft_desc = {
	"im_invfft", 			/* Name */
	"inverse fast-fourier transform",
	IM_FN_TRANSFORM,		/* Flags */
	invfft_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_invfftr via arg vector.
 */
static int
invfftr_vec( im_object *argv )
{
	return( im_invfftr( argv[0], argv[1] ) );
}

/* Description of im_invfftr.
 */ 
static im_function invfftr_desc = {
	"im_invfftr", 			/* Name */
	"real part of inverse fast-fourier transform",
	IM_FN_TRANSFORM,		/* Flags */
	invfftr_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_phasecor_fft via arg vector.
 */
static int
phasecor_fft_vec( im_object *argv )
{
	return( im_phasecor_fft( argv[0], argv[1], argv[2] ) );
}

/* Description of im_phasecor_fft.
 */ 
static im_function phasecor_fft_desc = {
	"im_phasecor_fft",	 		/* Name */
	"non-normalised correlation of gradient of in2 within in1",
	IM_FN_TRANSFORM,	/* Flags */
	phasecor_fft_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *freq_list[] = {
	&create_fmask_desc,
	&disp_ps_desc,
	&flt_image_freq_desc,
	&fractsurf_desc,
	&freqflt_desc,
	&fwfft_desc,
	&rotquad_desc,
	&invfft_desc,
	&phasecor_fft_desc,
	&invfftr_desc
};

/* Package of functions.
 */
im_package im__freq_filt = {
	"freq_filt",
	IM_NUMBER( freq_list ),
	freq_list
};
