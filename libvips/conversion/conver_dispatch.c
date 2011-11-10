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

#include <vips/vips.h>

/** 
 * SECTION: conversion
 * @short_description: convert images in some way: change band format, change header, insert, extract, join
 * @see_also: <link linkend="libvips-resample">resample</link>
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations convert an image in some way. They can be split into a two
 * main groups.
 *
 * The first set of operations change an image's format in some way. You
 * can change the band format (for example, cast to 32-bit unsigned
 * int), form complex images from real images, convert images to
 * matrices and back, change header fields, and a few others.
 *
 * The second group move pixels about in some way. You can flip, rotate,
 * extract, insert and join pairs of images in various ways.
 *
 */

static int
system_vec( im_object *argv )
{
	IMAGE *in = argv[0];
	char *cmd = argv[1];
	char **out = (char **) &argv[2];

	if( im_system( in, cmd, out ) )
		return( -1 );

	return( 0 );
}

static im_arg_desc system_args[] = {
	IM_INPUT_IMAGE( "im" ),
	IM_INPUT_STRING( "command" ),
	IM_OUTPUT_STRING( "output" )
};

static im_function system_desc = {
	"im_system",			/* Name */
	"run command on image",		/* Description */
	0,				/* Flags */
	system_vec, 			/* Dispatch function */
	IM_NUMBER( system_args ),	/* Size of arg list */
	system_args 			/* Arg list */
};

static int
system_image_vec( im_object *argv )
{
	IMAGE *in = argv[0];
	IMAGE *out = argv[1];
	char *in_format = argv[2];
	char *out_format = argv[3];
	char *cmd = argv[4];
	char **log = (char **) &argv[5];

	IMAGE *out_image;

	if( !(out_image = im_system_image( in, 
		in_format, out_format, cmd, log )) ) {
		im_error( "im_system_image", "%s", *log );
		return( -1 );
	}

	if( im_copy( out_image, out ) ||
		im_add_close_callback( out, 
			(im_callback_fn) im_close, out_image, NULL ) ) {
		im_close( out_image );
		return( -1 );
	}

	return( 0 );
}

static im_arg_desc system_image_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_STRING( "in_format" ),
	IM_INPUT_STRING( "out_format" ),
	IM_INPUT_STRING( "command" ),
	IM_OUTPUT_STRING( "log" )
};

static im_function system_image_desc = {
	"im_system_image",		/* Name */
	"run command on image, with image output",/* Description */
	0,				/* Flags */
	system_image_vec, 		/* Dispatch function */
	IM_NUMBER( system_image_args ),	/* Size of arg list */
	system_image_args 		/* Arg list */
};

static int
subsample_vec( im_object *argv )
{
	IMAGE *in = argv[0];
	IMAGE *out = argv[1];
	int xsh = *((int *) argv[2]);
	int ysh = *((int *) argv[3]);

	if( im_subsample( in, out, xsh, ysh ) )
		return( -1 );

	return( 0 );
}

static im_arg_desc subsample_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "xshrink" ),
	IM_INPUT_INT( "yshrink" )
};

static im_function subsample_desc = {
	"im_subsample",			/* Name */
	"subsample image by integer factors",	/* Description */
	IM_FN_PIO,			/* Flags */
	subsample_vec,			/* Dispatch function */
	IM_NUMBER( subsample_args ), 	/* Size of arg list */
	subsample_args 			/* Arg list */
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

/* Args to im_extract.
 */
static im_arg_desc extract_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "left" ),
	IM_INPUT_INT( "top" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" ),
	IM_INPUT_INT( "band" )
};

/* Call im_extract via arg vector.
 */
static int
extract_vec( im_object *argv )
{
	int left = *((int *) argv[2]);
	int top = *((int *) argv[3]);
	int width = *((int *) argv[4]);
	int height = *((int *) argv[5]);
	int band = *((int *) argv[6]);

	return( im_extract_areabands( argv[0], argv[1], 
		left, top, width, height, band, 1 ) );
}

/* Description of im_extract.
 */
static im_function extract_desc = {
	"im_extract", 			/* Name */
	"extract area/band",		/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	extract_vec, 			/* Dispatch function */
	IM_NUMBER( extract_args ), 	/* Size of arg list */
	extract_args 			/* Arg list */
};

/* Args to im_extract_area.
 */
static im_arg_desc extract_area_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "left" ),
	IM_INPUT_INT( "top" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" )
};

/* Call im_extract_area via arg vector.
 */
static int
extract_area_vec( im_object *argv )
{
	int x = *((int *) argv[2]);
	int y = *((int *) argv[3]);
	int w = *((int *) argv[4]);
	int h = *((int *) argv[5]);

	return( im_extract_area( argv[0], argv[1], x, y, w, h ) );
}

/* Description of im_extract_area.
 */
static im_function extract_area_desc = {
	"im_extract_area", 		/* Name */
	"extract area",			/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	extract_area_vec, 		/* Dispatch function */
	IM_NUMBER( extract_area_args ), /* Size of arg list */
	extract_area_args 		/* Arg list */
};

/* Args to im_extract_bands.
 */
static im_arg_desc extract_bands_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "band" ),
	IM_INPUT_INT( "nbands" ),
};

/* Call im_extract_bands via arg vector.
 */
static int
extract_bands_vec( im_object *argv )
{
	int chsel = *((int *) argv[2]);
	int nbands = *((int *) argv[3]);

	return( im_extract_bands( argv[0], argv[1], chsel, nbands ) );
}

/* Description of im_extract_bands.
 */
static im_function extract_bands_desc = {
	"im_extract_bands", 		/* Name */
	"extract several bands",	/* Description */
	IM_FN_PIO,			/* Flags */
	extract_bands_vec, 		/* Dispatch function */
	IM_NUMBER( extract_bands_args ),/* Size of arg list */
	extract_bands_args 		/* Arg list */
};

/* Args to im_extract_band.
 */
static im_arg_desc extract_band_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "band" )
};

/* Call im_extract_band via arg vector.
 */
static int
extract_band_vec( im_object *argv )
{
	int chsel = *((int *) argv[2]);

	return( im_extract_band( argv[0], argv[1], chsel ) );
}

/* Description of im_extract_band.
 */
static im_function extract_band_desc = {
	"im_extract_band", 		/* Name */
	"extract band",			/* Description */
	IM_FN_PIO,			/* Flags */
	extract_band_vec, 		/* Dispatch function */
	IM_NUMBER( extract_band_args ), /* Size of arg list */
	extract_band_args 		/* Arg list */
};

/* Args to im_extract_areabands.
 */
static im_arg_desc extract_areabands_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "left" ),
	IM_INPUT_INT( "top" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" ),
	IM_INPUT_INT( "band" ),
	IM_INPUT_INT( "nbands" )
};

/* Call im_extract_areabands via arg vector.
 */
static int
extract_areabands_vec( im_object *argv )
{
	int left = *((int *) argv[2]);
	int top = *((int *) argv[3]);
	int width = *((int *) argv[4]);
	int height = *((int *) argv[5]);
	int band = *((int *) argv[6]);
	int nbands = *((int *) argv[7]);

	return( im_extract_areabands( argv[0], argv[1],
		left, top, width, height, band, nbands ) );
}

/* Description of im_extract_areabands.
 */
static im_function extract_areabands_desc = {
	"im_extract_areabands",         /* Name */
	"extract area and bands",       /* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	extract_areabands_vec,          /* Dispatch function */
	IM_NUMBER( extract_areabands_args ),/* Size of arg list */
	extract_areabands_args          /* Arg list */
};

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

/* Call im_bandjoin via arg vector.
 */
static int
bandjoin_vec( im_object *argv )
{
	return( im_bandjoin( argv[0], argv[1], argv[2] ) );
}

/* Description of im_bandjoin.
 */
static im_function bandjoin_desc = {
	"im_bandjoin", 			/* Name */
	"bandwise join of two images",	/* Description */
	IM_FN_PIO,			/* Flags */
	bandjoin_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

static im_arg_desc gbandjoin_args[] = {
	IM_INPUT_IMAGEVEC( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

static int
gbandjoin_vec( im_object *argv )
{
	im_imagevec_object *iv = (im_imagevec_object *) argv[0];

	return( im_gbandjoin( iv->vec, argv[1], iv->n ) );
}

static im_function gbandjoin_desc = {
	"im_gbandjoin", 		/* Name */
	"bandwise join of many images",	/* Description */
	IM_FN_PIO,			/* Flags */
	gbandjoin_vec, 			/* Dispatch function */
	IM_NUMBER( gbandjoin_args ), 	/* Size of arg list */
	gbandjoin_args 			/* Arg list */
};

/* Args to im_text.
 */
static im_arg_desc text_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_STRING( "text" ),
	IM_INPUT_STRING( "font" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "alignment" ),
	IM_INPUT_INT( "dpi" )
};

/* Call im_text via arg vector.
 */
static int
text_vec( im_object *argv )
{
	int width = *((int *) argv[3]);
	int alignment = *((int *) argv[4]);
	int dpi = *((int *) argv[5]);

	return( im_text( argv[0], argv[1], argv[2], width, alignment, dpi ) );
}

/* Description of im_text.
 */
static im_function text_desc = {
	"im_text", 			/* Name */
	"generate text image",		/* Description */
	IM_FN_PIO,			/* Flags */
	text_vec, 			/* Dispatch function */
	IM_NUMBER( text_args ), 	/* Size of arg list */
	text_args 			/* Arg list */
};

/* Args to im_black.
 */
static im_arg_desc black_args[] = {
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "x_size" ),
	IM_INPUT_INT( "y_size" ),
	IM_INPUT_INT( "bands" )
};

/* Call im_black via arg vector.
 */
static int
black_vec( im_object *argv )
{
	int xs = *((int *) argv[1]);
	int ys = *((int *) argv[2]);
	int bands = *((int *) argv[3]);

	return( im_black( argv[0], xs, ys, bands ) );
}

/* Description of im_black.
 */
static im_function black_desc = {
	"im_black", 			/* Name */
	"generate black image",		/* Description */
	IM_FN_PIO,			/* Flags */
	black_vec, 			/* Dispatch function */
	IM_NUMBER( black_args ), 	/* Size of arg list */
	black_args 			/* Arg list */
};

/* Args to im_clip2fmt.
 */
static im_arg_desc clip2fmt_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "ofmt" )
};

/* Call im_clip2fmt via arg vector.
 */
static int
clip2fmt_vec( im_object *argv )
{
	int ofmt = *((int *) argv[2]);

	return( im_clip2fmt( argv[0], argv[1], ofmt ) );
}

/* Description of im_clip2fmt.
 */
static im_function clip2fmt_desc = {
	"im_clip2fmt", 			/* Name */
	"convert image format to ofmt",	/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	clip2fmt_vec, 			/* Dispatch function */
	IM_NUMBER( clip2fmt_args ),	/* Size of arg list */
	clip2fmt_args 			/* Arg list */
};

/* Call im_c2rect via arg vector.
 */
static int
c2rect_vec( im_object *argv )
{
	return( im_c2rect( argv[0], argv[1] ) );
}

/* Description of im_c2rect.
 */
static im_function c2rect_desc = {
	"im_c2rect", 			/* Name */
	"convert phase and amplitude to real and imaginary",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	c2rect_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_c2amph via arg vector.
 */
static int
c2amph_vec( im_object *argv )
{
	return( im_c2amph( argv[0], argv[1] ) );
}

/* Description of im_c2amph.
 */
static im_function c2amph_desc = {
	"im_c2amph", 			/* Name */
	"convert real and imaginary to phase and amplitude",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	c2amph_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_ri2c via arg vector.
 */
static int
ri2c_vec( im_object *argv )
{
	return( im_ri2c( argv[0], argv[1], argv[2] ) );
}

/* Description of im_ri2c.
 */
static im_function ri2c_desc = {
	"im_ri2c", 			/* Name */
	"join two non-complex images to form complex",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	ri2c_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_c2imag via arg vector.
 */
static int
c2imag_vec( im_object *argv )
{
	return( im_c2imag( argv[0], argv[1] ) );
}

/* Description of im_c2imag.
 */
static im_function c2imag_desc = {
	"im_c2imag", 			/* Name */
	"extract imaginary part of complex image",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	c2imag_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_c2real via arg vector.
 */
static int
c2real_vec( im_object *argv )
{
	return( im_c2real( argv[0], argv[1] ) );
}

/* Description of im_c2real.
 */
static im_function c2real_desc = {
	"im_c2real", 			/* Name */
	"extract real part of complex image",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	c2real_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Args to im_copy_set.
 */
static im_arg_desc copy_set_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "Type" ),
	IM_INPUT_DOUBLE( "Xres" ),
	IM_INPUT_DOUBLE( "Yres" ),
	IM_INPUT_INT( "Xoffset" ),
	IM_INPUT_INT( "Yoffset" )
};

/* Call im_copy_set via arg vector.
 */
static int
copy_set_vec( im_object *argv )
{
	int Type = *((int *) argv[2]);
	float Xres = *((double *) argv[3]);
	float Yres = *((double *) argv[4]);
	int Xoffset = *((int *) argv[5]);
	int Yoffset = *((int *) argv[6]);

	return( im_copy_set( argv[0], argv[1],
		Type, Xres, Yres, Xoffset, Yoffset ) );
}

/* Description of im_copy_set.
 */
static im_function copy_set_desc = {
	"im_copy_set", 			/* Name */
	"copy image, setting informational fields",

	/* Can't set PTOP ... we don't want to zap the LUT, we want the real
	 * image.
	 */
	IM_FN_PIO,			/* Flags */

	copy_set_vec, 			/* Dispatch function */
	IM_NUMBER( copy_set_args ), 	/* Size of arg list */
	copy_set_args 			/* Arg list */
};

/* Args to im_copy_set_meta.
 */
static im_arg_desc copy_set_meta_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_STRING( "field" ),
	IM_INPUT_GVALUE( "value" )
};

/* Call im_copy_set_meta via arg vector.
 */
static int
copy_set_meta_vec( im_object *argv )
{
	const char *field = argv[2];
	GValue *value = argv[3];

	return( im_copy_set_meta( argv[0], argv[1], field, value ) ); 
}

/* Description of im_copy_set_meta.
 */
static im_function copy_set_meta_desc = {
	"im_copy_set_meta", 		/* Name */
	"copy image, setting a meta field",

	/* Can't set PTOP ... we don't want to zap the LUT, we want the real
	 * image.
	 */
	IM_FN_PIO,			/* Flags */

	copy_set_meta_vec, 		/* Dispatch function */
	IM_NUMBER( copy_set_meta_args ),/* Size of arg list */
	copy_set_meta_args 		/* Arg list */
};

/* Args to im_copy_morph.
 */
static im_arg_desc copy_morph_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "Bands" ),
	IM_INPUT_INT( "BandFmt" ),
	IM_INPUT_INT( "Coding" )
};

/* Call im_copy_morph via arg vector.
 */
static int
copy_morph_vec( im_object *argv )
{
	int Bands = *((int *) argv[2]);
	int BandFmt = *((int *) argv[3]);
	int Coding = *((int *) argv[4]);

	return( im_copy_morph( argv[0], argv[1],
		Bands, BandFmt, Coding ) );
}

/* Description of im_copy_morph.
 */
static im_function copy_morph_desc = {
	"im_copy_morph", 			/* Name */
	"copy image, setting pixel layout",

	/* Can't set PTOP ... we don't want to zap the LUT, we want the real
	 * image.
	 */
	IM_FN_PIO,			/* Flags */

	copy_morph_vec, 		/* Dispatch function */
	IM_NUMBER( copy_morph_args ), 	/* Size of arg list */
	copy_morph_args 		/* Arg list */
};

/* Call im_copy via arg vector.
 */
static int
copy_vec( im_object *argv )
{
	return( im_copy( argv[0], argv[1] ) );
}

/* Description of im_copy.
 */
static im_function copy_desc = {
	"im_copy", 			/* Name */
	"copy image",

	/* Can't set PTOP ... we don't want to zap the LUT, we want the real
	 * image.
	 */
	IM_FN_PIO,			/* Flags */

	copy_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_copy_file via arg vector.
 */
static int
copy_file_vec( im_object *argv )
{
	return( im_copy_file( argv[0], argv[1] ) );
}

/* Description of im_copy_file.
 */
static im_function copy_file_desc = {
	"im_copy_file", 			/* Name */
	"copy image to a file and return that",

	/* Can't set PTOP ... we don't want to zap the LUT, we want the real
	 * image.
	 */
	IM_FN_PIO,			/* Flags */

	copy_file_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_copy_swap via arg vector.
 */
static int
copy_swap_vec( im_object *argv )
{
	return( im_copy_swap( argv[0], argv[1] ) );
}

/* Description of im_copy_swap.
 */
static im_function copy_swap_desc = {
	"im_copy_swap", 			/* Name */
	"copy image, swapping byte order",

	/* Can't set PTOP ... we don't want to zap the LUT, we want the real
	 * image.
	 */
	IM_FN_PIO,			/* Flags */

	copy_swap_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_fliphor via arg vector.
 */
static int
fliphor_vec( im_object *argv )
{
	return( im_fliphor( argv[0], argv[1] ) );
}

/* Description of im_fliphor.
 */
static im_function fliphor_desc = {
	"im_fliphor", 			/* Name */
	"flip image left-right",
	IM_FN_PIO,			/* Flags */
	fliphor_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_flipver via arg vector.
 */
static int
flipver_vec( im_object *argv )
{
	return( im_flipver( argv[0], argv[1] ) );
}

/* Description of im_flipver.
 */
static im_function flipver_desc = {
	"im_flipver", 			/* Name */
	"flip image top-bottom",
	IM_FN_PIO,			/* Flags */
	flipver_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_falsecolour via arg vector.
 */
static int
falsecolour_vec( im_object *argv )
{
	return( im_falsecolour( argv[0], argv[1] ) );
}

/* Description of im_falsecolour.
 */
static im_function falsecolour_desc = {
	"im_falsecolour", 		/* Name */
	"turn luminance changes into chrominance changes",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	falsecolour_vec, 		/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Args for im_insert.
 */
static im_arg_desc insert_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_IMAGE( "sub" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" )
};

/* Call im_insert via arg vector.
 */
static int
insert_vec( im_object *argv )
{
	int x = *((int *) argv[3]);
	int y = *((int *) argv[4]);

	return( im_insert( argv[0], argv[1], argv[2], x, y ) );
}

/* Description of im_insert.
 */
static im_function insert_desc = {
	"im_insert", 			/* Name */
	"insert sub-image into main image at position",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	insert_vec, 			/* Dispatch function */
	IM_NUMBER( insert_args ), 	/* Size of arg list */
	insert_args 			/* Arg list */
};

/* Args for im_insertset.
 */
static im_arg_desc insertset_args[] = {
	IM_INPUT_IMAGE( "main" ),
	IM_INPUT_IMAGE( "sub" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INTVEC( "x" ),
	IM_INPUT_INTVEC( "y" )
};

/* Call im_insertplaceset via arg vector.
 */
static int
insertset_vec( im_object *argv )
{
	im_intvec_object *xv = (im_intvec_object *) argv[3];
	im_intvec_object *yv = (im_intvec_object *) argv[4];

	if( xv->n != yv->n ) {
		im_error( "im_insertset", "%s", 
			_( "vectors not same length" ) );
		return( -1 );
	}

	if( im_insertset( argv[0], argv[1], argv[2], xv->n, xv->vec, yv->vec ) )
		return( -1 );

	return( 0 );
}

/* Description of im_insertset.
 */ 
static im_function insertset_desc = {
	"im_insertset", 		/* Name */
	"insert sub into main at every position in x, y",
	0,				/* Flags */
	insertset_vec, 			/* Dispatch function */
	IM_NUMBER( insertset_args ), 	/* Size of arg list */
	insertset_args 			/* Arg list */
};

/* Call im_insert_noexpand via arg vector.
 */
static int
insert_noexpand_vec( im_object *argv )
{
	int x = *((int *) argv[3]);
	int y = *((int *) argv[4]);

	return( im_insert_noexpand( argv[0], argv[1], argv[2], x, y ) );
}

/* Description of im_insert_noexpand.
 */
static im_function insert_noexpand_desc = {
	"im_insert_noexpand", 		/* Name */
	"insert sub-image into main image at position, no expansion",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	insert_noexpand_vec, 		/* Dispatch function */
	IM_NUMBER( insert_args ),	/* Size of arg list */
	insert_args 			/* Arg list */
};

/* Call im_rot180 via arg vector.
 */
static int
rot180_vec( im_object *argv )
{
	return( im_rot180( argv[0], argv[1] ) );
}

/* Description of im_rot180.
 */
static im_function rot180_desc = {
	"im_rot180", 			/* Name */
	"rotate image 180 degrees",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	rot180_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_rot90 via arg vector.
 */
static int
rot90_vec( im_object *argv )
{
	return( im_rot90( argv[0], argv[1] ) );
}

/* Description of im_rot90.
 */
static im_function rot90_desc = {
	"im_rot90", 			/* Name */
	"rotate image 90 degrees clockwise",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	rot90_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_rot270 via arg vector.
 */
static int
rot270_vec( im_object *argv )
{
	return( im_rot270( argv[0], argv[1] ) );
}

/* Description of im_rot270.
 */
static im_function rot270_desc = {
	"im_rot270", 			/* Name */
	"rotate image 270 degrees clockwise",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	rot270_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_lrjoin via arg vector.
 */
static int
lrjoin_vec( im_object *argv )
{
	return( im_lrjoin( argv[0], argv[1], argv[2] ) );
}

/* Description of im_lrjoin.
 */
static im_function lrjoin_desc = {
	"im_lrjoin", 			/* Name */
	"join two images left-right",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	lrjoin_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_tbjoin via arg vector.
 */
static int
tbjoin_vec( im_object *argv )
{
	return( im_tbjoin( argv[0], argv[1], argv[2] ) );
}

/* Description of im_tbjoin.
 */
static im_function tbjoin_desc = {
	"im_tbjoin", 			/* Name */
	"join two images top-bottom",
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	tbjoin_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_scale via arg vector.
 */
static int
scale_vec( im_object *argv )
{
	return( im_scale( argv[0], argv[1] ) );
}

/* Description of im_scale.
 */
static im_function scale_desc = {
	"im_scale", 			/* Name */
	"scale image linearly to fit range 0-255",
	IM_FN_PIO,			/* Flags */
	scale_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_scaleps via arg vector.
 */
static int
scaleps_vec( im_object *argv )
{
	return( im_scaleps( argv[0], argv[1] ) );
}

/* Description of im_scaleps.
 */
static im_function scaleps_desc = {
	"im_scaleps", 			/* Name */
	"logarithmic scale of image to fit range 0-255",
	0,				/* Flags */
	scaleps_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Args to im_grid.
 */
static im_arg_desc grid_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "tile_height" ),
	IM_INPUT_INT( "across" ),
	IM_INPUT_INT( "down" )
};

/* Call im_grid via arg vector.
 */
static int
grid_vec( im_object *argv )
{
	int tile_height = *((int *) argv[2]);
	int across = *((int *) argv[3]);
	int down = *((int *) argv[4]);

	return( im_grid( argv[0], argv[1], tile_height, across, down ) );
}

/* Description of im_grid.
 */
static im_function grid_desc = {
	"im_grid", 			/* Name */
	"chop a tall thin image into a grid of images",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	grid_vec, 			/* Dispatch function */
	IM_NUMBER( grid_args ), 	/* Size of arg list */
	grid_args 			/* Arg list */
};

/* Args to im_replicate.
 */
static im_arg_desc replicate_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "across" ),
	IM_INPUT_INT( "down" )
};

/* Call im_replicate via arg vector.
 */
static int
replicate_vec( im_object *argv )
{
	int across = *((int *) argv[2]);
	int down = *((int *) argv[3]);

	return( im_replicate( argv[0], argv[1], across, down ) );
}

/* Description of im_replicate.
 */
static im_function replicate_desc = {
	"im_replicate", 		/* Name */
	"replicate an image horizontally and vertically",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	replicate_vec, 			/* Dispatch function */
	IM_NUMBER( replicate_args ), 	/* Size of arg list */
	replicate_args 			/* Arg list */
};

/* Args to im_zoom.
 */
static im_arg_desc zoom_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_INT( "xfac" ),
	IM_INPUT_INT( "yfac" )
};

/* Call im_zoom via arg vector.
 */
static int
zoom_vec( im_object *argv )
{
	int xfac = *((int *) argv[2]);
	int yfac = *((int *) argv[3]);

	return( im_zoom( argv[0], argv[1], xfac, yfac ) );
}

/* Description of im_zoom.
 */
static im_function zoom_desc = {
	"im_zoom", 			/* Name */
	"simple zoom of an image by integer factors",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	zoom_vec, 			/* Dispatch function */
	IM_NUMBER( zoom_args ),		/* Size of arg list */
	zoom_args 			/* Arg list */
};

/* Call im_msb via arg vector.
 */
static int
msb_vec (im_object * argv)
{
  return im_msb (argv[0], argv[1]);
}

/* Description of im_msb.
 */
static im_function msb_desc = {
  "im_msb",			/* Name */
  "convert to uchar by discarding bits",
  IM_FN_PIO | IM_FN_PTOP,	/* Flags */
  msb_vec,			/* Dispatch function */
  IM_NUMBER (one_in_one_out),	/* Size of arg list */
  one_in_one_out		/* Arg list */
};

/* Args to im_msb_band.
 */
static im_arg_desc msb_band_args[] = {
  IM_INPUT_IMAGE ("in"),
  IM_OUTPUT_IMAGE ("out"),
  IM_INPUT_INT ("band")
};

/* Call im_msb_band via arg vector.
 */
static int
msb_band_vec (im_object * argv)
{
  IMAGE *in = (IMAGE *) argv[0];
  IMAGE *out = (IMAGE *) argv[1];
  int *band = (int *) argv[2];

  return im_msb_band (in, out, *band);
}

/* Description of im_msb_band.
 */
static im_function msb_band_desc = {
  "im_msb_band",		/* Name */
  "convert to single band uchar by discarding bits",
  IM_FN_PIO | IM_FN_PTOP,	/* Flags */
  msb_band_vec,			/* Dispatch function */
  IM_NUMBER (msb_band_args),	/* Size of arg list */
  msb_band_args			/* Arg list */
};

/* Args to im_wrap.
 */
static im_arg_desc wrap_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" )
};

/* Call im_wrap via arg vector.
 */
static int
wrap_vec (im_object * argv)
{
  return im_wrap( argv[0], argv[1], *(int*)argv[2], *(int*)argv[3] );
}

/* Description of im_wrap.
 */
static im_function wrap_desc = {
  "im_wrap",			/* Name */
  "shift image origin, wrapping at sides",
  IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
  wrap_vec,			/* Dispatch function */
  IM_NUMBER (wrap_args),	/* Size of arg list */
  wrap_args			/* Arg list */
};

/* Args for im_embed.
 */
static im_arg_desc embed_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "type" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" )
};

/* Call im_embed via arg vector.
 */
static int
embed_vec( im_object *argv )
{
	int type = *((int *) argv[2]);
	int x = *((int *) argv[3]);
	int y = *((int *) argv[4]);
	int width = *((int *) argv[5]);
	int height = *((int *) argv[6]);

	return( im_embed( argv[0], argv[1], type, x, y, width, height ) );
}

/* Description of im_embed.
 */ 
static im_function embed_desc = {
	"im_embed",	 		/* Name */
	"embed in within a set of borders", 
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	embed_vec, 			/* Dispatch function */
	IM_NUMBER( embed_args ), 	/* Size of arg list */
	embed_args 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *conv_list[] = {
	&gaussnoise_desc,
	&bandjoin_desc,
	&black_desc,
	&c2amph_desc,
	&c2imag_desc,
	&c2real_desc,
	&c2rect_desc,
	&clip2fmt_desc,
	&copy_desc,
	&copy_file_desc,
	&copy_morph_desc,
	&copy_swap_desc,
	&copy_set_desc,
	&copy_set_meta_desc,
	&extract_area_desc,
	&extract_areabands_desc,
	&extract_band_desc,
	&extract_bands_desc,
	&extract_desc,
	&falsecolour_desc,
	&fliphor_desc,
	&flipver_desc,
	&gbandjoin_desc,
	&grid_desc,
	&insert_desc,
	&insertset_desc,
	&insert_noexpand_desc,
	&embed_desc,
	&lrjoin_desc,
        &msb_desc,
        &msb_band_desc,
	&replicate_desc,
	&ri2c_desc,
	&rot180_desc,
	&rot270_desc,
	&rot90_desc,
	&scale_desc,
	&scaleps_desc,
	&subsample_desc,
	&system_desc,
	&system_image_desc,
	&tbjoin_desc,
	&text_desc,
	&wrap_desc,
	&zoom_desc
};

/* Package of functions.
 */
im_package im__conversion = {
	"conversion",
	IM_NUMBER( conv_list ),
	conv_list
};
