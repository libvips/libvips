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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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
#include <vips/internal.h>

/* One image in, one out.
 */
static im_arg_desc one_in_one_out[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

static im_arg_desc quadratic_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_IMAGE( "coeff" )
};

static int
quadratic_vec( im_object *argv )
{
	return( im_quadratic( argv[0], argv[1], argv[2] ) );
}

static im_function quadratic_desc = {
	"im_quadratic", 		/* Name */
	"transform via quadratic",
	IM_FN_PIO,			/* Flags */
	quadratic_vec, 			/* Dispatch function */
	IM_NUMBER( quadratic_args ), 	/* Size of arg list */
	quadratic_args 			/* Arg list */
};

/* Two images in, one out.
 */
static im_arg_desc two_in_one_out[] = {
	IM_INPUT_IMAGE( "in1" ),
	IM_INPUT_IMAGE( "in2" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_clip via arg vector.
 */
static int
clip_vec( im_object *argv )
{
	return( im_clip( argv[0], argv[1] ) );
}

/* Description of im_clip.
 */
static im_function clip_desc = {
	"im_clip", 			/* Name */
	"convert to unsigned 8-bit integer",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_c2ps via arg vector.
 */
static int
c2ps_vec( im_object *argv )
{
	return( im_c2ps( argv[0], argv[1] ) );
}

/* Description of im_c2ps.
 */
static im_function c2ps_desc = {
	"im_c2ps", 			/* Name */
	"find power spectrum of complex image",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	c2ps_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Args for im_lhisteq.
 */
static im_arg_desc lhisteq_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" )
};

/* Args for im_stdif.
 */
static im_arg_desc stdif_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_DOUBLE( "m0" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_DOUBLE( "s0" ),
	IM_INPUT_INT( "xw" ),
	IM_INPUT_INT( "yw" )
};

/* Args to im_erode.
 */
static im_arg_desc erode_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_IMASK( "mask" )
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

/* affine args
 */
static im_arg_desc affine_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_DOUBLE( "c" ),
	IM_INPUT_DOUBLE( "d" ),
	IM_INPUT_DOUBLE( "dx" ),
	IM_INPUT_DOUBLE( "dy" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_INT( "w" ),
	IM_INPUT_INT( "h" )
};

/* Call im_affine via arg vector.
 */
static int
affine_vec( im_object *argv )
{
	double a = *((double *) argv[2]);
	double b = *((double *) argv[3]);
	double c = *((double *) argv[4]);
	double d = *((double *) argv[5]);
	double dx = *((double *) argv[6]);
	double dy = *((double *) argv[7]);
	int x = *((int *) argv[8]);
	int y = *((int *) argv[9]);
	int w = *((int *) argv[10]);
	int h = *((int *) argv[11]);

	return( im_affine( argv[0], argv[1], a, b, c, d, dx, dy, x, y, w, h ) );
}

/* Description of im_affine.
 */ 
static im_function affine_desc = {
	"im_affine", 			/* Name */
	"affine transform",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	affine_vec, 			/* Dispatch function */
	IM_NUMBER( affine_args ), 		/* Size of arg list */
	affine_args 			/* Arg list */
};

/* similarity args
 */
static im_arg_desc similarity_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_DOUBLE( "dx" ),
	IM_INPUT_DOUBLE( "dy" )
};

/* Call im_similarity via arg vector.
 */
static int
similarity_vec( im_object *argv )
{
	double a = *((double *) argv[2]);
	double b = *((double *) argv[3]);
	double dx = *((double *) argv[4]);
	double dy = *((double *) argv[5]);

	return( im_similarity( argv[0], argv[1], a, b, dx, dy ) );
}

/* Description of im_similarity.
 */ 
static im_function similarity_desc = {
	"im_similarity", 		/* Name */
	"similarity transformation",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	similarity_vec, 		/* Dispatch function */
	IM_NUMBER( similarity_args ), 	/* Size of arg list */
	similarity_args 		/* Arg list */
};

/* similarity_area args
 */
static im_arg_desc similarity_area_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_DOUBLE( "dx" ),
	IM_INPUT_DOUBLE( "dy" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_INT( "w" ),
	IM_INPUT_INT( "h" )
};

/* Call im_similarity_area via arg vector.
 */
static int
similarity_area_vec( im_object *argv )
{
	double a = *((double *) argv[2]);
	double b = *((double *) argv[3]);
	double dx = *((double *) argv[4]);
	double dy = *((double *) argv[5]);
	int x = *((int *) argv[6]);
	int y = *((int *) argv[7]);
	int w = *((int *) argv[8]);
	int h = *((int *) argv[9]);

	return( im_similarity_area( argv[0], argv[1], a, b, dx, dy,
		x, y, w, h ) );
}

/* Description of im_similarity_area.
 */ 
static im_function similarity_area_desc = {
	"im_similarity_area", 		/* Name */
	"output area xywh of similarity transformation",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	similarity_area_vec, 		/* Dispatch function */
	IM_NUMBER( similarity_area_args ), /* Size of arg list */
	similarity_area_args 		/* Arg list */
};

static int
icc_export_vec( im_object *argv )
{
	int intent = *((int *) argv[3]);

	return( im_icc_export( argv[0], argv[1], 
		argv[2], intent ) );
}

static im_arg_desc icc_export_args[] = {
        IM_INPUT_IMAGE( "in" ),
        IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_STRING( "output_profile" ),
	IM_INPUT_INT( "intent" )
};

/* Description of im_icc_export.
 */ 
static im_function icc_export_desc = {
	"im_icc_export", 		/* Name */
	"convert a float LAB to an 8-bit device image with an ICC profile",	
					/* Description */
	IM_FN_PIO,			/* Flags */
	icc_export_vec, 		/* Dispatch function */
	IM_NUMBER( icc_export_args ), 	/* Size of arg list */
	icc_export_args 		/* Arg list */
};

/* Args for im_segment().
 */
static im_arg_desc segment_args[] = {
	IM_INPUT_IMAGE( "test" ),
	IM_OUTPUT_IMAGE( "mask" ),
	IM_OUTPUT_INT( "segments" )
};

/* Call im_segment() via arg vector.
 */
static int
segment_vec( im_object *argv )
{
	IMAGE *test = argv[0];
	IMAGE *mask = argv[1];
	int *serial = (int *) argv[2];

	return( im_segment( test, mask, serial ) );
}

/* Description of im_segment().
 */ 
static im_function segment_desc = {
	"im_segment",		/* Name */
	"number continuous regions in an image",
	0,			/* Flags */
	segment_vec, 		/* Dispatch function */
	IM_NUMBER( segment_args ),/* Size of arg list */
	segment_args 		/* Arg list */
};

static int
print_vec( im_object *argv )
{
	const char *message = argv[0];
	char **out = (char **) &argv[1];

	if( im_print( message ) )
		return( -1 );
	*out = im_strdup( NULL, "printed" );

	return( 0 );
}

static im_arg_desc print_arg_types[] = {
	IM_INPUT_STRING( "message" ),
	IM_OUTPUT_STRING( "result" )
};

static im_function print_desc = {
	"im_print",			/* Name */
	"print string to stdout",	/* Description */
	0,				/* Flags */
	print_vec, 			/* Dispatch function */
	IM_NUMBER( print_arg_types ),	/* Size of arg list */
	print_arg_types 		/* Arg list */
};

/* Call im_clip2dcm via arg vector.
 */
static int
clip2dcm_vec( im_object *argv )
{
	return( im_clip2dcm( argv[0], argv[1] ) );
}

/* Description of im_clip2dcm.
 */
static im_function clip2dcm_desc = {
	"im_clip2dcm", 			/* Name */
	"convert to double complex",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip2dcm_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_clip2cm via arg vector.
 */
static int
clip2cm_vec( im_object *argv )
{
	return( im_clip2cm( argv[0], argv[1] ) );
}

/* Description of im_clip2cm.
 */
static im_function clip2cm_desc = {
	"im_clip2cm", 			/* Name */
	"convert to complex",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip2cm_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_clip2us via arg vector.
 */
static int
clip2us_vec( im_object *argv )
{
	return( im_clip2us( argv[0], argv[1] ) );
}

/* Description of im_clip2us.
 */
static im_function clip2us_desc = {
	"im_clip2us", 			/* Name */
	"convert to unsigned 16-bit integer",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip2us_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_clip2ui via arg vector.
 */
static int
clip2ui_vec( im_object *argv )
{
	return( im_clip2ui( argv[0], argv[1] ) );
}

/* Description of im_clip2ui.
 */
static im_function clip2ui_desc = {
	"im_clip2ui", 			/* Name */
	"convert to unsigned 32-bit integer",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip2ui_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_clip2s via arg vector.
 */
static int
clip2s_vec( im_object *argv )
{
	return( im_clip2s( argv[0], argv[1] ) );
}

/* Description of im_clip2s.
 */
static im_function clip2s_desc = {
	"im_clip2s", 			/* Name */
	"convert to signed 16-bit integer",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip2s_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_clip2i via arg vector.
 */
static int
clip2i_vec( im_object *argv )
{
	return( im_clip2i( argv[0], argv[1] ) );
}

/* Description of im_clip2i.
 */
static im_function clip2i_desc = {
	"im_clip2i", 			/* Name */
	"convert to signed 32-bit integer",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip2i_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_clip2d via arg vector.
 */
static int
clip2d_vec( im_object *argv )
{
	return( im_clip2d( argv[0], argv[1] ) );
}

/* Description of im_clip2d.
 */
static im_function clip2d_desc = {
	"im_clip2d", 			/* Name */
	"convert to double-precision float",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip2d_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_clip2f via arg vector.
 */
static int
clip2f_vec( im_object *argv )
{
	return( im_clip2f( argv[0], argv[1] ) );
}

/* Description of im_clip2f.
 */
static im_function clip2f_desc = {
	"im_clip2f", 			/* Name */
	"convert to single-precision float",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip2f_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_clip2c via arg vector.
 */
static int
clip2c_vec( im_object *argv )
{
	return( im_clip2c( argv[0], argv[1] ) );
}

/* Description of im_clip2c.
 */
static im_function clip2c_desc = {
	"im_clip2c", 			/* Name */
	"convert to signed 8-bit integer",
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	clip2c_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Args to im_thresh.
 */
static im_arg_desc thresh_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_DOUBLE( "threshold" )
};

/* Call im_thresh via arg vector.
 */
static int
thresh_vec( im_object *argv )
{
	double t1 = *((double *) argv[2]);

	return( im_thresh( argv[0], argv[1], t1 ) );
}

/* Description of im_thresh.
 */
static im_function thresh_desc = {
	"im_thresh", 			/* Name */
	"slice an image at a threshold",
	0,				/* Flags */
	thresh_vec, 			/* Dispatch function */
	IM_NUMBER( thresh_args ), 	/* Size of arg list */
	thresh_args 			/* Arg list */
};

/* Args to im_slice.
 */
static im_arg_desc slice_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
	IM_INPUT_DOUBLE( "thresh1" ),
	IM_INPUT_DOUBLE( "thresh2" )
};

/* Call im_slice via arg vector.
 */
static int
slice_vec( im_object *argv )
{
	double t1 = *((double *) argv[2]);
	double t2 = *((double *) argv[3]);

	return( im_slice( argv[0], argv[1], t1, t2 ) );
}

/* Description of im_slice.
 */
static im_function slice_desc = {
	"im_slice", 			/* Name */
	"slice an image using two thresholds",
	0,				/* Flags */
	slice_vec, 			/* Dispatch function */
	IM_NUMBER( slice_args ), 	/* Size of arg list */
	slice_args 			/* Arg list */
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

/* Args to im_bernd.
 */
static im_arg_desc bernd_args[] = {
	IM_INPUT_STRING( "tiffname" ),
	IM_INPUT_INT( "left" ),
	IM_INPUT_INT( "top" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" )
};

/* Call im_bernd via arg vector.
 */
static int
bernd_vec( im_object *argv )
{
	char *name = argv[0];
	int left = *((int *) argv[1]);
	int top = *((int *) argv[2]);
	int width = *((int *) argv[3]);
	int height = *((int *) argv[4]);

	return( im_bernd( name, left, top, width, height ) );
}

/* Description of im_bernd.
 */
static im_function bernd_desc = {
	"im_bernd", 			/* Name */
	"extract from pyramid as jpeg",	/* Description */
	0,				/* Flags */
	bernd_vec, 			/* Dispatch function */
	IM_NUMBER( bernd_args ), 	/* Size of arg list */
	bernd_args 			/* Arg list */
};

/* Args for im_line.
 */
static im_arg_desc line_args[] = {
	IM_RW_IMAGE( "im" ),
	IM_INPUT_INT( "x1" ),
	IM_INPUT_INT( "y1" ),
	IM_INPUT_INT( "x2" ),
	IM_INPUT_INT( "y2" ),
	IM_INPUT_INT( "pelval" )
};

/* Call im_line via arg vector.
 */
static int
line_vec( im_object *argv )
{
	int x1 = *((int *) argv[1]);
	int y1 = *((int *) argv[2]);
	int x2 = *((int *) argv[3]);
	int y2 = *((int *) argv[4]);
	int pel = *((int *) argv[5]);

	return( im_line( argv[0], x1, y1, x2, y2, pel ) );
}

/* Description of im_line.
 */ 
static im_function line_desc = {
	"im_line", 		/* Name */
	"draw line between points (x1,y1) and (x2,y2)",
	0,			/* Flags */
	line_vec, 		/* Dispatch function */
	IM_NUMBER( line_args ),	/* Size of arg list */
	line_args 		/* Arg list */
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
	IM_NUMBER( resize_linear_args ), /* Size of arg list */
	resize_linear_args 		/* Arg list */
};

/* Args for im_insertplaceset.
 */
static im_arg_desc insertplaceset_args[] = {
	IM_INPUT_IMAGE( "main" ),
	IM_INPUT_IMAGE( "sub" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INTVEC( "x" ),
	IM_INPUT_INTVEC( "y" )
};

/* Call im_insertplaceplaceset via arg vector.
 */
static int
insertplaceset_vec( im_object *argv )
{
	im_intvec_object *xv = (im_intvec_object *) argv[3];
	im_intvec_object *yv = (im_intvec_object *) argv[4];

	if( xv->n != yv->n ) {
		im_error( "im_insertplaceset", "%s", 
			_( "vectors not same length" ) );
		return( -1 );
	}

	if( im_insertset( argv[0], argv[1], argv[2], xv->n, xv->vec, yv->vec ) )
		return( -1 );

	return( 0 );
}

/* Description of im_insertplaceset.
 */ 
static im_function insertplaceset_desc = {
	"im_insertplaceset", 		/* Name */
	"insert sub into main at every position in x, y",
	0,				/* Flags */
	insertplaceset_vec, 		/* Dispatch function */
	IM_NUMBER( insertplaceset_args ), /* Size of arg list */
	insertplaceset_args 		/* Arg list */
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

/* Call im_stdif_raw via arg vector.
 */
static int
stdif_raw_vec( im_object *argv )
{
	double a = *((double *) argv[2]);
	double m0 = *((double *) argv[3]);
	double b = *((double *) argv[4]);
	double s0 = *((double *) argv[5]);
	int xw = *((int *) argv[6]);
	int yw = *((int *) argv[7]);

	return( im_stdif_raw( argv[0], argv[1], a, m0, b, s0, xw, yw ) );
}

/* Description of im_stdif.
 */ 
static im_function stdif_raw_desc = {
	"im_stdif_raw", 	/* Name */
	"statistical differencing, no border",
	IM_FN_PIO,		/* Flags */
	stdif_raw_vec, 		/* Dispatch function */
	IM_NUMBER( stdif_args ), 	/* Size of arg list */
	stdif_args 		/* Arg list */
};

/* Call im_lhisteq_raw via arg vector.
 */
static int
lhisteq_raw_vec( im_object *argv )
{
	int xw = *((int *) argv[2]);
	int yw = *((int *) argv[3]);

	return( im_lhisteq_raw( argv[0], argv[1], xw, yw ) );
}

/* Description of im_lhisteq_raw.
 */ 
static im_function lhisteq_raw_desc = {
	"im_lhisteq_raw",	/* Name */
	"local histogram equalisation, no border",
	IM_FN_PIO,		/* Flags */
	lhisteq_raw_vec, 	/* Dispatch function */
	IM_NUMBER( lhisteq_args ), /* Size of arg list */
	lhisteq_args 		/* Arg list */
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
	IM_NUMBER( rank_args ), 	/* Size of arg list */
	rank_args 			/* Arg list */
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

/* Args for im_circle.
 */
static im_arg_desc circle_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_INT( "cx" ),
	IM_INPUT_INT( "cy" ),
	IM_INPUT_INT( "radius" ),
	IM_INPUT_INT( "intensity" )
};

/* Call im_circle via arg vector.
 */
static int
circle_vec( im_object *argv )
{
	int cx = *((int *) argv[1]);
	int cy = *((int *) argv[2]);
	int radius = *((int *) argv[3]);
	int intensity = *((int *) argv[4]);

	return( im_circle( argv[0], cx, cy, radius, intensity ) );
}

/* Description of im_circle.
 */ 
static im_function circle_desc = {
	"im_circle", 			/* Name */
	"plot circle on image",
	0,				/* Flags */
	circle_vec, 			/* Dispatch function */
	IM_NUMBER( circle_args ), 	/* Size of arg list */
	circle_args 			/* Arg list */
};

/* Args for im_flood_blob_copy().
 */
static im_arg_desc flood_blob_copy_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "start_x" ),
	IM_INPUT_INT( "start_y" ),
	IM_INPUT_DOUBLEVEC( "ink" )
};

/* Call im_flood_blob_copy() via arg vector.
 */
static int
flood_blob_copy_vec( im_object *argv )
{
	IMAGE *in = argv[0];
	IMAGE *out = argv[1];
	int start_x = *((int *) argv[2]);
	int start_y = *((int *) argv[3]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[4];

	PEL *ink;

	if( !(ink = im__vector_to_ink( "im_flood_blob_copy",
		in, dv->n, dv->vec )) )
		return( -1 );

	return( im_flood_blob_copy( in, out, start_x, start_y, ink ) );
}

/* Description of im_flood_blob_copy().
 */ 
static im_function flood_blob_copy_desc = {
	"im_flood_blob_copy",	/* Name */
	"flood with ink from start_x, start_y while pixel == start pixel",
	0,			/* Flags */
	flood_blob_copy_vec, 	/* Dispatch function */
	IM_NUMBER( flood_blob_copy_args ),/* Size of arg list */
	flood_blob_copy_args 	/* Arg list */
};

/* Args for im_flood_copy().
 */
static im_arg_desc flood_copy_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "start_x" ),
	IM_INPUT_INT( "start_y" ),
	IM_INPUT_DOUBLEVEC( "ink" )
};

/* Call im_flood_copy() via arg vector.
 */
static int
flood_copy_vec( im_object *argv )
{
	IMAGE *in = argv[0];
	IMAGE *out = argv[1];
	int start_x = *((int *) argv[2]);
	int start_y = *((int *) argv[3]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[4];

	PEL *ink;

	if( !(ink = im__vector_to_ink( "im_flood_copy",
		in, dv->n, dv->vec )) )
		return( -1 );

	return( im_flood_copy( in, out, start_x, start_y, ink ) );
}

/* Description of im_flood_copy().
 */ 
static im_function flood_copy_desc = {
	"im_flood_copy",	/* Name */
	"flood with ink from start_x, start_y while pixel == start pixel",
	0,			/* Flags */
	flood_copy_vec, 	/* Dispatch function */
	IM_NUMBER( flood_copy_args ),/* Size of arg list */
	flood_copy_args 	/* Arg list */
};

/* Args for im_flood_other_copy().
 */
static im_arg_desc flood_other_copy_args[] = {
	IM_INPUT_IMAGE( "test" ),
	IM_INPUT_IMAGE( "mark" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "start_x" ),
	IM_INPUT_INT( "start_y" ),
	IM_INPUT_INT( "serial" )
};

/* Call im_flood_other_copy() via arg vector.
 */
static int
flood_other_copy_vec( im_object *argv )
{
	IMAGE *test = argv[0];
	IMAGE *mark = argv[1];
	IMAGE *out = argv[2];
	int start_x = *((int *) argv[3]);
	int start_y = *((int *) argv[4]);
	int serial = *((int *) argv[5]);

	return( im_flood_other_copy( test, mark, out, 
		start_x, start_y, serial ) );
}

/* Description of im_flood_other_copy().
 */ 
static im_function flood_other_copy_desc = {
	"im_flood_other_copy",	/* Name */
	"flood mark with serial from start_x, start_y while pixel == start pixel",
	0,			/* Flags */
	flood_other_copy_vec, 	/* Dispatch function */
	IM_NUMBER( flood_other_copy_args ),/* Size of arg list */
	flood_other_copy_args 	/* Arg list */
};

/* Args for im_insertplace.
 */
static im_arg_desc insertplace_args[] = {
	IM_RW_IMAGE( "main" ),
	IM_INPUT_IMAGE( "sub" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" )
};

/* Call im_insertplace via arg vector.
 */
static int
insertplace_vec( im_object *argv )
{
	int x = *((int *) argv[2]);
	int y = *((int *) argv[3]);

	return( im_insertplace( argv[0], argv[1], x, y ) );
}

/* Description of im_insertplace.
 */ 
static im_function insertplace_desc = {
	"im_insertplace", 		/* Name */
	"draw image sub inside image main at position (x,y)",
	0,				/* Flags */
	insertplace_vec, 		/* Dispatch function */
	IM_NUMBER( insertplace_args ), 	/* Size of arg list */
	insertplace_args 		/* Arg list */
};

/* Used to be called im_remainderconst_vec, stupidly.
 */
static int
remainderconst_vec_vec( im_object *argv )
{
	im_doublevec_object *dv = (im_doublevec_object *) argv[2];

	return( im_remainder_vec( argv[0], argv[1], dv->n, dv->vec ) );
}

static im_arg_desc remainderconst_vec_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLEVEC( "x" )
};

static im_function remainderconst_vec_desc = {
	"im_remainderconst_vec", 	/* Name */
	N_( "remainder after integer division by a vector of constants" ),
					/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	remainderconst_vec_vec, 	/* Dispatch function */
	IM_NUMBER( remainderconst_vec_args ),/* Size of arg list */
	remainderconst_vec_args 	/* Arg list */
};

/* Args to im_mask2vips.
 */
static im_arg_desc mask2vips_args[] = {
	IM_INPUT_DMASK( "input" ),
	IM_OUTPUT_IMAGE( "output" ),
};

/* Call im_mask2vips via arg vector.
 */
static int
mask2vips_vec( im_object *argv )
{
	im_mask_object *mo = argv[0];

	return( im_mask2vips( mo->mask, argv[1] ) );
}

/* Description of im_mask2vips.
 */
static im_function mask2vips_desc = {
	"im_mask2vips", 		/* Name */
	"convert DOUBLEMASK to VIPS image",
	0,				/* Flags */
	mask2vips_vec, 			/* Dispatch function */
	IM_NUMBER( mask2vips_args ), 	/* Size of arg list */
	mask2vips_args 			/* Arg list */
};

/* Args to im_vips2mask.
 */
static im_arg_desc vips2mask_args[] = {
	IM_INPUT_IMAGE( "input" ),
	IM_OUTPUT_DMASK( "output" ),
};

/* Call im_vips2mask via arg vector.
 */
static int
vips2mask_vec( im_object *argv )
{
	im_mask_object *mo = argv[1];

	if( !(mo->mask = im_vips2mask( argv[0], mo->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_vips2mask.
 */
static im_function vips2mask_desc = {
	"im_vips2mask", 		/* Name */
	"convert VIPS image to DOUBLEMASK",
	0,				/* Flags */
	vips2mask_vec, 			/* Dispatch function */
	IM_NUMBER( vips2mask_args ), 	/* Size of arg list */
	vips2mask_args 			/* Arg list */
};

/* One image plus one constant in, one image out.
 */
static im_arg_desc int_in_one_out[] = {
	IM_INPUT_IMAGE( "in1" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "c" )
};

/* One image plus one constant in, one image out.
 */
static im_arg_desc double_in_one_out[] = {
	IM_INPUT_IMAGE( "in1" ),
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
	IM_NUMBER( int_in_one_out ), 	/* Size of arg list */
	int_in_one_out 		/* Arg list */
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
	IM_NUMBER( int_in_one_out ), 	/* Size of arg list */
	int_in_one_out 		/* Arg list */
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
	IM_NUMBER( int_in_one_out ), 	/* Size of arg list */
	int_in_one_out 		/* Arg list */
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
	IM_NUMBER( int_in_one_out ), 	/* Size of arg list */
	int_in_one_out 		/* Arg list */
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
	IM_NUMBER( int_in_one_out ), 	/* Size of arg list */
	int_in_one_out 		/* Arg list */
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
	IM_NUMBER( double_in_one_out ), 	/* Size of arg list */
	double_in_one_out 		/* Arg list */
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
	IM_NUMBER( double_in_one_out ), 	/* Size of arg list */
	double_in_one_out 		/* Arg list */
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
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	lessconst_vec, 			/* Dispatch function */
	IM_NUMBER( double_in_one_out ), 	/* Size of arg list */
	double_in_one_out		/* Arg list */
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
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
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
	IM_FN_PTOP | IM_FN_PIO,		/* Flags */
	moreconst_vec, 			/* Dispatch function */
	IM_NUMBER( double_in_one_out ), 	/* Size of arg list */
	double_in_one_out		/* Arg list */
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
	IM_NUMBER( double_in_one_out ), 	/* Size of arg list */
	double_in_one_out		/* Arg list */
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
	IM_NUMBER( double_in_one_out ), 	/* Size of arg list */
	double_in_one_out		/* Arg list */
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

/* Call im_argb2rgba() via arg vector.
 */
static int
argb2rgba_vec( im_object *argv )
{
	return( im_argb2rgba( argv[0], argv[1] ) );
}

/* Description of im_argb2rgba.
 */ 
static im_function argb2rgba_desc = {
	"im_argb2rgba", 		/* Name */
	"convert pre-multipled argb to png-style rgba",	/* Description */
	IM_FN_PIO,			/* Flags */
	argb2rgba_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};


/* Package up all these functions.
 */
static im_function *deprecated_list[] = {
	&argb2rgba_desc,
	&flood_copy_desc,
	&flood_blob_copy_desc,
	&flood_other_copy_desc,
	&clip_desc,
	&c2ps_desc,
	&resize_linear_desc,
	&cmulnorm_desc,
	&fav4_desc,
	&gadd_desc,
	&icc_export_desc,
	&litecor_desc,
	&affine_desc,
	&clip2c_desc,
	&clip2cm_desc,
	&clip2d_desc,
	&clip2dcm_desc,
	&clip2f_desc,
	&clip2i_desc,
	&convsub_desc,
	&convf_desc,
	&convsepf_desc,
	&clip2s_desc,
	&clip2ui_desc,
	&insertplaceset_desc,
	&clip2us_desc,
	&print_desc,
	&slice_desc,
	&bernd_desc,
	&segment_desc,
	&line_desc,
	&thresh_desc,
	&convf_raw_desc,
	&conv_raw_desc,
	&contrast_surface_raw_desc,
	&convsepf_raw_desc,
	&convsep_raw_desc,
	&fastcor_raw_desc,
        &gradcor_raw_desc,
	&spcor_raw_desc,
	&lhisteq_raw_desc,
	&stdif_raw_desc,
	&rank_raw_desc,
	&dilate_raw_desc,
	&erode_raw_desc,
	&similarity_area_desc,
	&similarity_desc,
	&remainderconst_vec_desc,
	&mask2vips_desc,
	&vips2mask_desc,
	&insertplace_desc,
	&circle_desc,
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
	&shiftright_desc,
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
	&notequalconst_desc,
	&quadratic_desc
};

/* Package of functions.
 */
im_package im__deprecated = {
	"deprecated",
	IM_NUMBER( deprecated_list ),
	deprecated_list
};
