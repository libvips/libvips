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

/* Call im_remainderconst_vec via arg vector.
 */
static int
remainderconst_vec_vec( im_object *argv )
{
	im_doublevec_object *dv = (im_doublevec_object *) argv[2];

	return( im_remainder_vec( argv[0], argv[1], dv->n, dv->vec ) );
}

/* Args for im_remainderconst_vec().
 */
static im_arg_desc remainderconst_vec_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLEVEC( "x" )
};

/* Description of im_remainderconst_vec.
 */ 
static im_function remainderconst_vec_desc = {
	"im_remainderconst_vec", 	/* Name */
	N_( "remainder after integer division by a vector of constants" ),
					/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	remainderconst_vec_vec, 	/* Dispatch function */
	IM_NUMBER( remainderconst_vec_args ),/* Size of arg list */
	remainderconst_vec_args 	/* Arg list */
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

/* Package up all these functions.
 */
static im_function *deprecated_list[] = {
	&cmulnorm_desc,
	&remainderconst_vec_desc,
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
	&clip2s_desc,
	&clip2ui_desc,
	&clip2us_desc,
	&print_desc,
	&slice_desc,
	&bernd_desc,
	&line_desc,
	&thresh_desc,
	&similarity_area_desc,
	&similarity_desc
};

/* Package of functions.
 */
im_package im__deprecated = {
	"deprecated",
	IM_NUMBER( deprecated_list ),
	deprecated_list
};
