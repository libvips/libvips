/* Function dispatch tables for arithmetic.
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

/* Image in, number out.
 */
static im_arg_desc image_in_num_out[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_DOUBLE( "value" )
};

/* Call im_abs via arg vector.
 */
static int
abs_vec( im_object *argv )
{
	return( im_abs( argv[0], argv[1] ) );
}

/* Description of im_abs.
 */ 
static im_function abs_desc = {
	"im_abs", 			/* Name */
	N_( "absolute value" ),		/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	abs_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_add via arg vector.
 */
static int
add_vec( im_object *argv )
{
	return( im_add( argv[0], argv[1], argv[2] ) );
}

/* Description of im_add.
 */ 
static im_function add_desc = {
	"im_add", 			/* Name */
	N_( "add two images" ),		/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	add_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_avg via arg vector.
 */
static int
avg_vec( im_object *argv )
{
	double f;

	if( im_avg( argv[0], &f ) )
		return( -1 );

	*((double *) argv[1]) = f;
	return( 0 );
}

/* Description of im_avg.
 */ 
static im_function avg_desc = {
	"im_avg", 			/* Name */
	N_( "average value of image" ),	/* Description */
	IM_FN_PIO,			/* Flags */
	avg_vec, 			/* Dispatch function */
	IM_NUMBER( image_in_num_out ), 	/* Size of arg list */
	image_in_num_out 		/* Arg list */
};

/* Args to im_point_bilinear.
 */
static im_arg_desc point_bilinear_args[] = {
  IM_INPUT_IMAGE ("in"),
  IM_INPUT_DOUBLE("x"),
  IM_INPUT_DOUBLE("y"),
  IM_INPUT_INT("band"),
  IM_OUTPUT_DOUBLE("val")
};

/* Call im_point_bilinear via arg vector.
 */
static int
point_bilinear_vec( im_object *argv )
{
  return im_point_bilinear( argv[0], *(double*)argv[1], *(double*)argv[2], *(int*)argv[3], argv[4] );
}

/* Description of im_point_bilinear.
 */
static im_function point_bilinear_desc = {
  "im_point_bilinear",
  "interpolate value at single point, linearly",
  IM_FN_PIO,
  point_bilinear_vec,
  IM_NUMBER( point_bilinear_args ),
  point_bilinear_args
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

/* Call im_deviate via arg vector.
 */
static int
deviate_vec( im_object *argv )
{
	double f;

	if( im_deviate( argv[0], &f ) )
		return( -1 );

	*((double *) argv[1]) = f;
	return( 0 );
}

/* Description of im_deviate.
 */ 
static im_function deviate_desc = {
	"im_deviate", 			/* Name */
	N_( "standard deviation of image" ),	/* Description */
	IM_FN_PIO,			/* Flags */
	deviate_vec, 			/* Dispatch function */
	IM_NUMBER( image_in_num_out ), 	/* Size of arg list */
	image_in_num_out 		/* Arg list */
};

/* Call im_exp10tra via arg vector.
 */
static int
exp10tra_vec( im_object *argv )
{
	return( im_exp10tra( argv[0], argv[1] ) );
}

/* Description of im_exp10tra.
 */ 
static im_function exp10tra_desc = {
	"im_exp10tra", 			/* Name */
	N_( "10^pel of image" ),		/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	exp10tra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_exptra via arg vector.
 */
static int
exptra_vec( im_object *argv )
{
	return( im_exptra( argv[0], argv[1] ) );
}

/* Description of im_exptra.
 */ 
static im_function exptra_desc = {
	"im_exptra", 			/* Name */
	N_( "e^pel of image" ),		/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	exptra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Args for im_powtra().
 */
static im_arg_desc powtra_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "x" )
};

/* Call im_expntra via arg vector.
 */
static int
expntra_vec( im_object *argv )
{
	double a = *((double *) argv[2]);

	return( im_expntra( argv[0], argv[1], a ) );
}

/* Description of im_expntra.
 */ 
static im_function expntra_desc = {
	"im_expntra", 			/* Name */
	N_( "x^pel of image" ),		/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	expntra_vec, 			/* Dispatch function */
	IM_NUMBER( powtra_args ), 	/* Size of arg list */
	powtra_args 			/* Arg list */
};

/* Args for im_expntra_vec().
 */
static im_arg_desc expntra_vec_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLEVEC( "v" )
};

/* Call im_expntra_vec() via arg vector.
 */
static int
expntra_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_expntra_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_expntra_vec.
 */ 
static im_function expntra_vec_desc = {
	"im_expntra_vec", 		/* Name */
	N_( "[x,y,z]^pel of image" ),	/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	expntra_vec_vec, 		/* Dispatch function */
	IM_NUMBER( expntra_vec_args ), 	/* Size of arg list */
	expntra_vec_args 		/* Arg list */
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

/* Call im_divide via arg vector.
 */
static int
divide_vec( im_object *argv )
{
	return( im_divide( argv[0], argv[1], argv[2] ) );
}

/* Description of im_divide.
 */ 
static im_function divide_desc = {
	"im_divide", 			/* Name */
	N_( "divide two images" ),
	IM_FN_PIO,			/* Flags */
	divide_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
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

/* Call im_invert via arg vector.
 */
static int
invert_vec( im_object *argv )
{
	return( im_invert( argv[0], argv[1] ) );
}

/* Description of im_invert.
 */ 
static im_function invert_desc = {
	"im_invert", 			/* Name */
	N_( "photographic negative" ),	/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	invert_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Args for im_lintra().
 */
static im_arg_desc lintra_args[] = {
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_lintra() via arg vector.
 */
static int
lintra_vec( im_object *argv )
{
	double a = *((double *) argv[0]);
	double b = *((double *) argv[2]);

	return( im_lintra( a, argv[1], b, argv[3] ) );
}

/* Description of im_lintra().
 */ 
static im_function lintra_desc = {
	"im_lintra", 			/* Name */
	N_( "calculate a*in + b = outfile" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	lintra_vec, 			/* Dispatch function */
	IM_NUMBER( lintra_args ), 		/* Size of arg list */
	lintra_args 			/* Arg list */
};

/* Args for im_lintra_vec().
 */
static im_arg_desc lintra_vec_args[] = {
	IM_INPUT_DOUBLEVEC( "a" ),
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_DOUBLEVEC( "b" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_lintra_vec() via arg vector.
 */
static int
lintra_vec_vec( im_object *argv )
{
	im_doublevec_object *dva = (im_doublevec_object *) argv[0];
	im_doublevec_object *dvb = (im_doublevec_object *) argv[2];

	if( dva->n != dvb->n ) {
		im_error( "im_lintra_vec", 
			"%s", _( "vectors not equal length" ) );
		return( -1 );
	}

	return( im_lintra_vec( dva->n, dva->vec, argv[1], dvb->vec, argv[3] ) );
}

/* Description of im_lintra_vec().
 */ 
static im_function lintra_vec_desc = {
	"im_lintra_vec", 		/* Name */
	N_( "calculate a*in + b -> out, a and b vectors" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	lintra_vec_vec, 		/* Dispatch function */
	IM_NUMBER( lintra_vec_args ), 	/* Size of arg list */
	lintra_vec_args 		/* Arg list */
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

/* Call im_log10tra via arg vector.
 */
static int
log10tra_vec( im_object *argv )
{
	return( im_log10tra( argv[0], argv[1] ) );
}

/* Description of im_log10tra.
 */ 
static im_function log10tra_desc = {
	"im_log10tra", 			/* Name */
	N_( "log10 of image" ),		/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	log10tra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_logtra via arg vector.
 */
static int
logtra_vec( im_object *argv )
{
	return( im_logtra( argv[0], argv[1] ) );
}

/* Description of im_logtra.
 */ 
static im_function logtra_desc = {
	"im_logtra", 			/* Name */
	N_( "ln of image" ),			/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	logtra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_tantra via arg vector.
 */
static int
tantra_vec( im_object *argv )
{
	return( im_tantra( argv[0], argv[1] ) );
}

/* Description of im_tantra.
 */ 
static im_function tantra_desc = {
	"im_tantra", 			/* Name */
	N_( "tan of image (angles in degrees)" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	tantra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_atantra via arg vector.
 */
static int
atantra_vec( im_object *argv )
{
	return( im_atantra( argv[0], argv[1] ) );
}

/* Description of im_atantra.
 */ 
static im_function atantra_desc = {
	"im_atantra", 			/* Name */
	N_( "atan of image (result in degrees)" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	atantra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_costra via arg vector.
 */
static int
costra_vec( im_object *argv )
{
	return( im_costra( argv[0], argv[1] ) );
}

/* Description of im_costra.
 */ 
static im_function costra_desc = {
	"im_costra", 			/* Name */
	N_( "cos of image (angles in degrees)" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	costra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_acostra via arg vector.
 */
static int
acostra_vec( im_object *argv )
{
	return( im_acostra( argv[0], argv[1] ) );
}

/* Description of im_acostra.
 */ 
static im_function acostra_desc = {
	"im_acostra", 			/* Name */
	N_( "acos of image (result in degrees)" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	acostra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_ceil via arg vector.
 */
static int
ceil_vec( im_object *argv )
{
	return( im_ceil( argv[0], argv[1] ) );
}

/* Description of im_ceil.
 */ 
static im_function ceil_desc = {
	"im_ceil", 			/* Name */
	N_( "round to smallest integal value not less than" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	ceil_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_floor via arg vector.
 */
static int
floor_vec( im_object *argv )
{
	return( im_floor( argv[0], argv[1] ) );
}

/* Description of im_floor.
 */ 
static im_function floor_desc = {
	"im_floor", 			/* Name */
	N_( "round to largest integal value not greater than" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	floor_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_rint via arg vector.
 */
static int
rint_vec( im_object *argv )
{
	return( im_rint( argv[0], argv[1] ) );
}

/* Description of im_rint.
 */ 
static im_function rint_desc = {
	"im_rint", 			/* Name */
	N_( "round to nearest integal value" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	rint_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_sintra via arg vector.
 */
static int
sintra_vec( im_object *argv )
{
	return( im_sintra( argv[0], argv[1] ) );
}

/* Description of im_sintra.
 */ 
static im_function sintra_desc = {
	"im_sintra", 			/* Name */
	N_( "sin of image (angles in degrees)" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	sintra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_bandmean via arg vector.
 */
static int
bandmean_vec( im_object *argv )
{
	return( im_bandmean( argv[0], argv[1] ) );
}

/* Description of im_bandmean.
 */ 
static im_function bandmean_desc = {
	"im_bandmean", 			/* Name */
	N_( "average image bands" ),
	IM_FN_PIO,			/* Flags */
	bandmean_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_sign via arg vector.
 */
static int
sign_vec( im_object *argv )
{
	return( im_sign( argv[0], argv[1] ) );
}

/* Description of im_sign.
 */ 
static im_function sign_desc = {
	"im_sign", 			/* Name */
	N_( "unit vector in direction of value" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	sign_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_asintra via arg vector.
 */
static int
asintra_vec( im_object *argv )
{
	return( im_asintra( argv[0], argv[1] ) );
}

/* Description of im_asintra.
 */ 
static im_function asintra_desc = {
	"im_asintra", 			/* Name */
	N_( "asin of image (result in degrees)" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	asintra_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_max via arg vector.
 */
static int
max_vec( im_object *argv )
{
	double f;

	if( im_max( argv[0], &f ) )
		return( -1 );
	*((double *) argv[1]) = f;

	return( 0 );
}

/* Description of im_max.
 */ 
static im_function max_desc = {
	"im_max", 			/* Name */
	N_( "maximum value of image" ),	/* Description */
	IM_FN_PIO,			/* Flags */
	max_vec, 			/* Dispatch function */
	IM_NUMBER( image_in_num_out ), 	/* Size of arg list */
	image_in_num_out 		/* Arg list */
};

/* Args for maxpos (and minpos).
 */
static im_arg_desc maxpos_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_COMPLEX( "position" )
};

/* Call im_maxpos via arg vector.
 */
static int
maxpos_vec( im_object *argv )
{
	double f;
	int x, y;

	if( im_maxpos( argv[0], &x, &y, &f ) )
		return( -1 );

	((double *) argv[1])[0] = x;
	((double *) argv[1])[1] = y;

	return( 0 );
}

/* Description of im_maxpos.
 */ 
static im_function maxpos_desc = {
	"im_maxpos", 			/* Name */
	N_( "position of maximum value of image" ),
	0,				/* Flags */
	maxpos_vec, 			/* Dispatch function */
	IM_NUMBER( maxpos_args ), 		/* Size of arg list */
	maxpos_args 			/* Arg list */
};

/* Args to im_maxpos_avg.
 */
static im_arg_desc maxpos_avg_args[] = {
  IM_INPUT_IMAGE ("in"),
  IM_OUTPUT_DOUBLE("x"),
  IM_OUTPUT_DOUBLE("y"),
  IM_OUTPUT_DOUBLE("out")
};

/* Call im_maxpos_avg via arg vector.
 */
static int
maxpos_avg_vec( im_object *argv )
{
  return im_maxpos_avg( argv[0], argv[1], argv[2], argv[3] );
}

/* Description of im_maxpos_avg.
 */
static im_function maxpos_avg_desc = {
  "im_maxpos_avg",
  "position of maximum value of image, averaging in case of draw",
  IM_FN_PIO,
  maxpos_avg_vec,
  IM_NUMBER( maxpos_avg_args ),
  maxpos_avg_args
};

/* Args to im_min/maxpos_vec.
 */
static im_arg_desc maxpos_vec_args[] = {
  IM_INPUT_IMAGE ("in"),
  IM_INPUT_INT ("n"),
  IM_OUTPUT_INTVEC("xes"),
  IM_OUTPUT_INTVEC("yes"),
  IM_OUTPUT_DOUBLEVEC("maxima")
};

/* Call im_maxpos_vec via arg vector.
 */
static int
maxpos_vec_vec( im_object *argv )
{
  int n = *((int *) argv[1]);
  im_intvec_object *xes = argv[2];
  im_intvec_object *yes = argv[3];
  im_doublevec_object *maxima = argv[4];

  xes->vec = IM_ARRAY( NULL, n, int );
  xes->n = n;
  yes->vec = IM_ARRAY( NULL, n, int );
  yes->n = n;
  maxima->vec = IM_ARRAY( NULL, n, double );
  maxima->n = n;
  if( !xes->vec || !yes->vec || !maxima->vec ||
    im_maxpos_vec( argv[0], xes->vec, yes->vec, maxima->vec, n ) )
    return -1;

  return 0;
}

/* Description of im_maxpos_vec.
 */
static im_function maxpos_vec_desc = {
  "im_maxpos_vec",
  "position and value of n maxima of image",
  IM_FN_PIO,
  maxpos_vec_vec,
  IM_NUMBER( maxpos_vec_args ),
  maxpos_vec_args
};

/* Call im_minpos_vec via arg vector.
 */
static int
minpos_vec_vec( im_object *argv )
{
  int n = *((int *) argv[1]);
  im_intvec_object *xes = argv[2];
  im_intvec_object *yes = argv[3];
  im_doublevec_object *minima = argv[4];

  xes->vec = IM_ARRAY( NULL, n, int );
  xes->n = n;
  yes->vec = IM_ARRAY( NULL, n, int );
  yes->n = n;
  minima->vec = IM_ARRAY( NULL, n, double );
  minima->n = n;
  if( !xes->vec || !yes->vec || !minima->vec ||
    im_minpos_vec( argv[0], xes->vec, yes->vec, minima->vec, n ) )
    return -1;

  return 0;
}

/* Description of im_minpos_vec.
 */
static im_function minpos_vec_desc = {
  "im_minpos_vec",
  "position and value of n minima of image",
  IM_FN_PIO,
  minpos_vec_vec,
  IM_NUMBER( maxpos_vec_args ),
  maxpos_vec_args
};

/* Args for measure.
 */
static im_arg_desc measure_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_DMASK( "mask" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_INT( "w" ),
	IM_INPUT_INT( "h" ),
	IM_INPUT_INT( "h_patches" ),
	IM_INPUT_INT( "v_patches" )
};

/* Call im_measure via arg vector.
 */
static int
measure_vec( im_object *argv )
{
	IMAGE_BOX box;
	int h, v, i;
	int *sel;
	int nsel;
	im_mask_object *mo = argv[1];

	box.xstart = *((int *) argv[2]);
	box.ystart = *((int *) argv[3]);
	box.xsize = *((int *) argv[4]);
	box.ysize = *((int *) argv[5]);
	box.chsel = 0;

	h = *((int *) argv[6]);
	v = *((int *) argv[7]);

	nsel = h * v;
	if( !(sel = IM_ARRAY( NULL, nsel, int )) )
		return( -1 );
	for( i = 0; i < nsel; i++ )
		sel[i] = i + 1;

	if( !(mo->mask = 
		im_measure( argv[0], &box, h, v, sel, nsel, mo->name )) ) {
		im_free( sel );
		return( -1 );
	}
	im_free( sel );

	return( 0 );
}

/* Description of im_measure.
 */
static im_function measure_desc = {
	"im_measure", 			/* Name */
	N_( "measure averages of a grid of patches" ),
	IM_FN_PIO,			/* Flags */
	measure_vec, 			/* Dispatch function */
	IM_NUMBER( measure_args ), 	/* Size of arg list */
	measure_args 			/* Arg list */
};

/* Call im_min via arg vector.
 */
static int
min_vec( im_object *argv )
{
	double f;

	if( im_min( argv[0], &f ) )
		return( -1 );
	*((double *) argv[1]) = f;

	return( 0 );
}

/* Description of im_min.
 */ 
static im_function min_desc = {
	"im_min", 			/* Name */
	N_( "minimum value of image" ),	/* Description */
	IM_FN_PIO,			/* Flags */
	min_vec, 			/* Dispatch function */
	IM_NUMBER( image_in_num_out ), 	/* Size of arg list */
	image_in_num_out 		/* Arg list */
};

/* Call im_minpos via arg vector.
 */
static int
minpos_vec( im_object *argv )
{
	double f;
	int x, y;

	if( im_minpos( argv[0], &x, &y, &f ) )
		return( -1 );

	((double *) argv[1])[0] = x;
	((double *) argv[1])[1] = y;

	return( 0 );
}

/* Description of im_minpos.
 */ 
static im_function minpos_desc = {
	"im_minpos", 			/* Name */
	N_( "position of minimum value of image" ),
	0,				/* Flags */
	minpos_vec, 			/* Dispatch function */
	IM_NUMBER( maxpos_args ), 		/* Size of arg list */
	maxpos_args 			/* Arg list */
};

/* Call im_remainder via arg vector.
 */
static int
remainder_vec( im_object *argv )
{
	return( im_remainder( argv[0], argv[1], argv[2] ) );
}

/* Description of im_remainder.
 */ 
static im_function remainder_desc = {
	"im_remainder", 		/* Name */
	N_( "remainder after integer division" ),	/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	remainder_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_remainderconst via arg vector.
 */
static int
remainderconst_vec( im_object *argv )
{
	double c = *((double *) argv[2]);

	return( im_remainderconst( argv[0], argv[1], c ) );
}

/* Args for im_remainderconst().
 */
static im_arg_desc remainderconst_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "x" )
};

/* Description of im_remainderconst.
 */ 
static im_function remainderconst_desc = {
	"im_remainderconst", 		/* Name */
	N_( "remainder after integer division by a constant" ),/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	remainderconst_vec, 		/* Dispatch function */
	IM_NUMBER( remainderconst_args ), 	/* Size of arg list */
	remainderconst_args 		/* Arg list */
};

/* Call im_remainderconst_vec via arg vector.
 */
static int
remainderconst_vec_vec( im_object *argv )
{
	im_doublevec_object *dv = (im_doublevec_object *) argv[2];

	return( im_remainderconst_vec( argv[0], argv[1], dv->n, dv->vec ) );
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
	IM_NUMBER( remainderconst_vec_args ), 	/* Size of arg list */
	remainderconst_vec_args 	/* Arg list */
};

/* Call im_multiply via arg vector.
 */
static int
multiply_vec( im_object *argv )
{
	return( im_multiply( argv[0], argv[1], argv[2] ) );
}

/* Description of im_multiply.
 */ 
static im_function multiply_desc = {
	"im_multiply", 			/* Name */
	N_( "multiply two images" ),	/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	multiply_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_powtra() via arg vector.
 */
static int
powtra_vec( im_object *argv )
{
	double a = *((double *) argv[2]);

	return( im_powtra( argv[0], argv[1], a ) );
}

/* Description of im_powtra().
 */ 
static im_function powtra_desc = {
	"im_powtra", 			/* Name */
	N_( "pel^x ofbuildimage" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	powtra_vec, 			/* Dispatch function */
	IM_NUMBER( powtra_args ), 	/* Size of arg list */
	powtra_args 			/* Arg list */
};

/* Call im_powtra_vec() via arg vector.
 */
static int
powtra_vec_vec( im_object *argv )
{
	im_doublevec_object *rv = (im_doublevec_object *) argv[2];

	return( im_powtra_vec( argv[0], argv[1], rv->n, rv->vec ) );
}

/* Description of im_powtra_vec().
 */ 
static im_function powtra_vec_desc = {
	"im_powtra_vec", 		/* Name */
	N_( "pel^[x,y,z] of image" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	powtra_vec_vec, 		/* Dispatch function */
	IM_NUMBER( expntra_vec_args ), 	/* Size of arg list */
	expntra_vec_args 		/* Arg list */
};

/* Args for im_stats.
 */
static im_arg_desc stats_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_DMASK_STATS( "statistics" )
};

/* Call im_stats() via arg vector.
 */
static int
stats_vec( im_object *argv )
{
	im_mask_object *mo = argv[1];

	if( !(mo->mask = im_stats( argv[0] )) )
		return( -1 );

	return( 0 );
}

/* Description of im_stats().
 */ 
static im_function stats_desc = {
	"im_stats", 			/* Name */
	N_( "many image statistics in one pass" ),
	IM_FN_PIO,			/* Flags */
	stats_vec, 			/* Dispatch function */
	IM_NUMBER( stats_args ), 		/* Size of arg list */
	stats_args 			/* Arg list */
};

/* Call im_subtract via arg vector.
 */
static int
subtract_vec( im_object *argv )
{
	return( im_subtract( argv[0], argv[1], argv[2] ) );
}

/* Description of im_subtract.
 */ 
static im_function subtract_desc = {
	"im_subtract", 			/* Name */
	N_( "subtract two images" ),	/* Description */
	IM_FN_PIO,			/* Flags */
	subtract_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Args for im_linreg.
 */
static im_arg_desc linreg_args[] = {
	IM_INPUT_IMAGEVEC( "ins" ),
	IM_OUTPUT_IMAGE( "out" ),
        IM_INPUT_DOUBLEVEC( "xs" )
};

/* Call im_linreg() via arg vector.
 */
static int
linreg_vec( im_object *argv )
{
#define FUNCTION_NAME "im_linreg_vec"
  im_imagevec_object *ins_vec= (im_imagevec_object*) argv[0];
  im_doublevec_object *xs_vec= (im_doublevec_object*) argv[2];
  IMAGE *out= (IMAGE*) argv[1];
  IMAGE **ins= IM_ARRAY( out, ins_vec-> n + 1, IMAGE* );
  int i;

  if( ! ins )
    return -1;

  for( i= 0; i < ins_vec-> n; ++i )
    ins[ i ]= ins_vec-> vec[ i ];

  ins[ ins_vec-> n ]= NULL;
  
  if( xs_vec-> n != ins_vec-> n ){
    im_error( FUNCTION_NAME, "image vector and x vector differ in length" );
    return -1;
  }
  return im_linreg( ins, out, xs_vec-> vec );

#undef FUNCTION_NAME
}

/* Description of im_linreg().
 */ 
static im_function linreg_desc = {
	"im_linreg", 			/* Name */
	N_( "pixelwise linear regression" ),
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	linreg_vec, 			/* Dispatch function */
	IM_NUMBER( linreg_args ), 	/* Size of arg list */
	linreg_args 			/* Arg list */
};

/* Call im_cross_phase via arg vector.
 */
static int
cross_phase_vec( im_object *argv )
{
	return( im_cross_phase( argv[0], argv[1], argv[2] ) );
}

/* Description of im_cross_phase.
 */ 
static im_function cross_phase_desc = {
	"im_cross_phase", 			/* Name */
	N_( "phase of cross power spectrum of two complex images" ),	/* Description */
	IM_FN_PIO | IM_FN_PTOP,		/* Flags */
	cross_phase_vec, 		/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *arith_list[] = {
	&abs_desc,
	&acostra_desc,
	&add_desc,
	&asintra_desc,
	&atantra_desc,
	&avg_desc,
        &point_bilinear_desc,
        &bandmean_desc,
	&ceil_desc,
	&cmulnorm_desc,
	&costra_desc,
	&cross_phase_desc,
	&deviate_desc,
	&divide_desc,
	&exp10tra_desc,
	&expntra_desc,
	&expntra_vec_desc,
	&exptra_desc,
	&fav4_desc,
	&floor_desc,
	&gadd_desc,
	&invert_desc,
	&lintra_desc,
	&linreg_desc,
	&lintra_vec_desc,
	&litecor_desc,
	&log10tra_desc,
	&logtra_desc,
	&max_desc,
	&maxpos_desc,
	&maxpos_avg_desc,
	&maxpos_vec_desc,
	&measure_desc,
	&min_desc,
	&minpos_desc,
	&minpos_vec_desc,
	&multiply_desc,
	&powtra_desc,
	&powtra_vec_desc,
	&remainder_desc,
	&remainderconst_desc,
	&remainderconst_vec_desc,
	&rint_desc,
	&sign_desc,
	&sintra_desc,
	&stats_desc,
	&subtract_desc,
	&tantra_desc
};

/* Package of functions.
 */
im_package im__arithmetic = {
	"arithmetic",
	IM_NUMBER( arith_list ),
	arith_list
};
