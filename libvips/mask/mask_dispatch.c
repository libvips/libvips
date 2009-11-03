/* VIPS function dispatch tables for matricies.
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

/* One matrix in, one out.
 */
static im_arg_desc one_in_one_out[] = {
	IM_INPUT_DMASK( "in" ),
	IM_OUTPUT_DMASK( "out" )
};

/* Two matricies in, one out.
 */
static im_arg_desc two_in_one_out[] = {
	IM_INPUT_DMASK( "in1" ),
	IM_INPUT_DMASK( "in2" ),
	IM_OUTPUT_DMASK( "out" )
};

/* Call im_matinv via arg vector.
 */
static int
matinv_vec( im_object *argv )
{
	im_mask_object *in = argv[0];
	im_mask_object *out = argv[1];

	if( !(out->mask = 
		im_matinv( in->mask, out->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_matinv.
 */ 
static im_function matinv_desc = {
	"im_matinv",	 		/* Name */
	"invert matrix",
	0,				/* Flags */
	matinv_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_mattrn via arg vector.
 */
static int
mattrn_vec( im_object *argv )
{
	im_mask_object *in = argv[0];
	im_mask_object *out = argv[1];

	if( !(out->mask = 
		im_mattrn( in->mask, out->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_mattrn.
 */ 
static im_function mattrn_desc = {
	"im_mattrn",	 		/* Name */
	"transpose matrix",
	0,				/* Flags */
	mattrn_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_matcat via arg vector.
 */
static int
matcat_vec( im_object *argv )
{
	im_mask_object *in1 = argv[0];
	im_mask_object *in2 = argv[1];
	im_mask_object *out = argv[2];

	if( !(out->mask = 
		im_matcat( in1->mask, in2->mask, out->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_matcat.
 */ 
static im_function matcat_desc = {
	"im_matcat",	 		/* Name */
	"append matrix in2 to the end of matrix in1",
	0,				/* Flags */
	matcat_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
};

/* Call im_matmul via arg vector.
 */
static int
matmul_vec( im_object *argv )
{
	im_mask_object *in1 = argv[0];
	im_mask_object *in2 = argv[1];
	im_mask_object *out = argv[2];

	if( !(out->mask = 
		im_matmul( in1->mask, in2->mask, out->name )) )
		return( -1 );

	return( 0 );
}

/* Description of im_matmul.
 */ 
static im_function matmul_desc = {
	"im_matmul",	 		/* Name */
	"multiply matrix in1 by matrix in2",
	0,				/* Flags */
	matmul_vec, 			/* Dispatch function */
	IM_NUMBER( two_in_one_out ), 	/* Size of arg list */
	two_in_one_out 			/* Arg list */
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

/* Call im_gauss_imask_sep via arg vector.
 */
static int
gauss_imask_sep_vec( im_object *argv )
{
	im_mask_object *mo = argv[0];
	double sigma = *((double *) argv[1]);
	double min_amp = *((double *) argv[2]);

	if( !(mo->mask = 
		im_gauss_imask_sep( mo->name, sigma, min_amp )) )
		return( -1 );
	
	return( 0 );
}

/* Description of im_gauss_imask_sep.
 */ 
static im_function gauss_imask_sep_desc = {
	"im_gauss_imask_sep", 		/* Name */
	"generate separable gaussian INTMASK",
	0,				/* Flags */
	gauss_imask_sep_vec, 		/* Dispatch function */
	IM_NUMBER( gauss_imask_args ), 	/* Size of arg list */
	gauss_imask_args 		/* Arg list */
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
static im_function *mask_list[] = {
	&gauss_dmask_desc,
	&log_dmask_desc,
	&log_imask_desc,
	&gauss_imask_desc,
	&gauss_imask_sep_desc,
        &dmask_xsize_desc,
        &dmask_ysize_desc,
        &imask_xsize_desc,
        &imask_ysize_desc,
	&read_dmask_desc,
	&rotate_dmask45_desc,
	&rotate_dmask90_desc,
	&rotate_imask45_desc,
	&rotate_imask90_desc,
	&matcat_desc,
	&matinv_desc,
	&matmul_desc,
	&mattrn_desc
};

/* Package of functions.
 */
im_package im__mask = {
	"mask",
	IM_NUMBER( mask_list ),
	mask_list
};
