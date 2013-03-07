/* Function dispatch tables for other.
 *
 * J. Cupitt, 8/2/95
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

/** 
 * SECTION: other
 * @short_description: miscellaneous operators
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These functions generate various test images. You can combine them with
 * the arithmetic and rotate functions to build more complicated images.
 *
 * The im_benchmark() operations are for testing the VIPS SMP system.
 */

/* Args for im_sines.
 */
static im_arg_desc sines_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "xsize" ),
	IM_INPUT_INT( "ysize" ),
	IM_INPUT_DOUBLE( "horfreq" ),
	IM_INPUT_DOUBLE( "verfreq" )
};

/* Call im_sines via arg vector.
 */
static int
sines_vec( im_object *argv )
{
	int xsize = *((int *) argv[1]);
	int ysize = *((int *) argv[2]);
	double horfreq = *((double *) argv[3]);
	double verfreq = *((double *) argv[4]);

	return( im_sines( argv[0], xsize, ysize, horfreq, verfreq ) );
}

/* Description of im_sines.
 */ 
static im_function sines_desc = {
	"im_sines", 			/* Name */
	"generate 2D sine image",
	0,				/* Flags */
	sines_vec, 			/* Dispatch function */
	IM_NUMBER( sines_args ), 	/* Size of arg list */
	sines_args 			/* Arg list */
};

/* Args for im_eye.
 */
static im_arg_desc eye_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "xsize" ),
	IM_INPUT_INT( "ysize" ),
	IM_INPUT_DOUBLE( "factor" )
};

/* Call im_eye via arg vector.
 */
static int
eye_vec( im_object *argv )
{
	int xsize = *((int *) argv[1]);
	int ysize = *((int *) argv[2]);
	double factor = *((double *) argv[3]);

	return( im_eye( argv[0], xsize, ysize, factor ) );
}

/* Description of im_eye.
 */ 
static im_function eye_desc = {
	"im_eye", 			/* Name */
	"generate IM_BANDFMT_UCHAR [0,255] frequency/amplitude image",
	0,				/* Flags */
	eye_vec, 			/* Dispatch function */
	IM_NUMBER( eye_args ), 		/* Size of arg list */
	eye_args 			/* Arg list */
};

/* Call im_feye via arg vector.
 */
static int
feye_vec( im_object *argv )
{
	int xsize = *((int *) argv[1]);
	int ysize = *((int *) argv[2]);
	double factor = *((double *) argv[3]);

	return( im_feye( argv[0], xsize, ysize, factor ) );
}

/* Description of im_feye.
 */ 
static im_function feye_desc = {
	"im_feye", 			/* Name */
	"generate IM_BANDFMT_FLOAT [-1,1] frequency/amplitude image",
	0,				/* Flags */
	feye_vec, 			/* Dispatch function */
	IM_NUMBER( eye_args ), 		/* Size of arg list */
	eye_args 			/* Arg list */
};

/* Args for im_zone.
 */
static im_arg_desc zone_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "size" )
};

/* Call im_zone via arg vector.
 */
static int
zone_vec( im_object *argv )
{
	int size = *((int *) argv[1]);

	return( im_zone( argv[0], size ) );
}

/* Description of im_zone.
 */ 
static im_function zone_desc = {
	"im_zone", 			/* Name */
	"generate IM_BANDFMT_UCHAR [0,255] zone plate image", /* Description */
	0,				/* Flags */
	zone_vec, 			/* Dispatch function */
	IM_NUMBER( zone_args ), 		/* Size of arg list */
	zone_args 			/* Arg list */
};

/* Call im_fzone via arg vector.
 */
static int
fzone_vec( im_object *argv )
{
	int size = *((int *) argv[1]);

	return( im_fzone( argv[0], size ) );
}

/* Description of im_fzone.
 */ 
static im_function fzone_desc = {
	"im_fzone", 			/* Name */
	"generate IM_BANDFMT_FLOAT [-1,1] zone plate image", /* Description */
	0,				/* Flags */
	fzone_vec, 			/* Dispatch function */
	IM_NUMBER( zone_args ), 		/* Size of arg list */
	zone_args 			/* Arg list */
};

/* Args for im_benchmark.
 */
static im_arg_desc benchmark_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_benchmark via arg vector.
 */
static int
benchmark_vec( im_object *argv )
{
	return( im_benchmarkn( argv[0], argv[1], 1 ) );
}

/* Description of im_benchmark.
 */ 
static im_function benchmark_desc = {
	"im_benchmark", 		/* Name */
	"do something complicated for testing", /* Description */
	IM_FN_PIO,			/* Flags */
	benchmark_vec, 			/* Dispatch function */
	IM_NUMBER( benchmark_args ), 	/* Size of arg list */
	benchmark_args 			/* Arg list */
};

/* Args for im_benchmark2.
 */
static im_arg_desc benchmark2_args[] = {
        IM_INPUT_IMAGE( "in" ),
        IM_OUTPUT_DOUBLE( "value" )
};

/* Call im_benchmark2 via arg vector.
 */
static int
benchmark2_vec( im_object *argv )
{
        double f;

        if( im_benchmark2( argv[0], &f ) )
                return( -1 );

        *((double *) argv[1]) = f;

        return( 0 );
}

/* Description of im_benchmark2.
 */
static im_function benchmark2_desc = {
        "im_benchmark2",                /* Name */
        "do something complicated for testing", /* Description */
        IM_FN_PIO,                      /* Flags */
        benchmark2_vec,                 /* Dispatch function */
        IM_NUMBER( benchmark2_args ),   /* Size of arg list */
        benchmark2_args                 /* Arg list */
};

/* Args for im_benchmarkn.
 */
static im_arg_desc benchmarkn_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "n" )
};

/* Call im_benchmarkn via arg vector.
 */
static int
benchmarkn_vec( im_object *argv )
{
	int n = *((int *) argv[2]);

	return( im_benchmarkn( argv[0], argv[1], n ) );
}

/* Description of im_benchmarkn.
 */ 
static im_function benchmarkn_desc = {
	"im_benchmarkn", 		/* Name */
	"do something complicated for testing", /* Description */
	IM_FN_PIO,			/* Flags */
	benchmarkn_vec, 		/* Dispatch function */
	IM_NUMBER( benchmarkn_args ), 	/* Size of arg list */
	benchmarkn_args 		/* Arg list */
};

/* Args for im_grey.
 */
static im_arg_desc grey_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "xsize" ),
	IM_INPUT_INT( "ysize" )
};

/* Call im_grey via arg vector.
 */
static int
grey_vec( im_object *argv )
{
	int xsize = *((int *) argv[1]);
	int ysize = *((int *) argv[2]);

	return( im_grey( argv[0], xsize, ysize ) );
}

/* Description of im_grey.
 */ 
static im_function grey_desc = {
	"im_grey", 			/* Name */
	"generate IM_BANDFMT_UCHAR [0,255] grey scale image", /* Description */
	0,				/* Flags */
	grey_vec, 			/* Dispatch function */
	IM_NUMBER( grey_args ), 		/* Size of arg list */
	grey_args 			/* Arg list */
};

/* Call im_fgrey via arg vector.
 */
static int
fgrey_vec( im_object *argv )
{
	int xsize = *((int *) argv[1]);
	int ysize = *((int *) argv[2]);

	return( im_fgrey( argv[0], xsize, ysize ) );
}

/* Description of im_fgrey.
 */ 
static im_function fgrey_desc = {
	"im_fgrey", 			/* Name */
	"generate IM_BANDFMT_FLOAT [0,1] grey scale image", /* Description */
	0,				/* Flags */
	fgrey_vec, 			/* Dispatch function */
	IM_NUMBER( grey_args ), 		/* Size of arg list */
	grey_args 			/* Arg list */
};

/* Call im_make_xy via arg vector.
 */
static int
make_xy_vec( im_object *argv )
{
	int xsize = *((int *) argv[1]);
	int ysize = *((int *) argv[2]);

	return( im_make_xy( argv[0], xsize, ysize ) );
}

/* Description of im_make_xy.
 */ 
static im_function make_xy_desc = {
	"im_make_xy", 			/* Name */
	"generate image with pixel value equal to coordinate", /* Description */
	0,				/* Flags */
	make_xy_vec, 			/* Dispatch function */
	IM_NUMBER( grey_args ), 	/* Size of arg list */
	grey_args 			/* Arg list */
};

/* Package up all these functions.
 */
static im_function *other_list[] = {
	&benchmark_desc,
	&benchmark2_desc,
	&benchmarkn_desc,
	&eye_desc,
	&grey_desc,
	&feye_desc,
	&fgrey_desc,
	&fzone_desc,
	&make_xy_desc,
	&sines_desc,
	&zone_desc
};

/* Package of functions.
 */
im_package im__other = {
	"other",
	IM_NUMBER( other_list ),
	other_list
};
