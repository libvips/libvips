/* Function dispatch tables for mosaicing.
 *
 * J. Cupitt, 23/2/95
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
#include <vips/internal.h>

#include "transform.h"
#include "merge.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Merge args.
 */
static im_arg_desc merge_args[] = {
	IM_INPUT_IMAGE( "ref" ),
	IM_INPUT_IMAGE( "sec" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "dx" ),
	IM_INPUT_INT( "dy" ),
	IM_INPUT_INT( "mwidth" )
};

/* Merge1 args.
 */
static im_arg_desc merge1_args[] = {
	IM_INPUT_IMAGE( "ref" ),
	IM_INPUT_IMAGE( "sec" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "xr1" ),
	IM_INPUT_INT( "yr1" ),
	IM_INPUT_INT( "xs1" ),
	IM_INPUT_INT( "ys1" ),
	IM_INPUT_INT( "xr2" ),
	IM_INPUT_INT( "yr2" ),
	IM_INPUT_INT( "xs2" ),
	IM_INPUT_INT( "ys2" ),
	IM_INPUT_INT( "mwidth" )
};

/* Mosaic args.
 */
static im_arg_desc mosaic_args[] = {
	IM_INPUT_IMAGE( "ref" ),
	IM_INPUT_IMAGE( "sec" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "bandno" ),
	IM_INPUT_INT( "xr" ),
	IM_INPUT_INT( "yr" ),
	IM_INPUT_INT( "xs" ),
	IM_INPUT_INT( "ys" ),
	IM_INPUT_INT( "halfcorrelation" ),
	IM_INPUT_INT( "halfarea" ),
	IM_INPUT_INT( "balancetype" ),
	IM_INPUT_INT( "mwidth" )
};

/* Mosaic1 args.
 */
static im_arg_desc mosaic1_args[] = {
	IM_INPUT_IMAGE( "ref" ),
	IM_INPUT_IMAGE( "sec" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "bandno" ),
	IM_INPUT_INT( "xr1" ),
	IM_INPUT_INT( "yr1" ),
	IM_INPUT_INT( "xs1" ),
	IM_INPUT_INT( "ys1" ),
	IM_INPUT_INT( "xr2" ),
	IM_INPUT_INT( "yr2" ),
	IM_INPUT_INT( "xs2" ),
	IM_INPUT_INT( "ys2" ),
	IM_INPUT_INT( "halfcorrelation" ),
	IM_INPUT_INT( "halfarea" ),
	IM_INPUT_INT( "balancetype" ),
	IM_INPUT_INT( "mwidth" )
};

/* Call im_lrmosaic via arg vector.
 */
static int
lrmosaic_vec( im_object *argv )
{
	int bandno = *((int *) argv[3]);
	int xr = *((int *) argv[4]);
	int yr = *((int *) argv[5]);
	int xs = *((int *) argv[6]);
	int ys = *((int *) argv[7]);
	int halfcorrelation = *((int *) argv[8]);
	int halfarea = *((int *) argv[9]);
	int balancetype = *((int *) argv[10]);
	int mwidth = *((int *) argv[11]);

	return( im_lrmosaic( argv[0], argv[1], argv[2], 
		bandno, 
		xr, yr, xs, ys, 
		halfcorrelation, halfarea,
		balancetype, mwidth ) );
}

/* Call im_lrmosaic1 via arg vector.
 */
static int
lrmosaic1_vec( im_object *argv )
{
	int bandno = *((int *) argv[3]);
	int xr1 = *((int *) argv[4]);
	int yr1 = *((int *) argv[5]);
	int xs1 = *((int *) argv[6]);
	int ys1 = *((int *) argv[7]);
	int xr2 = *((int *) argv[8]);
	int yr2 = *((int *) argv[9]);
	int xs2 = *((int *) argv[10]);
	int ys2 = *((int *) argv[11]);
	int halfcorrelation = *((int *) argv[12]);
	int halfarea = *((int *) argv[13]);
	int balancetype = *((int *) argv[14]);
	int mwidth = *((int *) argv[15]);

	return( im_lrmosaic1( argv[0], argv[1], argv[2], 
		bandno, 
		xr1, yr1, xs1, ys1, 
		xr2, yr2, xs2, ys2, 
		halfcorrelation, halfarea,
		balancetype, mwidth ) );
}

/* Description of im_lrmosaic.
 */ 
static im_function lrmosaic_desc = {
	"im_lrmosaic", 			/* Name */
	"left-right mosaic of ref and sec",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	lrmosaic_vec, 			/* Dispatch function */
	IM_NUMBER( mosaic_args ), 		/* Size of arg list */
	mosaic_args 			/* Arg list */
};

static im_arg_desc find_overlap_args[] = {
	IM_INPUT_IMAGE( "ref" ),
	IM_INPUT_IMAGE( "sec" ),
	IM_INPUT_INT( "bandno" ),
	IM_INPUT_INT( "xr" ),
	IM_INPUT_INT( "yr" ),
	IM_INPUT_INT( "xs" ),
	IM_INPUT_INT( "ys" ),
	IM_INPUT_INT( "halfcorrelation" ),
	IM_INPUT_INT( "halfarea" ),
	IM_OUTPUT_INT( "dx0" ),
	IM_OUTPUT_INT( "dy0" ),
	IM_OUTPUT_DOUBLE( "scale1" ),
	IM_OUTPUT_DOUBLE( "angle1" ),
	IM_OUTPUT_DOUBLE( "dx1" ),
	IM_OUTPUT_DOUBLE( "dy1" )
};

/* Call im__find_lroverlap via arg vector.
 */
static int
find_lroverlap_vec( im_object *argv )
{
	int bandno = *((int *) argv[2]);
	int xr = *((int *) argv[3]);
	int yr = *((int *) argv[4]);
	int xs = *((int *) argv[5]);
	int ys = *((int *) argv[6]);
	int halfcorrelation = *((int *) argv[7]);
	int halfarea = *((int *) argv[8]);
	int *dx0 = (int *) argv[9];
	int *dy0 = (int *) argv[10];
	double *scale1 = (double *) argv[11];
	double *angle1 = (double *) argv[12];
	double *dx1 = (double *) argv[13];
	double *dy1 = (double *) argv[14];

	IMAGE *t;
	int result;

	if( !(t = im_open( "find_lroverlap_vec", "p" )) )
		return( -1 );
	result = im__find_lroverlap( argv[0], argv[1], t, 
		bandno, 
		xr, yr, xs, ys, 
		halfcorrelation, halfarea,
		dx0, dy0, scale1, angle1, dx1, dy1 );
	im_close( t );

	return( result );
}

/* Description of im__find_lroverlap.
 */ 
static im_function find_lroverlap_desc = {
	"im__find_lroverlap",		/* Name */
	"search for left-right overlap of ref and sec",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	find_lroverlap_vec, 		/* Dispatch function */
	IM_NUMBER( find_overlap_args ),	/* Size of arg list */
	find_overlap_args 		/* Arg list */
};

/* Description of im_lrmosaic1.
 */ 
static im_function lrmosaic1_desc = {
	"im_lrmosaic1",			/* Name */
	"first-order left-right mosaic of ref and sec",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	lrmosaic1_vec, 			/* Dispatch function */
	IM_NUMBER( mosaic1_args ), 	/* Size of arg list */
	mosaic1_args 			/* Arg list */
};

/* Call im_tbmosaic via arg vector.
 */
static int
tbmosaic_vec( im_object *argv )
{
	int bandno = *((int *) argv[3]);
	int x1 = *((int *) argv[4]);
	int y1 = *((int *) argv[5]);
	int x2 = *((int *) argv[6]);
	int y2 = *((int *) argv[7]);
	int halfcorrelation = *((int *) argv[8]);
	int halfarea = *((int *) argv[9]);
	int balancetype = *((int *) argv[10]);
	int mwidth = *((int *) argv[11]);

	return( im_tbmosaic( argv[0], argv[1], argv[2], 
		bandno, 
		x1, y1, x2, y2, 
		halfcorrelation, halfarea,
		balancetype, mwidth ) );
}

/* Call im_tbmosaic1 via arg vector.
 */
static int
tbmosaic1_vec( im_object *argv )
{
	int bandno = *((int *) argv[3]);
	int xr1 = *((int *) argv[4]);
	int yr1 = *((int *) argv[5]);
	int xs1 = *((int *) argv[6]);
	int ys1 = *((int *) argv[7]);
	int xr2 = *((int *) argv[8]);
	int yr2 = *((int *) argv[9]);
	int xs2 = *((int *) argv[10]);
	int ys2 = *((int *) argv[11]);
	int halfcorrelation = *((int *) argv[12]);
	int halfarea = *((int *) argv[13]);
	int balancetype = *((int *) argv[14]);
	int mwidth = *((int *) argv[15]);

	return( im_tbmosaic1( argv[0], argv[1], argv[2], 
		bandno, 
		xr1, yr1, xs1, ys1, 
		xr2, yr2, xs2, ys2, 
		halfcorrelation, halfarea,
		balancetype, mwidth ) );
}

/* Call im__find_tboverlap via arg vector.
 */
static int
find_tboverlap_vec( im_object *argv )
{
	int bandno = *((int *) argv[2]);
	int xr = *((int *) argv[3]);
	int yr = *((int *) argv[4]);
	int xs = *((int *) argv[5]);
	int ys = *((int *) argv[6]);
	int halfcorrelation = *((int *) argv[7]);
	int halfarea = *((int *) argv[8]);
	int *dx0 = (int *) argv[9];
	int *dy0 = (int *) argv[10];
	double *scale1 = (double *) argv[11];
	double *angle1 = (double *) argv[12];
	double *dx1 = (double *) argv[13];
	double *dy1 = (double *) argv[14];

	IMAGE *t;
	int result;

	if( !(t = im_open( "find_tboverlap_vec", "p" )) )
		return( -1 );
	result = im__find_tboverlap( argv[0], argv[1], t, 
		bandno, 
		xr, yr, xs, ys, 
		halfcorrelation, halfarea,
		dx0, dy0, scale1, angle1, dx1, dy1 );
	im_close( t );

	return( result );
}

/* Description of im__find_tboverlap.
 */ 
static im_function find_tboverlap_desc = {
	"im__find_tboverlap",		/* Name */
	"search for top-bottom overlap of ref and sec",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	find_tboverlap_vec, 		/* Dispatch function */
	IM_NUMBER( find_overlap_args ),	/* Size of arg list */
	find_overlap_args 		/* Arg list */
};

/* Description of im_tbmosaic.
 */ 
static im_function tbmosaic_desc = {
	"im_tbmosaic", 			/* Name */
	"top-bottom mosaic of in1 and in2",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	tbmosaic_vec, 			/* Dispatch function */
	IM_NUMBER( mosaic_args ), 		/* Size of arg list */
	mosaic_args 			/* Arg list */
};

/* Description of im_tbmosaic1.
 */ 
static im_function tbmosaic1_desc = {
	"im_tbmosaic1",			/* Name */
	"first-order top-bottom mosaic of ref and sec",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	tbmosaic1_vec, 			/* Dispatch function */
	IM_NUMBER( mosaic1_args ), 	/* Size of arg list */
	mosaic1_args 			/* Arg list */
};

/* Call im_lrmerge via arg vector.
 */
static int
lrmerge_vec( im_object *argv )
{
	int dx = *((int *) argv[3]);
	int dy = *((int *) argv[4]);
	int mwidth = *((int *) argv[5]);

	return( im_lrmerge( argv[0], argv[1], argv[2], dx, dy, mwidth ) );
}

/* Call im_lrmerge1 via arg vector.
 */
static int
lrmerge1_vec( im_object *argv )
{
	int xr1 = *((int *) argv[3]);
	int yr1 = *((int *) argv[4]);
	int xs1 = *((int *) argv[5]);
	int ys1 = *((int *) argv[6]);
	int xr2 = *((int *) argv[7]);
	int yr2 = *((int *) argv[8]);
	int xs2 = *((int *) argv[9]);
	int ys2 = *((int *) argv[10]);
	int mwidth = *((int *) argv[11]);

	return( im_lrmerge1( argv[0], argv[1], argv[2], 
		xr1, yr1, xs1, ys1, 
		xr2, yr2, xs2, ys2, mwidth ) ); 
}

/* Description of im_lrmerge.
 */ 
static im_function lrmerge_desc = {
	"im_lrmerge", 			/* Name */
	"left-right merge of in1 and in2",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	lrmerge_vec, 			/* Dispatch function */
	IM_NUMBER( merge_args ), 		/* Size of arg list */
	merge_args 			/* Arg list */
};

/* Description of im_lrmerge1.
 */ 
static im_function lrmerge1_desc = {
	"im_lrmerge1", 			/* Name */
	"first-order left-right merge of ref and sec",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	lrmerge1_vec, 			/* Dispatch function */
	IM_NUMBER( merge1_args ), 		/* Size of arg list */
	merge1_args 			/* Arg list */
};

/* Call im_tbmerge via arg vector.
 */
static int
tbmerge_vec( im_object *argv )
{
	int dx = *((int *) argv[3]);
	int dy = *((int *) argv[4]);
	int mwidth = *((int *) argv[5]);

	return( im_tbmerge( argv[0], argv[1], argv[2], dx, dy, mwidth ) );
}

/* Call im_tbmerge1 via arg vector.
 */
static int
tbmerge1_vec( im_object *argv )
{
	int xr1 = *((int *) argv[3]);
	int yr1 = *((int *) argv[4]);
	int xs1 = *((int *) argv[5]);
	int ys1 = *((int *) argv[6]);
	int xr2 = *((int *) argv[7]);
	int yr2 = *((int *) argv[8]);
	int xs2 = *((int *) argv[9]);
	int ys2 = *((int *) argv[10]);
	int mwidth = *((int *) argv[11]);

	return( im_tbmerge1( argv[0], argv[1], argv[2], 
		xr1, yr1, xs1, ys1, 
		xr2, yr2, xs2, ys2, mwidth ) ); 
}

/* Description of im_tbmerge.
 */ 
static im_function tbmerge_desc = {
	"im_tbmerge", 			/* Name */
	"top-bottom merge of in1 and in2",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	tbmerge_vec, 			/* Dispatch function */
	IM_NUMBER( merge_args ), 		/* Size of arg list */
	merge_args 			/* Arg list */
};

/* Description of im_tbmerge1.
 */ 
static im_function tbmerge1_desc = {
	"im_tbmerge1", 			/* Name */
	"first-order top-bottom merge of in1 and in2",/* Description */
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	tbmerge1_vec, 			/* Dispatch function */
	IM_NUMBER( merge1_args ), 		/* Size of arg list */
	merge1_args 			/* Arg list */
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

/* affinei args
 */
static im_arg_desc affinei_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_STRING( "interpolate" ),
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

/* Call im_affinei via arg vector.
 */
static int
affinei_vec( im_object *argv )
{
	const char *interpol = argv[2];
	double a = *((double *) argv[3]);
	double b = *((double *) argv[4]);
	double c = *((double *) argv[5]);
	double d = *((double *) argv[6]);
	double dx = *((double *) argv[7]);
	double dy = *((double *) argv[8]);
	int x = *((int *) argv[9]);
	int y = *((int *) argv[10]);
	int w = *((int *) argv[11]);
	int h = *((int *) argv[12]);
	VipsInterpolate *interpolate;
	int result;

	if( !(interpolate = vips_interpolate_new( interpol )) )
		return( -1 );
	result = im_affinei( argv[0], argv[1], interpolate, 
		a, b, c, d, dx, dy, x, y, w, h );
	g_object_unref( interpolate );

	return( result );
}

/* Description of im_affinei.
 */ 
static im_function affinei_desc = {
	"im_affinei", 			/* Name */
	"affine transform",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	affinei_vec, 			/* Dispatch function */
	IM_NUMBER( affinei_args ),	/* Size of arg list */
	affinei_args 			/* Arg list */
};

/* affinei args
 */
static im_arg_desc affinei_all_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INTERPOLATE( "interpolate" ),
	IM_INPUT_DOUBLE( "a" ),
	IM_INPUT_DOUBLE( "b" ),
	IM_INPUT_DOUBLE( "c" ),
	IM_INPUT_DOUBLE( "d" ),
	IM_INPUT_DOUBLE( "dx" ),
	IM_INPUT_DOUBLE( "dy" )
};

/* Call im_affinei via arg vector.
 */
static int
affinei_all_vec( im_object *argv )
{
	VipsInterpolate *interpolate = VIPS_INTERPOLATE( argv[2] );
	double a = *((double *) argv[3]);
	double b = *((double *) argv[4]);
	double c = *((double *) argv[5]);
	double d = *((double *) argv[6]);
	double dx = *((double *) argv[7]);
	double dy = *((double *) argv[8]);

	return( im_affinei_all( argv[0], argv[1], interpolate, 
		a, b, c, d, dx, dy ) );
}

/* Description of im_affinei.
 */ 
static im_function affinei_all_desc = {
	"im_affinei_all", 		/* Name */
	"affine transform of whole image",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	affinei_all_vec, 		/* Dispatch function */
	IM_NUMBER( affinei_all_args ),	/* Size of arg list */
	affinei_all_args 		/* Arg list */
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

/* match_linear args
 */
static im_arg_desc match_linear_args[] = {
	IM_INPUT_IMAGE( "ref" ),
	IM_INPUT_IMAGE( "sec" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "xref1" ),
	IM_INPUT_INT( "yref1" ),
	IM_INPUT_INT( "xsec1" ),
	IM_INPUT_INT( "ysec1" ),
	IM_INPUT_INT( "xref2" ),
	IM_INPUT_INT( "yref2" ),
	IM_INPUT_INT( "xsec2" ),
	IM_INPUT_INT( "ysec2" )
};

/* Call im_match_linear via arg vector.
 */
static int
match_linear_vec( im_object *argv )
{
	int xref1 = *((int *) argv[3]);
	int yref1 = *((int *) argv[4]);
	int xsec1 = *((int *) argv[5]);
	int ysec1 = *((int *) argv[6]);
	int xref2 = *((int *) argv[7]);
	int yref2 = *((int *) argv[8]);
	int xsec2 = *((int *) argv[9]);
	int ysec2 = *((int *) argv[10]);

	return( im_match_linear( argv[0], argv[1], argv[2],
		xref1, yref1, xsec1, ysec1, 
		xref2, yref2, xsec2, ysec2 ) );
}

/* Description of im_match_linear.
 */ 
static im_function match_linear_desc = {
	"im_match_linear", 		/* Name */
	"resample ref so that tie-points match",
	IM_FN_PIO,			/* Flags */
	match_linear_vec, 		/* Dispatch function */
	IM_NUMBER( match_linear_args ), 	/* Size of arg list */
	match_linear_args 		/* Arg list */
};

/* match_linear_search args
 */
static im_arg_desc match_linear_search_args[] = {
	IM_INPUT_IMAGE( "ref" ),
	IM_INPUT_IMAGE( "sec" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "xref1" ),
	IM_INPUT_INT( "yref1" ),
	IM_INPUT_INT( "xsec1" ),
	IM_INPUT_INT( "ysec1" ),
	IM_INPUT_INT( "xref2" ),
	IM_INPUT_INT( "yref2" ),
	IM_INPUT_INT( "xsec2" ),
	IM_INPUT_INT( "ysec2" ),
	IM_INPUT_INT( "hwindowsize" ),
	IM_INPUT_INT( "hsearchsize" )
};

/* Call im_match_linear_search via arg vector.
 */
static int
match_linear_search_vec( im_object *argv )
{
	int xref1 = *((int *) argv[3]);
	int yref1 = *((int *) argv[4]);
	int xsec1 = *((int *) argv[5]);
	int ysec1 = *((int *) argv[6]);
	int xref2 = *((int *) argv[7]);
	int yref2 = *((int *) argv[8]);
	int xsec2 = *((int *) argv[9]);
	int ysec2 = *((int *) argv[10]);
	int hwin = *((int *) argv[11]);
	int hsrch = *((int *) argv[12]);

	return( im_match_linear_search( argv[0], argv[1], argv[2],
		xref1, yref1, xsec1, ysec1, 
		xref2, yref2, xsec2, ysec2,
		hwin, hsrch ) );
}

/* Description of im_match_linear_search.
 */ 
static im_function match_linear_search_desc = {
	"im_match_linear_search", 	/* Name */
	"search sec, then resample so that tie-points match",
	IM_FN_PIO,			/* Flags */
	match_linear_search_vec, 	/* Dispatch function */
	IM_NUMBER( match_linear_search_args ),/* Size of arg list */
	match_linear_search_args 	/* Arg list */
};

/* correl args
 */
static im_arg_desc correl_args[] = {
	IM_INPUT_IMAGE( "ref" ),
	IM_INPUT_IMAGE( "sec" ),
	IM_INPUT_INT( "xref" ),
	IM_INPUT_INT( "yref" ),
	IM_INPUT_INT( "xsec" ),
	IM_INPUT_INT( "ysec" ),
	IM_INPUT_INT( "hwindowsize" ),
	IM_INPUT_INT( "hsearchsize" ),
	IM_OUTPUT_DOUBLE( "correlation" ),
	IM_OUTPUT_INT( "x" ),
	IM_OUTPUT_INT( "y" )
};

/* Call im_correl via arg vector.
 */
static int
correl_vec( im_object *argv )
{
	int xref = *((int *) argv[2]);
	int yref = *((int *) argv[3]);
	int xsec = *((int *) argv[4]);
	int ysec = *((int *) argv[5]);
	int cor = *((int *) argv[6]);
	int area = *((int *) argv[7]);
	int *x = (int *) argv[8];
	int *y = (int *) argv[9];
	double *correlation = (double *) argv[10];

	return( im_correl( argv[0], argv[1], 
		xref, yref, xsec, ysec, cor, area, correlation, x, y ) );
}

/* Description of im_correl.
 */ 
static im_function correl_desc = {
	"im_correl", 			/* Name */
	"search area around sec for match for area around ref",
	IM_FN_PIO,			/* Flags */
	correl_vec, 			/* Dispatch function */
	IM_NUMBER( correl_args ), 		/* Size of arg list */
	correl_args 			/* Arg list */
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

/* global_balance args
 */
static im_arg_desc global_balance_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "gamma" )
};

/* Call im_global_balance via arg vector.
 */
static int
global_balance_vec( im_object *argv )
{
	double gamma = *((double *) argv[2]);

	return( im_global_balance( argv[0], argv[1], gamma ) );
}

/* Description of im_global_balance.
 */ 
static im_function global_balance_desc = {
	"im_global_balance",		/* Name */
	"automatically rebuild mosaic with balancing",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	global_balance_vec, 		/* Dispatch function */
	IM_NUMBER( global_balance_args ),	/* Size of arg list */
	global_balance_args 		/* Arg list */
};

/* Call im_global_balancef via arg vector.
 */
static int
global_balancef_vec( im_object *argv )
{
	double gamma = *((double *) argv[2]);

	return( im_global_balancef( argv[0], argv[1], gamma ) );
}

/* Description of im_global_balancef.
 */ 
static im_function global_balancef_desc = {
	"im_global_balancef",		/* Name */
	"automatically rebuild mosaic with balancing, float output",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	global_balancef_vec, 		/* Dispatch function */
	IM_NUMBER( global_balance_args ),	/* Size of arg list */
	global_balance_args 		/* Arg list */
};

/* remosaic args
 */
static im_arg_desc remosaic_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_STRING( "old_str" ),
	IM_INPUT_STRING( "new_str" )
};

/* Call im_remosaic via arg vector.
 */
static int
remosaic_vec( im_object *argv )
{
	return( im_remosaic( argv[0], argv[1], argv[2], argv[3] ) );
}

/* Description of im_remosaic.
 */ 
static im_function remosaic_desc = {
	"im_remosaic",		/* Name */
	"automatically rebuild mosaic with new files",
	IM_FN_TRANSFORM | IM_FN_PIO,	/* Flags */
	remosaic_vec, 		/* Dispatch function */
	IM_NUMBER( remosaic_args ),/* Size of arg list */
	remosaic_args 		/* Arg list */
};

static int align_bands_vec( im_object *argv ){
  return im_align_bands( (IMAGE*)argv[0], (IMAGE*)argv[1] );
}

static im_arg_desc align_bands_arg_types[]= {
  IM_INPUT_IMAGE( "in" ),
  IM_OUTPUT_IMAGE( "out" )
};

static im_function align_bands_desc= {
  "im_align_bands",
  "align the bands of an image",
  0,
  align_bands_vec,
  IM_NUMBER( align_bands_arg_types ),
  align_bands_arg_types
};

static int maxpos_subpel_vec( im_object *argv ){
  return im_maxpos_subpel( (IMAGE*)argv[0], (double*)argv[1], (double*)argv[2] );
}

static im_arg_desc maxpos_subpel_arg_types[]= {
  IM_INPUT_IMAGE( "im" ),
  IM_OUTPUT_DOUBLE( "x" ),
  IM_OUTPUT_DOUBLE( "y" )
};

static im_function maxpos_subpel_desc= {
  "im_maxpos_subpel",
  "subpixel position of maximum of (phase correlation) image",
  IM_FN_PIO,
  maxpos_subpel_vec,
  IM_NUMBER( maxpos_subpel_arg_types ),
  maxpos_subpel_arg_types
};

/* Package up all these functions.
 */
static im_function *mos_list[] = {
	&affine_desc,
	&affinei_desc,
	&affinei_all_desc,
        &align_bands_desc,
	&correl_desc,
	&find_lroverlap_desc,
	&find_tboverlap_desc,
	&global_balance_desc,
	&global_balancef_desc,
	&lrmerge_desc,
	&lrmerge1_desc,
	&lrmosaic_desc,
	&lrmosaic1_desc,
	&match_linear_desc,
	&match_linear_search_desc,
        &maxpos_subpel_desc,
	&remosaic_desc,
	&similarity_area_desc,
	&similarity_desc,
	&tbmerge_desc,
	&tbmerge1_desc,
	&tbmosaic_desc,
	&tbmosaic1_desc
};

/* Package of functions.
 */
im_package im__mosaicing = {
	"mosaicing",
	IM_NUMBER( mos_list ),
	mos_list
};
