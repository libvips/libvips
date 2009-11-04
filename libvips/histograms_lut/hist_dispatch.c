/* VIPS function dispatch tables for histogram_lut.
 *
 * J. Cupitt, 24/5/95.
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

/**
 * SECTION: histograms_lut
 * @short_description: find, manipulate and apply histograms and lookup tables
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 */

/* One image in, one out.
 */
static im_arg_desc one_in_one_out[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Args for im_gammacorrect.
 */
static im_arg_desc gammacorrect_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_DOUBLE( "exponent" )
};

/* Call im_gammacorrect via arg vector.
 */
static int
gammacorrect_vec( im_object *argv )
{
	double exp = *((double *) argv[2]);

	return( im_gammacorrect( argv[0], argv[1], exp ) );
}

/* Description of im_gammacorrect.
 */ 
static im_function gammacorrect_desc = {
	"im_gammacorrect", 		/* Name */
	"gamma-correct image",		/* Description */
	IM_FN_PIO,			/* Flags */
	gammacorrect_vec, 		/* Dispatch function */
	IM_NUMBER( gammacorrect_args ), 	/* Size of arg list */
	gammacorrect_args 		/* Arg list */
};

/* Image plus number in, image out.
 */
static im_arg_desc heq_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "band_number" )
};

/* Call im_heq via arg vector.
 */
static int
heq_vec( im_object *argv )
{
	int bn = *((int *) argv[2]);

	return( im_heq( argv[0], argv[1], bn ) );
}

/* Description of im_heq.
 */ 
static im_function heq_desc = {
	"im_heq", 			/* Name */
	"histogram-equalise image",	/* Description */
	IM_FN_PIO,			/* Flags */
	heq_vec, 			/* Dispatch function */
	IM_NUMBER( heq_args ), 		/* Size of arg list */
	heq_args 			/* Arg list */
};

static im_arg_desc histindexed_args[] = {
	IM_INPUT_IMAGE( "index" ),
	IM_INPUT_IMAGE( "value" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_histindexed via arg vector.
 */
static int
histindexed_vec( im_object *argv )
{
	return( im_hist_indexed( argv[0], argv[1], argv[2] ) );
}

/* Description of im_histindexed.
 */ 
static im_function histindexed_desc = {
	"im_hist_indexed", 		/* Name */
	"make a histogram with an index image",	/* Description */
	IM_FN_PIO,			/* Flags */
	histindexed_vec, 		/* Dispatch function */
	IM_NUMBER( histindexed_args ), 	/* Size of arg list */
	histindexed_args 		/* Arg list */
};

/* Call im_hist via arg vector.
 */
static int
hist_vec( im_object *argv )
{
	int bn = *((int *) argv[2]);

	return( im_hist( argv[0], argv[1], bn ) );
}

/* Description of im_hist.
 */ 
static im_function hist_desc = {
	"im_hist", 			/* Name */
	"find and graph histogram of image",	/* Description */
	IM_FN_PIO | IM_FN_TRANSFORM,	/* Flags */
	hist_vec, 			/* Dispatch function */
	IM_NUMBER( heq_args ), 		/* Size of arg list */
	heq_args 			/* Arg list */
};

/* Call im_histcum via arg vector.
 */
static int
histcum_vec( im_object *argv )
{
	return( im_histcum( argv[0], argv[1] ) );
}

/* Description of im_histcum.
 */ 
static im_function histcum_desc = {
	"im_histcum", 			/* Name */
	"turn histogram to cumulative histogram",/* Description */
	IM_FN_PIO,			/* Flags */
	histcum_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_histnorm via arg vector.
 */
static int
histnorm_vec( im_object *argv )
{
	return( im_histnorm( argv[0], argv[1] ) );
}

/* Description of im_histcum.
 */ 
static im_function histnorm_desc = {
	"im_histnorm", 			/* Name */
	"form normalised histogram",/* Description */
	IM_FN_PIO,			/* Flags */
	histnorm_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_histeq via arg vector.
 */
static int
histeq_vec( im_object *argv )
{
	return( im_histeq( argv[0], argv[1] ) );
}

/* Description of im_histeq.
 */ 
static im_function histeq_desc = {
	"im_histeq", 			/* Name */
	"form histogram equalistion LUT",/* Description */
	IM_FN_PIO,			/* Flags */
	histeq_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Call im_histgr via arg vector.
 */
static int
histgr_vec( im_object *argv )
{
	int bn = *((int *) argv[2]);

	return( im_histgr( argv[0], argv[1], bn ) );
}

/* Description of im_histgr.
 */ 
static im_function histgr_desc = {
	"im_histgr", 			/* Name */
	"find histogram of image",	/* Description */
	IM_FN_TRANSFORM,		/* Flags */
	histgr_vec, 			/* Dispatch function */
	IM_NUMBER( heq_args ), 		/* Size of arg list */
	heq_args 			/* Arg list */
};

/* Call im_histnD() via arg vector.
 */
static int
histnD_vec( im_object *argv )
{
	int bins = *((int *) argv[2]);

	return( im_histnD( argv[0], argv[1], bins ) );
}

/* Args for im_histnD().
 */
static im_arg_desc histnD_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "bins" )
};

/* Description of im_histnD().
 */ 
static im_function histnD_desc = {
	"im_histnD", 			/* Name */
	"find 1D, 2D or 3D histogram of image",	/* Description */
	IM_FN_TRANSFORM,		/* Flags */
	histnD_vec, 			/* Dispatch function */
	IM_NUMBER( histnD_args ), 	/* Size of arg list */
	histnD_args 			/* Arg list */
};

/* Call im_histplot via arg vector.
 */
static int
histplot_vec( im_object *argv )
{
	return( im_histplot( argv[0], argv[1] ) );
}

/* Description of im_histplot.
 */ 
static im_function histplot_desc = {
	"im_histplot", 			/* Name */
	"plot graph of histogram",	/* Description */
	IM_FN_PIO,			/* Flags */
	histplot_vec, 			/* Dispatch function */
	IM_NUMBER( one_in_one_out ), 	/* Size of arg list */
	one_in_one_out 			/* Arg list */
};

/* Args for im_histspec.
 */
static im_arg_desc histspec_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_IMAGE( "ref" ),
	IM_OUTPUT_IMAGE( "out" ),
};

/* Call im_histspec via arg vector.
 */
static int
histspec_vec( im_object *argv )
{
	return( im_histspec( argv[0], argv[1], argv[2] ) );
}

/* Description of im_histspec.
 */ 
static im_function histspec_desc = {
	"im_histspec", 			/* Name */
	"find histogram which will make pdf of in match ref",
	0,				/* Flags */
	histspec_vec, 			/* Dispatch function */
	IM_NUMBER( histspec_args ), 	/* Size of arg list */
	histspec_args 			/* Arg list */
};

/* Call im_hsp via arg vector.
 */
static int
hsp_vec( im_object *argv )
{
	return( im_hsp( argv[0], argv[1], argv[2] ) );
}

/* Description of im_hsp.
 */ 
static im_function hsp_desc = {
	"im_hsp", 			/* Name */
	"match stats of in to stats of ref",
	0,				/* Flags */
	hsp_vec, 			/* Dispatch function */
	IM_NUMBER( histspec_args ), 	/* Size of arg list */
	histspec_args 			/* Arg list */
};

/* Args for im_identity.
 */
static im_arg_desc identity_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "nbands" )
};

/* Call im_identity via arg vector.
 */
static int
identity_vec( im_object *argv )
{
	int nb = *((int *) argv[1]);

	return( im_identity( argv[0], nb ) );
}

/* Description of im_identity.
 */ 
static im_function identity_desc = {
	"im_identity", 			/* Name */
	"generate identity histogram",
	0,				/* Flags */
	identity_vec, 			/* Dispatch function */
	IM_NUMBER( identity_args ), 	/* Size of arg list */
	identity_args 			/* Arg list */
};

/* Args for im_identity_ushort.
 */
static im_arg_desc identity_ushort_args[] = {
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "nbands" ),
	IM_INPUT_INT( "size" )
};

/* Call im_identity_ushort via arg vector.
 */
static int
identity_ushort_vec( im_object *argv )
{
	int nb = *((int *) argv[1]);
	int sz = *((int *) argv[2]);

	return( im_identity_ushort( argv[0], nb, sz ) );
}

/* Description of im_identity_ushort.
 */ 
static im_function identity_ushort_desc = {
	"im_identity_ushort", 		/* Name */
	"generate ushort identity histogram",
	0,				/* Flags */
	identity_ushort_vec, 		/* Dispatch function */
	IM_NUMBER( identity_ushort_args ), /* Size of arg list */
	identity_ushort_args 		/* Arg list */
};

/* Args for im_lhisteq.
 */
static im_arg_desc lhisteq_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" )
};

/* Call im_lhisteq via arg vector.
 */
static int
lhisteq_vec( im_object *argv )
{
	int xw = *((int *) argv[2]);
	int yw = *((int *) argv[3]);

	return( im_lhisteq( argv[0], argv[1], xw, yw ) );
}

/* Description of im_lhisteq.
 */ 
static im_function lhisteq_desc = {
	"im_lhisteq", 		/* Name */
	"local histogram equalisation",
	IM_FN_PIO,		/* Flags */
	lhisteq_vec, 		/* Dispatch function */
	IM_NUMBER( lhisteq_args ), /* Size of arg list */
	lhisteq_args 		/* Arg list */
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

/* Args for im_maplut.
 */
static im_arg_desc maplut_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_IMAGE( "lut" )
};

/* Call im_maplut via arg vector.
 */
static int
maplut_vec( im_object *argv )
{
	return( im_maplut( argv[0], argv[1], argv[2] ) );
}

/* Description of im_maplut.
 */ 
static im_function maplut_desc = {
	"im_maplut", 		/* Name */
	"map image through LUT",
	IM_FN_PIO,		/* Flags */
	maplut_vec, 		/* Dispatch function */
	IM_NUMBER( maplut_args ), 	/* Size of arg list */
	maplut_args 		/* Arg list */
};

/* Call im_project() via arg vector.
 */
static int
project_vec( im_object *argv )
{
	return( im_project( argv[0], argv[1], argv[2] ) );
}

/* Args for im_project().
 */
static im_arg_desc project_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "hout" ),
	IM_OUTPUT_IMAGE( "vout" )
};

/* Description of im_project().
 */ 
static im_function project_desc = {
	"im_project", 			/* Name */
	"find horizontal and vertical projections of an image",	
	IM_FN_TRANSFORM,		/* Flags */
	project_vec, 			/* Dispatch function */
	IM_NUMBER( project_args ), 	/* Size of arg list */
	project_args 			/* Arg list */
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

/* Call im_stdif via arg vector.
 */
static int
stdif_vec( im_object *argv )
{
	double a = *((double *) argv[2]);
	double m0 = *((double *) argv[3]);
	double b = *((double *) argv[4]);
	double s0 = *((double *) argv[5]);
	int xw = *((int *) argv[6]);
	int yw = *((int *) argv[7]);

	return( im_stdif( argv[0], argv[1], a, m0, b, s0, xw, yw ) );
}

/* Description of im_stdif.
 */ 
static im_function stdif_desc = {
	"im_stdif", 		/* Name */
	"statistical differencing",
	IM_FN_PIO,		/* Flags */
	stdif_vec, 		/* Dispatch function */
	IM_NUMBER( stdif_args ), 	/* Size of arg list */
	stdif_args 		/* Arg list */
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

/* Args for im_buildlut.
 */
static im_arg_desc buildlut_args[] = {
	IM_INPUT_DMASK( "xyes" ),
	IM_OUTPUT_IMAGE( "lut" )
};

/* Call im_buildlut via arg vector.
 */
static int
buildlut_vec( im_object *argv )
{
	im_mask_object *mi = argv[0];

	return( im_buildlut( mi->mask, argv[1] ) );
}

/* Description of im_buildlut.
 */ 
static im_function buildlut_desc = {
	"im_buildlut", 	/* Name */
	"generate LUT table from set of x/y positions",
	0,			/* Flags */
	buildlut_vec, 		/* Dispatch function */
	IM_NUMBER( buildlut_args ),/* Size of arg list */
	buildlut_args 		/* Arg list */
};

/* Args for im_invertlut.
 */
static im_arg_desc invertlut_args[] = {
	IM_INPUT_DMASK( "measures" ),
	IM_OUTPUT_IMAGE( "lut" ),
	IM_INPUT_INT( "lut_size" )
};

/* Call im_invertlut via arg vector.
 */
static int
invertlut_vec( im_object *argv )
{
	im_mask_object *mi = argv[0];
	int lut_size = *((int *) argv[2]);

	return( im_invertlut( mi->mask, argv[1], lut_size ) );
}

/* Description of im_invertlut.
 */ 
static im_function invertlut_desc = {
	"im_invertlut", 	/* Name */
	"generate correction table from set of measures",
	0,			/* Flags */
	invertlut_vec, 		/* Dispatch function */
	IM_NUMBER( invertlut_args ),/* Size of arg list */
	invertlut_args 		/* Arg list */
};

/* Args for im_tone_build.
 */
static im_arg_desc tone_build_args[] = {
	IM_OUTPUT_IMAGE( "hist" ),
	IM_INPUT_DOUBLE( "Lb" ),
	IM_INPUT_DOUBLE( "Lw" ),
	IM_INPUT_DOUBLE( "Ps" ),
	IM_INPUT_DOUBLE( "Pm" ),
	IM_INPUT_DOUBLE( "Ph" ),
	IM_INPUT_DOUBLE( "S" ),
	IM_INPUT_DOUBLE( "M" ),
	IM_INPUT_DOUBLE( "H" )
};

/* Call im_tone_build via arg vector.
 */
static int
tone_build_vec( im_object *argv )
{
	double Lb = *((double *) argv[1]);
	double Lw = *((double *) argv[2]);
	double Ps = *((double *) argv[3]);
	double Pm = *((double *) argv[4]);
	double Ph = *((double *) argv[5]);
	double S = *((double *) argv[6]);
	double M = *((double *) argv[7]);
	double H = *((double *) argv[8]);

	return( im_tone_build( argv[0], Lb, Lw, Ps, Pm, Ph, S, M, H ) );
}

/* Description of im_tone_build.
 */ 
static im_function tone_build_desc = {
	"im_tone_build", 		/* Name */
	"create LUT for tone adjustment of LabS images",
	0,				/* Flags */
	tone_build_vec, 		/* Dispatch function */
	IM_NUMBER( tone_build_args ), 	/* Size of arg list */
	tone_build_args 		/* Arg list */
};

/* Args for im_tone_build_range.
 */
static im_arg_desc tone_build_range_args[] = {
	IM_OUTPUT_IMAGE( "hist" ),
	IM_INPUT_INT( "in_max" ),
	IM_INPUT_INT( "out_max" ),
	IM_INPUT_DOUBLE( "Lb" ),
	IM_INPUT_DOUBLE( "Lw" ),
	IM_INPUT_DOUBLE( "Ps" ),
	IM_INPUT_DOUBLE( "Pm" ),
	IM_INPUT_DOUBLE( "Ph" ),
	IM_INPUT_DOUBLE( "S" ),
	IM_INPUT_DOUBLE( "M" ),
	IM_INPUT_DOUBLE( "H" )
};

/* Call im_tone_build_range via arg vector.
 */
static int
tone_build_range_vec( im_object *argv )
{
	int in_max = *((int *) argv[1]);
	int out_max = *((int *) argv[2]);
	double Lb = *((double *) argv[3]);
	double Lw = *((double *) argv[4]);
	double Ps = *((double *) argv[5]);
	double Pm = *((double *) argv[6]);
	double Ph = *((double *) argv[7]);
	double S = *((double *) argv[8]);
	double M = *((double *) argv[9]);
	double H = *((double *) argv[10]);

	return( im_tone_build_range( argv[0], in_max, out_max,
		Lb, Lw, Ps, Pm, Ph, S, M, H ) );
}

/* Description of im_tone_build_range.
 */ 
static im_function tone_build_range_desc = {
	"im_tone_build_range", 		/* Name */
	"create LUT for tone adjustment",
	0,				/* Flags */
	tone_build_range_vec, 		/* Dispatch function */
	IM_NUMBER( tone_build_range_args ),/* Size of arg list */
	tone_build_range_args 		/* Arg list */
};

/* Args for im_tone_analyse.
 */
static im_arg_desc tone_analyse_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "hist" ),
	IM_INPUT_DOUBLE( "Ps" ),
	IM_INPUT_DOUBLE( "Pm" ),
	IM_INPUT_DOUBLE( "Ph" ),
	IM_INPUT_DOUBLE( "S" ),
	IM_INPUT_DOUBLE( "M" ),
	IM_INPUT_DOUBLE( "H" )
};

/* Call im_tone_analyse via arg vector.
 */
static int
tone_analyse_vec( im_object *argv )
{
	double Ps = *((double *) argv[2]);
	double Pm = *((double *) argv[3]);
	double Ph = *((double *) argv[4]);
	double S = *((double *) argv[5]);
	double M = *((double *) argv[6]);
	double H = *((double *) argv[7]);

	return( im_tone_analyse( argv[0], argv[1], Ps, Pm, Ph, S, M, H ) );
}

/* Description of im_tone_analyse.
 */ 
static im_function tone_analyse_desc = {
	"im_tone_analyse", 		/* Name */
	"analyse in and create LUT for tone adjustment",
	0,				/* Flags */
	tone_analyse_vec, 		/* Dispatch function */
	IM_NUMBER( tone_analyse_args ), 	/* Size of arg list */
	tone_analyse_args 		/* Arg list */
};

/* Args for im_ismonotonic.
 */
static im_arg_desc ismonotonic_args[] = {
	IM_INPUT_IMAGE( "lut" ),
	IM_OUTPUT_INT( "mono" )
};

/* Call im_ismonotonic via arg vector.
 */
static int
ismonotonic_vec( im_object *argv )
{
	int *res = (int *) argv[1];

	return( im_ismonotonic( argv[0], res ) );
}

/* Description of im_ismonotonic.
 */ 
static im_function ismonotonic_desc = {
	"im_ismonotonic", 		/* Name */
	"test LUT for monotonicity",
	0,				/* Flags */
	ismonotonic_vec, 		/* Dispatch function */
	IM_NUMBER( ismonotonic_args ), 	/* Size of arg list */
	ismonotonic_args 		/* Arg list */
};

/* Args for im_tone_map
 */
static im_arg_desc tone_map_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_IMAGE( "lut" )
};

/* Call im_tone_map via arg vector.
 */
static int
tone_map_vec( im_object *argv )
{
	return( im_tone_map( argv[0], argv[1], argv[2] ) );
}

/* Description of im_tone_map.
 */ 
static im_function tone_map_desc = {
	"im_tone_map", 		/* Name */
	"map L channel of LabS or LabQ image through LUT",
	IM_FN_PIO,		/* Flags */
	tone_map_vec, 		/* Dispatch function */
	IM_NUMBER( tone_map_args ),/* Size of arg list */
	tone_map_args 		/* Arg list */
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

/* Package up all these functions.
 */
static im_function *hist_list[] = {
	&gammacorrect_desc,
	&heq_desc,
	&hist_desc,
	&histcum_desc,
	&histeq_desc,
	&histindexed_desc,
	&histgr_desc,
	&histnD_desc,
	&histnorm_desc,
	&histplot_desc,
	&histspec_desc,
	&hsp_desc,
	&identity_desc,
	&identity_ushort_desc,
	&ismonotonic_desc,
	&lhisteq_desc,
	&mpercent_desc,
	&lhisteq_raw_desc,
	&invertlut_desc,
	&buildlut_desc,
	&maplut_desc,
	&project_desc,
	&stdif_desc,
	&stdif_raw_desc,
	&tone_analyse_desc,
	&tone_build_desc,
	&tone_build_range_desc,
	&tone_map_desc
};

/* Package of functions.
 */
im_package im__histograms_lut = {
	"histograms_lut",
	IM_NUMBER( hist_list ),
	hist_list
};
