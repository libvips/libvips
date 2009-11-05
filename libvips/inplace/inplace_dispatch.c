/* Function dispatch tables for inplace.
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
 * SECTION: inplace
 * @short_description: in-place paintbox operations: flood, paste, line,
 * circle
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations modify the input image. You can't easily use them in
 * pipelines, but they are useful for paintbox-style programs.
 *
 */

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

/* Args for im_lineset.
 */
static im_arg_desc lineset_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_OUTPUT_IMAGE( "out" ),
	IM_INPUT_IMAGE( "mask" ),
	IM_INPUT_IMAGE( "ink" ),
	IM_INPUT_INTVEC( "x1" ),
	IM_INPUT_INTVEC( "y1" ),
	IM_INPUT_INTVEC( "x2" ),
	IM_INPUT_INTVEC( "y2" )
};

/* Call im_lineset via arg vector.
 */
static int
lineset_vec( im_object *argv )
{
	im_intvec_object *x1v = (im_intvec_object *) argv[4];
	im_intvec_object *y1v = (im_intvec_object *) argv[5];
	im_intvec_object *x2v = (im_intvec_object *) argv[6];
	im_intvec_object *y2v = (im_intvec_object *) argv[7];

	if( x1v->n != y1v->n || x1v->n != x2v->n || x1v->n != y2v->n ) {
		im_error( "im_lineset", "%s", _( "vectors not same length" ) );
		return( -1 );
	}

	return( im_lineset( argv[0], argv[1], argv[2], argv[3],
		x1v->n, x1v->vec, y1v->vec, x2v->vec, y2v->vec ) );
}

/* Description of im_lineset.
 */ 
static im_function lineset_desc = {
	"im_lineset", 		/* Name */
	"draw line between points (x1,y1) and (x2,y2)",
	0,			/* Flags */
	lineset_vec, 		/* Dispatch function */
	IM_NUMBER( lineset_args ), 	/* Size of arg list */
	lineset_args 		/* Arg list */
};

/* Calculate a pixel for an image from a vec of double. Valid while im is
 * valid.
 */
static PEL *
vector_to_ink( IMAGE *im, double *vec )
{
	const int n = im->Bands;

	IMAGE *t[3];
	double *zeros;
	int i;

	if( im_open_local_array( im, t, 3, "vector_to_ink", "t" ) ||
		!(zeros = IM_ARRAY( im, n, double )) )
		return( NULL );
	for( i = 0; i < n; i++ )
		zeros[i] = 0.0;

	if( im_black( t[0], 1, 1, n ) ||
		im_lintra_vec( n, zeros, t[0], vec, t[1] ) ||
		im_clip2fmt( t[1], t[2], im->BandFmt ) )
		return( NULL );

	return( (PEL *) t[2]->data );
}

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

	if( dv->n != in->Bands ) {
		im_error( "im_flood_blob_copy", 
			"%s", _( "bad vector length" ) );
		return( -1 );
	}
	if( !(ink = vector_to_ink( in, dv->vec )) )
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

/* Args for im_flood_other_copy().
 */
static im_arg_desc flood_other_copy_args[] = {
	IM_INPUT_IMAGE( "mask" ),
	IM_INPUT_IMAGE( "test" ),
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
	IMAGE *mask = argv[0];
	IMAGE *test = argv[1];
	IMAGE *out = argv[2];
	int start_x = *((int *) argv[3]);
	int start_y = *((int *) argv[4]);
	int serial = *((int *) argv[5]);

	return( im_flood_other_copy( mask, test, out, 
		start_x, start_y, serial ) );
}

/* Description of im_flood_other_copy().
 */ 
static im_function flood_other_copy_desc = {
	"im_flood_other_copy",	/* Name */
	"flood mask with serial number from start_x, start_y while pixel == start pixel",
	0,			/* Flags */
	flood_other_copy_vec, 	/* Dispatch function */
	IM_NUMBER( flood_other_copy_args ),/* Size of arg list */
	flood_other_copy_args 	/* Arg list */
};

/* To do:
 * these all need some kind of pel type
 *
	im_flood.c
	im_paintrect.c
	im_plotmask.c
	line_draw.c
	plot_point.c
	smudge_area.c
 *
 */

/* Package up all these functions.
 */
static im_function *inplace_list[] = {
	&circle_desc,
	&flood_blob_copy_desc,
	&flood_other_copy_desc,
	&insertplace_desc,
	&lineset_desc
};

/* Package of functions.
 */
im_package im__inplace = {
	"inplace",
	IM_NUMBER( inplace_list ),
	inplace_list
};
