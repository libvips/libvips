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

/** 
 * SECTION: inplace
 * @short_description: in-place paintbox operations: flood, paste, line,
 * circle
 * @stability: Stable
 * @include: vips/vips.h
 *
 * These operations directly modify the image. They do not thread, on 32-bit
 * machines they will be limited to 2GB images, and a little care needs to be
 * taken if you use them as part of an image pipeline. 
 *
 * They are mostly supposed to be useful 
 * for paintbox-style programs.
 *
 */

/* Calculate a pixel for an image from a vec of double. Valid while im is
 * valid.
 */
VipsPel *
im__vector_to_ink( const char *domain, IMAGE *im, int n, double *vec )
{
	IMAGE *t[3];
	double *zeros;
	int i;

	if( im_check_vector( domain, n, im ) )
		return( NULL );
	if( im_open_local_array( im, t, 3, domain, "t" ) ||
		!(zeros = IM_ARRAY( im, n, double )) )
		return( NULL );
	for( i = 0; i < n; i++ )
		zeros[i] = 0.0;

	if( im_black( t[0], 1, 1, im->Bands ) ||
		im_lintra_vec( n, zeros, t[0], vec, t[1] ) ||
		im_clip2fmt( t[1], t[2], im->BandFmt ) )
		return( NULL );

	return( t[2]->data );
}

double *
im__ink_to_vector( const char *domain, IMAGE *im, VipsPel *ink )
{
	double *vec;
	int i;

	if( im_check_uncoded( "im__ink_to_vector", im ) ||
		im_check_noncomplex( "im__ink_to_vector", im ) )
		return( NULL );
	if( !(vec = IM_ARRAY( NULL, im->Bands, double )) )
		return( NULL );

#define READ( TYPE ) \
	vec[i] = ((TYPE *) ink)[i];

	for( i = 0; i < im->Bands; i++ )
		switch( im->BandFmt ) {
		case IM_BANDFMT_UCHAR: 		READ( unsigned char ); break;
		case IM_BANDFMT_CHAR:  		READ( signed char ); break;
		case IM_BANDFMT_USHORT: 	READ( unsigned short ); break;
		case IM_BANDFMT_SHORT: 		READ( signed short ); break;
		case IM_BANDFMT_UINT: 		READ( unsigned int ); break;
		case IM_BANDFMT_INT: 		READ( signed int ); break;
		case IM_BANDFMT_FLOAT:  	READ( float ); break;
		case IM_BANDFMT_DOUBLE: 	READ( double ); break;

		default:
			g_assert( 0 ); 
		}

	return( vec );
}

/* Args for im_draw_image.
 */
static im_arg_desc draw_image_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_IMAGE( "sub" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" )
};

/* Call im_draw_image via arg vector.
 */
static int
draw_image_vec( im_object *argv )
{
	int x = *((int *) argv[2]);
	int y = *((int *) argv[3]);

	return( im_draw_image( argv[0], argv[1], x, y ) );
}

/* Description of im_draw_image.
 */ 
static im_function draw_image_desc = {
	"im_draw_image", 		/* Name */
	"draw image sub inside image main at position (x,y)",
	0,				/* Flags */
	draw_image_vec, 		/* Dispatch function */
	IM_NUMBER( draw_image_args ), 	/* Size of arg list */
	draw_image_args 		/* Arg list */
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

/* Args for im_draw_mask.
 */
static im_arg_desc draw_mask_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_IMAGE( "mask" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_DOUBLEVEC( "ink" )
};

/* Call im_draw_mask via arg vector.
 */
static int
draw_mask_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	IMAGE *mask = argv[1];
	int x = *((int *) argv[2]);
	int y = *((int *) argv[3]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[4];

	VipsPel *ink;

	if( !(ink = im__vector_to_ink( "im_draw_mask", 
		image, dv->n, dv->vec )) )
		return( -1 );

	return( im_draw_mask( image, mask, x, y, ink ) );
}

/* Description of im_draw_mask.
 */ 
static im_function draw_mask_desc = {
	"im_draw_mask", 		/* Name */
	"draw mask sub inside image main at position (x,y)",
	0,				/* Flags */
	draw_mask_vec, 			/* Dispatch function */
	IM_NUMBER( draw_mask_args ), 	/* Size of arg list */
	draw_mask_args 			/* Arg list */
};

/* Args for im_draw_flood_blob().
 */
static im_arg_desc draw_flood_blob_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_DOUBLEVEC( "ink" )
};

/* Call im_draw_flood_blob() via arg vector.
 */
static int
draw_flood_blob_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	int x = *((int *) argv[1]);
	int y = *((int *) argv[2]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[3];

	VipsPel *ink;

	if( !(ink = im__vector_to_ink( "im_draw_flood_blob", 
		image, dv->n, dv->vec )) )
		return( -1 );

	return( im_draw_flood_blob( image, x, y, ink, NULL ) );
}

/* Description of im_draw_flood_blob().
 */ 
static im_function draw_flood_blob_desc = {
	"im_draw_flood_blob",	/* Name */
	"flood with ink from x, y while pixel == start",
	0,			/* Flags */
	draw_flood_blob_vec, 	/* Dispatch function */
	IM_NUMBER( draw_flood_blob_args ),/* Size of arg list */
	draw_flood_blob_args 	/* Arg list */
};

/* Args for im_draw_flood().
 */
static im_arg_desc draw_flood_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_DOUBLEVEC( "ink" )
};

/* Call im_draw_flood() via arg vector.
 */
static int
draw_flood_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	int x = *((int *) argv[1]);
	int y = *((int *) argv[2]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[3];

	VipsPel *ink;

	if( !(ink = im__vector_to_ink( "im_draw_flood", 
		image, dv->n, dv->vec )) )
		return( -1 );

	return( im_draw_flood( image, x, y, ink, NULL ) );
}

/* Description of im_draw_flood().
 */ 
static im_function draw_flood_desc = {
	"im_draw_flood",	/* Name */
	"flood with ink from x, y while pixel != ink",
	0,			/* Flags */
	draw_flood_vec, 	/* Dispatch function */
	IM_NUMBER( draw_flood_args ),/* Size of arg list */
	draw_flood_args 	/* Arg list */
};

/* Args for im_draw_flood_other().
 */
static im_arg_desc draw_flood_other_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_IMAGE( "test" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_INT( "serial" )
};

/* Call im_draw_flood_other() via arg vector.
 */
static int
draw_flood_other_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	IMAGE *test = argv[1];
	int x = *((int *) argv[2]);
	int y = *((int *) argv[3]);
	int serial = *((int *) argv[4]);

	return( im_draw_flood_other( image, test, x, y, serial, NULL ) );
}

/* Description of im_draw_flood_other().
 */ 
static im_function draw_flood_other_desc = {
	"im_draw_flood_other",	/* Name */
	"flood image with serial from x, y while pixel == start",
	0,			/* Flags */
	draw_flood_other_vec, 	/* Dispatch function */
	IM_NUMBER( draw_flood_other_args ),/* Size of arg list */
	draw_flood_other_args 	/* Arg list */
};

/* Args for im_draw_point.
 */
static im_arg_desc draw_point_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_INPUT_DOUBLEVEC( "ink" )
};

/* Call im_draw_point via arg vector.
 */
static int
draw_point_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	int x = *((int *) argv[1]);
	int y = *((int *) argv[2]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[3];

	VipsPel *ink;

	if( !(ink = im__vector_to_ink( "im_draw_point",
		image, dv->n, dv->vec )) )
		return( -1 );

	return( im_draw_point( image, x, y, ink ) );
}

/* Description of im_draw_point.
 */ 
static im_function draw_point_desc = {
	"im_draw_point", 		/* Name */
	"draw point on image",
	0,				/* Flags */
	draw_point_vec, 		/* Dispatch function */
	IM_NUMBER( draw_point_args ), 	/* Size of arg list */
	draw_point_args 		/* Arg list */
};

/* Args for im_read_point.
 */
static im_arg_desc read_point_args[] = {
	IM_INPUT_IMAGE( "image" ),
	IM_INPUT_INT( "x" ),
	IM_INPUT_INT( "y" ),
	IM_OUTPUT_DOUBLEVEC( "ink" )
};

/* Call im_read_point via arg vector.
 */
static int
read_point_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	int x = *((int *) argv[1]);
	int y = *((int *) argv[2]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[3];

	VipsPel *ink;

	if( !(ink = IM_ARRAY( image, IM_IMAGE_SIZEOF_PEL( image ), VipsPel )) ||
		im_read_point( image, x, y, ink ) ||
		!(dv->vec = im__ink_to_vector( "im_read_point", image, ink )) )
		return( -1 );
	dv->n = image->Bands;

	return( 0 );
}

/* Description of im_read_point.
 */ 
static im_function read_point_desc = {
	"im_read_point", 		/* Name */
	"read point from image",
	0,				/* Flags */
	read_point_vec, 		/* Dispatch function */
	IM_NUMBER( read_point_args ), 	/* Size of arg list */
	read_point_args 		/* Arg list */
};

/* Args for im_draw_line.
 */
static im_arg_desc draw_line_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_INT( "x1" ),
	IM_INPUT_INT( "y1" ),
	IM_INPUT_INT( "x2" ),
	IM_INPUT_INT( "y2" ),
	IM_INPUT_DOUBLEVEC( "ink" )
};

/* Call im_draw_line via arg vector.
 */
static int
draw_line_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	int x1 = *((int *) argv[1]);
	int y1 = *((int *) argv[2]);
	int x2 = *((int *) argv[3]);
	int y2 = *((int *) argv[4]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[5];

	VipsPel *ink;

	if( !(ink = im__vector_to_ink( "im_draw_line",
		image, dv->n, dv->vec )) )
		return( -1 );

	return( im_draw_line( image, x1, y1, x2, y2, ink ) );
}

/* Description of im_draw_line.
 */ 
static im_function draw_line_desc = {
	"im_draw_line", 		/* Name */
	"draw line on image",
	0,				/* Flags */
	draw_line_vec, 			/* Dispatch function */
	IM_NUMBER( draw_line_args ), 	/* Size of arg list */
	draw_line_args 			/* Arg list */
};

/* Args for im_draw_smudge.
 */
static im_arg_desc draw_smudge_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_INT( "left" ),
	IM_INPUT_INT( "top" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" )
};

/* Call im_draw_smudge via arg vector.
 */
static int
draw_smudge_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	int left = *((int *) argv[1]);
	int top = *((int *) argv[2]);
	int width = *((int *) argv[3]);
	int height = *((int *) argv[4]);

	return( im_draw_smudge( image, left, top, width, height ) );
}

/* Description of im_draw_smudge.
 */ 
static im_function draw_smudge_desc = {
	"im_draw_smudge", 		/* Name */
	"smudge part of an image",
	0,				/* Flags */
	draw_smudge_vec, 		/* Dispatch function */
	IM_NUMBER( draw_smudge_args ), 	/* Size of arg list */
	draw_smudge_args 		/* Arg list */
};

/* Args for im_draw_rect.
 */
static im_arg_desc draw_rect_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_INT( "left" ),
	IM_INPUT_INT( "top" ),
	IM_INPUT_INT( "width" ),
	IM_INPUT_INT( "height" ),
	IM_INPUT_INT( "fill" ),
	IM_INPUT_DOUBLEVEC( "ink" )
};

/* Call im_draw_rect via arg vector.
 */
static int
draw_rect_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	int left = *((int *) argv[1]);
	int top = *((int *) argv[2]);
	int width = *((int *) argv[3]);
	int height = *((int *) argv[4]);
	int fill = *((int *) argv[5]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[6];

	VipsPel *ink;

	if( !(ink = im__vector_to_ink( "im_draw_rect",
		image, dv->n, dv->vec )) )
		return( -1 );

	return( im_draw_rect( image, left, top, width, height, fill, ink ) );
}

/* Description of im_draw_rect.
 */ 
static im_function draw_rect_desc = {
	"im_draw_rect", 		/* Name */
	"draw rect on image",
	0,				/* Flags */
	draw_rect_vec, 			/* Dispatch function */
	IM_NUMBER( draw_rect_args ), 	/* Size of arg list */
	draw_rect_args 			/* Arg list */
};

/* Args for im_draw_circle.
 */
static im_arg_desc draw_circle_args[] = {
	IM_RW_IMAGE( "image" ),
	IM_INPUT_INT( "cx" ),
	IM_INPUT_INT( "cy" ),
	IM_INPUT_INT( "radius" ),
	IM_INPUT_INT( "fill" ),
	IM_INPUT_DOUBLEVEC( "ink" )
};

/* Call im_draw_circle via arg vector.
 */
static int
draw_circle_vec( im_object *argv )
{
	IMAGE *image = argv[0];
	int cx = *((int *) argv[1]);
	int cy = *((int *) argv[2]);
	int radius = *((int *) argv[3]);
	int fill = *((int *) argv[4]);
	im_doublevec_object *dv = (im_doublevec_object *) argv[5];

	VipsPel *ink;

	if( !(ink = im__vector_to_ink( "im_draw_circle", 
		image, dv->n, dv->vec )) )
		return( -1 );

	return( im_draw_circle( image, cx, cy, radius, fill, ink ) );
}

/* Description of im_draw_circle.
 */ 
static im_function draw_circle_desc = {
	"im_draw_circle", 		/* Name */
	"draw circle on image",
	0,				/* Flags */
	draw_circle_vec, 		/* Dispatch function */
	IM_NUMBER( draw_circle_args ), 	/* Size of arg list */
	draw_circle_args 		/* Arg list */
};

/* Package up all these functions.
 */
static im_function *inplace_list[] = {
	&draw_circle_desc,
	&draw_rect_desc,
	&draw_line_desc,
	&draw_point_desc,
	&read_point_desc,
	&draw_smudge_desc,
	&draw_flood_desc,
	&draw_flood_blob_desc,
	&draw_flood_other_desc,
	&draw_image_desc,
	&draw_mask_desc,
	&lineset_desc
};

/* Package of functions.
 */
im_package im__inplace = {
	"inplace",
	IM_NUMBER( inplace_list ),
	inplace_list
};
