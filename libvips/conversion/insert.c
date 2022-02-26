/* VipsInsert
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/08/1990
 * Modified on : 
 * 31/8/93 JC
 *	- ANSIfied
 *	- Nicos' reformatting undone. Grr!
 * 22/12/94
 *	- modernised
 *	- now does IM_CODING_LABQ too
 * 22/6/95 JC
 *	- partialized
 * 10/2/02 JC
 *	- adapted for im_prepare_to() stuff
 * 14/4/04
 *	- sets Xoffset / Yoffset
 * 3/7/06
 * 	- add sanity range checks
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 30/1/10
 * 	- cleanups
 * 	- formatalike/bandalike
 * 	- gtkdoc
 * 29/9/11
 * 	- rewrite as a class
 * 	- add expand, bg options
 * 5/11/21
 * 	- add minimise for seq pipelines
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

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pconversion.h"

typedef struct _VipsInsert {
	VipsConversion parent_instance;

	/* Params.
	 */
	VipsImage *main;
	VipsImage *sub;
	int x;
	int y;
	gboolean expand;
	VipsArrayDouble *background;

	/* Pixel we paint calculated from background.
	 */
	VipsPel *ink;

	/* Inputs cast and banded up, plus a NULL at the end. main is 0, sub
	 * is 1.
	 */
	VipsImage *processed[3];

	/* Geometry.
	 */
	VipsRect rout;		/* Output space */
	VipsRect rimage[2];	/* Position of input in output */

	/* TRUE if we've minimised an input.
	 */
	gboolean minimised[2];

} VipsInsert;

typedef VipsConversionClass VipsInsertClass;

G_DEFINE_TYPE( VipsInsert, vips_insert, VIPS_TYPE_CONVERSION );

/* Trivial case: we just need pels from one of the inputs.
 *
 * Also used by vips_arrayjoin.
 */
int
vips__insert_just_one( VipsRegion *or, VipsRegion *ir, int x, int y )
{
	VipsRect need;

	/* Find the part of pos we need.
	 */
	need = or->valid;
	need.left -= x;
	need.top -= y;
	if( vips_region_prepare( ir, &need ) )
		return( -1 );

	/* Attach our output to it.
	 */
	if( vips_region_region( or, ir, &or->valid, need.left, need.top ) )
		return( -1 );

	return( 0 );
}

/* Paste in parts of ir that fall within or --- ir is an input REGION for an 
 * image positioned at pos within or.
 *
 * Also used by vips_arrayjoin.
 */
int
vips__insert_paste_region( VipsRegion *or, VipsRegion *ir, VipsRect *pos )
{
	VipsRect ovl;

	/* Does any of the sub-image appear in the area we have been asked
	 * to make?
	 */
	vips_rect_intersectrect( &or->valid, pos, &ovl );
	if( !vips_rect_isempty( &ovl ) ) {
		/* Find the part of in we need.
		 */
		ovl.left -= pos->left;
		ovl.top -= pos->top;

		/* Paint this area of pixels into or.
		 */
		if( vips_region_prepare_to( ir, or, &ovl, 
			ovl.left + pos->left, ovl.top + pos->top ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_insert_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsRect *r = &or->valid;
	VipsInsert *insert = (VipsInsert *) b; 
	VipsConversion *conversion = VIPS_CONVERSION( insert );

	int i;

	/* Three cases:
	 *
	 * 1. If r is entirely within sub, we can just paint from sub.
	 * 2. If r is entirely within main and does not touch sub, we can 
	 *    paint from main.
	 * 3. We must paint from both, and the background.
	 */
	if( vips_rect_includesrect( &insert->rimage[1], r ) ) {
		/* Just the subimage.
		 */
		if( vips__insert_just_one( or, ir[1],
			insert->rimage[1].left, insert->rimage[1].top ) )
			return( -1 );
	}
	else if( vips_rect_includesrect( &insert->rimage[0], r ) &&
		!vips_rect_overlapsrect( &insert->rimage[1], r ) ) {
		/* Just the main image.
		 */
		if( vips__insert_just_one( or, ir[0],
			insert->rimage[0].left, insert->rimage[0].top ) )
			return( -1 );
	}
	else {
		/* Output requires both (or neither) input. If it is not 
		 * entirely inside both the main and the sub, then there is 
		 * going to be some background. 
		 */
		vips_region_paint_pel( or, r, insert->ink );

		/* Paste the background first.
		 */
		for( i = 0; i < 2; i++ ) 
			if( vips__insert_paste_region( or, ir[i], 
				&insert->rimage[i] ) )
				return( -1 );
	}

	/* See arrayjoin for almost this code again. Move into conversion.c?
	 */
	if( vips_image_is_sequential( conversion->out ) )
		for( i = 0; i < 2; i++ ) {
			int bottom_edge = 
				VIPS_RECT_BOTTOM( &insert->rimage[i] );

			/* 1024 is a generous margin. 256 is too small.
			 */
			if( !insert->minimised[i] &&
				r->top > bottom_edge + 1024 ) {
				insert->minimised[i] = TRUE;
				vips_image_minimise_all( insert->processed[i] );
			}
		}

	return( 0 );
}

/* Make a pair of vector constants into a set of formatted pixels. bands can
 * be 3 while n is 1, meaning expand the constant to the number of bands. 
 * imag can be NULL, meaning all zero for the imaginary component.
 */
VipsPel *
vips__vector_to_pels( const char *domain, 
	int bands, VipsBandFormat format, VipsCoding coding, 
	double *real, double *imag, int n )
{
	/* Run our pipeline relative to this.
	 */
	VipsImage *context = vips_image_new(); 

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( context ), 8 );

	VipsImage *in;
	double *ones;
	VipsPel *result;
	int i;

#ifdef VIPS_DEBUG
	printf( "vips__vector_to_pels: starting\n" );
#endif /*VIPS_DEBUG*/

	ones = VIPS_ARRAY( context, n, double );
	for( i = 0; i < n; i++ )
		ones[i] = 1.0;

	/* Make the real and imaginary parts.
	 */
	if( vips_black( &t[0], 1, 1, "bands", bands, NULL ) ||
		vips_linear( t[0], &t[1], ones, real, n, NULL ) ) {
		g_object_unref( context );
		return( NULL );
	}
	in = t[1];

	if( imag ) { 
		if( vips_black( &t[2], 1, 1, "bands", bands, NULL ) ||
			vips_linear( t[2], &t[3], ones, imag, n, NULL ) ||
			vips_complexform( in, t[3], &t[4], NULL ) ) {
			g_object_unref( context );
			return( NULL );
		}
		in = t[4];
	}

	/* Cast to the output type and coding. 
	 */
	if( vips_cast( in, &t[5], format, NULL ) ||
		vips_image_encode( t[5], &t[6], coding ) ) {
		g_object_unref( context );
		return( NULL );
	}
	in = t[6];

	/* Write to memory, copy to output buffer. 
	 */
	vips_image_set_int( in, "hide-progress", 1 );
	if( !(t[7] = vips_image_new_memory()) ||
		vips_image_write( in, t[7] ) ) {
		g_object_unref( context );
		return( NULL );
	}
	in = t[7];

	if( !(result = 
		VIPS_ARRAY( NULL, VIPS_IMAGE_SIZEOF_PEL( in ), VipsPel )) ) {
		g_object_unref( context );
		return( NULL );
	}

	memcpy( result, in->data, VIPS_IMAGE_SIZEOF_PEL( in ) ); 

#ifdef VIPS_DEBUG
{
	int i;

	printf( "vips__vector_to_ink:\n" );
	printf( "\t(real, imag) = " ); 
	for( i = 0; i < n; i++ )
		printf( "(%g, %g) ", real[i], imag ? imag[i] : 0 );
	printf( "\n" ); 
	printf( "\tink = " ); 
	for( i = 0; i < VIPS_IMAGE_SIZEOF_PEL( in ); i++ )
		printf( "%d ", result[i] );
	printf( "\n" ); 
}
#endif /*VIPS_DEBUG*/

	g_object_unref( context );

	return( result ); 
}

static void
vips__vector_to_ink_cb( VipsObject *object, char *buf )
{
	g_free( buf );
}

/* Calculate a pixel for an image from a vec of double. Valid while im is
 * valid. 
 */
VipsPel *
vips__vector_to_ink( const char *domain, 
	VipsImage *im, double *real, double *imag, int n )
{
	int bands; 
	VipsBandFormat format;
	VipsPel *result;

	vips_image_decode_predict( im, &bands, &format );

	if( !(result = vips__vector_to_pels( domain, 
		bands, format, im->Coding, real, imag, n )) )
		return( NULL );

	g_signal_connect( im, "postclose", 
		G_CALLBACK( vips__vector_to_ink_cb ), result );

	return( result ); 
}

static int
vips_insert_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsInsert *insert = (VipsInsert *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 6 );

	if( VIPS_OBJECT_CLASS( vips_insert_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( insert->main ) || 
		vips_image_pio_input( insert->sub ) || 
		vips_check_bands_1orn( class->nickname, 
			insert->main, insert->sub ) ||
		vips_check_coding_known( class->nickname, insert->main ) ||
		vips_check_coding_same( class->nickname, 
			insert->main, insert->sub ) )
		return( -1 );

	/* Cast our input images up to a common format and bands.
	 */
	if( vips__formatalike( insert->main, insert->sub, &t[0], &t[1] ) ||
		vips__bandalike( class->nickname, t[0], t[1], &t[2], &t[3] ) )
		return( -1 );
	insert->processed[0] = t[2];
	insert->processed[1] = t[3];

	/* Joins can get very wide (eg. consider joining a set of tiles
	 * horizontally to make a large image), we don't want mem use to shoot
	 * up. SMALLTILE will guarantee we keep small and local.
	 */
	if( vips_image_pipeline_array( conversion->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, insert->processed ) )
		return( -1 );

	/* Calculate geometry. 
	 */
	insert->rimage[0].left = 0;
	insert->rimage[0].top = 0;
	insert->rimage[0].width = insert->processed[0]->Xsize;
	insert->rimage[0].height = insert->processed[0]->Ysize;

	insert->rimage[1].left = insert->x;
	insert->rimage[1].top = insert->y;
	insert->rimage[1].width = insert->processed[1]->Xsize;
	insert->rimage[1].height = insert->processed[1]->Ysize;

	if( insert->expand ) {
		/* Expand output to bounding box of these two.
		 */
		vips_rect_unionrect( &insert->rimage[0], &insert->rimage[1], 
			&insert->rout );

		/* Translate origin to top LH corner of rout.
		 */
		insert->rimage[0].left -= insert->rout.left;
		insert->rimage[0].top -= insert->rout.top;
		insert->rimage[1].left -= insert->rout.left;
		insert->rimage[1].top -= insert->rout.top;
		insert->rout.left = 0;
		insert->rout.top = 0;
	}
	else 
		insert->rout = insert->rimage[0];

	conversion->out->Xsize = insert->rout.width;
	conversion->out->Ysize = insert->rout.height;

	if( !(insert->ink = vips__vector_to_ink( 
		class->nickname, conversion->out,
		(double *) VIPS_ARRAY_ADDR( insert->background, 0 ), NULL, 
		VIPS_AREA( insert->background )->n )) )
		return( -1 );

	if( vips_image_generate( conversion->out,
		vips_start_many, vips_insert_gen, vips_stop_many, 
		insert->processed, insert ) )
		return( -1 );

	return( 0 );
}

static void
vips_insert_class_init( VipsInsertClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_insert_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "insert";
	vobject_class->description = 
		_( "insert image @sub into @main at @x, @y" );
	vobject_class->build = vips_insert_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "main", 0, 
		_( "Main" ), 
		_( "Main input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInsert, main ) );

	VIPS_ARG_IMAGE( class, "sub", 1, 
		_( "Sub-image" ), 
		_( "Sub-image to insert into main image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInsert, sub ) );

	VIPS_ARG_INT( class, "x", 3, 
		_( "X" ), 
		_( "Left edge of sub in main" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInsert, x ),
		-VIPS_MAX_COORD, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( class, "y", 4, 
		_( "Y" ), 
		_( "Top edge of sub in main" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInsert, y ),
		-VIPS_MAX_COORD, VIPS_MAX_COORD, 0 );

	VIPS_ARG_BOOL( class, "expand", 5, 
		_( "Expand" ), 
		_( "Expand output to hold all of both inputs" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsInsert, expand ),
		FALSE );

	VIPS_ARG_BOXED( class, "background", 6, 
		_( "Background" ), 
		_( "Color for new pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsInsert, background ),
		VIPS_TYPE_ARRAY_DOUBLE );
}

static void
vips_insert_init( VipsInsert *insert )
{
	/* Init our instance fields.
	 */
	insert->background = vips_array_double_newv( 1, 0.0 );
}

/**
 * vips_insert: (method)
 * @main: big image
 * @sub: small image
 * @out: (out): output image
 * @x: left position of @sub
 * @y: top position of @sub
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @expand: expand output to hold whole of both images
 * * @background: colour for new pixels
 *
 * Insert @sub into @main at position @x, @y. 
 *
 * Normally @out shows the whole of @main. If @expand is #TRUE then @out is
 * made large enough to hold all of @main and @sub. 
 * Any areas of @out not coming from
 * either @main or @sub are set to @background (default 0). 
 *
 * If @sub overlaps @main,
 * @sub will appear on top of @main. 
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="libvips-arithmetic">arithmetic</link>).
 *
 * See also: vips_join(), vips_embed(), vips_extract_area().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_insert( VipsImage *main, VipsImage *sub, VipsImage **out, 
	int x, int y, ... )
{
	va_list ap;
	int result;

	va_start( ap, y );
	result = vips_call_split( "insert", ap, main, sub, out, x, y );
	va_end( ap );

	return( result );
}
