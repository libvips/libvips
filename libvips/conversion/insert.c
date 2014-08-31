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
#include <vips/intl.h>

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

	/* Inputs cast and banded up.
	 */
	VipsImage *main_processed;
	VipsImage *sub_processed;

	/* Geometry.
	 */
	VipsRect rout;		/* Output space */
	VipsRect rmain;		/* Position of main in output */
	VipsRect rsub;		/* Position of sub in output */
} VipsInsert;

typedef VipsConversionClass VipsInsertClass;

G_DEFINE_TYPE( VipsInsert, vips_insert, VIPS_TYPE_CONVERSION );

/* Trivial case: we just need pels from one of the inputs.
 */
static int
vips_insert_just_one( VipsRegion *or, VipsRegion *ir, int x, int y )
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
 */
static int
vips_insert_paste_region( VipsRegion *or, VipsRegion *ir, VipsRect *pos )
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

/* Insert generate function.
 */
static int
vips_insert_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsRect *r = &or->valid;
	VipsInsert *insert = (VipsInsert *) b; 

	VipsRect ovl;

	/* Does the rect we have been asked for fall entirely inside the
	 * sub-image?
	 */
	if( vips_rect_includesrect( &insert->rsub, &or->valid ) ) 
		return( vips_insert_just_one( or, ir[1], 
			insert->rsub.left, insert->rsub.top ) );
	
	/* Does it fall entirely inside the main, and not at all inside the
	 * sub?
	 */
	vips_rect_intersectrect( &or->valid, &insert->rsub, &ovl );
	if( vips_rect_includesrect( &insert->rmain, &or->valid ) &&
		vips_rect_isempty( &ovl ) ) 
		return( vips_insert_just_one( or, ir[0], 
			insert->rmain.left, insert->rmain.top ) );

	/* Output requires both (or neither) input. If it is not entirely 
	 * inside both the main and the sub, then there is going to be some
	 * background. 
	 */
	if( !(vips_rect_includesrect( &insert->rsub, &or->valid ) &&
		vips_rect_includesrect( &insert->rmain, &or->valid )) )
		vips_region_paint_pel( or, r, insert->ink );

	/* Paste from main.
	 */
	if( vips_insert_paste_region( or, ir[0], &insert->rmain ) )
		return( -1 );

	/* Paste from sub.
	 */
	if( vips_insert_paste_region( or, ir[1], &insert->rsub ) )
		return( -1 );

	return( 0 );
}

/* Calculate a pixel for an image from a vec of double. Valid while im is
 * valid. imag can be NULL, meaning all zero for the imaginary component.
 */
VipsPel *
vips__vector_to_ink( const char *domain, 
	VipsImage *im, double *real, double *imag, int n )
{
	/* Run our pipeline relative to this.
	 */
	VipsImage *context = vips_image_new(); 

	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( context ), 6 );

	VipsBandFormat format;
	int bands; 
	double *ones;
	VipsPel *result;
	int i;

#ifdef VIPS_DEBUG
	printf( "vips__vector_to_ink: starting\n" );
#endif /*VIPS_DEBUG*/

	vips_image_decode_predict( im, &bands, &format );
	ones = VIPS_ARRAY( im, n, double );
	for( i = 0; i < n; i++ )
		ones[i] = 1.0;

	/* Cast vec to match the decoded image.
	 */
	if( vips_black( &t[1], 1, 1, "bands", bands, NULL ) ||
		vips_linear( t[1], &t[2], ones, real, n, NULL ) || 
		vips_cast( t[2], &t[3], format, NULL ) ) {
		g_object_unref( context );
		return( NULL );
	}

	/* And now recode the vec to match the original im.
	 */
	if( vips_image_encode( t[3], &t[4], im->Coding ) || 
		!(t[5] = vips_image_new_memory()) ||
		vips_image_write( t[4], t[5] ) ) {
		g_object_unref( context );
		return( NULL );
	}

	if( !(result = 
		VIPS_ARRAY( im, VIPS_IMAGE_SIZEOF_PEL( t[5] ), VipsPel )) ) {
		g_object_unref( context );
		return( NULL );
	}

	g_assert( VIPS_IMAGE_SIZEOF_PEL( t[5] ) == 
		VIPS_IMAGE_SIZEOF_PEL( im ) ); 

	memcpy( result, t[5]->data, VIPS_IMAGE_SIZEOF_PEL( im ) ); 

	g_object_unref( context );

#ifdef VIPS_DEBUG
{
	int i;

	printf( "vips__vector_to_ink:\n" );
	printf( "\t(real, imag) = " ); 
	for( i = 0; i < n; i++ )
		printf( "(%g, %g) ", real[i], imag ? imag[i] : 0 );
	printf( "\n" ); 
	printf( "\tink = " ); 
	for( i = 0; i < VIPS_IMAGE_SIZEOF_PEL( im ); i++ )
		printf( "%d ", result[i] );
	printf( "\n" ); 
}
#endif /*VIPS_DEBUG*/

	return( result ); 
}

/* The inverse: take ink to a vec of double. Used in the vips7 compat
 * wrappers. Result valid while im is valid. 
 */
double *
vips__ink_to_vector( const char *domain, VipsImage *im, VipsPel *ink, int *n )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( im ), 6 );

	double *result;

#ifdef VIPS_DEBUG
	printf( "vips__ink_to_vector: starting\n" );
#endif /*VIPS_DEBUG*/

	/* Wrap a VipsImage around ink.
	 */
	t[0] = vips_image_new_from_memory( ink, 
		1, 1, VIPS_IMAGE_SIZEOF_PEL( im ), VIPS_FORMAT_UCHAR );
	if( vips_copy( t[0], &t[1], 
		"bands", im->Bands, 
		"format", im->BandFmt, 
		"coding", im->Coding, 
		"interpretation", im->Type, 
		NULL ) )
		return( NULL ); 

	/* The image may be coded .. unpack to double.
	 */
	if( vips_image_decode( t[1], &t[2] ) ||
		vips_cast( t[2], &t[3], VIPS_FORMAT_DOUBLE, NULL ) )
		return( NULL );

	/* To a mem buffer, then copy to out. 
	 */
	if( !(t[4] = vips_image_new_memory()) ||
		vips_image_write( t[3], t[4] ) )
		return( NULL ); 

	if( !(result = VIPS_ARRAY( im, t[4]->Bands, double )) )
		return( NULL ); 
	memcpy( result, t[4]->data, VIPS_IMAGE_SIZEOF_PEL( t[4] ) ); 
	*n = t[4]->Bands; 

#ifdef VIPS_DEBUG
{
	int i;

	printf( "vips__ink_to_vector:\n" );
	printf( "\tink = " ); 
	for( i = 0; i < n; i++ )
		printf( "%d ", ink[i] );
	printf( "\n" ); 

	printf( "\tvec = " ); 
	for( i = 0; i < *n; i++ )
		printf( "%d ", result[i] );
	printf( "\n" ); 
}
#endif /*VIPS_DEBUG*/

	return( result ); 
}

static int
vips_insert_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsInsert *insert = (VipsInsert *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 6 );

	VipsImage **arry;

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
	insert->main_processed = t[2];
	insert->sub_processed = t[3];
	if( !(arry = vips_allocate_input_array( conversion->out, 
		insert->main_processed, insert->sub_processed, NULL )) )
		return( -1 );

	if( vips_image_pipeline_array( conversion->out, 
		VIPS_DEMAND_STYLE_ANY, arry ) )
		return( -1 );

	/* Calculate geometry. 
	 */
	insert->rmain.left = 0;
	insert->rmain.top = 0;
	insert->rmain.width = insert->main_processed->Xsize;
	insert->rmain.height = insert->main_processed->Ysize;
	insert->rsub.left = insert->x;
	insert->rsub.top = insert->y;
	insert->rsub.width = insert->sub_processed->Xsize;
	insert->rsub.height = insert->sub_processed->Ysize;

	if( insert->expand ) {
		/* Expand output to bounding box of these two.
		 */
		vips_rect_unionrect( &insert->rmain, &insert->rsub, 
			&insert->rout );

		/* Translate origin to top LH corner of rout.
		 */
		insert->rmain.left -= insert->rout.left;
		insert->rmain.top -= insert->rout.top;
		insert->rsub.left -= insert->rout.left;
		insert->rsub.top -= insert->rout.top;
		insert->rout.left = 0;
		insert->rout.top = 0;
	}
	else 
		insert->rout = insert->rmain;

	conversion->out->Xsize = insert->rout.width;
	conversion->out->Ysize = insert->rout.height;

	if( !(insert->ink = vips__vector_to_ink( 
		class->nickname, conversion->out,
		(double *) VIPS_ARRAY_ADDR( insert->background, 0 ), NULL, 
		VIPS_AREA( insert->background )->n )) )
		return( -1 );

	if( vips_image_generate( conversion->out,
		vips_start_many, vips_insert_gen, vips_stop_many, 
		arry, insert ) )
		return( -1 );

	return( 0 );
}

/* xy range we sanity check on ... just to stop crazy numbers from 1/0 etc.
 * causing g_assert() failures later.
 */
#define RANGE (100000000)

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

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "main", -1, 
		_( "Main" ), 
		_( "Main input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInsert, main ) );

	VIPS_ARG_IMAGE( class, "sub", 0, 
		_( "Sub-image" ), 
		_( "Sub-image to insert into main image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInsert, sub ) );

	VIPS_ARG_INT( class, "x", 2, 
		_( "X" ), 
		_( "Left edge of sub in main" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInsert, x ),
		-RANGE, RANGE, 0 );

	VIPS_ARG_INT( class, "y", 3, 
		_( "Y" ), 
		_( "Top edge of sub in main" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInsert, y ),
		-RANGE, RANGE, 0 );

	VIPS_ARG_BOOL( class, "expand", 4, 
		_( "Expand" ), 
		_( "Expand output to hold all of both inputs" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsInsert, expand ),
		FALSE );

	VIPS_ARG_BOXED( class, "background", 5, 
		_( "Background" ), 
		_( "Colour for new pixels" ),
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
 * vips_insert:
 * @main: big image
 * @sub: small image
 * @out: output image
 * @x: left position of @sub
 * @y: top position of @sub
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @expand: expand output to hold whole of both images
 * @background: colour for new pixels
 *
 * Insert one image into another. @sub is inserted into image @main at
 * position @x, @y relative to the top LH corner of @main. 
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
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
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
