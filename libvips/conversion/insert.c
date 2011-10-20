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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "conversion.h"

/**
 * VipsInsert:
 * @main: big image
 * @sub: small image
 * @out: output image
 * @x: left position of @sub
 * @y: top position of @sub
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
 * See also: im_insert_noexpand(), im_lrjoin().
 *
 * Returns: 0 on success, -1 on error
 */

typedef struct _VipsInsert {
	VipsConversion parent_instance;

	/* Params.
	 */
	VipsImage *main;
	VipsImage *sub;
	int x;
	int y;
	gboolean expand;
	GArray *background;

	/* Pixel we paint calculated from background.
	 */
	PEL *ink;

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
	VIpsRect need;

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

	Rect ovl;

	/* Ask for input we need.
	 */
	if( vips_region_prepare( ir, r ) )
		return( -1 );

	/* Does the rect we have been asked for fall entirely inside the
	 * sub-image?
	 */
	if( vips_rect_includesrect( &ins->rsub, &or->valid ) ) 
		return( vips_insert_just_one( or, ir[1], 
			ins->rsub.left, ins->rsub.top ) );
	
	/* Does it fall entirely inside the main, and not at all inside the
	 * sub?
	 */
	vips_rect_intersectrect( &or->valid, &ins->rsub, &ovl );
	if( vips_rect_includesrect( &ins->rmain, &or->valid ) &&
		vips_rect_isempty( &ovl ) ) 
		return( vips_insert_just_one( or, ir[0], 
			ins->rmain.left, ins->rmain.top ) );

	/* Output requires both (or neither) input. If it is not entirely 
	 * inside both the main and the sub, then there is going to be some
	 * background. 
	 */
	if( !(vips_rect_includesrect( &ins->rsub, &or->valid ) &&
		vips_rect_includesrect( &ins->rmain, &or->valid )) )
		vips_region_paint_pel( or, r, insert->ink );

	/* Paste from main.
	 */
	if( vips_insert_paste_region( or, ir[0], &ins->rmain ) )
		return( -1 );

	/* Paste from sub.
	 */
	if( vips_insert_paste_region( or, ir[1], &ins->rsub ) )
		return( -1 );

	return( 0 );
}

/* Calculate a pixel for an image from a vec of double. Valid while im is
 * valid.
 */
PEL *
vips__vector_to_ink( const char *domain, VipsImage *im, int n, double *vec )
{
	VipsImage *t[3];
	double *zeros;
	int i;

	if( vips_check_vector( domain, n, im ) )
		return( NULL );
	if( vips_open_local_array( im, t, 3, domain, "t" ) ||
		!(zeros = VIPS_ARRAY( im, n, double )) )
		return( NULL );
	for( i = 0; i < n; i++ )
		zeros[i] = 0.0;

	if( im_black( t[0], 1, 1, im->Bands ) ||
		im_lintra_vec( n, zeros, t[0], vec, t[1] ) ||
		im_clip2fmt( t[1], t[2], im->BandFmt ) )
		return( NULL );

	return( (PEL *) t[2]->data );
}

/* xy range we sanity check on ... just to stop crazy numbers from 1/0 etc.
 * causing assert() failures later.
 */
#define RANGE (100000000)

static int
vips_insert_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsInsert *insert = (VipsInsert *) object;

	VipsImage *t[4];
	VipsImage **arry;
	int i;

	/* Check args.
	 */
	if( insert->x > RANGE || insert->x < -RANGE || 
		insert->y > RANGE || insert->y < -RANGE ) {
		vips_error( "VipsInsert", "%s", _( "xy out of range" ) );
		return( -1 ); 
	}

	if( VIPS_OBJECT_CLASS( vips_insert_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( insert->main ) || 
		vips_image_pio_input( insert->sub ) || 
		vips_image_pio_output( conversion->output ) ||
		vips_check_bands_1orn( domain, in1, in2 ) ||
		vips_check_coding_known( domain, in1 ) ||
		vips_check_coding_same( domain, in1, in2 ) )
		return( -1 );

	if( vips_image_new_array( object, t, 4 ) )
		return( -1 );

	/* Cast our input images up to a common format and bands.
	 */
	if( vips__formatalike( insert->main, insert->sub, t[0], t[1] ) ||
		vips__bandalike( domain, t[0], t[1], t[2], t[3] ) )
		return( -1 );
	insert->main_processed = t[2];
	insert->sub_processed = t[3];
	if( !(arry = vips_allocate_input_array( conversion->output, 
		insert->main_processed, insert->sub_processed, NULL )) )
		return( -1 );

	if( vips_image_copy_fields_array( conversion->output, arry ) )
		return( -1 );
        vips_demand_hint_array( arithmetic->output, 
		VIPS_DEMAND_STYLE_SMALLTILE, arry );

	/* Calculate geometry. 
	 */
	insert->rmain.left = 0;
	insert->rmain.top = 0;
	insert->rmain.width = insert->main_processed->Xsize;
	insert->rmain.height = insert->main_processed->Ysize;
	insert->rsub.left = x;
	insert->rsub.top = y;
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
		ins->rout = ins->rmain;

	conversion->output->Xsize = insert->rout.width;
	conversion->output->Ysize = insert->rout.height;

	if( !(insert->ink = vips__vector_to_ink( 
		"VipsInsert", conversion->output,
		insert->background, insert->n )) )
		return( -1 );

	if( vips_image_generate( conversion->output,
		vips_start_many, vips_insert_gen, vips_stop_many, 
		arry, insert ) )
		return( -1 );

	return( 0 );
}

static void
vips_insert_class_init( VipsInsertClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_insert_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "insert";
	vobject_class->description = _( "insert an image" );
	vobject_class->build = vips_insert_build;

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
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "y", 3, 
		_( "Y" ), 
		_( "Top edge of sub in main" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsInsert, y ),
		0, 1000000, 0 );

	VIPS_ARG_BOOL( class, "expand", 4, 
		_( "Expand" ), 
		_( "Expand output to hold all of both inputs" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsInsert, expand ),
		FALSE );

	VIPS_ARG_ARRAY( class, "background", 5, 
		_( "Background" ), 
		_( "Colour for new pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsInsert, background ),
		FALSE );

}

static void
vips_insert_init( VipsInsert *insert )
{
	/* Init our instance fields.
	 */
}

int
vips_insert( VipsImage *main, VipsImage *sub, VipsImage **out, 
	int x, int y, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "insert", ap, main, sub, out, x, y );
	va_end( ap );

	return( result );
}
