/* Fold up x into bands. 
 *
 * 5/6/15
 * 	- from copy.c
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

typedef struct _VipsBandfold {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *in;

} VipsBandfold;

typedef VipsConversionClass VipsBandfoldClass;

G_DEFINE_TYPE( VipsBandfold, vips_bandfold, VIPS_TYPE_CONVERSION );

static int
vips_bandfold_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsImage *in = ir->im;
	VipsImage *out = or->im;
	VipsRect *r = &or->valid;
	int psize = VIPS_IMAGE_SIZEOF_PEL( out );

	VipsRect need;
	int y;

	need.left = 0;
	need.top = r->top;
	need.width = in->Xsize;
	need.height = r->height;
	if( vips_region_prepare( ir, &need ) )
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir, 0, r->top + y );
		VipsPel *q = VIPS_REGION_ADDR( or, 0, r->top + y );

		/* We can't use vips_region_region() since we change pixel
		 * coordinates.
		 */
		memcpy( q, p, psize );
	}

	return( 0 );
}

static int
vips_bandfold_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBandfold *bandfold = (VipsBandfold *) object;

	if( VIPS_OBJECT_CLASS( vips_bandfold_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( bandfold->in ) )
		return( -1 );

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, bandfold->in, NULL ) )
		return( -1 );

	conversion->out->Xsize = 1;
	conversion->out->Bands *= bandfold->in->Xsize;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_bandfold_gen, vips_stop_one, 
		bandfold->in, bandfold ) )
		return( -1 );

	return( 0 );
}

static void
vips_bandfold_class_init( VipsBandfoldClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_bandfold_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "bandfold";
	vobject_class->description = _( "fold up x axis into bands" );
	vobject_class->build = vips_bandfold_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBandfold, in ) );

}

static void
vips_bandfold_init( VipsBandfold *bandfold )
{
}

/**
 * vips_bandfold:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Fold up an image horizontally: width is collapsed into bands. 
 * @out has width 1 and has bands 
 * equal to @in bands times @in width. 
 *
 * See also: vips_csvload(), vips_bandunfold().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_bandfold( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "bandfold", ap, in, out );
	va_end( ap );

	return( result );
}
