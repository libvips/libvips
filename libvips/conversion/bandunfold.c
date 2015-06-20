/* Fold up x into bands. 
 *
 * 5/6/15
 * 	- from copy.c
 * 10/6/15
 * 	- add @factor option
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

typedef struct _VipsBandunfold {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *in;

	int factor;

} VipsBandunfold;

typedef VipsConversionClass VipsBandunfoldClass;

G_DEFINE_TYPE( VipsBandunfold, vips_bandunfold, VIPS_TYPE_CONVERSION );

static int
vips_bandunfold_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsBandunfold *bandunfold = (VipsBandunfold *) b;
	VipsRegion *ir = (VipsRegion *) seq;
	VipsImage *in = ir->im;
	VipsImage *out = or->im;
	VipsRect *r = &or->valid;
	int esize = VIPS_IMAGE_SIZEOF_ELEMENT( in );
	int psize = VIPS_IMAGE_SIZEOF_PEL( out );

	VipsRect need;
	int y;

	need.left = r->left / bandunfold->factor;
	need.top = r->top;
	need.width = (1 + r->width) / bandunfold->factor;
	need.height = r->height;
	if( vips_region_prepare( ir, &need ) )
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir, 
			r->left / bandunfold->factor, r->top + y ) + 
			(r->left % bandunfold->factor) * esize;
		VipsPel *q = VIPS_REGION_ADDR( or, r->left, r->top + y );

		/* We can't use vips_region_region() since we change pixel
		 * coordinates.
		 */
		memcpy( q, p, r->width * psize );
	}

	return( 0 );
}

static int
vips_bandunfold_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBandunfold *bandunfold = (VipsBandunfold *) object;

	if( VIPS_OBJECT_CLASS( vips_bandunfold_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( bandunfold->in ) )
		return( -1 );

	if( bandunfold->factor == 0 )
		bandunfold->factor = bandunfold->in->Bands;
	if( bandunfold->in->Bands % bandunfold->factor != 0 ) {
		vips_error( class->nickname, 
			"%s", _( "@factor must be a factor of image bands" ) );
		return( -1 ); 
	}

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, bandunfold->in, NULL ) )
		return( -1 );

	conversion->out->Xsize *= bandunfold->factor;
	conversion->out->Bands /= bandunfold->factor;

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_bandunfold_gen, vips_stop_one, 
		bandunfold->in, bandunfold ) )
		return( -1 );

	return( 0 );
}

static void
vips_bandunfold_class_init( VipsBandunfoldClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_bandunfold_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "bandunfold";
	vobject_class->description = _( "unfold image bands into x axis" );
	vobject_class->build = vips_bandunfold_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBandunfold, in ) );

	VIPS_ARG_INT( class, "factor", 11, 
		_( "Factor" ), 
		_( "Unfold by this factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsBandunfold, factor ),
		0, 10000000, 0 );
}

static void
vips_bandunfold_init( VipsBandunfold *bandunfold )
{
	/* 0 means unfold by width, see above.
	 */
	bandunfold->factor = 0;
}

/**
 * vips_bandunfold:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @factor: unfold by this factor
 *
 * Unfold image bands into x axis. 
 * Use @factor to set how much to unfold by: @factor 3, for example, will make
 * the output image three times wider than the input, and with one third 
 * as many bands. By default, all bands are unfolded.
 *
 * See also: vips_csvload(), vips_bandfold().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_bandunfold( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "bandunfold", ap, in, out );
	va_end( ap );

	return( result );
}
