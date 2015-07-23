/* Swap image byte order.
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

typedef struct _VipsByteswap {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *in;

} VipsByteswap;

typedef VipsConversionClass VipsByteswapClass;

G_DEFINE_TYPE( VipsByteswap, vips_byteswap, VIPS_TYPE_CONVERSION );

/* Swap pairs of bytes.
 */
static void
vips_byteswap_swap2( VipsPel *in, VipsPel *out, int width, VipsImage *im )
{ 
	guint16 *p = (guint16 *) in;
	guint16 *q = (guint16 *) out;
        int sz = (VIPS_IMAGE_SIZEOF_PEL( im ) * width) / 2;    

        int x;

        for( x = 0; x < sz; x++ ) 
		q[x] = GUINT16_SWAP_LE_BE( p[x] );
}

/* Swap 4- of bytes.
 */
static void
vips_byteswap_swap4( VipsPel *in, VipsPel *out, int width, VipsImage *im )
{
	guint32 *p = (guint32 *) in;
	guint32 *q = (guint32 *) out;
        int sz = (VIPS_IMAGE_SIZEOF_PEL( im ) * width) / 4;    

        int x;

        for( x = 0; x < sz; x++ ) 
		q[x] = GUINT32_SWAP_LE_BE( p[x] );
}

/* Swap 8- of bytes.
 */
static void
vips_byteswap_swap8( VipsPel *in, VipsPel *out, int width, VipsImage *im )
{
	guint64 *p = (guint64 *) in;
	guint64 *q = (guint64 *) out;
        int sz = (VIPS_IMAGE_SIZEOF_PEL( im ) * width) / 8;    

        int x;

        for( x = 0; x < sz; x++ ) 
		q[x] = GUINT64_SWAP_LE_BE( p[x] );
}

typedef void (*SwapFn)( VipsPel *in, VipsPel *out, int width, VipsImage *im );

static SwapFn vips_byteswap_swap_fn[] = {
	NULL, 			/* VIPS_FORMAT_UCHAR = 0, */
	NULL, 			/* VIPS_FORMAT_CHAR = 1, */
	vips_byteswap_swap2,	/* VIPS_FORMAT_USHORT = 2, */
	vips_byteswap_swap2, 	/* VIPS_FORMAT_SHORT = 3, */
	vips_byteswap_swap4, 	/* VIPS_FORMAT_UINT = 4, */
	vips_byteswap_swap4, 	/* VIPS_FORMAT_INT = 5, */
	vips_byteswap_swap4, 	/* VIPS_FORMAT_FLOAT = 6, */
	vips_byteswap_swap4, 	/* VIPS_FORMAT_COMPLEX = 7, */
	vips_byteswap_swap8, 	/* VIPS_FORMAT_DOUBLE = 8, */
	vips_byteswap_swap8 	/* VIPS_FORMAT_DPCOMPLEX = 9, */
};

/* Byteswap, turning bands into the x axis.
 */
static int
vips_byteswap_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsImage *im = ir->im;
	VipsRect *r = &or->valid;
	SwapFn swap = vips_byteswap_swap_fn[im->BandFmt];

	int y;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	for( y = 0; y < r->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir, r->left, r->top + y );
		VipsPel *q = VIPS_REGION_ADDR( or, r->left, r->top + y );

		swap( p, q, r->width, im );
	}

	return( 0 );
}

static int
vips_byteswap_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsByteswap *byteswap = (VipsByteswap *) object;

	if( VIPS_OBJECT_CLASS( vips_byteswap_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( byteswap->in ) )
		return( -1 );

	if( vips_image_pipelinev( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, byteswap->in, NULL ) )
		return( -1 );

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_byteswap_gen, vips_stop_one, 
		byteswap->in, byteswap ) )
		return( -1 );

	return( 0 );
}

static void
vips_byteswap_class_init( VipsByteswapClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_byteswap_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "byteswap";
	vobject_class->description = _( "byteswap an image" );
	vobject_class->build = vips_byteswap_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsByteswap, in ) );

}

static void
vips_byteswap_init( VipsByteswap *byteswap )
{
}

/**
 * vips_byteswap:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Swap the byte order in an image. 
 *
 * See also: vips_rawload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_byteswap( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "byteswap", ap, in, out );
	va_end( ap );

	return( result );
}

/* Convenience function: swap if @swap is %TRUE, otherwise copy.
 */
int
vips__byteswap_bool( VipsImage *in, VipsImage **out, gboolean swap )
{
	if( swap ) 
		return( vips_byteswap( in, out, NULL ) );
	else
		return( vips_copy( in, out, NULL ) );
}
