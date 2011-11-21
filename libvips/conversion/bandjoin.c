/* VipsBandjoin -- bandwise join of a set of images
 *
 * Copyright: 1991, N. Dessipris, modification of im_bandjoin()
 *
 * Author: N. Dessipris
 * Written on: 17/04/1991
 * Modified on : 
 * 16/3/94 JC
 *	- rewritten for partials
 *	- now in ANSI C
 *	- now works for any number of input images, except zero
 * 7/10/94 JC
 *	- new IM_NEW()
 * 16/4/07
 * 	- fall back to im_copy() for 1 input image
 * 17/1/09
 * 	- cleanups
 * 	- gtk-doc
 * 	- im_bandjoin() just calls this
 * 	- works for RAD coding too
 * 27/1/10
 * 	- formatalike inputs
 * 17/5/11
 * 	- sizealike inputs
 * 27/10/11
 * 	- rewrite as a class
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
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "bandary.h"

typedef struct _VipsBandjoin {
	VipsBandary parent_instance;

	/* The input images.
	 */
	VipsArea *in;
} VipsBandjoin;

typedef VipsBandaryClass VipsBandjoinClass;

G_DEFINE_TYPE( VipsBandjoin, vips_bandjoin, VIPS_TYPE_BANDARY );

static void
vips_bandjoin_buffer( VipsBandary *bandary, PEL *q, PEL **p, int width )
{
	VipsConversion *conversion = (VipsConversion *) bandary;
	VipsImage **in = bandary->ready;

	/* Output pel size.
	 */
	const int ops = VIPS_IMAGE_SIZEOF_PEL( conversion->out );

	int i;

	/* Loop for each input image. Scattered write is faster than
	 * scattered read.
	 */
	for( i = 0; i < bandary->n; i++ ) {
		/* Input pel size.
		 */
		int ips = VIPS_IMAGE_SIZEOF_PEL( in[i] );

		PEL *p1, *q1;
		int x, z;

		q1 = q + i * ips;
		p1 = p[i];

		for( x = 0; x < width; x++ ) {
			for( z = 0; z < ips; z++ )
				q1[z] = p1[z];

			p1 += ips;
			q1 += ops;
		}
	}
}

static int
vips_bandjoin_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBandary *bandary = (VipsBandary *) object;
	VipsBandjoin *bandjoin = (VipsBandjoin *) object;

	if( bandjoin->in ) {
		bandary->in = bandjoin->in->data;
		bandary->n = bandjoin->in->n;
		
		if( bandary->n == 1 ) {
			g_object_set( conversion, 
				"out", vips_image_new(), 
				NULL ); 

			return( vips_image_write( bandary->in[0], 
				conversion->out ) );
		}
		else {
			int i;

			bandary->out_bands = 0;
			for( i = 0; i < bandary->n; i++ ) 
				bandary->out_bands += bandary->in[i]->Bands;
		}
	}

	if( VIPS_OBJECT_CLASS( vips_bandjoin_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_bandjoin_class_init( VipsBandjoinClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsBandaryClass *bandary_class = VIPS_BANDARY_CLASS( class );

	VIPS_DEBUG_MSG( "vips_bandjoin_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "bandjoin";
	vobject_class->description = _( "bandwise join a set of images" );
	vobject_class->build = vips_bandjoin_build;

	bandary_class->process_line = vips_bandjoin_buffer;

	VIPS_ARG_BOXED( class, "in", 0, 
		_( "Input" ), 
		_( "Array of input images" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBandjoin, in ),
		VIPS_TYPE_ARRAY_IMAGE );

}

static void
vips_bandjoin_init( VipsBandjoin *bandjoin )
{
	/* Init our instance fields.
	 */
}

static int
vips_bandjoinv( VipsImage **in, VipsImage **out, int n, va_list ap )
{
	VipsArea *area;
	VipsImage **array; 
	int i;
	int result;

	area = vips_area_new_array_object( n );
	array = (VipsImage **) area->data;
	for( i = 0; i < n; i++ ) {
		array[i] = in[i];
		g_object_ref( array[i] );
	}

	result = vips_call_split( "bandjoin", ap, area, out );

	vips_area_unref( area );

	return( result );
}

/**
 * vips_bandjoin:
 * @in: array of input images
 * @out: output image
 * @n: number of input images
 * @...: %NULL-terminated list of optional named arguments
 *
 * Join a set of images together, bandwise. 
 *
 * If the images
 * have n and m bands, then the output image will have n + m
 * bands, with the first n coming from the first image and the last m
 * from the second. 
 *
 * If the images differ in size, the smaller images are enlarged to match the
 * larger by adding zero pixels along the bottom and right.
 *
 * The input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: vips_insert().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandjoin( VipsImage **in, VipsImage **out, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_bandjoinv( in, out, n, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_bandjoin2:
 * @in1: first input image
 * @in2: second input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Join a pair of images together, bandwise. See vips_bandjoin().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandjoin2( VipsImage *in1, VipsImage *in2, VipsImage **out, ... )
{
	va_list ap;
	int result;
	VipsImage *in[2];

	in[0] = in1;
	in[1] = in2;

	va_start( ap, out );
	result = vips_bandjoinv( in, out, 2, ap );
	va_end( ap );

	return( result );
}
