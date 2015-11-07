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
 * 7/11/15
 * 	- added bandjoin_const
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
	VipsArrayImage *in;
} VipsBandjoin;

typedef VipsBandaryClass VipsBandjoinClass;

G_DEFINE_TYPE( VipsBandjoin, vips_bandjoin, VIPS_TYPE_BANDARY );

static void
vips_bandjoin_buffer( VipsBandary *bandary, VipsPel *q, VipsPel **p, int width )
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

		VipsPel *p1, *q1;
		int x, z;

		q1 = q;
		p1 = p[i];

		for( x = 0; x < width; x++ ) {
			for( z = 0; z < ips; z++ )
				q1[z] = p1[z];

			p1 += ips;
			q1 += ops;
		}

		q += ips;
	}
}

static int
vips_bandjoin_build( VipsObject *object )
{
	VipsBandary *bandary = (VipsBandary *) object;
	VipsBandjoin *bandjoin = (VipsBandjoin *) object;

	if( bandjoin->in ) {
		bandary->in = vips_array_image_get( bandjoin->in, &bandary->n );

		if( bandary->n == 1 ) 
			return( vips_bandary_copy( bandary ) );
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
	VipsArrayImage *array; 
	int result;

	array = vips_array_image_new( in, n ); 
	result = vips_call_split( "bandjoin", ap, array, out );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}

/**
 * vips_bandjoin:
 * @in: (array length=n) (transfer none): array of input images
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
 * <link linkend="libvips-arithmetic">arithmetic</link>).
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

typedef struct _VipsBandjoinConst {
	VipsBandary parent_instance;

	VipsImage *in;
	VipsArrayDouble *c;

	/* The constant expanded to in's format, ready to be appended to each
	 * pixel.
	 */
	int n;
	VipsPel *c_ready;

} VipsBandjoinConst;

typedef VipsBandaryClass VipsBandjoinConstClass;

G_DEFINE_TYPE( VipsBandjoinConst, vips_bandjoin_const, VIPS_TYPE_BANDARY );

static void
vips_bandjoin_const_finalize( GObject *object )
{
	VipsBandjoinConst *bandjoin = (VipsBandjoinConst *) object;

	VIPS_FREE( bandjoin->c_ready ); 

	G_OBJECT_CLASS( vips_bandjoin_const_parent_class )->finalize( object );
}

static void
vips_bandjoin_const_buffer( VipsBandary *bandary, 
	VipsPel *q, VipsPel **p, int width )
{
	VipsConversion *conversion = (VipsConversion *) bandary;
	VipsBandjoinConst *bandjoin = (VipsBandjoinConst *) bandary;
	VipsImage *in = bandary->ready[0];

	/* Output pel size.
	 */
	const int ops = VIPS_IMAGE_SIZEOF_PEL( conversion->out );

	/* Input pel size.
	 */
	const int ips = VIPS_IMAGE_SIZEOF_PEL( in );

	/* Extra bands size.
	 */
	const int ebs = ops - ips; 

	VipsPel * restrict p1;
	VipsPel * restrict q1;
	int x, z;

	q1 = q;
	p1 = p[0];

	for( x = 0; x < width; x++ ) {
		for( z = 0; z < ips; z++ )
			q1[z] = p1[z];

		p1 += ips;
		q1 += ips;

		for( z = 0; z < ebs; z++ )
			q1[z] = bandjoin->c_ready[z];

		q1 += ebs;
	}
}

static int
vips_bandjoin_const_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsBandary *bandary = (VipsBandary *) object;
	VipsBandjoinConst *bandjoin = (VipsBandjoinConst *) object;

	if( bandjoin->c &&
		bandjoin->in ) {
		double *c;
		int n;

		c = vips_array_double_get( bandjoin->c, &n );

		if( n == 0 ) 
			return( vips_bandary_copy( bandary ) );
		else 
			bandary->out_bands = bandjoin->in->Bands + n;

		bandary->n = 1;
		bandary->in = &bandjoin->in;

		if( !(bandjoin->c_ready = vips__vector_to_pels( class->nickname,
			n, bandjoin->in->BandFmt, bandjoin->in->Coding, 
			c, NULL, n )) )
			return( -1 );

	}

	if( VIPS_OBJECT_CLASS( vips_bandjoin_const_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_bandjoin_const_class_init( VipsBandjoinConstClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsBandaryClass *bandary_class = VIPS_BANDARY_CLASS( class );

	VIPS_DEBUG_MSG( "vips_bandjoin_const_class_init\n" );

	gobject_class->finalize = vips_bandjoin_const_finalize;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "bandjoin_const";
	vobject_class->description = _( "append a constant band to an image" );
	vobject_class->build = vips_bandjoin_const_build;

	bandary_class->process_line = vips_bandjoin_const_buffer;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBandjoinConst, in ) ); 

	VIPS_ARG_BOXED( class, "c", 12, 
		_( "Constants" ), 
		_( "Array of constants to add" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsBandjoinConst, c ),
		VIPS_TYPE_ARRAY_DOUBLE );

}

static void
vips_bandjoin_const_init( VipsBandjoinConst *bandjoin )
{
	/* Init our instance fields.
	 */
}

static int
vips_bandjoin_constv( VipsImage *in, VipsImage **out, 
	double *c, int n, va_list ap )
{
	VipsArrayDouble *array; 
	int result;

	array = vips_array_double_new( c, n ); 
	result = vips_call_split( "bandjoin_const", ap, in, out, array );
	vips_area_unref( VIPS_AREA( array ) );

	return( result );
}

/**
 * vips_bandjoin_const:
 * @in: (array length=n) (transfer none): array of input images
 * @out: output image
 * @c: (array length=n): array of constants to append
 * @n: number of constants
 * @...: %NULL-terminated list of optional named arguments
 *
 * Append a set of constant bands to an image. 
 *
 * See also: vips_bandjoin().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandjoin_const( VipsImage *in, VipsImage **out, double *c, int n, ... )
{
	va_list ap;
	int result;

	va_start( ap, n );
	result = vips_bandjoin_constv( in, out, c, n, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_bandjoin_const1:
 * @in: input image
 * @out: output image
 * @c: constant to append
 * @...: %NULL-terminated list of optional named arguments
 *
 * Append a single constant band to an image.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_bandjoin_const1( VipsImage *in, VipsImage **out, double c, ... )
{
	va_list ap;
	int result;

	va_start( ap, c );
	result = vips_bandjoin_constv( in, out, &c, 1, ap );
	va_end( ap );

	return( result );
}
