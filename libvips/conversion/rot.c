/* rotate by 0/90/180/270 degrees
 *
 * Copyright: 1991, N. Dessipris
 * Written on: 28/10/91
 * Updated on: 2/4/92, J.Cupitt 
 * 	bugs in im_la90rot fixed, now works for any type.
 * 19/7/93 JC
 *	- IM_CODING_LABQ allowed now
 * 15/11/94 JC
 *	- name changed
 *	- memory leaks fixed
 * 8/2/95 JC
 *	- oops! memory allocation problem fixed
 * 18/5/95 JC
 * 	- IM_MAXLINES increased
 * 13/8/96 JC
 *	- rewritten for partials
 * 6/11/02 JC
 *	- speed-up ... replace memcpy() with a loop for small pixels
 * 14/4/04
 *	- sets Xoffset / Yoffset
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 1/2/10
 * 	- cleanups
 * 	- gtkdoc
 * 4/11/11
 * 	- rewrite as a class
 * 7/3/17
 * 	- added 90/180/270 convenience functions
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
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pconversion.h"

typedef struct _VipsRot {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *in;

	/* Rotate by ...
	 */
	VipsAngle angle;

} VipsRot;

typedef VipsConversionClass VipsRotClass;

G_DEFINE_TYPE( VipsRot, vips_rot, VIPS_TYPE_CONVERSION );

static int
vips_rot90_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsImage *in = (VipsImage *) a;

	/* Output area.
	 */
	VipsRect *r = &or->valid;
	int le = r->left;
	int ri = VIPS_RECT_RIGHT(r);
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);

	int x, y, i;

	/* Pixel geometry.
	 */
	int ps, ls;

	/* Find the area of the input image we need.
	 */
	VipsRect need;

	need.left = to;
	need.top = in->Ysize - ri;
	need.width = r->height;
	need.height = r->width;
	if( vips_region_prepare( ir, &need ) )
		return( -1 );
	
	/* Find PEL size and line skip for ir.
	 */
	ps = VIPS_IMAGE_SIZEOF_PEL( in );
	ls = VIPS_REGION_LSKIP( ir );

	/* Rotate the bit we now have.
	 */
	for( y = to; y < bo; y++ ) {
		/* Start of this output line.
		 */
		VipsPel *q = VIPS_REGION_ADDR( or, le, y );

		/* Corresponding position in ir.
		 */
		VipsPel *p = VIPS_REGION_ADDR( ir, 
			need.left + y - to, 
			need.top + need.height - 1 );

		for( x = le; x < ri; x++ ) {
			for( i = 0; i < ps; i++ )
				q[i] = p[i];

			q += ps;
			p -= ls;
		}
	}

	return( 0 );
}

static int
vips_rot180_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsImage *in = (VipsImage *) a;

	/* Output area.
	 */
	VipsRect *r = &or->valid;
	int le = r->left;
	int ri = VIPS_RECT_RIGHT(r);
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);

	int x, y;

	/* Pixel geometry.
	 */
	int ps;

	/* Find the area of the input image we need.
	 */
	VipsRect need;

	need.left = in->Xsize - ri;
	need.top = in->Ysize - bo;
	need.width = r->width;
	need.height = r->height;
	if( vips_region_prepare( ir, &need ) )
		return( -1 );

	/* Find PEL size and line skip for ir.
	 */
	ps = VIPS_IMAGE_SIZEOF_PEL( in );

	/* Rotate the bit we now have.
	 */
	for( y = to; y < bo; y++ ) {
		/* Start of this output line.
		 */
		VipsPel *q = VIPS_REGION_ADDR( or, le, y );

		/* Corresponding position in ir.
		 */
		VipsPel *p = VIPS_REGION_ADDR( ir, 
			need.left + need.width - 1, 
			need.top + need.height - (y - to) - 1 );

		/* Blap across!
		 */
		for( x = le; x < ri; x++ ) {
			memcpy( q, p, ps );
			q += ps;
			p -= ps;
		}
	}

	return( 0 );
}

static int
vips_rot270_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsImage *in = (VipsImage *) a;

	/* Output area.
	 */
	VipsRect *r = &or->valid;
	int le = r->left;
	int ri = VIPS_RECT_RIGHT(r);
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);

	int x, y, i;

	/* Pixel geometry.
	 */
	int ps, ls;

	/* Find the area of the input image we need.
	 */
	VipsRect need;

	need.left = in->Xsize - bo;
	need.top = le;
	need.width = r->height;
	need.height = r->width;
	if( vips_region_prepare( ir, &need ) )
		return( -1 );
	
	/* Find PEL size and line skip for ir.
	 */
	ps = VIPS_IMAGE_SIZEOF_PEL( in );
	ls = VIPS_REGION_LSKIP( ir );

	/* Rotate the bit we now have.
	 */
	for( y = to; y < bo; y++ ) {
		/* Start of this output line.
		 */
		VipsPel *q = VIPS_REGION_ADDR( or, le, y );

		/* Corresponding position in ir.
		 */
		VipsPel *p = VIPS_REGION_ADDR( ir, 
			need.left + need.width - (y - to) - 1,
			need.top );

		for( x = le; x < ri; x++ ) {
			for( i = 0; i < ps; i++ )
				q[i] = p[i];

			q += ps;
			p += ls;
		}
	}

	return( 0 );
}

static int
vips_rot_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsRot *rot = (VipsRot *) object;

	VipsGenerateFn generate_fn;
	VipsDemandStyle hint;

	if( VIPS_OBJECT_CLASS( vips_rot_parent_class )->build( object ) )
		return( -1 );

	if( rot->angle == VIPS_ANGLE_D0 )
		return( vips_image_write( rot->in, conversion->out ) );

	if( vips_image_pio_input( rot->in ) )
		return( -1 );

	hint = rot->angle == VIPS_ANGLE_D180 ? 
		VIPS_DEMAND_STYLE_THINSTRIP :
		VIPS_DEMAND_STYLE_SMALLTILE; 

	if( vips_image_pipelinev( conversion->out, hint, rot->in, NULL ) )
		return( -1 );

	switch( rot->angle ) {
	case VIPS_ANGLE_D90:
		generate_fn = vips_rot90_gen;
		conversion->out->Xsize = rot->in->Ysize;
		conversion->out->Ysize = rot->in->Xsize;
		conversion->out->Xoffset = rot->in->Ysize;
		conversion->out->Yoffset = 0;
		break;

	case VIPS_ANGLE_D180:
		generate_fn = vips_rot180_gen;
		conversion->out->Xoffset = rot->in->Xsize;
		conversion->out->Yoffset = rot->in->Ysize;
		break;

	case VIPS_ANGLE_D270:
		generate_fn = vips_rot270_gen;
		conversion->out->Xsize = rot->in->Ysize;
		conversion->out->Ysize = rot->in->Xsize;
		conversion->out->Xoffset = 0;
		conversion->out->Yoffset = rot->in->Xsize;
		break;

	default:
		g_assert_not_reached();

		/* Stop compiler warnings.
		 */
		generate_fn = NULL;
	}

	if( vips_image_generate( conversion->out,
		vips_start_one, generate_fn, vips_stop_one, 
		rot->in, rot ) )
		return( -1 );

	return( 0 );
}

static void
vips_rot_class_init( VipsRotClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_rot_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "rot";
	vobject_class->description = _( "rotate an image" );
	vobject_class->build = vips_rot_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRot, in ) );

	VIPS_ARG_ENUM( class, "angle", 6, 
		_( "Angle" ), 
		_( "Angle to rotate image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRot, angle ),
		VIPS_TYPE_ANGLE, VIPS_ANGLE_D90 ); 
}

static void
vips_rot_init( VipsRot *rot )
{
}

static int
vips_rotv( VipsImage *in, VipsImage **out, VipsAngle angle, va_list ap )
{
	return( vips_call_split( "rot", ap, in, out, angle ) );
}

/**
 * vips_rot: (method)
 * @in: input image
 * @out: (out): output image
 * @angle: rotation angle
 * @...: %NULL-terminated list of optional named arguments
 *
 * Rotate @in by a multiple of 90 degrees.
 *
 * Use vips_similarity() to rotate by an arbitary angle. vips_rot45() is 
 * useful for rotating convolution masks by 45 degrees. 
 *
 * See also: vips_flip(), vips_similarity(), vips_rot45().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_rot( VipsImage *in, VipsImage **out, VipsAngle angle, ... )
{
	va_list ap;
	int result;

	va_start( ap, angle );
	result = vips_rotv( in, out, angle, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_rot90:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Rotate @in by 90 degress clockwise. A convenience function over vips_rot().
 *
 * See also: vips_rot().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_rot90( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_rotv( in, out, VIPS_ANGLE_D90, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_rot180: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Rotate @in by 180 degress. A convenience function over vips_rot().
 *
 * See also: vips_rot().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_rot180( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_rotv( in, out, VIPS_ANGLE_D180, ap );
	va_end( ap );

	return( result );
}

/**
 * vips_rot270: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Rotate @in by 270 degress clockwise. A convenience function over vips_rot().
 *
 * See also: vips_rot().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_rot270( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_rotv( in, out, VIPS_ANGLE_D270, ap );
	va_end( ap );

	return( result );
}
