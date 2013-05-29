/* Copy an image. 
 *
 * Copyright: 1990, N. Dessipris, based on im_powtra()
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 23/4/93 J.Cupitt
 *	- adapted to work with partial images
 * 30/6/93 JC
 *	- adapted for partial v2
 *	- and ANSI C
 * 7/7/93 JC
 *	- now does IM_CODING_LABQ too
 * 22/2/95 JC
 *	- new use of im_region_region()
 * 25/6/02 JC
 *	- added im_copy_set()
 *	- hint is IM_ANY
 * 5/9/02 JC
 *	- added xoff/yoff to copy_set
 * 14/4/04 JC
 *	- im_copy() now zeros Xoffset/Yoffset (since origin is the same as
 *	  input)
 * 26/5/04 JC
 *	- added im_copy_swap()
 * 1/6/05
 *	- added im_copy_morph()
 * 13/6/05
 *	- oop, im_copy_set() was messed up
 * 29/9/06
 * 	- added im_copy_set_meta(), handy wrapper for nip2 to set meta fields
 * 2/11/06
 * 	- moved im__convert_saveable() here so it's always defined (was part
 * 	  of JPEG write code)
 * 15/2/08
 * 	- added im__saveable_t ... so we can have CMYK JPEG write
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 28/1/10
 * 	- gtk-doc
 * 	- cleanups
 * 	- removed im_copy_from() and associated stuff
 * 	- added im_copy_native()
 * 28/11/10
 * 	- im_copy_set() now sets xoff / yoff again hmmm
 * 29/9/11
 * 	- rewrite as a class
 * 1/12/11
 * 	- use glib byteswap macros
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "conversion.h"

typedef struct _VipsCopy {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *in;

	/* Swap bytes on the way through.
	 */
	gboolean swap;

	/* Fields we can optionally set on the way through.
	 */
	VipsInterpretation interpretation;
	double xres;
	double yres;
	int xoffset;
	int yoffset;
	int bands;
	VipsBandFormat format;	
	VipsCoding coding;
	int width;
	int height;

} VipsCopy;

typedef VipsConversionClass VipsCopyClass;

G_DEFINE_TYPE( VipsCopy, vips_copy, VIPS_TYPE_CONVERSION );

/* Swap pairs of bytes.
 */
static void
vips_copy_swap2( VipsPel *in, VipsPel *out, int width, VipsImage *im )
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
vips_copy_swap4( VipsPel *in, VipsPel *out, int width, VipsImage *im )
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
vips_copy_swap8( VipsPel *in, VipsPel *out, int width, VipsImage *im )
{
	guint64 *p = (guint64 *) in;
	guint64 *q = (guint64 *) out;
        int sz = (VIPS_IMAGE_SIZEOF_PEL( im ) * width) / 8;    

        int x;

        for( x = 0; x < sz; x++ ) 
		q[x] = GUINT64_SWAP_LE_BE( p[x] );
}

typedef void (*SwapFn)( VipsPel *in, VipsPel *out, int width, VipsImage *im );

static SwapFn vips_copy_swap_fn[] = {
	NULL, 			/* VIPS_FORMAT_UCHAR = 0, */
	NULL, 			/* VIPS_FORMAT_CHAR = 1, */
	vips_copy_swap2,	/* VIPS_FORMAT_USHORT = 2, */
	vips_copy_swap2, 	/* VIPS_FORMAT_SHORT = 3, */
	vips_copy_swap4, 	/* VIPS_FORMAT_UINT = 4, */
	vips_copy_swap4, 	/* VIPS_FORMAT_INT = 5, */
	vips_copy_swap4, 	/* VIPS_FORMAT_FLOAT = 6, */
	vips_copy_swap4, 	/* VIPS_FORMAT_COMPLEX = 7, */
	vips_copy_swap8, 	/* VIPS_FORMAT_DOUBLE = 8, */
	vips_copy_swap8 	/* VIPS_FORMAT_DPCOMPLEX = 9, */
};

/* Copy a small area.
 */
static int
vips_copy_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &or->valid;
	VipsCopy *copy = (VipsCopy *) b; 
	SwapFn swap = vips_copy_swap_fn[copy->in->BandFmt];

	/* Ask for input we need.
	 */
	if( vips_region_prepare( ir, r ) )
		return( -1 );

	if( copy->swap && swap ) {
		int y;

		for( y = 0; y < r->height; y++ ) {
			VipsPel *p = VIPS_REGION_ADDR( ir, 
				r->left, r->top + y );
			VipsPel *q = VIPS_REGION_ADDR( or, 
				r->left, r->top + y );

			swap( p, q, r->width, copy->in );
		}
	}
	else
		/* Nothing to do, just copy with pointers.
		 */
		if( vips_region_region( or, ir, r, r->left, r->top ) )
			return( -1 );

	return( 0 );
}

/* The props we copy, if set, from the operation to the image.
 */
static const char *vips_copy_names[] = {
	"interpretation", 
	"xres", 	
	"yres", 
	"xoffset", 
	"yoffset",
	"bands", 
	"format", 		
	"coding", 	
	"width", 
	"height"
}; 

static int
vips_copy_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsCopy *copy = (VipsCopy *) object;

	int i;

	if( VIPS_OBJECT_CLASS( vips_copy_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( copy->in ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->out, copy->in ) )
		return( -1 );
        vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, copy->in, NULL );

	/* Use props to adjust header fields.
	 */
	for( i = 0; i < VIPS_NUMBER( vips_copy_names ); i++ ) {
		const char *name = vips_copy_names[i];

		GParamSpec *pspec;
		VipsArgumentClass *argument_class;
		VipsArgumentInstance *argument_instance;

		if( vips_object_get_argument( object, name,
			&pspec, &argument_class, &argument_instance ) )
			return( -1 );

		if( argument_instance->assigned ) {
			GType type = G_PARAM_SPEC_VALUE_TYPE( pspec );
			GValue value = { 0, };

			g_value_init( &value, type );
			g_object_get_property( G_OBJECT( object ), 
				name, &value );

#ifdef VIPS_DEBUG
{
			char *str;

			str = g_strdup_value_contents( &value );
			printf( "vips_copy_build: %s = %s\n", name, str );
			g_free( str );
}
#endif /* VIPS_DEBUG */

			g_object_set_property( G_OBJECT( conversion->out ), 
				name, &value );
			g_value_unset( &value );
		}
	}

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_copy_gen, vips_stop_one, 
		copy->in, copy ) )
		return( -1 );

	return( 0 );
}

static void
vips_copy_class_init( VipsCopyClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_copy_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "copy";
	vobject_class->description = _( "copy an image" );
	vobject_class->build = vips_copy_build;

	/* We use copy to make fresh vipsimages to stop sharing, so don't
	 * cache it. Plus copy is cheap.
	 */
	operation_class->flags = 
		VIPS_OPERATION_SEQUENTIAL | 
		VIPS_OPERATION_NOCACHE;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCopy, in ) );

	VIPS_ARG_BOOL( class, "swap", 2, 
		_( "Swap" ), 
		_( "Swap bytes in image between little and big-endian" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, swap ),
		FALSE );

	VIPS_ARG_INT( class, "width", 3, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, width ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "height", 4, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, height ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "bands", 5, 
		_( "Bands" ), 
		_( "Number of bands in image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, bands ),
		0, 1000000, 0 );

	VIPS_ARG_ENUM( class, "format", 6, 
		_( "Format" ), 
		_( "Pixel format in image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, format ),
		VIPS_TYPE_BAND_FORMAT, VIPS_FORMAT_UCHAR ); 

	VIPS_ARG_ENUM( class, "coding", 7, 
		_( "Coding" ), 
		_( "Pixel coding" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, coding ),
		VIPS_TYPE_CODING, VIPS_CODING_NONE ); 

	VIPS_ARG_ENUM( class, "interpretation", 8, 
		_( "Interpretation" ), 
		_( "Pixel interpretation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, interpretation ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_MULTIBAND ); 

	VIPS_ARG_DOUBLE( class, "xres", 9, 
		_( "Xres" ), 
		_( "Horizontal resolution in pixels/mm" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, xres ),
		-0.0, 1000000, 0 );

	VIPS_ARG_DOUBLE( class, "yres", 10, 
		_( "Yres" ), 
		_( "Vertical resolution in pixels/mm" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, yres ),
		-0.0, 1000000, 0 );

	VIPS_ARG_INT( class, "xoffset", 11, 
		_( "Xoffset" ), 
		_( "Horizontal offset of origin" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, xoffset ),
		-1000000, 1000000, 0 );

	VIPS_ARG_INT( class, "yoffset", 12, 
		_( "Yoffset" ), 
		_( "Vertical offset of origin" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsCopy, yoffset ),
		-1000000, 1000000, 0 );
}

static void
vips_copy_init( VipsCopy *copy )
{
	/* Init our instance fields.
	 */
}

/**
 * vips_copy:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @width: set image width
 * @height: set image height
 * @bands: set image bands
 * @format: set image format
 * @coding: set image coding
 * @interpretation: set image interpretation
 * @xres: set image xres
 * @yres: set image yres
 * @xoffset: set image xoffset
 * @yoffset: set image yoffset
 * @swap: swap byte order
 *
 * Copy an image, optionally modifying the header. VIPS copies images by 
 * copying pointers, so this operation is instant, even for very large images.
 *
 * You can optionally set any or all header fields during the copy. Some
 * header fields, such as "xres", the horizontal resolution, are safe to
 * change in any way, others, such as "width" will cause immediate crashes if
 * they are not set carefully. 
 *
 * Setting @swap to %TRUE will make vips_copy() swap the byte ordering of
 * pixels according to the image's format. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_copy( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "copy", ap, in, out );
	va_end( ap );

	return( result );
}

/**
 * vips_copy_file:
 * @in: input image
 * @out: output image
 *
 * A simple convenience function to copy an image to a file, then copy 
 * again to output. If the image is already a file, just copy straight 
 * through.
 *
 * The file is allocated with vips_image_new_temp_file(). 
 * The file is automatically deleted when @out is closed.
 *
 * See also: vips_copy(), vips_image_new_temp_file().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_copy_file( VipsImage *in, VipsImage **out )
{
	VipsImage *file;

	if( vips_image_isfile( in ) ) 
		return( vips_copy( in, out, NULL ) ); 

	if( !(file = vips_image_new_temp_file( "%s.v" )) )
		return( -1 ); 
	if( vips_image_write( in, file ) ||
		vips_copy( file, out, NULL ) ) {
		g_object_unref( file );
		return( -1 );
	}
	g_object_unref( file );

	return( 0 );
}
