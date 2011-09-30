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
 */
#define VIPS_DEBUG

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
 * VipsCopy:
 * @input: input image
 * @output: output image
 *
 * Copy an image, optionally modifying the header. VIPS copies images by 
 * copying pointers, so this operation is fast, even for very large images.
 *
 * You can optionally set any or all header fields during the copy. Some
 * header fields, such as "xres", the horizontal resolution, are safe to
 * change in any way, others, such as "width" will cause immediate crashes if
 * they are not set carefully. 
 *
 * Returns: 0 on success, -1 on error.
 */

/* Properties.
 *
 * Order important! Keep in sync with vips_copy_names[] below.
 */
enum {
	PROP_INPUT = 1,
	PROP_INTERPRETATION,
	PROP_XRES,
	PROP_YRES,
	PROP_XOFFSET,
	PROP_YOFFSET,
	PROP_BANDS,
	PROP_FORMAT,
	PROP_CODING,
	PROP_WIDTH,
	PROP_HEIGHT,

	PROP_LAST
}; 

typedef struct _VipsCopy {
	VipsConversion parent_instance;

	/* The input image.
	 */
	VipsImage *input;

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

/* Copy a small area.
 */
static int
vips_copy_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsRect *r = &or->valid;

	/* Ask for input we need.
	 */
	if( vips_region_prepare( ir, r ) )
		return( -1 );

	/* Attach output region to that.
	 */
	if( vips_region_region( or, ir, r, r->left, r->top ) )
		return( -1 );

	return( 0 );
}

/* The props we copy, if set, from the operation to the image.
 */
static const char *vips_copy_names[] = {
	NULL,			/* unused */
	NULL, 			/* PROP_INPUT = 1 */
	"interpretation", 	/* PROP_INTERPRETATION, */
	"xres", 		/* PROP_XRES, */
	"yres", 		/* PROP_YRES, */
	"xoffset", 		/* PROP_XOFFSET, */
	"xoffset", 		/* PROP_YOFFSET, */
	"bands", 		/* PROP_BANDS, */
	"format", 		/* PROP_FORMAT, */
	"coding", 		/* PROP_CODING, */
	"width", 		/* PROP_WIDTH, */
	"height" 		/* PROP_HEIGHT, */
}; 

static int
vips_copy_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsCopy *copy = (VipsCopy *) object;

	int i;

	if( VIPS_OBJECT_CLASS( vips_copy_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( copy->input ) || 
		vips_image_pio_output( conversion->output ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->output, copy->input ) )
		return( -1 );
        vips_demand_hint( conversion->output, 
		VIPS_DEMAND_STYLE_THINSTRIP, copy->input, NULL );

	/* Use props to adjust header fields.
	 */
	for( i = 2; i < PROP_LAST; i++ ) {
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

			VIPS_DEBUG_MSG( "vips_copy_build: assigning %s\n", 
				name );

			g_value_init( &value, type );
			g_object_get_property( G_OBJECT( object ), 
				name, &value );
			g_object_set_property( G_OBJECT( conversion->output ), 
				name, &value );
			g_value_unset( &value );
		}
	}

	if( vips_image_generate( conversion->output,
		vips_start_one, vips_copy_gen, vips_stop_one, 
		copy->input, copy ) )
		return( -1 );

	return( 0 );
}

static void
vips_copy_class_init( VipsCopyClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	GParamSpec *pspec;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "copy";
	vobject_class->description = _( "copy an image" );
	vobject_class->build = vips_copy_build;

	pspec = g_param_spec_object( "input", 
		"Input", "Input image argument",
		VIPS_TYPE_IMAGE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_INPUT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCopy, input ) );

	pspec = g_param_spec_enum( "interpretation", "Interpretation",
		_( "Pixel interpretation" ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_MULTIBAND, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_INTERPRETATION, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, interpretation ) );

	pspec = g_param_spec_double( "xres", "XRes",
		_( "Horizontal resolution in pixels/mm" ),
		0, 1000000, 0, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_XRES, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, xres ) );

	pspec = g_param_spec_double( "yres", "YRes",
		_( "Vertical resolution in pixels/mm" ),
		0, 1000000, 0, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_YRES, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, yres ) );

	pspec = g_param_spec_int( "xoffset", "XOffset",
		_( "Horizontal offset of origin" ),
		-10000000, 1000000, 0, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_XOFFSET, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, xoffset ) );

	pspec = g_param_spec_int( "yoffset", "YOffset",
		_( "Vertical offset of origin" ),
		-10000000, 1000000, 0, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_YOFFSET, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, yoffset ) );

	pspec = g_param_spec_int( "bands", "Bands",
		_( "Number of bands in image" ),
		0, 1000000, 0, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_BANDS, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, bands ) );

	pspec = g_param_spec_enum( "format", "Format",
		_( "Pixel format in image" ),
		VIPS_TYPE_BAND_FORMAT, VIPS_FORMAT_UCHAR, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_FORMAT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, format ) );

	pspec = g_param_spec_enum( "coding", "Coding",
		_( "Pixel coding" ),
		VIPS_TYPE_CODING, VIPS_CODING_NONE, 
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_FORMAT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, coding ) );

	pspec = g_param_spec_int( "width", "Width",
		_( "Image width in pixels" ),
		0, 1000000, 0,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_WIDTH, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, width ) );

	pspec = g_param_spec_int( "height", "Height",
		_( "Image height in pixels" ),
		0, 1000000, 0,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, PROP_HEIGHT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_SET_ONCE, 
		G_STRUCT_OFFSET( VipsCopy, height ) );

}

static void
vips_copy_init( VipsCopy *copy )
{
	/* Init our instance fields.
	 */
}
