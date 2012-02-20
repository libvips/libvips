/* Like copy, but ensure sequential access. 
 *
 * Handy with sequential for loading files formats which are strictly
 * top-to-bottom, like PNG. 
 *
 * 15/2/12
 * 	- from VipsForeignLoad
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

    You should have received a cache of the GNU Lesser General Public License
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
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "conversion.h"

typedef struct _VipsSequential {
	VipsConversion parent_instance;

	VipsImage *in;

	int y_pos;
} VipsSequential;

typedef VipsConversionClass VipsSequentialClass;

G_DEFINE_TYPE( VipsSequential, vips_sequential, VIPS_TYPE_CONVERSION );

static int
vips_sequential_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsSequential *sequential = (VipsSequential *) b;
        VipsRect *r = &or->valid;
	VipsRegion *ir = (VipsRegion *) seq;

	VIPS_DEBUG_MSG( "vips_sequential_generate %d\n", r->top );

	/* The y pos of the request must be the same as our current file
	 * position.
	 */
	if( r->top != sequential->y_pos ) {
		printf( "vips_sequential_generate: error -- "
			"at position %d in file, but position %d requested",
			sequential->y_pos, r->top );

		vips_error( "VipsSequential", 
			_( "non-sequential read --- "
			"at position %d in file, but position %d requested" ),
			sequential->y_pos, r->top );
		return( -1 );
	}

	/* We're inside a tilecache where tiles are the full image width, so
	 * this should always be true.
	 */
	g_assert( r->left == 0 );
	g_assert( r->width == or->im->Xsize );
	g_assert( VIPS_RECT_BOTTOM( r ) <= or->im->Ysize );

	/* Pointer copy.
	 */
        if( vips_region_prepare( ir, r ) ||
		vips_region_region( or, ir, r, r->left, r->top ) )
                return( -1 );

	sequential->y_pos += r->height;

	return( 0 );
}

static int
vips_sequential_build( VipsObject *object )
{
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsSequential *sequential = (VipsSequential *) object;

	VIPS_DEBUG_MSG( "vips_sequential_build\n" );

	if( VIPS_OBJECT_CLASS( vips_sequential_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( sequential->in ) )
		return( -1 );

	if( vips_image_copy_fields( conversion->out, sequential->in ) )
		return( -1 );
        vips_demand_hint( conversion->out, 
		VIPS_DEMAND_STYLE_FATSTRIP, sequential->in, NULL );

	if( vips_image_generate( conversion->out,
		vips_start_one, vips_sequential_generate, vips_stop_one, 
		sequential->in, sequential ) )
		return( -1 );

	return( 0 );
}

static void
vips_sequential_class_init( VipsSequentialClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_sequential_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "sequential";
	vobject_class->description = _( "check sequential access" );
	vobject_class->build = vips_sequential_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSequential, in ) );
}

static void
vips_sequential_init( VipsSequential *sequential )
{
}

/**
 * vips_sequential:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation behaves rather like vips_copy() between images
 * @in and @out, except that it checks that pixels are only requested
 * top-to-bottom. If an out of order request is made, it throws an exception.
 *
 * This operation is handy with tilecache for loading file formats which are 
 * strictly top-to-bottom, like PNG. 
 *
 * See also: vips_image_cache().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_sequential( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "sequential", ap, in, out );
	va_end( ap );

	return( result );
}
