/* make an xy index image 
 *
 * 21/4/04
 *	- from im_grey
 * 1/2/11
 * 	- gtk-doc
 * 31/10/11
 * 	- redo as a class
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

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "pcreate.h"

typedef struct _VipsXyz {
	VipsCreate parent_instance;

	int width;
	int height;
	int csize;
	int dsize;
	int esize;

	int dimensions;

} VipsXyz;

typedef VipsCreateClass VipsXyzClass;

G_DEFINE_TYPE( VipsXyz, vips_xyz, VIPS_TYPE_CREATE );

static int
vips_xyz_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsXyz *xyz = (VipsXyz *) a;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int ri = VIPS_RECT_RIGHT( r );
	int bo = VIPS_RECT_BOTTOM( r );

	int x, y, i;

	for( y = to; y < bo; y++ ) {
		unsigned int *q = (unsigned int *) 
			VIPS_REGION_ADDR( or, le, y );

		unsigned int dims[5];
		int r;
		int h;

		h = xyz->height * xyz->csize * xyz->dsize; 
		dims[4] = y / h;
		r = y % h;

		h /= xyz->dsize; 
		dims[3] = r / h;
		r %= h;

		h /= xyz->csize; 
		dims[2] = r / h;
		r %= h;

		dims[1] = r;

		for( x = le; x < ri; x++ ) {
			dims[0] = x;
			for( i = 0; i < xyz->dimensions; i++ )
				q[i] = dims[i];

			q += xyz->dimensions;
		}
	}

	return( 0 );
}

static int
vips_xyz_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsCreate *create = VIPS_CREATE( object );
	VipsXyz *xyz = (VipsXyz *) object;

	double d;
	int ysize;

	if( VIPS_OBJECT_CLASS( vips_xyz_parent_class )->build( object ) )
		return( -1 );

	if( (vips_object_argument_isset( object, "dsize" ) &&
		!vips_object_argument_isset( object, "csize" )) ||
		(vips_object_argument_isset( object, "esize" ) &&
		 !vips_object_argument_isset( object, "dsize" )) ) {
		vips_error( class->nickname, "%s", 
			_( "lower dimensions not set" ) );
		return( -1 ); 
	}

	if( vips_object_argument_isset( object, "csize" ) ) {
		xyz->dimensions += 1;

		if( vips_object_argument_isset( object, "dsize" ) ) {
			xyz->dimensions += 1;

			if( vips_object_argument_isset( object, "esize" ) ) 
				xyz->dimensions += 1;
		}
	}

	d = (double) xyz->height * xyz->csize * xyz->dsize * xyz->esize; 
	if( d > INT_MAX ) {
		vips_error( class->nickname, "%s", _( "image too large" ) );
		return( -1 ); 
	}
	ysize = d;

	vips_image_init_fields( create->out,
		xyz->width, ysize, xyz->dimensions, 
		VIPS_FORMAT_UINT, VIPS_CODING_NONE,
		VIPS_INTERPRETATION_MULTIBAND,
		1.0, 1.0 );
	vips_demand_hint( create->out, 
		VIPS_DEMAND_STYLE_ANY, NULL );

	if( vips_image_generate( create->out, 
		NULL, vips_xyz_gen, NULL, xyz, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_xyz_class_init( VipsXyzClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	VIPS_DEBUG_MSG( "vips_xyz_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "xyz";
	vobject_class->description = 
		_( "make an image where pixel values are coordinates" );
	vobject_class->build = vips_xyz_build;

	VIPS_ARG_INT( class, "width", 4, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsXyz, width ),
		1, 1000000, 64 );

	VIPS_ARG_INT( class, "height", 5, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsXyz, height ),
		1, 1000000, 64 );

	VIPS_ARG_INT( class, "csize", 6, 
		_( "csize" ), 
		_( "Size of third dimension" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsXyz, csize ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "dsize", 7, 
		_( "dsize" ), 
		_( "Size of fourth dimension" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsXyz, dsize ),
		1, 1000000, 1 );

	VIPS_ARG_INT( class, "esize", 8, 
		_( "esize" ), 
		_( "Size of fifth dimension" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsXyz, esize ),
		1, 1000000, 1 );

}

static void
vips_xyz_init( VipsXyz *xyz )
{
	xyz->width = 64;
	xyz->height = 64;
	xyz->dimensions = 2;
	xyz->csize = 1;
	xyz->dsize = 1;
	xyz->esize = 1;
}

/**
 * vips_xyz:
 * @out: output image
 * @width: horizontal size
 * @height: vertical size
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @csize: size for third dimension
 * @dsize: size for fourth dimension
 * @esize: size for fifth dimension
 *
 * Create a two-band uint32 image where the elements in the first band have the
 * value of their x coordinate and elements in the second band have their y
 * coordinate. 
 *
 * You can make any image where the value of a pixel is a function of its (x,
 * y) coordinate by combining this operator with the arithmetic operators. 
 *
 * Set @csize, @dsize, @esize to generate higher dimensions and add more
 * bands. The extra dimensions are placed down the vertical axis. Use
 * vips_grid() to change the layout. 
 *
 * See also: vips_grey(), vips_grid(), vips_identity().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_xyz( VipsImage **out, int width, int height, ... )
{
	va_list ap;
	int result;

	va_start( ap, height );
	result = vips_call_split( "xyz", ap, out, width, height );
	va_end( ap );

	return( result );
}
