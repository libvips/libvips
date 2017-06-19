/* Histogram-equalise an image.
 *
 * Copyright: 1991, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 27/03/1991
 * Modified on : 
 * 16/6/93 J.Cupitt
 *	- im_ioflag() changed to im_iocheck()
 * 24/5/95 JC
 *	- ANSIfied and tidied up
 * 3/3/01 JC
 *	- more cleanup
 * 23/3/10
 * 	- gtkdoc
 * 12/8/13	
 * 	- redone as a class
 * 19/6/17
 * 	- make output format always == input format, thanks Simon
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>

#include <vips/vips.h>

typedef struct _VipsHistEqual { 
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

	/* -1 for all bands, or the band we scan.
	 */
	int which;
} VipsHistEqual;

typedef VipsOperationClass VipsHistEqualClass;

G_DEFINE_TYPE( VipsHistEqual, vips_hist_equal, VIPS_TYPE_OPERATION );

static int
vips_hist_equal_build( VipsObject *object )
{
	VipsHistEqual *equal = (VipsHistEqual *) object; 
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	g_object_set( equal, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_hist_equal_parent_class )->build( object ) )
		return( -1 );

	/* norm can return a uchar output for a ushort input if the range is
	 * small, so make sure we cast back to the input type again.
	 */
	if( vips_hist_find( equal->in, &t[0], 
			"band", equal->which,
			NULL ) ||
		vips_hist_cum( t[0], &t[1], NULL ) ||
		vips_hist_norm( t[1], &t[2], NULL ) ||
		vips_cast( t[2], &t[3], equal->in->BandFmt, NULL ) ||
		vips_maplut( equal->in, &t[4], t[3], NULL ) ||
		vips_image_write( t[4], equal->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_hist_equal_class_init( VipsHistEqualClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hist_equal";
	object_class->description = _( "histogram equalisation" );
	object_class->build = vips_hist_equal_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistEqual, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistEqual, out ) );

	VIPS_ARG_INT( class, "band", 110, 
		_( "Band" ), 
		_( "Equalise with this band" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHistEqual, which ),
		-1, 100000, -1 );
}

static void
vips_hist_equal_init( VipsHistEqual *equal )
{
	equal->which = -1;
}

/**
 * vips_hist_equal:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @band: band to equalise
 *
 * Histogram-equalise @in. Equalise using band @bandno, or if @bandno is -1,
 * equalise bands independently. The output format is always the same as the
 * input format. 
 *
 * See also: 
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_hist_equal( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hist_equal", ap, in, out );
	va_end( ap );

	return( result );
}
