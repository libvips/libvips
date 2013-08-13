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

#include "phistogram.h"

typedef struct _VipsHistEqual { 
	VipsHistogram parent_instance;

	/* -1 for all bands, or the band we scan.
	 */
	int which;
} VipsHistEqual;

typedef VipsHistogramClass VipsHistEqualClass;

G_DEFINE_TYPE( VipsHistEqual, vips_hist_equal, VIPS_TYPE_HISTOGRAM );

static int
vips_hist_equal_build( VipsObject *object )
{
	VipsHistogram *histogram = VIPS_HISTOGRAM( object );
	VipsHistEqual *hist_equal = (VipsHistEqual *) histogram; 
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	if( VIPS_OBJECT_CLASS( vips_hist_equal_parent_class )->build( object ) )
		return( -1 );

	if( vips_hist_find( histogram->in, &t[0], 
			"band", hist_equal->which,
			NULL ) ||
		vips_hist_cum( t[0], &t[1], NULL ) ||
		vips_hist_norm( t[1], &t[2], NULL ) ||
		vips_maplut( histogram->in, &t[3], t[2], NULL ) ||
		vips_image_write( t[3], histogram->out ) )
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

	VIPS_ARG_INT( class, "band", 110, 
		_( "Band" ), 
		_( "Equalise with this band" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHistEqual, which ),
		-1, 100000, -1 );
}

static void
vips_hist_equal_init( VipsHistEqual *hist_equal )
{
	hist_equal->which = -1;
}

/**
 * vips_hist_equal:
 * @in: input image
 * @out: output image
 *
 * Optional arguments:
 *
 * @band: band to equalise
 *
 * Histogram-equalise @in. Equalise using band @bandno, or if @bandno is -1,
 * equalise bands independently.
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
