/* find percent of pixels
 *
 * Copyright: 1990, N. Dessipris
 *
 * Author: N. Dessipris
 * Written on: 02/08/1990
 * Modified on : 29/4/93 K.Martinez   for Sys5
 * 20/2/95 JC
 *	- now returns result through parameter
 *	- ANSIfied a little
 * 19/1/07
 * 	- redone with the vips hist operators
 * 25/3/10
 * 	- gtkdoc
 * 20/9/13
 * 	- wrap as a class
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
#include <string.h>

#include <vips/vips.h>

typedef struct _VipsHistPercent { 
	VipsOperation parent_instance;

	VipsImage *in;
	double percent;
	int threshold;

} VipsHistPercent;

typedef VipsOperationClass VipsHistPercentClass;

G_DEFINE_TYPE( VipsHistPercent, vips_hist_percent, VIPS_TYPE_OPERATION );

static int
vips_hist_percent_build( VipsObject *object )
{
	VipsHistPercent *percent = (VipsHistPercent *) object; 
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 6 );

	double threshold;

	if( VIPS_OBJECT_CLASS( vips_hist_percent_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_hist_find( percent->in, &t[0], NULL ) ||
		vips_hist_cum( t[0], &t[1], NULL ) ||
		vips_hist_norm( t[1], &t[2], NULL ) ||
		vips_less_const1( t[2], &t[3], 
			percent->percent * t[2]->Xsize, NULL ) ||
		vips_flip( t[3], &t[4], VIPS_DIRECTION_HORIZONTAL, NULL ) ||
		im_profile( t[4], &t[5], 1 ) ||
		vips_avg( t[5], &threshold ) ) 
		return( -1 );

	percent->threshold = threshold;

	return( 0 );
}

static void
vips_hist_percent_class_init( VipsHistPercentClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hist_percent";
	object_class->description = _( "find threshold for percent of pixels" );
	object_class->build = vips_hist_percent_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistPercent, in ) );

	VIPS_ARG_DOUBLE( class, "percent", 2, 
		_( "Percent" ), 
		_( "percent of pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsHistPercent, percent ),
		0, 100, 50 );

	VIPS_ARG_INT( class, "threshold", 2, 
		_( "threshold" ), 
		_( "threshold above which lie percent of pixels" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistPercent, threshold ),
		0, 65535, 0 );

}

static void
vips_hist_percent_init( VipsHistPercent *percent )
{
}

/**
 * vips_percent:
 * @in: input image
 * @percent: threshold percentage
 * @threshold: output threshold value
 * @...: %NULL-terminated list of optional named arguments
 *
 * vips_percent() returns (through the @threshold parameter) the threshold 
 * above which there are @percent values of @in. If for example percent=.1, the
 * number of pels of the input image with values greater than @threshold
 * will correspond to 10% of all pels of the image.
 *
 * The function works for uchar and ushort images only.  It can be used 
 * to threshold the scaled result of a filtering operation.
 *
 * See also: vips_hist_find(), vips_profile().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_hist_percent( VipsImage *in, double percent, int *threshold, ... )
{
	va_list ap;
	int result;

	va_start( ap, threshold );
	result = vips_call_split( "hist_percent", ap, in, percent, threshold );
	va_end( ap );

	return( result );
}
