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
 * 	- more accurate
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <string.h>

#include <vips/vips.h>

typedef struct _VipsPercent { 
	VipsOperation parent_instance;

	VipsImage *in;
	double percent;
	int threshold;

} VipsPercent;

typedef VipsOperationClass VipsPercentClass;

G_DEFINE_TYPE( VipsPercent, vips_percent, VIPS_TYPE_OPERATION );

static int
vips_percent_build( VipsObject *object )
{
	VipsPercent *percent = (VipsPercent *) object; 
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 7 );

	double threshold;

	if( VIPS_OBJECT_CLASS( vips_percent_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_hist_find( percent->in, &t[0], NULL ) ||
		vips_hist_cum( t[0], &t[1], NULL ) ||
		vips_hist_norm( t[1], &t[2], NULL ) ||
		vips_more_const1( t[2], &t[3], 
			(percent->percent / 100.0) * t[2]->Xsize, NULL ) ||
		vips_profile( t[3], &t[5], &t[6], NULL ) ||
		vips_avg( t[6], &threshold, NULL ) ) 
		return( -1 );

	g_object_set( object, "threshold", (int) threshold, NULL );

	return( 0 );
}

static void
vips_percent_class_init( VipsPercentClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "percent";
	object_class->description = _( "find threshold for percent of pixels" );
	object_class->build = vips_percent_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsPercent, in ) );

	VIPS_ARG_DOUBLE( class, "percent", 2, 
		_( "Percent" ), 
		_( "Percent of pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsPercent, percent ),
		0, 100, 50 );

	VIPS_ARG_INT( class, "threshold", 3, 
		_( "Threshold" ), 
		_( "Threshold above which lie percent of pixels" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsPercent, threshold ),
		0, 65535, 0 );

}

static void
vips_percent_init( VipsPercent *percent )
{
}

/**
 * vips_percent: (method)
 * @in: input image
 * @percent: threshold percentage
 * @threshold: (out): output threshold value
 * @...: %NULL-terminated list of optional named arguments
 *
 * vips_percent() returns (through the @threshold parameter) the threshold 
 * below which there are @percent values of @in. For example:
 *
 * |[
 * $ vips percent k2.jpg 90
 * 214
 * ]|
 *
 * Means that 90% of pixels in `k2.jpg` have a value less than 214.
 *
 * The function works for uchar and ushort images only.  It can be used 
 * to threshold the scaled result of a filtering operation.
 *
 * See also: vips_hist_find(), vips_profile().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_percent( VipsImage *in, double percent, int *threshold, ... )
{
	va_list ap;
	int result;

	va_start( ap, threshold );
	result = vips_call_split( "percent", ap, in, percent, threshold );
	va_end( ap );

	return( result );
}
