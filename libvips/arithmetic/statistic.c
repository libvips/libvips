/* base class for all stats operations
 *
 * properties:
 * 	- one image in, single value or matrix out
 * 	- output depends on whole of input, ie. we have a sink
 *
 * 24/8/11
 * 	- from im_avg.c
 */

/*

    Copyright (C) 1991-2005 The National Gallery

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
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
#include <vips/debug.h>
#include <vips/internal.h>

#include "statistic.h"

G_DEFINE_ABSTRACT_TYPE( VipsStatistic, vips_statistic, VIPS_TYPE_OPERATION );

static void *
vips_statistic_scan_start( VipsImage *in, void *a, void *b )
{
	VipsStatistic *statistic = VIPS_STATISTIC( a );
	VipsStatisticClass *class = VIPS_STATISTIC_GET_CLASS( statistic );

	return( class->start( statistic ) );
}

static int
vips_statistic_scan( VipsRegion *region, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsStatistic *statistic = VIPS_STATISTIC( a );
	VipsStatisticClass *class = VIPS_STATISTIC_GET_CLASS( statistic );

	VipsRect *r = &region->valid;
	int lsk = VIPS_REGION_LSKIP( region );

	int y;
	VipsPel *p;

	VIPS_DEBUG_MSG( "vips_statistic_scan: %d x %d @ %d x %d\n",
		r->width, r->height, r->left, r->top );

	p = VIPS_REGION_ADDR( region, r->left, r->top ); 
	for( y = 0; y < r->height; y++ ) { 
		if( class->scan( statistic, 
			seq, r->left, r->top + y, p, r->width ) ) 
			return( -1 );
		p += lsk;
	} 

	/* If we've requested stop, pass the message on.
	 */
	if( statistic->stop )
		*stop = TRUE;

	return( 0 );
}

static int
vips_statistic_scan_stop( void *seq, void *a, void *b )
{
	VipsStatistic *statistic = VIPS_STATISTIC( a );
	VipsStatisticClass *class = VIPS_STATISTIC_GET_CLASS( statistic );

	return( class->stop( statistic, seq ) );
}

static int
vips_statistic_build( VipsObject *object )
{
	VipsStatistic *statistic = VIPS_STATISTIC( object );
	VipsStatisticClass *sclass = VIPS_STATISTIC_GET_CLASS( statistic );
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

#ifdef DEBUG
	printf( "vips_statistic_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_statistic_parent_class )->build( object ) )
		return( -1 );

	statistic->ready = statistic->in;

	if( vips_image_decode( statistic->ready, &t[0] ) )
		return( -1 );
	statistic->ready = t[0];

	/* If there's a format table, cast the input.
	 */
	if( sclass->format_table ) {
		if( vips_cast( statistic->ready, &t[1], 
			sclass->format_table[statistic->in->BandFmt], NULL ) )
			return( -1 );
		statistic->ready = t[1];
	}

	if( vips_sink( statistic->ready, 
		vips_statistic_scan_start, 
		vips_statistic_scan, 
		vips_statistic_scan_stop, 
		statistic, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_statistic_class_init( VipsStatisticClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "statistic";
	vobject_class->description = _( "VIPS statistic operations" );
	vobject_class->build = vips_statistic_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsStatistic, in ) );
}

static void
vips_statistic_init( VipsStatistic *statistic )
{
}
