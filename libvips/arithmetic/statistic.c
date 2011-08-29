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

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "statistic.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Properties.
 */
enum {
	PROP_INPUT = 1,
	PROP_LAST
}; 

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
	int lsk = IM_REGION_LSKIP( region );

	int y;
	PEL *p;

	p = (PEL *) IM_REGION_ADDR( region, r->left, r->top ); 
	for( y = 0; y < r->height; y++ ) { 
		if( class->scan( statistic, seq, p, r->width ) ) 
			return( -1 );
		p += lsk;
	} 

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
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	const char *domain = class->nickname;

#ifdef DEBUG
	printf( "vips_statistic_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_statistic_parent_class )->build( object ) )
		return( -1 );

	if( vips_image_pio_input( statistic->input ) || 
		vips_check_uncoded( domain, statistic->input ) )
		return( -1 );

	if( vips_sink( statistic->input, 
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

	GParamSpec *pspec;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "statistic";
	vobject_class->description = _( "VIPS statistic operations" );
	vobject_class->build = vips_statistic_build;

	pspec = g_param_spec_object( "in", "Input", 
		_( "Input image" ),
		VIPS_TYPE_IMAGE,
		G_PARAM_READWRITE );
	g_object_class_install_property( gobject_class, 
		PROP_INPUT, pspec );
	vips_object_class_install_argument( vobject_class, pspec,
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsStatistic, input ) );
}

static void
vips_statistic_init( VipsStatistic *statistic )
{
}
