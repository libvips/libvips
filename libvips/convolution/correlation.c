/* base class for correlation 
 *
 * 7/11/13
 * 	- from convolution.c
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pconvolution.h"
#include "correlation.h"

G_DEFINE_ABSTRACT_TYPE( VipsCorrelation, vips_correlation, 
	VIPS_TYPE_OPERATION );

static int
vips_correlation_gen( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion *ir = (VipsRegion *) seq;
	VipsCorrelation *correlation = (VipsCorrelation *) b;
	VipsCorrelationClass *cclass = 
		VIPS_CORRELATION_GET_CLASS( correlation );
	VipsRect *r = &or->valid;

	VipsRect irect;

	/* What part of ir do we need?
	 */
	irect.left = r->left;
	irect.top = r->top;
	irect.width = r->width + correlation->ref_ready->Xsize - 1;
	irect.height = r->height + correlation->ref_ready->Ysize - 1;

	if( vips_region_prepare( ir, &irect ) )
		return( -1 );

	cclass->correlation( correlation, ir, or );

	return( 0 );
}

static int
vips_correlation_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsCorrelationClass *cclass = VIPS_CORRELATION_CLASS( class );
	VipsCorrelation *correlation = (VipsCorrelation *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	if( VIPS_OBJECT_CLASS( vips_correlation_parent_class )->
		build( object ) )
		return( -1 );

	/* Stretch input out.
	 */
	if( vips_embed( correlation->in, &t[0], 
		correlation->ref->Xsize / 2, correlation->ref->Ysize / 2, 
		correlation->in->Xsize + correlation->ref->Xsize - 1, 
		correlation->in->Ysize + correlation->ref->Ysize - 1,
		"extend", VIPS_EXTEND_COPY,
		NULL ) ||
		vips__formatalike( t[0], correlation->ref, &t[1], &t[2] ) ||
		vips__bandalike( class->nickname, t[1], t[2], &t[3], &t[4] ) ||
		vips_image_wio_input( t[4] ) ) 
		return( -1 );
	correlation->in_ready = t[3];
	correlation->ref_ready = t[4];

	g_object_set( object, "out", vips_image_new(), NULL ); 

	/* FATSTRIP is good for us as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( vips_image_pipelinev( correlation->out, 
		VIPS_DEMAND_STYLE_FATSTRIP, 
		correlation->in_ready, correlation->ref_ready, NULL ) )
		return( -1 ); 
	correlation->out->Xsize = correlation->in->Xsize;
	correlation->out->Ysize = correlation->in->Ysize;
	correlation->out->BandFmt = 
		cclass->format_table[correlation->in_ready->BandFmt];
	if( cclass->pre_generate &&
		cclass->pre_generate( correlation ) )
		return( -1 ); 
	if( vips_image_generate( correlation->out, 
		vips_start_one, vips_correlation_gen, vips_stop_one,
		correlation->in_ready, correlation ) )
		return( -1 );

	return( 0 );
}

static void
vips_correlation_class_init( VipsCorrelationClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "correlation";
	object_class->description = _( "correlation operation" );
	object_class->build = vips_correlation_build;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image argument" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsCorrelation, in ) );

	VIPS_ARG_IMAGE( class, "ref", 10, 
		_( "Mask" ), 
		_( "Input reference image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsCorrelation, ref ) );

	VIPS_ARG_IMAGE( class, "out", 20, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsCorrelation, out ) );

}

static void
vips_correlation_init( VipsCorrelation *correlation )
{
}
