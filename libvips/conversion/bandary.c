/* base class for various operations on bands
 *
 * Copyright: 1991, N. Dessipris, modification of im_bandary()
 *
 * Author: N. Dessipris
 * Written on: 17/04/1991
 * Modified on : 
 * 16/3/94 JC
 *	- rewritten for partials
 *	- now in ANSI C
 *	- now works for any number of input images, except zero
 * 7/10/94 JC
 *	- new IM_NEW()
 * 16/4/07
 * 	- fall back to im_copy() for 1 input image
 * 17/1/09
 * 	- cleanups
 * 	- gtk-doc
 * 	- im_bandary() just calls this
 * 	- works for RAD coding too
 * 27/1/10
 * 	- formatalike inputs
 * 17/5/11
 * 	- sizealike inputs
 * 27/10/11
 * 	- rewrite as a class
 * 20/11/11
 * 	- from bandjoin
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
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "bandary.h"

G_DEFINE_ABSTRACT_TYPE( VipsBandary, vips_bandary, VIPS_TYPE_CONVERSION );

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

static int
vips_bandary_gen( VipsRegion *or, void *seq, void *a, void *b, gboolean *stop )
{
	VipsRegion **ir = (VipsRegion **) seq;
	VipsBandary *bandary = (VipsBandary *) b;
	VipsBandaryClass *class = VIPS_BANDARY_GET_CLASS( bandary ); 
	VipsRect *r = &or->valid;

	VipsPel *p[MAX_INPUT_IMAGES], *q;
	int y, i;

	if( vips_reorder_prepare_many( or->im, ir, r ) )
		return( -1 );
	for( i = 0; i < bandary->n; i++ ) 
		p[i] = VIPS_REGION_ADDR( ir[i], r->left, r->top );
	p[i] = NULL;
	q = VIPS_REGION_ADDR( or, r->left, r->top );

	VIPS_GATE_START( "vips_bandary_gen: work" ); 

	for( y = 0; y < r->height; y++ ) {
		class->process_line( bandary, q, p, r->width );

		for( i = 0; i < bandary->n; i++ )
			p[i] += VIPS_REGION_LSKIP( ir[i] );
		q += VIPS_REGION_LSKIP( or );
	}

	VIPS_GATE_STOP( "vips_bandary_gen: work" ); 

	return( 0 );
}

static int
vips_bandary_build( VipsObject *object )
{
	VipsObjectClass *object_class = VIPS_OBJECT_GET_CLASS( object );
	VipsBandaryClass *class = VIPS_BANDARY_GET_CLASS( object ); 
	VipsConversion *conversion = VIPS_CONVERSION( object );
	VipsBandary *bandary = VIPS_BANDARY( object );

	int i;
	VipsImage **decode;
	VipsImage **format;
	VipsImage **size;

	if( VIPS_OBJECT_CLASS( vips_bandary_parent_class )->build( object ) )
		return( -1 );

	if( bandary->n <= 0 ) {
		vips_error( object_class->nickname, 
			"%s", _( "no input images" ) );
		return( -1 );
	}
	if( bandary->n > MAX_INPUT_IMAGES ) {
		vips_error( object_class->nickname, 
			"%s", _( "too many input images" ) );
		return( -1 );
	}

	decode = (VipsImage **) vips_object_local_array( object, bandary->n );
	format = (VipsImage **) vips_object_local_array( object, bandary->n );
	size = (VipsImage **) vips_object_local_array( object, bandary->n );

	for( i = 0; i < bandary->n; i++ )
		if( vips_image_decode( bandary->in[i], &decode[i] ) )
			return( -1 );
	if( vips__formatalike_vec( decode, format, bandary->n ) ||
		vips__sizealike_vec( format, size, bandary->n ) )
		return( -1 );
	bandary->ready = size;

	if( vips_image_pipeline_array( conversion->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, bandary->ready ) )
		return( -1 );

	conversion->out->Bands = bandary->out_bands;
	if( class->format_table )
		conversion->out->BandFmt = 
			class->format_table[bandary->ready[0]->BandFmt];

	if( vips_image_generate( conversion->out,
		vips_start_many, vips_bandary_gen, vips_stop_many, 
		bandary->ready, bandary ) )
		return( -1 );

	return( 0 );
}

static void
vips_bandary_class_init( VipsBandaryClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	VIPS_DEBUG_MSG( "vips_bandary_class_init\n" );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "bandary";
	vobject_class->description = _( "operations on image bands" );
	vobject_class->build = vips_bandary_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;
}

static void
vips_bandary_init( VipsBandary *bandary )
{
	bandary->out_bands = -1;
}

/* Call this before chaining up in _build() to make the operation fall back to
 * copy.
 */
int
vips_bandary_copy( VipsBandary *bandary )
{
	VipsConversion *conversion = VIPS_CONVERSION( bandary );

	/* This isn't set by arith until build(), so we have to set
	 * again here.
	 *
	 * Should arith set out in _init()?
	 */
	g_object_set( bandary, "out", vips_image_new(), NULL ); 

	return( vips_image_write( bandary->in[0], conversion->out ) );
}
