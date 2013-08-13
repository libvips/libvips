/* a hist operation implemented as a buffer processor
 *
 * properties:
 * 	- single hist to single hist
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
#include <vips/internal.h>

#include "phistogram.h"
#include "hist_buffer.h"

G_DEFINE_ABSTRACT_TYPE( VipsHistBuffer, vips_hist_buffer, VIPS_TYPE_HISTOGRAM );

static int
vips_hist_buffer_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsHistogram *histogram = VIPS_HISTOGRAM( object );
	VipsHistBuffer *hist_buffer = VIPS_HIST_BUFFER( object );
	VipsHistBufferClass *hclass = VIPS_HIST_BUFFER_GET_CLASS( hist_buffer );

	VipsPel *outbuf;		

#ifdef DEBUG
	printf( "vips_hist_buffer_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_hist_buffer_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_check_hist( class->nickname, histogram->in ) ||
		vips_check_uncoded( class->nickname, histogram->in ) )
		return( -1 ); 

	if( vips_image_wio_input( histogram->in ) ||
		vips_image_copy_fields( histogram->out, histogram->in ) ) 
		return( -1 );

	histogram->out->Xsize = VIPS_IMAGE_N_PELS( histogram->in );
	histogram->out->Ysize = 1;
	if( hclass->format_table ) 
		histogram->out->BandFmt = 
			hclass->format_table[histogram->in->BandFmt];

	if( !(outbuf = vips_malloc( object, 
		VIPS_IMAGE_SIZEOF_LINE( histogram->out ))) )
                return( -1 );

	hclass->process( hist_buffer, 
		outbuf, VIPS_IMAGE_ADDR( histogram->in, 0, 0 ), 
		histogram->in->Xsize );

	if( vips_image_write_line( histogram->out, 0, outbuf ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_hist_buffer_class_init( VipsHistBufferClass *class )
{
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	vobject_class->nickname = "hist_buffer";
	vobject_class->description = _( "hist_buffer operations" );
	vobject_class->build = vips_hist_buffer_build;

}

static void
vips_hist_buffer_init( VipsHistBuffer *hist_buffer )
{
}
