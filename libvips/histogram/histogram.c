/* base class for all histogram operations
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

/**
 * SECTION: histogram
 * @short_description: find, manipulate and apply histograms and lookup tables
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 * Histograms and look-up tables are 1xn or nx1 images, where n is less than
 * 256 or less than 65536, corresponding to 8- and 16-bit unsigned int images. 
 * They are
 * tagged with a #VipsType of IM_TYPE_HISTOGRAM and usually displayed by
 * user-interfaces such as nip2 as plots rather than images.
 *
 * These functions can be broadly grouped as things to find or build 
 * histograms (im_histgr(), im_buildlut(), in_identity()), operations that 
 * manipulate histograms in some way (im_histcum(), im_histnorm()), operations
 * to apply histograms (im_maplut()), and a variety of utility 
 * operations.
 *
 * A final group of operations build tone curves. These are useful in
 * pre-press work for adjusting the appearance of images. They are designed
 * for CIELAB images, but might be useful elsewhere.
 */

G_DEFINE_ABSTRACT_TYPE( VipsHistogram, vips_histogram, VIPS_TYPE_OPERATION );

/* sizealike by expanding in just one dimension and copying the final element. 
 */
static int
vips__hist_sizealike_vec( VipsImage **in, VipsImage **out, int n )
{
	int i;
	int max_size;

	g_assert( n >= 1 );

	max_size = VIPS_MAX( in[0]->Xsize, in[0]->Ysize );
	for( i = 1; i < n; i++ ) 
		max_size = VIPS_MAX( max_size, 
			VIPS_MAX( in[0]->Xsize, in[0]->Ysize ) );

	for( i = 0; i < n; i++ ) 
		if( in[i]->Ysize == 1 ) {
			if( vips_embed( in[i], &out[i], 0, 0, max_size, 1, 
				"extend", VIPS_EXTEND_COPY,
				NULL ) )
				return( -1 );
		}
		else {
			if( vips_embed( in[i], &out[i], 0, 0, 1, max_size, 
				"extend", VIPS_EXTEND_COPY,
				NULL ) )
				return( -1 );
		}

	return( 0 );
}

static int
vips_histogram_build( VipsObject *object )
{
	VipsHistogram *histogram = VIPS_HISTOGRAM( object );
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsHistogramClass *hclass = VIPS_HISTOGRAM_GET_CLASS( histogram );

	VipsImage **format;
	VipsImage **band;
	VipsImage **size;

	VipsPel *outbuf;		
	VipsPel **inbuf;		
	int i;

#ifdef DEBUG
	printf( "vips_histogram_build: " );
	vips_object_print_name( object );
	printf( "\n" );
#endif /*DEBUG*/

	if( VIPS_OBJECT_CLASS( vips_histogram_parent_class )->build( object ) )
		return( -1 );

	g_assert( histogram->n > 0 ); 

	/* Must be NULL-terminated.
	 */
	g_assert( !histogram->in[histogram->n] ); 

	format = (VipsImage **) vips_object_local_array( object, histogram->n );
	band = (VipsImage **) vips_object_local_array( object, histogram->n );
	size = (VipsImage **) vips_object_local_array( object, histogram->n );

	g_object_set( histogram, "out", vips_image_new(), NULL ); 

	for( i = 0; i < histogram->n; i++ ) 
		if( vips_check_uncoded( class->nickname, histogram->in[i] ) ||
			vips_check_hist( class->nickname, histogram->in[i] ) )
			return( -1 ); 

	/* Cast our input images up to a common format, bands and size.
	 */
	if( vips__formatalike_vec( histogram->in, format, histogram->n ) ||
		vips__bandalike_vec( class->nickname, 
			format, band, histogram->n, 1 ) ||
		vips__hist_sizealike_vec( band, size, histogram->n ) ) 
		return( -1 );

	/* Keep a copy of the processed images here for subclasses.
	 */
	histogram->ready = size;

	if( vips_image_pipeline_array( histogram->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, histogram->ready ) ) 
		return( -1 );

	histogram->out->Xsize = VIPS_IMAGE_N_PELS( histogram->ready[0] );
	histogram->out->Ysize = 1;
	if( hclass->format_table ) 
		histogram->out->BandFmt = 
			hclass->format_table[histogram->ready[0]->BandFmt];
	histogram->out->Type = VIPS_INTERPRETATION_HISTOGRAM;

	if( !(outbuf = vips_malloc( object, 
		VIPS_IMAGE_SIZEOF_LINE( histogram->out ))) )
                return( -1 );

	if( !(inbuf = VIPS_ARRAY( object, histogram->n + 1, VipsPel * )) )
                return( -1 );
	for( i = 0; i < histogram->n; i++ ) {
		if( vips_image_wio_input( histogram->ready[i] ) )
			return( -1 ); 
		inbuf[i] = VIPS_IMAGE_ADDR( histogram->ready[i], 0, 0 );
	}
	inbuf[i] = NULL; 

	hclass->process( histogram, outbuf, inbuf, histogram->ready[0]->Xsize );

	if( vips_image_write_line( histogram->out, 0, outbuf ) )
		return( -1 ); 

	return( 0 );
}

static void
vips_histogram_class_init( VipsHistogramClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "histogram";
	vobject_class->description = _( "histogram operations" );
	vobject_class->build = vips_histogram_build;

	/* Inputs set by subclassess.
	 */

	VIPS_ARG_IMAGE( class, "out", 10, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistogram, out ) );

}

static void
vips_histogram_init( VipsHistogram *histogram )
{
	/* Sanity check this above.
	 */
	histogram->n = -1;
}

/* Called from iofuncs to init all operations in this dir. Use a plugin system
 * instead?
 */
void
vips_histogram_operation_init( void )
{
	extern GType vips_maplut_get_type( void ); 
	extern GType vips_percent_get_type( void ); 
	extern GType vips_hist_cum_get_type( void ); 
	extern GType vips_hist_norm_get_type( void ); 
	extern GType vips_hist_equal_get_type( void ); 
	extern GType vips_hist_plot_get_type( void ); 
	extern GType vips_hist_match_get_type( void ); 
	extern GType vips_hist_local_get_type( void ); 
	extern GType vips_hist_ismonotonic_get_type( void ); 
	extern GType vips_stdif_get_type( void ); 

	vips_maplut_get_type(); 
	vips_percent_get_type(); 
	vips_stdif_get_type(); 
	vips_hist_cum_get_type(); 
	vips_hist_norm_get_type(); 
	vips_hist_equal_get_type(); 
	vips_hist_plot_get_type(); 
	vips_hist_match_get_type(); 
	vips_hist_local_get_type(); 
	vips_hist_ismonotonic_get_type(); 
}
