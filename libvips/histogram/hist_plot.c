/* draw a histogram
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris.
 * Written on: 09/07/1990
 * Modified on : 12/03/1991
 * 20/6/95 JC
 *	- rules rationalised
 *	- im_lineprof removed
 *	- rewritten
 * 13/8/99 JC
 *	- rewritten again for partial, rules redone
 * 19/9/99 JC
 *	- oooops, broken for >1 band
 * 26/9/99 JC
 *	- oooops, graph float was wrong
 * 17/11/99 JC
 *	- oops, failed for all 0's histogram 
 * 14/12/05
 * 	- redone plot function in C, also use incheck() to cache calcs
 * 	- much, much faster!
 * 12/5/09
 *	- fix signed/unsigned warning
 * 24/3/10
 * 	- gtkdoc
 * 	- small cleanups
 * 	- oop, would fail for signed int histograms
 * 19/8/13
 * 	- wrap as a class, left a rewrite for now
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
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "phistogram.h"

typedef struct _VipsHistPlot {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
} VipsHistPlot;

typedef VipsOperationClass VipsHistPlotClass;

G_DEFINE_TYPE( VipsHistPlot, vips_hist_plot, VIPS_TYPE_OPERATION );

#define VERT( TYPE ) { \
	TYPE *p1 = (TYPE *) p; \
	\
	for( x = le; x < ri; x++ ) { \
		for( z = 0; z < nb; z++ )  \
			q[z] = p1[z] < ((TYPE) x) ? 0 : 255; \
		\
		q += nb; \
	} \
}

/* Generate function.
 */
static int
vips_hist_plot_vert_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsImage *in = (VipsImage *) a;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int ri = VIPS_RECT_RIGHT( r );
	int bo = VIPS_RECT_BOTTOM( r );
	int nb = in->Bands;

	int x, y, z;

	for( y = to; y < bo; y++ ) {
		VipsPel *q = VIPS_REGION_ADDR( or, le, y );
		VipsPel *p = VIPS_IMAGE_ADDR( in, 0, y );

		switch( in->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	VERT( unsigned char ); break;
		case VIPS_FORMAT_CHAR: 		VERT( signed char ); break; 
		case VIPS_FORMAT_USHORT: 	VERT( unsigned short ); break; 
		case VIPS_FORMAT_SHORT: 	VERT( signed short ); break; 
		case VIPS_FORMAT_UINT: 		VERT( unsigned int ); break; 
		case VIPS_FORMAT_INT: 		VERT( signed int );  break; 
		case VIPS_FORMAT_FLOAT: 	VERT( float ); break; 
		case VIPS_FORMAT_DOUBLE:	VERT( double ); break; 

		default:
			g_assert_not_reached(); 
		}
	}

	return( 0 );
}

#define HORZ( TYPE ) { \
	TYPE *p1 = (TYPE *) p; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < nb; z++ )  \
			q[z] = p1[z] < ((TYPE) (ht - y)) ? 0 : 255; \
		\
		q += lsk; \
	} \
}

/* Generate function.
 */
static int
vips_hist_plot_horz_gen( VipsRegion *or, void *seq, void *a, void *b,
	gboolean *stop )
{
	VipsImage *in = (VipsImage *) a;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int ri = VIPS_RECT_RIGHT( r );
	int bo = VIPS_RECT_BOTTOM( r );
	int nb = in->Bands;
	int lsk = VIPS_REGION_LSKIP( or );
	int ht = or->im->Ysize;

	int x, y, z;

	for( x = le; x < ri; x++ ) {
		VipsPel *q = VIPS_REGION_ADDR( or, x, to );
		VipsPel *p = VIPS_IMAGE_ADDR( in, x, 0 );

		switch( in->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	HORZ( unsigned char ); break;
		case VIPS_FORMAT_CHAR: 		HORZ( signed char ); break; 
		case VIPS_FORMAT_USHORT:	HORZ( unsigned short ); break; 
		case VIPS_FORMAT_SHORT: 	HORZ( signed short ); break; 
		case VIPS_FORMAT_UINT: 		HORZ( unsigned int ); break; 
		case VIPS_FORMAT_INT: 		HORZ( signed int );  break; 
		case VIPS_FORMAT_FLOAT: 	HORZ( float ); break; 
		case VIPS_FORMAT_DOUBLE:	HORZ( double ); break; 

		default:
			g_assert_not_reached();
		}
	}

	return( 0 );
}

static int
vips_hist_plot_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsHistPlot *plot = (VipsHistPlot *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;
	double min, max;
	int width, height, tsize;
	VipsGenerateFn generate_fn;

	g_object_set( plot, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_hist_plot_parent_class )->build( object ) )
		return( -1 );

	in = plot->in;

	if( vips_check_uncoded( class->nickname, in ) ||
		vips_check_noncomplex( class->nickname, in ) ||
		vips_check_hist( class->nickname, in ) )
		return( -1 );

	if( !vips_band_format_isuint( in->BandFmt ) &&
		vips_band_format_isint( in->BandFmt ) ) {
		/* A signed int type. Move min up to 0. 
		 */
		double min;

		if( vips_min( in, &min, NULL ) ||
			vips_linear1( in, &t[0], 1.0, -min, NULL ) )
			return( -1 );

		in = t[0];
	}
	else if( vips_band_format_isfloat( in->BandFmt ) ) {
		/* Float image: scale min--max to 0--any. Output square
		 * graph.
		 */
		int any = in->Xsize * in->Ysize;

		if( vips_stats( in, &t[0], NULL ) )
			return( -1 );
		min = *VIPS_MATRIX( t[0], 0, 0 );
		max = *VIPS_MATRIX( t[0], 1, 0 );

		if( vips_linear1( in, &t[1], 
			any / (max - min), -min * any / (max - min), NULL ) )
			return( -1 );

		in = t[1];
	}

	if( vips_image_wio_input( in ) )
		return( -1 );

	/* Find range we will plot.
	 */
	if( vips_max( in, &max, NULL ) )
		return( -1 );
	g_assert( max >= 0 );
	if( in->BandFmt == VIPS_FORMAT_UCHAR )
		tsize = 256;
	else
		tsize = VIPS_CEIL( max );

	/* Make sure we don't make a zero height image.
	 */
	if( tsize == 0 )
		tsize = 1;

	if( in->Xsize == 1 ) {
		/* Vertical graph.
		 */
		width = tsize;
		height = in->Ysize;
		generate_fn = vips_hist_plot_vert_gen;
	}
	else {
		/* Horizontal graph.
		 */
		width = in->Xsize;
		height = tsize;
		generate_fn = vips_hist_plot_horz_gen;
	}

	/* Set image.
	 */
	vips_image_init_fields( plot->out, width, height, in->Bands, 
		VIPS_FORMAT_UCHAR, VIPS_CODING_NONE, 
		VIPS_INTERPRETATION_HISTOGRAM, 
		1.0, 1.0 ); 
	vips_image_pipelinev( plot->out, 
		VIPS_DEMAND_STYLE_ANY, NULL );

	if( vips_image_generate( plot->out, 
		NULL, generate_fn, NULL, in, NULL ) )
		return( -1 );

	return( 0 );
}

static void
vips_hist_plot_class_init( VipsHistPlotClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hist_plot";
	object_class->description = _( "plot histogram" );
	object_class->build = vips_hist_plot_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsHistPlot, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistPlot, out ) );
}

static void
vips_hist_plot_init( VipsHistPlot *hist_plot )
{
}

/**
 * vips_hist_plot: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Plot a 1 by any or any by 1 image file as a max by any or 
 * any by max image using these rules:
 * 
 * <emphasis>unsigned char</emphasis> max is always 256 
 *
 * <emphasis>other unsigned integer types</emphasis> output 0 - maxium 
 * value of @in.
 *
 * <emphasis>signed int types</emphasis> min moved to 0, max moved to max + min.
 *
 * <emphasis>float types</emphasis> min moved to 0, max moved to any 
 * (square output)
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_hist_plot( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hist_plot", ap, in, out );
	va_end( ap );

	return( result );
}


