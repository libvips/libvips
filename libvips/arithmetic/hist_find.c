/* find histograms
 *
 * Copyright: 1990, 1991, N. Dessipris.
 *
 * Author: Nicos Dessipris.
 * Written on: 09/07/1990
 * Modified on : 11/03/1991
 * 19/7/93 JC
 *	- test for Coding type added
 * 26/10/94 JC
 *	- rewritten for ANSI
 *	- now does USHORT too
 *	- 5 x faster!
 * 2/6/95 JC
 *	- rewritten for partials
 * 3/3/01 JC
 *	- tiny speed ups
 * 21/1/07
 * 	- number bands from zero
 * 24/3/10
 * 	- gtkdoc
 * 	- small cleanups
 * 25/1/12
 * 	- cast @in to u8/u16.
 * 12/8/13
 * 	- redo as a class
 * 28/2/16 lovell
 * 	- unroll common cases
 * 1/2/21 erdmann
 * 	- use double for very large histograms
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

#include <string.h>

#include <vips/vips.h>

#include "statistic.h"

/* Accumulate a histogram in one of these.
 */
typedef struct {
	int n_bands;		/* Number of bands in output */
	int band;		/* If one band in out, which band of input */
	int size;		/* Number of bins for each band */
	int mx;			/* Maximum value we have seen */
	VipsPel **bins;		/* double or uint bins */
} Histogram;

typedef struct _VipsHistFind {
	VipsStatistic parent_instance;

	/* -1 for all bands, or the band we scan.
	 */
	int band;

	/* Main image histogram. Subhists accumulate to this.
	 */
	Histogram *hist;

	/* Write hist to this output image.
	 */
	VipsImage *out; 

	/* TRUE for "large" histograms ... causes double output rather than
	 * uint.
	 */
	gboolean large;

} VipsHistFind;

typedef VipsStatisticClass VipsHistFindClass;

G_DEFINE_TYPE( VipsHistFind, vips_hist_find, VIPS_TYPE_STATISTIC );

/* Build a Histogram.
 */
static Histogram *
histogram_new( VipsHistFind *hist_find, int n_bands, int band, int size )
{
	/* We won't use all of this for uint accumulators.
	 */
	int n_bytes = size * sizeof( double );

	Histogram *hist;
	int i;

	if( !(hist = VIPS_NEW( hist_find, Histogram )) ||
		!(hist->bins = VIPS_ARRAY( hist_find, n_bands, VipsPel * )) )
		return( NULL );

	for( i = 0; i < n_bands; i++ ) {
		if( !(hist->bins[i] = VIPS_ARRAY( hist_find, 
			n_bytes, VipsPel )) )
			return( NULL );
		memset( hist->bins[i], 0, n_bytes );
	}

	hist->n_bands = n_bands;
	hist->band = band;
	hist->size = size;
	hist->mx = 0;

	return( hist );
}

static int
vips_hist_find_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsHistFind *hist_find = (VipsHistFind *) object;
	VipsImage *in = statistic->in;

	VipsPel *obuffer;

	g_object_set( object, 
		"out", vips_image_new(),
		NULL );

	if( in &&
		vips_check_bandno( class->nickname, in, hist_find->band ) )
		return( -1 ); 

	/* Is this a large histogram? We want to avoid overflow of the uint
	 * accumulators.
	 */
	if( in &&
		(guint64) in->Xsize * (guint64) in->Ysize >= 
			((guint64) 1 << 32) ) 
		hist_find->large = TRUE;

	/* main hist made on in vips_hist_find_start().
	 */

	if( VIPS_OBJECT_CLASS( vips_hist_find_parent_class )->build( object ) )
		return( -1 );

	/* Make the output image.
	 */
	if( vips_image_pipelinev( hist_find->out, 
		VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL ) ) 
		return( -1 );
	vips_image_init_fields( hist_find->out,
		hist_find->hist->mx + 1, 1, hist_find->hist->n_bands, 
		hist_find->large ? VIPS_FORMAT_DOUBLE : VIPS_FORMAT_UINT, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_HISTOGRAM, 1.0, 1.0 );

	/* Interleave for output.
	 */
	if( !(obuffer = VIPS_ARRAY( object, 
		VIPS_IMAGE_SIZEOF_LINE( hist_find->out ), VipsPel )) )
		return( -1 );

#define INTERLEAVE( TYPE ) G_STMT_START { \
	TYPE **bins = (TYPE **) hist_find->hist->bins; \
	\
	TYPE *q; \
	int i, j; \
	\
	for( q = (TYPE *) obuffer, j = 0; j < hist_find->out->Xsize; j++ ) \
		for( i = 0; i < hist_find->out->Bands; i++ ) \
			*q++ = bins[i][j]; \
} G_STMT_END

	if( hist_find->large )  
		INTERLEAVE( double );
	else
		INTERLEAVE( unsigned int );

	if( vips_image_write_line( hist_find->out, 0, obuffer ) )
		return( -1 );

	return( 0 );
}

/* Build a sub-hist, based on the main hist.
 */
static void *
vips_hist_find_start( VipsStatistic *statistic )
{
	VipsHistFind *hist_find = (VipsHistFind *) statistic;

	/* Make the main hist, if necessary.
	 */
	if( !hist_find->hist ) 
		hist_find->hist = histogram_new( hist_find, 
			hist_find->band == -1 ?
				statistic->ready->Bands : 1,
			hist_find->band, 
			statistic->ready->BandFmt == VIPS_FORMAT_UCHAR ? 
				256 : 65536 );

	return( (void *) histogram_new( hist_find, 
		hist_find->hist->n_bands, 
		hist_find->hist->band, 
		hist_find->hist->size ) );
}

/* Join a sub-hist onto the main hist.
 */
static int
vips_hist_find_stop( VipsStatistic *statistic, void *seq )
{
	Histogram *sub_hist = (Histogram *) seq;
	VipsHistFind *hist_find = (VipsHistFind *) statistic;
	Histogram *hist = hist_find->hist; 

	int i, j;

	g_assert( sub_hist->n_bands == hist->n_bands && 
		sub_hist->size == hist->size );

	/* Add on sub-data.
	 */
	hist->mx = VIPS_MAX( hist->mx, sub_hist->mx );

#define SUM( TYPE ) G_STMT_START { \
	TYPE **main_bins = (TYPE **) hist->bins; \
	TYPE **sub_bins = (TYPE **) sub_hist->bins; \
	\
	for( i = 0; i < hist->n_bands; i++ ) \
		for( j = 0; j < hist->size; j++ ) \
			main_bins[i][j] += sub_bins[i][j]; \
} G_STMT_END

	if( hist_find->large ) 
		SUM( double );
	else
		SUM( unsigned int ); 
			
	/* Blank out sub-hist to make sure we can't add it again.
	 */
	sub_hist->mx = 0;
	for( i = 0; i < sub_hist->n_bands; i++ )
		sub_hist->bins[i] = NULL;

	return( 0 );
}

#define SCANOP G_STMT_START { \
	for( z = 0; z < nb; z++ ) { \
		int v = p[z]; \
		\
		if( v > mx ) \
			mx = v; \
		\
		bins[z][v] += 1; \
	} \
	\
	p += nb; \
} G_STMT_END

/* No need to track max for uchar images (it's always 255).
 */
#define UCSCANOP G_STMT_START { \
	for( z = 0; z < nb; z++ ) { \
		int v = p[z]; \
		\
		bins[z][v] += 1; \
	} \
	\
	p += nb; \
} G_STMT_END

/* Hist of all bands. This one is just about worth unrolling.
 */
#define SCAN( IMAGE_TYPE, HIST_TYPE, OP ) G_STMT_START { \
	HIST_TYPE **bins = (HIST_TYPE **) hist->bins; \
	IMAGE_TYPE *p = (IMAGE_TYPE *) in; \
	\
	int z; \
	\
	VIPS_UNROLL( n, OP ); \
} G_STMT_END

/* Hist of selected band.
 */
#define SCAN1( IMAGE_TYPE, HIST_TYPE ) G_STMT_START { \
	HIST_TYPE *bins = (HIST_TYPE *) hist->bins[0]; \
	IMAGE_TYPE *p = (IMAGE_TYPE *) in; \
	int max = nb * n; \
	\
	for( i = hist->band; i < max; i += nb ) { \
		int v = p[i]; \
		\
		if( v > mx ) \
			mx = v; \
		\
		bins[v] += 1; \
	} \
} G_STMT_END

static int
vips_hist_find_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	VipsHistFind *hist_find = (VipsHistFind *) statistic;
	Histogram *hist = (Histogram *) seq;
	int nb = statistic->ready->Bands; 
	int mx = hist->mx;

	int i;

	if( hist_find->band < 0 ) 
		switch( statistic->ready->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			if( hist_find->large )
				SCAN( unsigned char, double, UCSCANOP );
			else
				SCAN( unsigned char, unsigned int, UCSCANOP );
			mx = 255;
			break;

		case VIPS_FORMAT_USHORT:
			if( hist_find->large )
				SCAN( unsigned short, double, SCANOP );
			else
				SCAN( unsigned short, unsigned int, SCANOP );
			break;

		default:
			g_assert_not_reached();
		}
	else 
		switch( statistic->ready->BandFmt ) {
		case VIPS_FORMAT_UCHAR:
			if( hist_find->large )
				SCAN1( unsigned char, double );
			else
				SCAN1( unsigned char, unsigned int );
			break;

		case VIPS_FORMAT_USHORT:
			if( hist_find->large )
				SCAN1( unsigned short, double );
			else
				SCAN1( unsigned short, unsigned int );
			break;

		default:
			g_assert_not_reached();
		}

	hist->mx = mx;

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT

/* Type mapping: go to uchar or ushort.
 */
static const VipsBandFormat vips_hist_find_format_table[10] = {
/* UC   C  US   S  UI   I   F   X   D  DX */
   UC, UC, US, US, US, US, US, US, US, US
};

static void
vips_hist_find_class_init( VipsHistFindClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hist_find";
	object_class->description = _( "find image histogram" );
	object_class->build = vips_hist_find_build;

	sclass->start = vips_hist_find_start;
	sclass->scan = vips_hist_find_scan;
	sclass->stop = vips_hist_find_stop;
	sclass->format_table = vips_hist_find_format_table;

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output histogram" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistFind, out ) );

	VIPS_ARG_INT( class, "band", 110, 
		_( "Band" ), 
		_( "Find histogram of band" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHistFind, band ),
		-1, 100000, -1 );

}

static void
vips_hist_find_init( VipsHistFind *hist_find )
{
	hist_find->band = -1;
}

/**
 * vips_hist_find: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @band: band to equalise
 *
 * Find the histogram of @in. Find the histogram for band @band (producing a
 * one-band histogram), or for all bands (producing an n-band histogram) if 
 * @band is -1. 
 *
 * @in is cast to u8 or u16. @out is always u32.
 *
 * See also: vips_hist_find_ndim(), vips_hist_find_indexed().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_hist_find( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hist_find", ap, in, out );
	va_end( ap );

	return( result );
}
