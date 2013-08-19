/* indexed histogram: use an index image to pick the bins
 *
 * 13/10/09
 * 	- from im_histgr.c
 * 24/3/10
 * 	- gtkdoc
 * 17/8/13
 * 	- redo as a class
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
#include <string.h>

#include <vips/vips.h>

#include "statistic.h"

/* Accumulate a histogram in one of these.
 */
typedef struct {
	REGION *vreg;		/* Get index pixels with this */

	int bands;		/* Number of bands in output */
	int size;		/* Length of bins */
	int mx;			/* Maximum value we have seen */
	double *bins;		/* All the bins! */
} Histogram;

typedef struct _VipsHistFind {
	VipsStatistic parent_instance;

	VipsImage *index;

	/* Main image histogram. Subhists accumulate to this.
	 */
	Histogram *hist;

	/* Write hist to this output image.
	 */
	VipsImage *out; 

} VipsHistFind;

typedef VipsStatisticClass VipsHistFindClass;

G_DEFINE_TYPE( VipsHistFind, vips_hist_find, VIPS_TYPE_STATISTIC );

/* Free a Histogram.
 */
static void
histogram_free( Histogram *hist )
{
	IM_FREE( hist->bins );
	IM_FREEF( im_region_free, hist->vreg );
	IM_FREE( hist );
}

/* Build a Histogram.
 */
static Histogram *
histogram_new( IMAGE *index, IMAGE *value, IMAGE *out, int bands, int size )
{
	Histogram *hist;

	if( !(hist = IM_NEW( NULL, Histogram )) )
		return( NULL );

	hist->index = index;
	hist->value = value;
	hist->out = out;
	hist->vreg = NULL;
	hist->bands = bands;
	hist->size = size;
	hist->mx = 0;
	hist->bins = NULL;

	if( !(hist->bins = IM_ARRAY( NULL, bands * size, double )) ||
		!(hist->vreg = im_region_create( value )) ) {
		hist_free( hist );
		return( NULL );
	}

	memset( hist->bins, 0, bands * size * sizeof( double ) );

	return( hist );
}

/* Build a sub-hist, based on the main hist.
 */
static void *
hist_start( IMAGE *out, void *a, void *b )
{
	Histogram *mhist = (Histogram *) a;

	return( (void *) 
		hist_build( mhist->index, mhist->value, mhist->out, 
			mhist->bands, mhist->size ) );
}

/* Join a sub-hist onto the main hist, then free it.
 */
static int
hist_stop( void *seq, void *a, void *b )
{
	Histogram *shist = (Histogram *) seq;
	Histogram *mhist = (Histogram *) a;
	int i;

	g_assert( shist->bands == mhist->bands && shist->size == mhist->size );

	/* Add on sub-data.
	 */
	mhist->mx = IM_MAX( mhist->mx, shist->mx );
	for( i = 0; i < mhist->bands * mhist->size; i++ )
		mhist->bins[i] += shist->bins[i];

	hist_free( shist );
	
	return( 0 );
}

/* Accumulate a buffer of pels, uchar index.
 */
#define ACCUMULATE_UCHAR( TYPE ) { \
	int x, z; \
	TYPE *tv = (TYPE *) v; \
	\
	for( x = 0; x < width; x++ ) { \
		double *bin = hist->bins + i[x] * bands; \
		\
		for( z = 0; z < bands; z++ ) \
			bin[z] += tv[z]; \
		\
		tv += bands; \
	} \
}

/* A uchar index image.
 */
static int
hist_scan_uchar( REGION *reg, void *seq, void *a, void *b, gboolean *stop )
{
	Histogram *hist = (Histogram *) seq;
	Rect *r = &reg->valid;
	IMAGE *value = hist->value;
	int bands = value->Bands;
	int width = r->width;

	int y;

	/* Need the correspondiing area of the value image.
	 */
	if( im_prepare( hist->vreg, r ) )
		return( -1 );

	/* Accumulate!
	 */
	for( y = 0; y < r->height; y++ ) {
		VipsPel *i = IM_REGION_ADDR( reg, r->left, r->top + y );
		VipsPel *v = IM_REGION_ADDR( hist->vreg, 
			r->left, r->top + y );

		switch( value->BandFmt ) {
		case IM_BANDFMT_UCHAR: 	
			ACCUMULATE_UCHAR( unsigned char ); break; 
		case IM_BANDFMT_CHAR: 	
			ACCUMULATE_UCHAR( signed char ); break; 
		case IM_BANDFMT_USHORT: 
			ACCUMULATE_UCHAR( unsigned short ); break; 
		case IM_BANDFMT_SHORT: 	
			ACCUMULATE_UCHAR( signed short ); break; 
		case IM_BANDFMT_UINT: 	
			ACCUMULATE_UCHAR( unsigned int ); break; 
		case IM_BANDFMT_INT: 	
			ACCUMULATE_UCHAR( signed int ); break; 
		case IM_BANDFMT_FLOAT: 		
			ACCUMULATE_UCHAR( float ); break; 
		case IM_BANDFMT_DOUBLE:	
			ACCUMULATE_UCHAR( double ); break; 

		default:
			g_assert( 0 );
		}
	}

	/* Max is always 255.
	 */
	hist->mx = 255;

	return( 0 );
}

/* Accumulate a buffer of pels, ushort index.
 */
#define ACCUMULATE_USHORT( TYPE ) { \
	int x, z; \
	TYPE *tv = (TYPE *) v; \
	\
	for( x = 0; x < width; x++ ) { \
		int ix = i[x]; \
		double *bin = hist->bins + ix * bands; \
		\
		if( ix > mx ) \
			mx = ix; \
		\
		for( z = 0; z < bands; z++ ) \
			bin[z] += tv[z]; \
		\
		tv += bands; \
	} \
}

/* A ushort index image.
 */
static int
hist_scan_ushort( REGION *reg, void *seq, void *a, void *b, gboolean *stop )
{
	Histogram *hist = (Histogram *) seq;
	Rect *r = &reg->valid;
	IMAGE *value = hist->value;
	int bands = value->Bands;
	int width = r->width;

	int y, mx;

	/* Need the correspondiing area of the value image.
	 */
	if( im_prepare( hist->vreg, r ) )
		return( -1 );

	/* Accumulate!
	 */
	mx = hist->mx;
	for( y = 0; y < r->height; y++ ) {
		unsigned short *i = (unsigned short *) IM_REGION_ADDR( reg, 
				r->left, r->top + y );
		VipsPel *v = IM_REGION_ADDR( hist->vreg, 
			r->left, r->top + y );

		switch( value->BandFmt ) {
		case IM_BANDFMT_UCHAR: 	
			ACCUMULATE_USHORT( unsigned char ); break; 
		case IM_BANDFMT_CHAR: 	
			ACCUMULATE_USHORT( signed char ); break; 
		case IM_BANDFMT_USHORT: 
			ACCUMULATE_USHORT( unsigned short ); break; 
		case IM_BANDFMT_SHORT: 	
			ACCUMULATE_USHORT( signed short ); break; 
		case IM_BANDFMT_UINT: 	
			ACCUMULATE_USHORT( unsigned int ); break; 
		case IM_BANDFMT_INT: 	
			ACCUMULATE_USHORT( signed int ); break; 
		case IM_BANDFMT_FLOAT: 		
			ACCUMULATE_USHORT( float ); break; 
		case IM_BANDFMT_DOUBLE:	
			ACCUMULATE_USHORT( double ); break; 

		default:
			g_assert( 0 );
		}
	}

	/* Note the maximum.
	 */
	hist->mx = mx;

	return( 0 );
}

static int
hist_write( IMAGE *out, Histogram *hist )
{
	if( im_cp_descv( out, hist->index, hist->value, NULL ) ) 
		return( -1 );
	im_initdesc( out,
		hist->mx + 1, 1, hist->value->Bands, 
		IM_BBITS_DOUBLE, IM_BANDFMT_DOUBLE, 
		IM_CODING_NONE, IM_TYPE_HISTOGRAM, 1.0, 1.0, 0, 0 );
	if( im_setupout( out ) )
		return( -1 );

	if( im_writeline( 0, out, (VipsPel *) hist->bins ) )
		return( -1 );

	return( 0 );
}

/**
 * im_hist_indexed:
 * @index: input image
 * @value: input image
 * @out: output image
 *
 * Make a histogram of @value, but use image @index to pick the bins. In other
 * words, element zero in @out contains the sum of all the pixels in @value
 * whose corresponding pixel in @index is zero.
 *
 * @index must have just one band and be u8 or u16. @value must be
 * non-complex. @out always has the same size and format as @value.
 *
 * This operation is useful in conjunction with im_label_regions(). You can
 * use it to find the centre of gravity of blobs in an image, for example.
 *
 * See also: im_histgr(), im_label_regions().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_hist_indexed( IMAGE *index, IMAGE *value, IMAGE *out )
{
	int size;		/* Length of hist */
	Histogram *mhist;
	VipsGenerateFn scanfn;

	/* Check images. PIO from in, WIO to out.
	 */
	if( im_pincheck( index ) || 
		im_pincheck( value ) || 
		im_outcheck( out ) ||
		im_check_uncoded( "im_hist_indexed", index ) ||
		im_check_uncoded( "im_hist_indexed", value ) ||
		im_check_noncomplex( "im_hist_indexed", value ) ||
		im_check_size_same( "im_hist_indexed", index, value ) ||
		im_check_u8or16( "im_hist_indexed", index ) ||
		im_check_mono( "im_hist_indexed", index ) )
		return( -1 );

	/* Find the range of pixel values we must handle.
	 */
	if( index->BandFmt == IM_BANDFMT_UCHAR ) {
		size = 256;
		scanfn = hist_scan_uchar;
	}
	else {
		size = 65536;
		scanfn = hist_scan_ushort;
	}

	/* Build main hist we accumulate data in.
	 */
	if( !(mhist = hist_build( index, value, out, value->Bands, size )) )
		return( -1 );

	/* Accumulate data.
	 */
	if( vips_sink( index, 
		hist_start, scanfn, hist_stop, mhist, NULL ) ||
		hist_write( out, mhist ) ) {
		hist_free( mhist );
		return( -1 );
	}

	hist_free( mhist );

	return( 0 );
}
