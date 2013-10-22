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

struct _VipsHistFindIndexed;

/* Accumulate a histogram in one of these.
 */
typedef struct {
	struct _VipsHistFindIndexed *indexed;

	VipsRegion *reg;	/* Get index pixels with this */

	int size;		/* Length of bins */
	int mx;			/* Maximum value we have seen */
	double *bins;		/* All the bins! */
} Histogram;

typedef struct _VipsHistFindIndexed {
	VipsStatistic parent_instance;

	VipsImage *index;

	/* Index image, cast to uchar/ushort.
	 */
	VipsImage *index_ready; 

	/* Main image histogram. Subhists accumulate to this.
	 */
	Histogram *hist;

	/* Write hist to this output image.
	 */
	VipsImage *out; 

} VipsHistFindIndexed;

typedef VipsStatisticClass VipsHistFindIndexedClass;

G_DEFINE_TYPE( VipsHistFindIndexed, 
	vips_hist_find_indexed, VIPS_TYPE_STATISTIC );

static Histogram *
histogram_new( VipsHistFindIndexed *indexed )
{
	VipsStatistic *statistic = VIPS_STATISTIC( indexed ); 
	int bands = statistic->ready->Bands; 
	Histogram *hist;

	if( !(hist = VIPS_NEW( indexed, Histogram )) )
		return( NULL );

	hist->indexed = indexed;
	hist->reg = NULL;
	hist->size = indexed->index_ready->BandFmt == VIPS_FORMAT_UCHAR ? 
		256 : 65536;
	hist->mx = 0;
	hist->bins = NULL;

	if( !(hist->bins = VIPS_ARRAY( indexed, bands * hist->size, double )) ||
		!(hist->reg = vips_region_new( indexed->index_ready )) ) 
		return( NULL );

	memset( hist->bins, 0, bands * hist->size * sizeof( double ) );

	return( hist );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT

/* Type mapping: go to uchar or ushort.
 */
static const VipsBandFormat vips_hist_find_indexed_format[10] = {
/* UC   C  US   S  UI   I   F   X   D  DX */
   UC, UC, US, US, US, US, US, US, US, US
};

static int
vips_hist_find_indexed_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsHistFindIndexed *indexed = (VipsHistFindIndexed *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 1 );

	g_object_set( object, 
		"out", vips_image_new(),
		NULL );

	/* main hist made on first thread start.
	 */

	/* index image must be cast to uchar/ushort.
	 */
	if( indexed->index &&
		statistic->in ) { 
		if( vips_check_uncoded( class->nickname, indexed->index ) ||
			vips_check_size_same( class->nickname, 
				indexed->index, statistic->in ) ||
			vips_check_mono( class->nickname, indexed->index ) )
			return( -1 );

		if( vips_cast( indexed->index, &t[0], 
			vips_hist_find_indexed_format[indexed->index->BandFmt],
			NULL ) )
			return( -1 );

		indexed->index_ready = t[0];
	}

	if( VIPS_OBJECT_CLASS( vips_hist_find_indexed_parent_class )->
		build( object ) )
		return( -1 );

	VIPS_UNREF( indexed->hist->reg );

	if( vips_image_pipelinev( indexed->out, 
		VIPS_DEMAND_STYLE_ANY, 
		statistic->ready, indexed->index_ready, NULL ) ) 
		return( -1 );
	vips_image_init_fields( indexed->out,
		indexed->hist->mx + 1, 1, statistic->ready->Bands, 
		VIPS_FORMAT_DOUBLE, VIPS_CODING_NONE, 
		VIPS_INTERPRETATION_HISTOGRAM, 1.0, 1.0 ); 

	if( vips_image_write_line( indexed->out, 0, 
		(VipsPel *) indexed->hist->bins ) )
		return( -1 );

	return( 0 );
}

static void *
vips_hist_find_indexed_start( VipsStatistic *statistic )
{
	VipsHistFindIndexed *indexed = (VipsHistFindIndexed *) statistic;

	/* Make the main hist, if necessary.
	 */
	if( !indexed->hist ) 
		indexed->hist = histogram_new( indexed );  

	return( (void *) histogram_new( indexed ) );
}

/* Join a sub-hist onto the main hist.
 */
static int
vips_hist_find_indexed_stop( VipsStatistic *statistic, void *seq )
{
	Histogram *sub_hist = (Histogram *) seq;
	VipsHistFindIndexed *indexed = (VipsHistFindIndexed *) statistic;
	Histogram *hist = indexed->hist; 
	int bands = statistic->ready->Bands; 

	int i;

	/* Add on sub-data.
	 */
	hist->mx = VIPS_MAX( hist->mx, sub_hist->mx );
	for( i = 0; i < bands * hist->size; i++ ) {
		hist->bins[i] += sub_hist->bins[i];
		sub_hist->bins[i] = 0;
	}

	VIPS_UNREF( sub_hist->reg );

	return( 0 );
}

/* Accumulate a buffer of pels, uchar index.
 */
#define ACCUMULATE_UCHAR( TYPE ) { \
	int x, z; \
	TYPE *tv = (TYPE *) in; \
	\
	for( x = 0; x < n; x++ ) { \
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
static void 
vips_hist_find_indexed_uchar_scan( VipsHistFindIndexed *indexed,
	Histogram *hist, void *in, void *index, int n )
{
	VipsStatistic *statistic = VIPS_STATISTIC( indexed ); 
	int bands = statistic->ready->Bands;
	unsigned char *i = (unsigned char *) index;

	switch( statistic->ready->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	
		ACCUMULATE_UCHAR( unsigned char ); break; 
	case VIPS_FORMAT_CHAR: 	
		ACCUMULATE_UCHAR( signed char ); break; 
	case VIPS_FORMAT_USHORT: 
		ACCUMULATE_UCHAR( unsigned short ); break; 
	case VIPS_FORMAT_SHORT: 	
		ACCUMULATE_UCHAR( signed short ); break; 
	case VIPS_FORMAT_UINT: 	
		ACCUMULATE_UCHAR( unsigned int ); break; 
	case VIPS_FORMAT_INT: 	
		ACCUMULATE_UCHAR( signed int ); break; 
	case VIPS_FORMAT_FLOAT: 		
		ACCUMULATE_UCHAR( float ); break; 
	case VIPS_FORMAT_DOUBLE:	
		ACCUMULATE_UCHAR( double ); break; 

	default:
		g_assert( 0 );
	}

	/* Max is always 255.
	 */
	hist->mx = 255;
}

/* Accumulate a buffer of pels, ushort index.
 */
#define ACCUMULATE_USHORT( TYPE ) { \
	int x, z; \
	TYPE *tv = (TYPE *) in; \
	\
	for( x = 0; x < n; x++ ) { \
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
static void 
vips_hist_find_indexed_ushort_scan( VipsHistFindIndexed *indexed,
	Histogram *hist, void *in, void *index, int n )
{
	VipsStatistic *statistic = VIPS_STATISTIC( indexed ); 
	int bands = statistic->ready->Bands;
	unsigned short *i = (unsigned short *) index;

	int mx;

	mx = hist->mx;

	switch( statistic->ready->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	
		ACCUMULATE_USHORT( unsigned char ); break; 
	case VIPS_FORMAT_CHAR: 	
		ACCUMULATE_USHORT( signed char ); break; 
	case VIPS_FORMAT_USHORT: 
		ACCUMULATE_USHORT( unsigned short ); break; 
	case VIPS_FORMAT_SHORT: 	
		ACCUMULATE_USHORT( signed short ); break; 
	case VIPS_FORMAT_UINT: 	
		ACCUMULATE_USHORT( unsigned int ); break; 
	case VIPS_FORMAT_INT: 	
		ACCUMULATE_USHORT( signed int ); break; 
	case VIPS_FORMAT_FLOAT: 		
		ACCUMULATE_USHORT( float ); break; 
	case VIPS_FORMAT_DOUBLE:	
		ACCUMULATE_USHORT( double ); break; 

	default:
		g_assert( 0 );
	}

	/* Note the maximum.
	 */
	hist->mx = mx;
}

typedef void (*VipsHistFindIndexedScanFn)( VipsHistFindIndexed *indexed,
	Histogram *hist, void *in, void *index, int n );

static int
vips_hist_find_indexed_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	Histogram *hist = (Histogram *) seq;
	VipsHistFindIndexed *indexed = (VipsHistFindIndexed *) statistic;

	VipsRect r = { x, y, n, 1 }; 
	VipsHistFindIndexedScanFn scan;

	/* Need the corresponding area of the index image.
	 */
	if( vips_region_prepare( hist->reg, &r ) )
		return( -1 );

	if( indexed->index_ready->BandFmt == VIPS_FORMAT_UCHAR ) 
		scan = vips_hist_find_indexed_uchar_scan;
	else
		scan = vips_hist_find_indexed_ushort_scan;

	scan( indexed, hist, in, VIPS_REGION_ADDR( hist->reg, x, y ), n );

	return( 0 ); 
}

static void
vips_hist_find_indexed_class_init( VipsHistFindIndexedClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hist_find_indexed";
	object_class->description = _( "find indexed image histogram" );
	object_class->build = vips_hist_find_indexed_build;

	sclass->start = vips_hist_find_indexed_start;
	sclass->scan = vips_hist_find_indexed_scan;
	sclass->stop = vips_hist_find_indexed_stop;

	VIPS_ARG_IMAGE( class, "index", 90, 
		_( "Index" ), 
		_( "Index image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsHistFindIndexed, index ) );

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output histogram" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistFindIndexed, out ) );

}

static void
vips_hist_find_indexed_init( VipsHistFindIndexed *hist_find )
{
}

/**
 * vips_hist_find_indexed:
 * @in: input image
 * @index: input index image 
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Make a histogram of @in, but use image @index to pick the bins. In other
 * words, element zero in @out contains the sum of all the pixels in @in
 * whose corresponding pixel in @index is zero.
 *
 * @index must have just one band and be u8 or u16. @value must be
 * non-complex. @out always has the same size and format as @value.
 *
 * This operation is useful in conjunction with im_label_regions(). You can
 * use it to find the centre of gravity of blobs in an image, for example.
 *
 * See also: vips_hist_find(), im_label_regions().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_hist_find_indexed( VipsImage *in, VipsImage *index, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hist_find_indexed", ap, in, index, out );
	va_end( ap );

	return( result );
}
