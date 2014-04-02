/* hough transform
 *
 * 7/3/14
<<<<<<< HEAD
 * 	- from hough.c
=======
 * 	- from hist_find.c
>>>>>>> origin/master
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
<<<<<<< HEAD

typedef struct _VipsHough {
	VipsStatistic parent_instance;

	/* Lock writes to the output image with this. We can't have a separate
	 * output for each thread, memory use would be crazy.
	 */
	GMutex *lock;

	/* Accumulate the transform in this large memory image.
	 */
	VipsImage *out; 

} VipsHough;

typedef VipsStatisticClass VipsHoughClass;

G_DEFINE_TYPE( VipsHough, vips_hough, VIPS_TYPE_STATISTIC );

static void
vips_hough_dispose( GObject *gobject )
{
	VipsHough *hough = (VipsHough *) gobject;

	VIPS_FREEF( vips_g_mutex_free, hough->lock );

	G_OBJECT_CLASS( vips_hough_parent_class )->dispose( gobject );
=======
#include "hough.h"

G_DEFINE_ABSTRACT_TYPE( VipsHough, vips_hough, VIPS_TYPE_STATISTIC );

static VipsImage *
vips_hough_new_accumulator( VipsHough *hough )
{
	VipsHoughClass *class = VIPS_HOUGH_GET_CLASS( hough );
	VipsStatistic *statistic = VIPS_STATISTIC( hough ); 

	VipsImage *accumulator; 

	accumulator = vips_image_new_buffer(); 

	vips_image_pipelinev( accumulator,
		VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL );

	if( class->init_accumulator( hough, accumulator ) ||
		vips_image_write_prepare( accumulator ) ) {
		g_object_unref( accumulator );
		return( NULL );
	}

	/* vips does not guarantee image mem is zeroed.
	 */
	memset( VIPS_IMAGE_ADDR( accumulator, 0, 0 ), 0,
		VIPS_IMAGE_SIZEOF_IMAGE( accumulator ) ); 

	return( accumulator );
>>>>>>> origin/master
}

static int
vips_hough_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsHough *hough = (VipsHough *) object;

<<<<<<< HEAD
	unsigned int *obuffer;
	unsigned int *q;
	int i, j;

	g_object_set( object, 
		"out", vips_image_new_buffer(),
=======
	VipsImage *out; 

	/* Mono only, we use the bands dimension of the output image for
	 * a parameter.
	 */
	if( statistic->in ) 
		if( vips_check_mono( class->nickname, statistic->in ) )
			return( -1 );

	if( !(out = vips_hough_new_accumulator( hough )) )
		return( -1 );
	g_object_set( object, 
		"out", out,
>>>>>>> origin/master
		NULL );

	if( VIPS_OBJECT_CLASS( vips_hough_parent_class )->build( object ) )
		return( -1 );

<<<<<<< HEAD
	/* Make the output image.
	 */
	if( vips_image_pipelinev( hough->out, 
		VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL ) ) 
		return( -1 );
	vips_image_init_fields( hough->out,
		hough->hist->mx + 1, 1, hough->hist->bands, 
		VIPS_FORMAT_UINT, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_HISTOGRAM, 1.0, 1.0 );
	if( vips_image_write_prepare( hough->out ) )
		return( -1 ); 

	return( 0 );
}

/* Build a sub-hist, based on the main hist.
=======
	return( 0 );
}

/* Build a new accumulator. 
>>>>>>> origin/master
 */
static void *
vips_hough_start( VipsStatistic *statistic )
{
	VipsHough *hough = (VipsHough *) statistic;

<<<<<<< HEAD
	/* Make the main hist, if necessary.
	 */
	if( !hough->hist ) 
		hough->hist = histogram_new( hough, 
			hough->which == -1 ?
				statistic->ready->Bands : 1,
			hough->which, 
			statistic->ready->BandFmt == VIPS_FORMAT_UCHAR ? 
				256 : 65536 );

	return( (void *) histogram_new( hough, 
		hough->hist->bands, 
		hough->hist->which, 
		hough->hist->size ) );
}

/* Join a sub-hist onto the main hist.
 */
static int
vips_hough_stop( VipsStatistic *statistic, void *seq )
{
	Histogram *sub_hist = (Histogram *) seq;
	VipsHough *hough = (VipsHough *) statistic;
	Histogram *hist = hough->hist; 

	int i, j;

	g_assert( sub_hist->bands == hist->bands && 
		sub_hist->size == hist->size );

	/* Add on sub-data.
	 */
	hist->mx = VIPS_MAX( hist->mx, sub_hist->mx );
	for( i = 0; i < hist->bands; i++ )
		for( j = 0; j < hist->size; j++ )
			hist->bins[i][j] += sub_hist->bins[i][j];

	/* Blank out sub-hist to make sure we can't add it again.
	 */
	sub_hist->mx = 0;
	for( i = 0; i < sub_hist->bands; i++ )
		sub_hist->bins[i] = NULL;

	return( 0 );
}

/* Hist of all bands of uchar.
 */
static int
vips_hough_uchar_scan( VipsStatistic *statistic, 
	void *seq, int x, int y, void *in, int n )
{
	Histogram *hist = (Histogram *) seq;
	int nb = statistic->ready->Bands;
	VipsPel *p = (VipsPel *) in;

	int i, j, z;

	/* Tried swapping these loops, no meaningful speedup. 
	 */

	for( i = 0, j = 0; j < n; j++ )
		for( z = 0; z < nb; z++, i++ )
			hist->bins[z][p[i]] += 1;

	/* Note the maximum.
	 */
	hist->mx = 255;
=======
	VipsImage *accumulator;

	if( !(accumulator = vips_hough_new_accumulator( hough )) )
		return( NULL ); 

	return( (void *) accumulator ); 
}

/* Add our finished accumulator to the main area.
 */
static int
vips_hough_stop( VipsStatistic *statistic, void *seq )
{
	VipsImage *accumulator = (VipsImage *) seq;
	VipsHough *hough = (VipsHough *) statistic;

	if( vips_draw_image( hough->out, accumulator, 0, 0,
		"mode", VIPS_COMBINE_MODE_ADD,
		NULL ) ) {
		g_object_unref( accumulator ); 
		return( -1 ); 
	}

	g_object_unref( accumulator ); 
>>>>>>> origin/master

	return( 0 );
}

<<<<<<< HEAD
/* Histogram of a selected band of a uchar image.
 */
static int
vips_hough_uchar_extract_scan( VipsStatistic *statistic, 
	void *seq, int x, int y, void *in, int n )
{
	Histogram *hist = (Histogram *) seq;
	int nb = statistic->ready->Bands;
	int max = n * nb;
	unsigned int *bins = hist->bins[0];
=======
static int
vips_hough_scan( VipsStatistic *statistic, 
	void *seq, int x, int y, void *in, int n )
{
	VipsHough *hough = (VipsHough *) statistic;
	VipsHoughClass *class = VIPS_HOUGH_GET_CLASS( hough );
	VipsImage *accumulator = (VipsImage *) seq;
>>>>>>> origin/master
	VipsPel *p = (VipsPel *) in;

	int i;

<<<<<<< HEAD
	for( i = hist->which; i < max; i += nb ) 
		bins[p[i]] += 1;

	/* Note the maximum.
	 */
	hist->mx = 255;

	return( 0 );
}

/* Histogram of all bands of a ushort image.
 */
static int
vips_hough_ushort_scan( VipsStatistic *statistic, 
	void *seq, int x, int y, void *in, int n )
{
	Histogram *hist = (Histogram *) seq;
	int mx = hist->mx;
	int nb = statistic->ready->Bands;
	unsigned short *p = (unsigned short *) in; 

	int i, j, z; 

	for( i = 0, j = 0; j < n; j++ )
		for( z = 0; z < nb; z++, i++ ) {
			int v = p[i];

			/* Adjust maximum.
			 */
			if( v > mx )
				mx = v;

			hist->bins[z][v] += 1;
		}

	/* Note the maximum.
	 */
	hist->mx = mx;

	return( 0 );
}

/* Histogram of one band of a ushort image.
 */
static int
vips_hough_ushort_extract_scan( VipsStatistic *statistic, 
	void *seq, int x, int y, void *in, int n )
{
	Histogram *hist = (Histogram *) seq;
	int mx = hist->mx;
	unsigned int *bins = hist->bins[0];
	unsigned short *p = (unsigned short *) in;
	int nb = statistic->ready->Bands;
	int max = nb * n;

	int i; 

	for( i = hist->which; i < max; i += nb ) {
		int v = p[i];

		/* Adjust maximum.
		 */
		if( v > mx )
			mx = v;

		bins[v] += 1;
	}

	/* Note the maximum.
	 */
	hist->mx = mx;
=======
	for( i = 0; i < n; i++ )
		if( p[i] )
			class->vote( hough, accumulator, x + i, y );
>>>>>>> origin/master

	return( 0 );
}

<<<<<<< HEAD
static int
vips_hough_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	VipsHough *hough = (VipsHough *) statistic;
	VipsStatisticScanFn scan;

	if( hough->which < 0 ) {
		if( statistic->in->BandFmt == VIPS_FORMAT_UCHAR ) 
			scan = vips_hough_uchar_scan;
		else
			scan = vips_hough_ushort_scan;
	}
	else {
		if( statistic->in->BandFmt == VIPS_FORMAT_UCHAR ) 
			scan = vips_hough_uchar_extract_scan;
		else
			scan = vips_hough_ushort_extract_scan;
	}

	return( scan( statistic, seq, x, y, in, n ) ); 
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT

/* Type mapping: go to uchar or ushort.
 */
static const VipsBandFormat vips_histgr_format_table[10] = {
/* UC   C  US   S  UI   I   F   X   D  DX */
   UC, UC, US, US, US, US, US, US, US, US
=======
#define UC VIPS_FORMAT_UCHAR

/* Input image is cast to this format.
 */
static const VipsBandFormat vips_hough_format_table[10] = {
/* UC   C  US   S  UI   I   F   X   D  DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
>>>>>>> origin/master
};

static void
vips_hough_class_init( VipsHoughClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

<<<<<<< HEAD
	gobject_class->dispose = vips_hough_dispose;
=======
>>>>>>> origin/master
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hough";
<<<<<<< HEAD
	object_class->description = _( "find image histogram" );
=======
	object_class->description = _( "find hough transform" );
>>>>>>> origin/master
	object_class->build = vips_hough_build;

	sclass->start = vips_hough_start;
	sclass->scan = vips_hough_scan;
	sclass->stop = vips_hough_stop;
<<<<<<< HEAD
	sclass->format_table = vips_histgr_format_table;

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output histogram" ),
=======
	sclass->format_table = vips_hough_format_table;

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
>>>>>>> origin/master
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHough, out ) );

}

static void
vips_hough_init( VipsHough *hough )
{
<<<<<<< HEAD
	hough->lock = vips_g_mutex_new();
}

/**
 * vips_hough:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * See also: 
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_hough( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hough", ap, in, out );
	va_end( ap );

	return( result );
=======
>>>>>>> origin/master
}
