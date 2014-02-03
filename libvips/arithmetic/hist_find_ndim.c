/* n-dimensional histogram
 *
 * Written on: 8/7/03 
 * 10/11/04 
 *	- oops, was not checking the bandfmt coming in
 * 24/3/10
 * 	- gtkdoc
 * 	- small celanups
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

struct _VipsHistFindNDim;

/* Accumulate a histogram in one of these.
 */
typedef struct {
	struct _VipsHistFindNDim *ndim;

	int bins;
	int max_val;
	unsigned int ***data;		
} Histogram;

typedef struct _VipsHistFindNDim {
	VipsStatistic parent_instance;

	/* Number of bins on each axis.
	 */
	int bins;

	/* Main image histogram. Subhists accumulate to this.
	 */
	Histogram *hist;

	/* Write hist to this output image.
	 */
	VipsImage *out; 

} VipsHistFindNDim;

typedef VipsStatisticClass VipsHistFindNDimClass;

G_DEFINE_TYPE( VipsHistFindNDim, vips_hist_find_ndim, VIPS_TYPE_STATISTIC );

/* Build a Histogram.
 */
static Histogram *
histogram_new( VipsHistFindNDim *ndim )
{
	VipsImage *in = VIPS_STATISTIC( ndim )->ready;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( ndim );
	int bins = ndim->bins;

	/* How many dimensions do we need to allocate?
	 */
	int ilimit = in->Bands > 2 ? bins : 1;
	int jlimit = in->Bands > 1 ? bins : 1;

	int i, j;
	Histogram *hist;

	if( !(hist = VIPS_NEW( ndim, Histogram )) )
		return( NULL );

	hist->ndim = ndim;
	hist->bins = bins;
	hist->max_val = in->BandFmt == VIPS_FORMAT_UCHAR ? 256 : 65536;
	if( bins < 1 || 
		bins > hist->max_val ) {
		vips_error( class->nickname, 
			_( "bins out of range [1,%d]" ), hist->max_val );
		return( NULL );
	}

	if( !(hist->data = VIPS_ARRAY( ndim, bins, unsigned int ** )) )
		return( NULL );
	memset( hist->data, 0, bins * sizeof( unsigned int ** ) );

	for( i = 0; i < ilimit; i++ ) {
		if( !(hist->data[i] = 
			VIPS_ARRAY( ndim, bins, unsigned int * )) )
			return( NULL );
		memset( hist->data[i], 0, bins * sizeof( unsigned int * ) );
		for( j = 0; j < jlimit; j++ ) {
			if( !(hist->data[i][j] = 
				VIPS_ARRAY( ndim, bins, unsigned int )) )
				return( NULL );
			memset( hist->data[i][j], 
				0, bins * sizeof( unsigned int ) );
		}
	}

	return( hist );
}

static int
vips_hist_find_ndim_build( VipsObject *object )
{
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsHistFindNDim *ndim = (VipsHistFindNDim *) object;

	unsigned int *obuffer;
	int y, i, x, z; 

	g_object_set( object, 
		"out", vips_image_new(),
		NULL );

	/* main hist made on first thread start.
	 */

	if( VIPS_OBJECT_CLASS( vips_hist_find_ndim_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_image_pipelinev( ndim->out, 
		VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL ) ) 
		return( -1 );
	vips_image_init_fields( ndim->out,
		ndim->bins, 
		statistic->ready->Bands > 1 ? ndim->bins : 1, 
		statistic->ready->Bands > 2 ? ndim->bins : 1,
		VIPS_FORMAT_UINT, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_HISTOGRAM, 1.0, 1.0 ); 

	if( !(obuffer = VIPS_ARRAY( ndim, 
		VIPS_IMAGE_N_ELEMENTS( ndim->out ), unsigned int )) )
		return( -1 );

	for( y = 0; y < ndim->out->Ysize; y++ ) {
		for( i = 0, x = 0; x < ndim->out->Xsize; x++ ) 
			for( z = 0; z < ndim->out->Bands; z++, i++ )
				obuffer[i] = ndim->hist->data[z][y][x];

		if( vips_image_write_line( ndim->out, y, (VipsPel *) obuffer ) )
			return( -1 );
	}

	return( 0 );
}

static void *
vips_hist_find_ndim_start( VipsStatistic *statistic )
{
	VipsHistFindNDim *ndim = (VipsHistFindNDim *) statistic;

	/* Make the main hist, if necessary.
	 */
	if( !ndim->hist ) 
		ndim->hist = histogram_new( ndim );  

	return( (void *) histogram_new( ndim ) );
}

/* Join a sub-hist onto the main hist.
 */
static int
vips_hist_find_ndim_stop( VipsStatistic *statistic, void *seq )
{
	Histogram *sub_hist = (Histogram *) seq;
	VipsHistFindNDim *ndim = (VipsHistFindNDim *) statistic;
	Histogram *hist = ndim->hist; 

	int i, j, k;

	for( i = 0; i < hist->bins; i++ )
		for( j = 0; j < hist->bins; j++ )
			for( k = 0; k < hist->bins; k++ )
				if( hist->data[i] && hist->data[i][j] ) {
					hist->data[i][j][k] += 
						sub_hist->data[i][j][k];

					/* Zap sub-hist to make sure we 
					 * can't add it again.
					 */
					sub_hist->data[i][j][k] = 0;
				}

	return( 0 );
}

#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( i = 0, j = 0; j < n; j++ ) { \
		for( k = 0; k < nb; k++, i++ ) \
			index[k] = p[i] / scale; \
 		\
		hist->data[index[2]][index[1]][index[0]] += 1; \
	} \
}

static int
vips_hist_find_ndim_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	Histogram *hist = (Histogram *) seq;
	VipsImage *im = statistic->ready;
	int nb = im->Bands;
	double scale = (double) (hist->max_val + 1) / hist->bins;
	int i, j, k; 
	int index[3];

	/* Fill these with dimensions, backwards.
	 */
	index[0] = index[1] = index[2] = 0;

	switch( im->BandFmt ) {
	case VIPS_FORMAT_UCHAR:
		LOOP( unsigned char );
		break;

	case VIPS_FORMAT_USHORT:
		LOOP( unsigned short );
		break;

	default:
		g_assert( 0 ); 
	}

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT
#define UI VIPS_FORMAT_UINT

/* Type mapping: go to uchar or ushort.
 */
static const VipsBandFormat vips_hist_find_ndim_format_table[10] = {
/* UC   C  US   S  UI   I   F   X  D   DX */
   UC, UC, US, US, US, US, US, US, US, US
};

static void
vips_hist_find_ndim_class_init( VipsHistFindNDimClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "hist_find_ndim";
	object_class->description = _( "find n-dimensional image histogram" );
	object_class->build = vips_hist_find_ndim_build;

	sclass->start = vips_hist_find_ndim_start;
	sclass->scan = vips_hist_find_ndim_scan;
	sclass->stop = vips_hist_find_ndim_stop;
	sclass->format_table = vips_hist_find_ndim_format_table;

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output histogram" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistFindNDim, out ) );

	VIPS_ARG_INT( class, "bins", 110, 
		_( "Bins" ), 
		_( "Number of bins in each dimension" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsHistFindNDim, bins ),
		1, 65536, 10 );

}

static void
vips_hist_find_ndim_init( VipsHistFindNDim *ndim )
{
	ndim->bins = 10;
}

/**
 * vips_hist_find_ndim:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @bins: number of bins to make on each axis
 *
 * Make a one, two or three dimensional histogram of a 1, 2 or
 * 3 band image. Divide each axis into @bins bins .. ie.
 * output is 1 x bins, bins x bins, or bins x bins x bins bands.
 * @bins defaults to 10. 
 *
 * Images are cast to uchar or ushort before histogramming.
 *
 * See also: vips_hist_find(), vips_hist_find_indexed().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_hist_find_ndim( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "hist_find_ndim", ap, in, out );
	va_end( ap );

	return( result );
}
