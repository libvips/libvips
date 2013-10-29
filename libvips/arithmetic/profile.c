/* find image profiles 
 *
 * 11/8/99 JC
 *	- from im_cntlines()
 * 22/4/04
 *	- now outputs horizontal/vertical image
 * 9/11/10
 * 	- any image format, any number of bands
 * 	- gtk-doc
 * 21/9/13
 * 	- rewrite as a class
 * 	- output h and v profile in one pass
 * 	- partial
 * 	- output is int rather than ushort
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

struct _Edges;

typedef struct {
	/* Horizontal array: Ys of top-most non-zero pixel.
	 */
	int *column_edges;

	/* Vertical array: Xs of left-most non-zero pixel.
	 */
	int *row_edges;

} Edges;

typedef struct _VipsProfile {
	VipsStatistic parent_instance;

	/* Main edge set. Threads accumulate to this.
	 */
	Edges *edges;

	/* Write profiles here.
	 */
	VipsImage *columns; 
	VipsImage *rows; 

} VipsProfile;

typedef VipsStatisticClass VipsProfileClass;

G_DEFINE_TYPE( VipsProfile, vips_profile, VIPS_TYPE_STATISTIC );

static Edges *
edges_new( VipsProfile *profile )
{
	VipsStatistic *statistic = VIPS_STATISTIC( profile ); 
	VipsImage *in = statistic->ready; 

	Edges *edges;
	int i; 

	if( !(edges = VIPS_NEW( profile, Edges )) )
		return( NULL );
	edges->column_edges = VIPS_ARRAY( profile, in->Xsize * in->Bands, int );
	edges->row_edges = VIPS_ARRAY( profile, in->Ysize * in->Bands, int );
	if( !edges->column_edges || 
		!edges->row_edges )
		return( NULL );

	for( i = 0; i < in->Xsize * in->Bands; i++ )
		edges->column_edges[i] = in->Ysize; 
	for( i = 0; i < in->Ysize * in->Bands; i++ )
		edges->row_edges[i] = in->Xsize; 

	return( edges );
}

static int
vips_profile_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsStatistic *statistic = VIPS_STATISTIC( object ); 
	VipsProfile *profile = (VipsProfile *) object;

	int y;

	if( statistic->in &&
		vips_check_noncomplex( class->nickname, statistic->in ) )
		return( -1 ); 

	g_object_set( object, 
		"columns", vips_image_new(),
		"rows", vips_image_new(),
		NULL );

	/* main edge set made on first thread start.
	 */

	if( VIPS_OBJECT_CLASS( vips_profile_parent_class )->build( object ) )
		return( -1 );

	/* Make the output image.
	 */
	if( vips_image_pipelinev( profile->columns, 
			VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL ) || 
		vips_image_pipelinev( profile->rows, 
			VIPS_DEMAND_STYLE_ANY, statistic->ready, NULL ) ) 
		return( -1 );
	profile->columns->Ysize = 1;
	profile->columns->BandFmt = VIPS_FORMAT_INT; 
	profile->columns->Type = VIPS_INTERPRETATION_HISTOGRAM;
	profile->rows->Xsize = 1;
	profile->rows->BandFmt = VIPS_FORMAT_INT; 
	profile->rows->Type = VIPS_INTERPRETATION_HISTOGRAM;

	if( vips_image_write_line( profile->columns, 0, 
		(VipsPel *) profile->edges->column_edges ) )
		return( -1 );
	for( y = 0; y < profile->rows->Ysize; y++ )
		if( vips_image_write_line( profile->rows, y, 
			(VipsPel *) profile->edges->row_edges + 
				y * VIPS_IMAGE_SIZEOF_PEL( profile->rows ) ) )
			return( -1 );

	return( 0 );
}

/* New edge accumulator. 
 */
static void *
vips_profile_start( VipsStatistic *statistic )
{
	VipsProfile *profile = (VipsProfile *) statistic;

	/* Make the main hist, if necessary.
	 */
	if( !profile->edges ) 
		profile->edges = edges_new( profile );  

	return( (void *) edges_new( profile ) );  
}

/* We do this a lot.
 */
#define MINBANG( V, C ) ((V) = VIPS_MIN( V, C ))

/* Add a line of pixels.
 */
#define ADD_PIXELS( TYPE ) { \
	TYPE *p; \
	int *column_edges; \
	int *row_edges; \
	\
	p = (TYPE *) in; \
	column_edges = edges->column_edges + x * nb; \
	row_edges = edges->row_edges + y * nb; \
	for( i = 0; i < n; i++ ) { \
		for( j = 0; j < nb; j++ ) { \
			if( p[j] ) { \
				MINBANG( column_edges[j], y ); \
				MINBANG( row_edges[j], x + i ); \
			} \
		} \
		\
		p += nb; \
		column_edges += nb; \
	} \
}

/* Add a region to a profile.
 */
static int
vips_profile_scan( VipsStatistic *statistic, void *seq, 
	int x, int y, void *in, int n )
{
	int nb = statistic->ready->Bands;
	Edges *edges = (Edges *) seq;
	int i, j;

	switch( statistic->ready->BandFmt ) {
	case VIPS_FORMAT_UCHAR:
		ADD_PIXELS( guchar );
		break;

	case VIPS_FORMAT_CHAR:
		ADD_PIXELS( char );
		break;

	case VIPS_FORMAT_USHORT:
		ADD_PIXELS( gushort );
		break;

	case VIPS_FORMAT_SHORT:
		ADD_PIXELS( short );
		break;

	case VIPS_FORMAT_UINT:
		ADD_PIXELS( guint );
		break;

	case VIPS_FORMAT_INT:
		ADD_PIXELS( int );
		break;

	case VIPS_FORMAT_FLOAT:
		ADD_PIXELS( float );
		break;

	case VIPS_FORMAT_DOUBLE:
		ADD_PIXELS( double );
		break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}

/* Join a sub-profile onto the main profile.
 */
static int
vips_profile_stop( VipsStatistic *statistic, void *seq )
{
	VipsProfile *profile = (VipsProfile *) statistic;
	Edges *edges = profile->edges; 
	Edges *sub_edges = (Edges *) seq;
	VipsImage *in = statistic->ready;

	int i; 

	for( i = 0; i < in->Xsize * in->Bands; i++ )
		MINBANG( edges->column_edges[i], sub_edges->column_edges[i] ); 

	for( i = 0; i < in->Ysize * in->Bands; i++ )
		MINBANG( edges->row_edges[i], sub_edges->row_edges[i] ); 

	/* Blank out sub-profile to make sure we can't add it again.
	 */
	sub_edges->row_edges = NULL; 
	sub_edges->column_edges = NULL; 

	return( 0 );
}

static void
vips_profile_class_init( VipsProfileClass *class )
{
	GObjectClass *gobject_class = (GObjectClass *) class;
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsStatisticClass *sclass = VIPS_STATISTIC_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "profile";
	object_class->description = _( "find image profiles" );
	object_class->build = vips_profile_build;

	sclass->start = vips_profile_start;
	sclass->scan = vips_profile_scan;
	sclass->stop = vips_profile_stop;

	VIPS_ARG_IMAGE( class, "columns", 100, 
		_( "Columns" ), 
		_( "First non-zero pixel in column" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsProfile, columns ) );

	VIPS_ARG_IMAGE( class, "rows", 101, 
		_( "Rows" ), 
		_( "First non-zero pixel in row" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsProfile, rows ) );

}

static void
vips_profile_init( VipsProfile *profile )
{
}

/**
 * vips_profile:
 * @in: input image
 * @columns: distances from top edge
 * @rows: distances from left edge
 * @...: %NULL-terminated list of optional named arguments
 *
 * vips_profile() searches inward from the edge of @in and finds the 
 * first non-zero pixel. Pixels in @columns have the distance from the top edge 
 * to the first non-zero pixel in that column, @rows has the distance from the 
 * left edge to the first non-zero pixel in that row.
 *
 * See also: vips_project(), vips_hist_find().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_profile( VipsImage *in, VipsImage **columns, VipsImage **rows, ... )
{
	va_list ap;
	int result;

	va_start( ap, rows );
	result = vips_call_split( "profile", ap, in, columns, rows );
	va_end( ap );

	return( result );
}

