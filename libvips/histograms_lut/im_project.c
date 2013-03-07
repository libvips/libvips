/* horizontal and vertical projection
 *
 * 20/4/06
 *	- from im_histgr()
 * 25/3/10
 * 	- gtkdoc
 * 	- small celanups
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

/* Accumulate a projection in one of these.
 */
typedef struct {
	IMAGE *in;
	IMAGE *hout;
	IMAGE *vout;
	void *columns;
	void *rows;
} Project;

/* For each input bandfmt, the type we accumulate pixels in.
 */
static int project_type[] = {
	IM_BANDFMT_UINT,	/* IM_BANDFMT_UCHAR */
	IM_BANDFMT_INT,		/* IM_BANDFMT_CHAR */
	IM_BANDFMT_UINT,	/* IM_BANDFMT_USHORT */
	IM_BANDFMT_INT,		/* IM_BANDFMT_SHORT */
	IM_BANDFMT_UINT,	/* IM_BANDFMT_UINT */
	IM_BANDFMT_INT,		/* IM_BANDFMT_INT */
	IM_BANDFMT_DOUBLE,	/* IM_BANDFMT_FLOAT */
	IM_BANDFMT_NOTSET,	/* IM_BANDFMT_COMPLEX */
	IM_BANDFMT_DOUBLE,	/* IM_BANDFMT_DOUBLE */
	IM_BANDFMT_NOTSET	/* IM_BANDFMT_DPCOMPLEX */
};

static Project *
project_new( IMAGE *in, IMAGE *hout, IMAGE *vout )
{
	Project *project;
	int psize = IM_IMAGE_SIZEOF_PEL( hout );

	if( !(project = IM_NEW( hout, Project )) )
		return( NULL );
	project->in = in;
	project->hout = hout;
	project->vout = vout;
	project->columns = IM_ARRAY( hout, psize * in->Xsize, guchar );
	project->rows = IM_ARRAY( hout, psize * in->Ysize, guchar );
	if( !project->columns || !project->rows )
		return( NULL );

	memset( project->columns, 0, psize * in->Xsize );
	memset( project->rows, 0, psize * in->Ysize );

	return( project );
}

/* Build a sub-project, based on the main project.
 */
static void *
project_new_sub( IMAGE *out, void *a, void *b )
{
	Project *mproject = (Project *) a;

	return( project_new( mproject->in, mproject->hout, mproject->vout ) );
}

#define ADD_BUFFER( TYPE, Q, P, N ) { \
	TYPE *p = (TYPE *) (P); \
	TYPE *q = (TYPE *) (Q); \
	int n = (N); \
	int i; \
	\
	for( i = 0; i < n; i++ ) \
		q[i] += p[i]; \
}

/* Join a sub-project onto the main project.
 */
static int
project_merge( void *seq, void *a, void *b )
{
	Project *sproject = (Project *) seq;
	Project *mproject = (Project *) a;
	IMAGE *in = mproject->in;
	IMAGE *out = mproject->hout;
	int hsz = in->Xsize * in->Bands;
	int vsz = in->Ysize * in->Bands;

	g_assert( sproject->hout == mproject->hout );
	g_assert( sproject->vout == mproject->vout );

	/* Add on sub-data.
	 */
	switch( out->BandFmt ) {
	case IM_BANDFMT_UINT:
		ADD_BUFFER( guint, mproject->columns, sproject->columns, hsz );
		ADD_BUFFER( guint, mproject->rows, sproject->rows, vsz );
		break;

	case IM_BANDFMT_INT:
		ADD_BUFFER( int, mproject->columns, sproject->columns, hsz );
		ADD_BUFFER( int, mproject->rows, sproject->rows, vsz );
		break;

	case IM_BANDFMT_DOUBLE:
		ADD_BUFFER( double, mproject->columns, sproject->columns, hsz );
		ADD_BUFFER( double, mproject->rows, sproject->rows, vsz );
		break;

	default:
		g_assert( 0 );
	}

	/* Blank out sub-project to make sure we can't add it again.
	 */
	memset( sproject->columns, 0, IM_IMAGE_SIZEOF_ELEMENT( out ) * hsz );
	memset( sproject->rows, 0, IM_IMAGE_SIZEOF_ELEMENT( out ) * vsz );

	return( 0 );
}

/* Add an area of pixels.
 */
#define ADD_PIXELS( OUTTYPE, INTYPE ) { \
	OUTTYPE *rows; \
	OUTTYPE *columns; \
	INTYPE *p; \
	\
	rows = ((OUTTYPE *) project->rows) + to * nb; \
	for( y = 0; y < r->height; y++ ) { \
		columns = ((OUTTYPE *) project->columns) + le * nb; \
		p = (INTYPE *) IM_REGION_ADDR( reg, le, y + to ); \
		\
		for( x = 0; x < r->width; x++ ) { \
			for( z = 0; z < nb; z++ ) { \
				columns[z] += p[z]; \
				rows[z] += p[z]; \
			} \
			\
			p += nb; \
			columns += nb; \
		} \
		\
		rows += nb; \
	} \
}

/* Add a region to a project.
 */
static int
project_scan( REGION *reg, void *seq, void *a, void *b, gboolean *stop )
{
	Project *project = (Project *) seq;
	Rect *r = &reg->valid;
	int le = r->left;
	int to = r->top;
	int nb = project->in->Bands;
	int x, y, z;

	switch( project->in->BandFmt ) {
	case IM_BANDFMT_UCHAR:
		ADD_PIXELS( guint, guchar );
		break;

	case IM_BANDFMT_CHAR:
		ADD_PIXELS( int, char );
		break;

	case IM_BANDFMT_USHORT:
		ADD_PIXELS( guint, gushort );
		break;

	case IM_BANDFMT_SHORT:
		ADD_PIXELS( int, short );
		break;

	case IM_BANDFMT_UINT:
		ADD_PIXELS( guint, guint );
		break;

	case IM_BANDFMT_INT:
		ADD_PIXELS( int, int );
		break;

	case IM_BANDFMT_FLOAT:
		ADD_PIXELS( double, float );
		break;

	case IM_BANDFMT_DOUBLE:
		ADD_PIXELS( double, double );
		break;

	default:
		g_assert( 0 );
	}

	return( 0 );
}

/**
 * im_project:
 * @in: input image
 * @hout: sums of rows
 * @vout: sums of columns
 *
 * Find the horizontal and vertical projections of an image, ie. the sum
 * of every row of pixels, and the sum of every column of pixels. The output
 * format is uint, int or double, depending on the input format.
 *
 * Non-complex images only.
 *
 * See also: im_histgr(), im_profile().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_project( IMAGE *in, IMAGE *hout, IMAGE *vout )
{
	Project *mproject;
	int y;

	/* Check images. PIO from in, WIO to out.
	 */
	if( im_check_uncoded( "im_project", in ) ||
		im_check_noncomplex( "im_project", in ) ||
		im_pincheck( in ) || 
		im_outcheck( hout ) || 
		im_outcheck( vout ) )
		return( -1 );

	/* Make the output images. 
	 */
	if( im_cp_desc( hout, in ) || 
		im_cp_desc( vout, in ) ) 
		return( -1 );
	hout->Xsize = 1;
	hout->BandFmt = project_type[in->BandFmt];
	hout->Type = IM_TYPE_HISTOGRAM;
	vout->Ysize = 1;
	vout->BandFmt = project_type[in->BandFmt];
	vout->Type = IM_TYPE_HISTOGRAM;

	/* Build the main project we accumulate data in.
	 */
	if( !(mproject = project_new( in, hout, vout )) )
		return( -1 );

	/* Accumulate data.
	 */
	if( vips_sink( in, 
		project_new_sub, project_scan, project_merge, mproject, NULL ) )
		return( -1 );

	if( im_setupout( hout ) || 
		im_setupout( vout ) )
		return( -1 );

	if( im_writeline( 0, vout, (VipsPel *) mproject->columns ) )
		return( -1 );
	for( y = 0; y < in->Ysize; y++ )
		if( im_writeline( y, hout, (VipsPel *) mproject->rows + 
			y * IM_IMAGE_SIZEOF_PEL( hout ) ) )
			return( -1 );

	return( 0 );
}
