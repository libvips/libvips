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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

/* Normalise an image using the rules noted above.
 */
static int
normalise( IMAGE *in, IMAGE *out )
{
	if( im_check_uncoded( "im_histplot", in ) ||
		im_check_noncomplex( "im_histplot", in ) )
		return( -1 );

	if( vips_bandfmt_isuint( in->BandFmt ) ) {
		if( im_copy( in, out ) )
			return( -1 );
	}
	else if( vips_bandfmt_isint( in->BandFmt ) ) {
		IMAGE *t1;
		double min;

		/* Move min up to 0. 
		 */
		if( !(t1 = im_open_local( out, "im_histplot", "p" )) ||
			im_min( in, &min ) ||
			im_lintra( 1.0, in, -min, t1 ) )
			return( -1 );
	}
	else {
		/* Float image: scale min--max to 0--any. Output square
		 * graph.
		 */
		IMAGE *t1;
		DOUBLEMASK *stats;
		double min, max;
		int any;

		if( in->Xsize == 1 )
			any = in->Ysize;
		else
			any = in->Xsize;

		if( !(stats = im_stats( in )) )
			return( -1 );
		min = stats->coeff[0];
		max = stats->coeff[1];
		im_free_dmask( stats );

		if( !(t1 = im_open_local( out, "im_histplot", "p" )) ||
			im_lintra( any / (max - min), in, 
				-min * any / (max - min), out ) )
			return( -1 );
	}

	return( 0 );
}

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
make_vert_gen( REGION *or, void *seq, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int ri = IM_RECT_RIGHT( r );
	int bo = IM_RECT_BOTTOM( r );
	int nb = in->Bands;

	int x, y, z;

	for( y = to; y < bo; y++ ) {
		PEL *q = (PEL *) IM_REGION_ADDR( or, le, y );
		PEL *p = (PEL *) IM_IMAGE_ADDR( in, 0, y );

		switch( in->BandFmt ) {
		case IM_BANDFMT_UCHAR: 	VERT( unsigned char ); break;
		case IM_BANDFMT_CHAR: 	VERT( signed char ); break; 
		case IM_BANDFMT_USHORT: VERT( unsigned short ); break; 
		case IM_BANDFMT_SHORT: 	VERT( signed short ); break; 
		case IM_BANDFMT_UINT: 	VERT( unsigned int ); break; 
		case IM_BANDFMT_INT: 	VERT( signed int );  break; 
		case IM_BANDFMT_FLOAT: 	VERT( float ); break; 
		case IM_BANDFMT_DOUBLE:	VERT( double ); break; 

		default:
			g_assert( 0 ); 
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
make_horz_gen( REGION *or, void *seq, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int ri = IM_RECT_RIGHT( r );
	int bo = IM_RECT_BOTTOM( r );
	int nb = in->Bands;
	int lsk = IM_REGION_LSKIP( or );
	int ht = or->im->Ysize;

	int x, y, z;

	for( x = le; x < ri; x++ ) {
		PEL *q = (PEL *) IM_REGION_ADDR( or, x, to );
		PEL *p = (PEL *) IM_IMAGE_ADDR( in, x, 0 );

		switch( in->BandFmt ) {
		case IM_BANDFMT_UCHAR: 	HORZ( unsigned char ); break;
		case IM_BANDFMT_CHAR: 	HORZ( signed char ); break; 
		case IM_BANDFMT_USHORT: HORZ( unsigned short ); break; 
		case IM_BANDFMT_SHORT: 	HORZ( signed short ); break; 
		case IM_BANDFMT_UINT: 	HORZ( unsigned int ); break; 
		case IM_BANDFMT_INT: 	HORZ( signed int );  break; 
		case IM_BANDFMT_FLOAT: 	HORZ( float ); break; 
		case IM_BANDFMT_DOUBLE:	HORZ( double ); break; 

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

/* Plot image.
 */
static int
plot( IMAGE *in, IMAGE *out )
{
	double max;
	int tsize;
	int xsize;
	int ysize;

	if( im_incheck( in ) ||
		im_poutcheck( out ) )
		return( -1 );

	/* Find range we will plot.
	 */
	if( im_max( in, &max ) )
		return( -1 );
	g_assert( max >= 0 );
	if( in->BandFmt == IM_BANDFMT_UCHAR )
		tsize = 256;
	else
		tsize = ceil( max );

	/* Make sure we don't make a zero height image.
	 */
	if( tsize == 0 )
		tsize = 1;

	if( in->Xsize == 1 ) {
		/* Vertical graph.
		 */
		xsize = tsize;
		ysize = in->Ysize;
	}
	else {
		/* Horizontal graph.
		 */
		xsize = in->Xsize;
		ysize = tsize;
	}

	/* Set image.
	 */
	im_initdesc( out, xsize, ysize, in->Bands, 
		IM_BBITS_BYTE, IM_BANDFMT_UCHAR, 
		IM_CODING_NONE, IM_TYPE_HISTOGRAM, 1.0, 1.0, 0, 0 );

	/* Set hints - ANY is ok with us.
	 */
	if( im_demand_hint( out, IM_ANY, NULL ) )
		return( -1 );
	
	/* Generate image.
	 */
	if( in->Xsize == 1 ) {
		if( im_generate( out, NULL, make_vert_gen, NULL, in, NULL ) )
			return( -1 );
	}
	else {
		if( im_generate( out, NULL, make_horz_gen, NULL, in, NULL ) )
			return( -1 );
	}

	return( 0 );
}

/**
 * im_histplot:
 * @in: input image
 * @out: output image
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
 * See also: im_hist_indexed(), im_histeq().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_histplot( IMAGE *in, IMAGE *out )
{
	IMAGE *t1;

	if( im_check_hist( "im_histplot", in ) )
		return( -1 );

	if( !(t1 = im_open_local( out, "im_histplot:1", "p" )) ||
		normalise( in, t1 ) ||
		plot( t1, out ) )
		return( -1 );
	
	return( 0 );
}
