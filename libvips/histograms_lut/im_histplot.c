/* @(#) im_histplot: plot a 1xany or anyx1 image file as a max x any or 
 * @(#) any x max graph using these rules:
 * @(#)
 * @(#) - unsigned char
 * @(#) 	always output 256 
 * @(#) - other unsigned integer types
 * @(#) 	output 0 - max
 * @(#) - signed int types
 * @(#) 	min moved to 0, max moved to max + min.
 * @(#) - float types
 * @(#) 	min moved to 0, max moved to any (square output)
 * @(#)
 * @(#) usage:
 * @(#)
 * @(#)  	int 
 * @(#)  	im_histplot( hist, histplot )
 * @(#)  	IMAGE *hist, *histplot;
 * @(#) 
 * @(#) Returns non-zero on error
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Normalise an image using the rules noted above.
 */
static int
normalise( IMAGE *in, IMAGE *out )
{
	IMAGE *t1 = im_open_local( out, "im_histplot:2", "p" );
	double min, max;

	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_histplot", "%s", _( "uncoded only" ) );
		return( -1 );
	}
	if( im_iscomplex( in ) ) {
		im_error( "im_histplot", "%s", _( "non-complex only" ) );
		return( -1 );
	}

	if( im_isuint( in ) ) {
		/* Trivial case.
		 */
		if( im_copy( in, out ) )
			return( -1 );
	}
	else if( im_isint( in ) ) {
		/* Move min up to 0. incheck(), because we have to min() so we
		 * might as well save the calcs.
		 */
		if( !t1 || 
			im_incheck( in ) ||
			im_min( in, &max ) ||
			im_lintra( 1.0, in, -min, t1 ) )
			return( -1 );
	}
	else {
		/* Float image: scale min--max to 0--any. Output square
		 * graph.
		 */
		int any;

		if( in->Xsize == 1 )
			any = in->Ysize;
		else
			any = in->Xsize;

		/* incheck(), because we have to min()/max() so we
		 * might as well save the calcs.
		 */
		if( !t1 || 
			im_incheck( in ) ||
			im_min( in, &min ) || 
			im_max( in, &max ) ||
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
		unsigned char *q = (unsigned char *) 
			IM_REGION_ADDR( or, le, y );
		unsigned char *p = (unsigned char *) 
			IM_IMAGE_ADDR( in, 0, y );

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
			im_error( "im_histplot", 
				"%s", _( "internal error #8255" ) );
			return( -1 );
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
		unsigned char *q = (unsigned char *) 
			IM_REGION_ADDR( or, x, to );
		unsigned char *p = (unsigned char *) 
			IM_IMAGE_ADDR( in, x, 0 );

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
			im_error( "im_histplot", 
				"%s", _( "internal error #8255" ) );
			return( -1 );
		}
	}

	return( 0 );
}

/* Plot image.
 */
static int
plot( IMAGE *in, IMAGE *out )
{
	IMAGE *t[5];
	double max;
	int tsize;
	int xsize;
	int ysize;

	if( im_incheck( in ) ||
		im_poutcheck( out ) )
		return( -1 );

	/* Find range we will plot.
	 */
	if( im_open_local_array( out, t, 5, "im_histplot", "p" ) ||
		im_max( in, &max ) )
		return( -1 );
	if( max < 0 ) {
		im_error( "im_histplot", "%s", _( "internal error #8254" ) );
		return( -1 );
	}
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

int 
im_histplot( IMAGE *hist, IMAGE *histplot )
{
	IMAGE *norm = im_open_local( histplot, "im_histplot:1", "p" );

	if( !norm )
		return( -1 );
	if( hist->Xsize != 1 && hist->Ysize != 1 ) {
		im_error( "im_histplot", "%s", _( "Xsize or Ysize not 1" ) );
		return( -1 );
	}

	if( normalise( hist, norm ) ||
		plot( norm, histplot ) )
		return( -1 );
	
	return( 0 );
}
