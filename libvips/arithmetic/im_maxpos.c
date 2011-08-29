/* im_maxpos.c
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/05/1990
 * Modified on : 18/03/1991, N. Dessipris
 * 	23/11/92:  J.Cupitt - correct result for more than 1 band now.
 * 23/7/93 JC
 *	- im_incheck() call added
 * 20/6/95 JC
 *	- now returns double for value, like im_max()
 * 4/9/09
 * 	- gtkdoc comment
 * 8/9/09
 * 	- rewrite based on im_max() to get partial
 * 	- move im_max() in here as a convenience function
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

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Get the value of pixel (0, 0). Use this to init the min/max value for
 * im_max()/im_stats()/etc. 
 */
int
im__value( IMAGE *im, double *value )
{
	IMAGE *t;

	if( !(t = im_open_local( im, "im__value", "p" )) ||
		im_extract_areabands( im, t, 0, 0, 1, 1, 0, 1 ) ||
		im_avg( t, value ) )
		return( -1 );

	return( 0 );
}

/* A position and maximum.
 */
typedef struct _Maxpos {
	int xpos;
	int ypos;
	double max;
} Maxpos;

/* New sequence value.
 */
static void *
maxpos_start( IMAGE *in, void *a, void *b )
{
	Maxpos *global_maxpos = (Maxpos *) b;
	Maxpos *maxpos;

	if( !(maxpos = IM_NEW( NULL, Maxpos )) ) 
		return( NULL );
	*maxpos = *global_maxpos;

	return( (void *) maxpos );
}

/* Merge the sequence value back into the per-call state.
 */
static int
maxpos_stop( void *seq, void *a, void *b )
{
	Maxpos *global_maxpos = (Maxpos *) b;
	Maxpos *maxpos = (Maxpos *) seq;

	/* Merge.
	 */
	if( maxpos->max > global_maxpos->max ) 
		*global_maxpos = *maxpos;

	im_free( seq );

	return( 0 );
}

#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE m; \
	\
	m = max; \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE v = p[x]; \
		\
		if( v > m ) { \
			m = v; \
			xpos = r->left + x / reg->im->Bands; \
			ypos = r->top + y; \
		} \
	} \
	\
	max = m; \
} 

#define CLOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	\
	for( x = 0; x < sz; x++ ) { \
		double mod, re, im; \
		\
		re = p[0]; \
		im = p[1]; \
		p += 2; \
		mod = re * re + im * im; \
		\
		if( mod > max ) { \
			max = mod; \
			xpos = r->left + x / reg->im->Bands; \
			ypos = r->top + y; \
		} \
	} \
} 

/* Loop over region, adding to seq.
 */
static int
maxpos_scan( REGION *reg, void *seq, void *a, void *b, gboolean *stop )
{
	const Rect *r = &reg->valid;
	const int sz = IM_REGION_N_ELEMENTS( reg );
	Maxpos *maxpos = (Maxpos *) seq;

	int x, y;
	double max;
	int xpos, ypos;

	xpos = maxpos->xpos;
	ypos = maxpos->ypos;
	max = maxpos->max;

	for( y = 0; y < r->height; y++ ) { 
		PEL *in = (PEL *) IM_REGION_ADDR( reg, r->left, r->top + y ); 

		switch( reg->im->BandFmt ) {
		case IM_BANDFMT_UCHAR:		LOOP( unsigned char ); break; 
		case IM_BANDFMT_CHAR:		LOOP( signed char ); break; 
		case IM_BANDFMT_USHORT:		LOOP( unsigned short ); break; 
		case IM_BANDFMT_SHORT:		LOOP( signed short ); break; 
		case IM_BANDFMT_UINT:		LOOP( unsigned int ); break;
		case IM_BANDFMT_INT:		LOOP( signed int ); break; 
		case IM_BANDFMT_FLOAT:		LOOP( float ); break; 
		case IM_BANDFMT_DOUBLE:		LOOP( double ); break; 
		case IM_BANDFMT_COMPLEX:	CLOOP( float ); break; 
		case IM_BANDFMT_DPCOMPLEX:	CLOOP( double ); break; 

		default:  
			g_assert( 0 );
		}
	} 

	maxpos->xpos = xpos;
	maxpos->ypos = ypos;
	maxpos->max = max;

	return( 0 );
}

/**
 * im_maxpos:
 * @in: image to search
 * @xpos: returned x position of maximum
 * @ypos: returned y position of maximum
 * @out: returned pixel value at that position
 *
 * Function to find the maximum of an image. Works for any 
 * image type. Returns a double and the location of max. For complex images,
 * finds the pixel with the highest modulus.
 *
 * See also: im_minpos(), im_min(), im_stats(), im_maxpos_avg(),
 * im_maxpos_subpel(), im_maxpos_vec().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_maxpos( IMAGE *in, int *xpos, int *ypos, double *out )
{
	Maxpos *global_maxpos;

	if( im_pincheck( in ) ||
		im_check_uncoded( "im_maxpos", in ) )
		return( -1 );

	if( !(global_maxpos = IM_NEW( in, Maxpos )) ) 
		return( -1 );
	if( im__value( in, &global_maxpos->max ) )
		return( -1 );
	global_maxpos->xpos = 0;
	global_maxpos->ypos = 0;

	/* We use square mod for scanning, for speed.
	 */
	if( vips_bandfmt_iscomplex( in->BandFmt ) )
		global_maxpos->max *= global_maxpos->max;

	if( vips_sink( in, maxpos_start, maxpos_scan, maxpos_stop, 
		in, global_maxpos ) ) 
		return( -1 );

	/* Back to modulus.
	 */
	if( vips_bandfmt_iscomplex( in->BandFmt ) )
		global_maxpos->max = sqrt( global_maxpos->max );

	if( xpos )
		*xpos = global_maxpos->xpos;
	if( ypos )
		*ypos = global_maxpos->ypos;
	if( out )
		*out = global_maxpos->max;

	return( 0 );
}

/** 
 * im_max:
 * @in: input #IMAGE
 * @out: output double
 *
 * Finds the the maximum value of image #in and returns it at the
 * location pointed by out.  If input is complex, the max modulus
 * is returned. im_max() finds the maximum of all bands: if you
 * want to find the maximum of each band separately, use im_stats().
 *
 * See also: im_maxpos(), im_min(), im_stats().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_max( IMAGE *in, double *out )
{
	return( im_maxpos( in, NULL, NULL, out ) );
}
