/* im_minpos.c
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/05/1990
 * Modified on : 18/03/1991, N. Dessipris
 * 23/11/92 JC
 *	- correct result for more than 1 band now.
 * 23/7/93 JC
 *	- im_incheck() added
 * 20/6/95 JC
 *	- now returns double for value, like im_max()
 * 4/9/09
 * 	- gtkdoc comment
 * 8/9/09
 * 	- rewrite, from im_maxpos()
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

/* A position and minimum.
 */
typedef struct _Minpos {
	int xpos;
	int ypos;
	double min;
} Minpos;

/* New sequence value.
 */
static void *
minpos_start( IMAGE *in, void *a, void *b )
{
	Minpos *global_minpos = (Minpos *) b;
	Minpos *minpos;

	if( !(minpos = IM_NEW( NULL, Minpos )) ) 
		return( NULL );
	*minpos = *global_minpos;

	return( (void *) minpos );
}

/* Merge the sequence value back into the per-call state.
 */
static int
minpos_stop( void *seq, void *a, void *b )
{
	Minpos *global_minpos = (Minpos *) b;
	Minpos *minpos = (Minpos *) seq;

	/* Merge.
	 */
	if( minpos->min > global_minpos->min ) 
		*global_minpos = *minpos;

	im_free( seq );

	return( 0 );
}

#define LOOP( TYPE ) { \
	TYPE *p = (TYPE *) in; \
	TYPE m; \
	\
	m = min; \
	\
	for( x = 0; x < sz; x++ ) { \
		TYPE v = p[x]; \
		\
		if( v < m ) { \
			m = v; \
			xpos = r->left + x / reg->im->Bands; \
			ypos = r->top + y; \
		} \
	} \
	\
	min = m; \
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
		if( mod < min ) { \
			min = mod; \
			xpos = r->left + x / reg->im->Bands; \
			ypos = r->top + y; \
		} \
	} \
} 

/* Loop over region, adding to seq.
 */
static int
minpos_scan( REGION *reg, void *seq, void *a, void *b )
{
	const Rect *r = &reg->valid;
	const int sz = IM_REGION_N_ELEMENTS( reg );
	Minpos *minpos = (Minpos *) seq;

	int x, y;
	double min;
	int xpos, ypos;

	xpos = minpos->xpos;
	ypos = minpos->ypos;
	min = minpos->min;

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

	minpos->xpos = xpos;
	minpos->ypos = ypos;
	minpos->min = min;

	return( 0 );
}

/**
 * im_minpos:
 * @in: image to search
 * @xpos: returned x position of minimum
 * @ypos: returned y position of minimum
 * @out: returned pixel value at that position
 *
 * Function to find the minimum of an image. Works for any 
 * image type. Returns a double and the location of min. For complex images,
 * finds the pixel with the smallest modulus.
 *
 * See also: im_maxpos(), im_min(), im_stats(), im_maxpos_avg().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_minpos( IMAGE *in, int *xpos, int *ypos, double *out )
{
	Minpos *global_minpos;

	if( im_pincheck( in ) ||
		im_check_uncoded( "im_minpos", in ) )
		return( -1 );

	if( !(global_minpos = IM_NEW( in, Minpos )) ) 
		return( -1 );
	if( im__value( in, &global_minpos->min ) )
		return( -1 );
	global_minpos->xpos = 0;
	global_minpos->ypos = 0;

	/* We use square mod for scanning, for speed.
	 */
	if( im_iscomplex( in ) )
		global_minpos->min *= global_minpos->min;

	if( im_iterate( in, minpos_start, minpos_scan, minpos_stop, 
		in, global_minpos ) ) 
		return( -1 );

	/* Back to modulus.
	 */
	if( im_iscomplex( in ) )
		global_minpos->min = sqrt( global_minpos->min );

	if( xpos )
		*xpos = global_minpos->xpos;
	if( ypos )
		*ypos = global_minpos->ypos;
	if( out )
		*out = global_minpos->min;

	return( 0 );
}

/** 
 * im_min:
 * @in: input #IMAGE
 * @out: output double
 *
 * Finds the the minimum value of image #in and returns it at the
 * location pointed by @out.  If input is complex, the min modulus
 * is returned. im_min() finds the minimum of all bands: if you
 * want to find the minimum of each band separately, use im_stats().
 *
 * See also: im_minpos(), im_min(), im_stats().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_min( IMAGE *in, double *out )
{
	return( im_minpos( in, NULL, NULL, out ) );
}
