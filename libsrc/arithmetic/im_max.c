/* @(#) Function to find the maximim of an image. Works for any 
 * @(#) image type. Returns a double.
 * @(#)
 * @(#) int im_max(in, max)
 * @(#) IMAGE *in;
 * @(#) double *max;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 02/05/1990
 * Modified on : 18/03/1991, N. Dessipris
 * 7/7/93 JC
 *	- complex case fixed
 *	- im_incheck() call added
 * 20/6/95 JC
 *	- now returns double
 *	- modernised a little
 *	- now returns max square amplitude rather than amplitude for complex
 * 9/5/02 JC
 *	- partialed
 * 3/4/02 JC
 *	- random wrong result for >1 thread :-( (thanks Joe)
 * 15/10/07
 * 	- oh, heh, seq->inf was not being set correctly, not that it mattered
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
#include <assert.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Per-call state.
 */
typedef struct _MaxInfo {
	/* Parameters.
	 */
	IMAGE *in;
	double *out;

	/* Global max so far.
	 */
	double value;
	int valid;		/* zero means value is unset */
} MaxInfo;

/* Per thread state.
 */
typedef struct _Seq {
	MaxInfo *inf;

	double value;
	int valid;		/* zero means value is unset */
} Seq;

/* New sequence value.
 */
static void *
max_start( IMAGE *in, void *a, void *b )
{
	MaxInfo *inf = (MaxInfo *) a;
	Seq *seq = IM_NEW( NULL, Seq );

	seq->inf = inf;
	seq->valid = 0;

	return( (void *) seq );
}

/* Merge the sequence value back into the per-call state.
 */
static int
max_stop( void *vseq, void *a, void *b )
{
	Seq *seq = (Seq *) vseq;
	MaxInfo *inf = (MaxInfo *) a;

	if( seq->valid ) {
		if( !inf->valid )
			/* Just copy.
			 */
			inf->value = seq->value;
		else 
			/* Merge.
			 */
			inf->value = IM_MAX( inf->value, seq->value );

		inf->valid = 1;
	}

	im_free( seq );

	return( 0 );
}

/* Loop over region, adding to seq.
 */
static int
max_scan( REGION *reg, void *vseq, void *a, void *b )
{
	Seq *seq = (Seq *) vseq;
	Rect *r = &reg->valid;
	IMAGE *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int nel = IM_REGION_N_ELEMENTS( reg );

	int x, y;

	double m;

#define loop(TYPE) { \
	m = *((TYPE *) IM_REGION_ADDR( reg, le, to )); \
	\
	for( y = to; y < bo; y++ ) { \
		TYPE *p = (TYPE *) IM_REGION_ADDR( reg, le, y ); \
		\
		for( x = 0; x < nel; x++ ) { \
			double v = p[x]; \
			\
			if( v > m ) \
				m = v; \
		} \
	} \
} 

#define complex_loop(TYPE) { \
	TYPE *p = (TYPE *) IM_REGION_ADDR( reg, le, to ); \
	double real = p[0]; \
	double imag = p[1]; \
	\
	m = real * real + imag * imag; \
	\
	for( y = to; y < bo; y++ ) { \
		TYPE *p = (TYPE *) IM_REGION_ADDR( reg, le, y ); \
		\
		for( x = 0; x < nel * 2; x += 2 ) { \
			double mod; \
			\
			real = p[x]; \
			imag = p[x + 1]; \
			mod = real * real + imag * imag; \
			\
			if( mod > m ) \
				m = mod; \
		} \
	} \
} 

	switch( im->BandFmt ) {
	case IM_BANDFMT_UCHAR:		loop( unsigned char ); break; 
	case IM_BANDFMT_CHAR:		loop( signed char ); break; 
	case IM_BANDFMT_USHORT:		loop( unsigned short ); break; 
	case IM_BANDFMT_SHORT:		loop( signed short ); break; 
	case IM_BANDFMT_UINT:		loop( unsigned int ); break;
	case IM_BANDFMT_INT:		loop( signed int ); break; 
	case IM_BANDFMT_FLOAT:		loop( float ); break; 
	case IM_BANDFMT_DOUBLE:		loop( double ); break; 
	case IM_BANDFMT_COMPLEX:	complex_loop( float ); break; 
	case IM_BANDFMT_DPCOMPLEX:	complex_loop( double ); break; 

	default:  
		assert( 0 );
	}

	if( seq->valid ) {
		seq->value = IM_MAX( seq->value, m ); 
	}
	else {
		seq->value = m;
		seq->valid = 1;
	}

#ifdef DEBUG
        printf( "im_max: left = %d, top = %d, width = %d, height = %d\n",
		r->left, r->top, r->width, r->height );
	printf( "   (max = %g)\n", seq->value );
#endif /*DEBUG*/

	return( 0 );
}

int
im_max( IMAGE *in, double *out )
{	
	MaxInfo inf;

	inf.in = in;
	inf.out = out;
	inf.valid = 0;

	if( im_pincheck( in ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_max", _( "not uncoded" ) );
		return( -1 );
	}

	if( im_iterate( in, max_start, max_scan, max_stop, &inf, NULL ) ) 
		return( -1 );

	*out = inf.value;

	return( 0 );
}
