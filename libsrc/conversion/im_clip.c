/* @(#) Clip any down to 0-255. Call im_copy if the image is already uchar. 
 * @(#)
 * @(#) int 
 * @(#) im_clip( in, out )
 * @(#) IMAGE *in, *out;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Author: Nicos Dessipris
 * Written on: 07/03/1991
 * Modified on: 
 * 04/05/1992 JC
 *	- works for char, uchar too
 *	- floating point code removed from integer clip operations
 *	- uses nint() instead of own rounding code
 *	- calculated the number of >255 clips for float/double input
 *	  incorrectly
 *	- rejects complex input correctly now
 * 27/4/93 JC
 *	- adapted to work with partial images
 *	- nint() removed, now just +0.5
 *	- im_warning code removed
 * 30/6/93 JC
 *	- adapted for partial v2
 * 31/8/93 JC
 *	- now detects and prints over/underflows
 * 27/10/93 JC
 *	- unsigned integer clips now faster!
 *	- falls back to im_copy() correctly
 * 5/5/94 JC
 *	- switched to rint()
 * 18/8/94 JC
 *	- now uses evalend callback
 * 9/5/95 JC
 *	- now does complex too
 * 11/7/95 JC
 *	- now uses IM_RINT() macro
 * 10/3/01 JC
 *	- slightly faster and simpler
 *	- generalised to im_clip2fmt(), all other clippers now just call
 *	  this
 * 21/4/04 JC
 *	- now does floor(), not rint() ... you'll need to round yourself
 *	  before calling this if you want round-to-nearest
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
#include <assert.h>
#include <limits.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Global state. Track over/under-flows for all sequences in this.
 */
typedef struct {
	IMAGE *in;		/* Parameters */
	IMAGE *out;
	int ofmt;

	int underflow;		/* Number of underflows */
	int overflow;		/* Number of overflows */
} Clip;

static int
clip_destroy( Clip *clip )
{
	/* Print warnings, if necessary. 
	 */
	if( clip->overflow || clip->underflow ) 
		im_warn( "im_clip", 
			_( "%d underflows and %d overflows detected" ),
			clip->underflow, clip->overflow );

	return( 0 );
}

/* Build a Clip.
 */
static Clip *
clip_new( IMAGE *in, IMAGE *out, int ofmt )
{
	Clip *clip = IM_NEW( out, Clip );

	if( !clip )
		 return( NULL );

	clip->in = in;
	clip->out = out;
	clip->ofmt = ofmt;
	clip->underflow = 0;
	clip->overflow = 0;

	if( im_add_close_callback( out, 
		(im_callback_fn) clip_destroy, clip, NULL ) )
		return( NULL );

	return( clip );
}

/* Our sequence value: the region this sequence is using, and two local stats.
 */
typedef struct {
	REGION *ir;		/* Input region */
	int underflow;		/* Number of underflows */
	int overflow;		/* Number of overflows */
} ClipSequence;

/* Destroy a sequence value.
 */
static int
stop_clip( ClipSequence *seq, IMAGE *in, Clip *clip )
{
	/* Add to global stats.
	 */
	clip->underflow += seq->underflow;
	clip->overflow += seq->overflow;

	/* Junk our region too.
	 */
	if( seq->ir ) {
		im_region_free( seq->ir );
		seq->ir = NULL;
	}

	return( 0 );
}

/* Make a sequence value.
 */
static void *
start_clip( IMAGE *out, IMAGE *in, Clip *clip )
{
	ClipSequence *seq = IM_NEW( out, ClipSequence );
	 
	if( !seq )
		 return( NULL );

	/* Init!
	 */
	seq->ir = NULL;
	seq->overflow = 0;
	seq->underflow = 0;

	if( !(seq->ir = im_region_create( in )) ) 
		return( NULL );

	return( (void *) seq );
}

/* Clip int types to an int type.
 */
#define IM_CLIP_INT_INT( ITYPE, OTYPE, IM_CLIP ) { \
	ITYPE *p = (ITYPE *) IM_REGION_ADDR( ir, le, y );\
	OTYPE *q = (OTYPE *) IM_REGION_ADDR( or, le, y );\
	\
	for( x = 0; x < sz; x++ ) {\
		int t = p[x];\
		\
		IM_CLIP( t, seq );\
		\
		q[x] = t;\
	}\
}

/* Clip float types to an int type.
 */
#define IM_CLIP_FLOAT_INT( ITYPE, OTYPE, IM_CLIP ) { \
	ITYPE *p = (ITYPE *) IM_REGION_ADDR( ir, le, y );\
	OTYPE *q = (OTYPE *) IM_REGION_ADDR( or, le, y );\
	\
	for( x = 0; x < sz; x++ ) {\
		ITYPE v = floor( p[x] );\
		\
		IM_CLIP( v, seq ); \
		\
		q[x] = v;\
	}\
}

/* Clip complex types to an int type. Just take the real part.
 */
#define IM_CLIP_COMPLEX_INT( ITYPE, OTYPE, IM_CLIP ) { \
	ITYPE *p = (ITYPE *) IM_REGION_ADDR( ir, le, y );\
	OTYPE *q = (OTYPE *) IM_REGION_ADDR( or, le, y );\
	\
	for( x = 0; x < sz; x++ ) {\
		ITYPE v = floor( p[0] );\
		p += 2;\
		\
		IM_CLIP( v, seq ); \
		\
		q[x] = v;\
	}\
}

/* Clip non-complex types to a float type.
 */
#define IM_CLIP_REAL_FLOAT( ITYPE, OTYPE ) { \
	ITYPE *p = (ITYPE *) IM_REGION_ADDR( ir, le, y );\
	OTYPE *q = (OTYPE *) IM_REGION_ADDR( or, le, y );\
	\
	for( x = 0; x < sz; x++ )\
		q[x] = p[x];\
}

/* Clip complex types to a float type ... just take real.
 */
#define IM_CLIP_COMPLEX_FLOAT( ITYPE, OTYPE ) { \
	ITYPE *p = (ITYPE *) IM_REGION_ADDR( ir, le, y );\
	OTYPE *q = (OTYPE *) IM_REGION_ADDR( or, le, y );\
	\
	for( x = 0; x < sz; x++ ) {\
		q[x] = p[0];\
		p += 2;\
	}\
}

/* Clip any to a complex type ... set imaginary to zero.
 */
#define IM_CLIP_ANY_COMPLEX( ITYPE, OTYPE ) { \
	ITYPE *p = (ITYPE *) IM_REGION_ADDR( ir, le, y );\
	OTYPE *q = (OTYPE *) IM_REGION_ADDR( or, le, y );\
	\
	for( x = 0; x < sz; x++ ) {\
		q[0] = p[x];\
		q[1] = 0.0;\
		q += 2;\
	}\
}

#define BAND_SWITCH_INNER( ITYPE, INT, FLOAT, COMPLEX ) { \
	switch( clip->out->BandFmt ) { \
	case IM_BANDFMT_UCHAR: \
		INT( ITYPE, unsigned char, IM_CLIP_UCHAR ); \
		break; \
	case IM_BANDFMT_CHAR: \
		INT( ITYPE, signed char, IM_CLIP_CHAR ); \
		break; \
	case IM_BANDFMT_USHORT: \
		INT( ITYPE, unsigned short, IM_CLIP_USHORT ); \
		break; \
	case IM_BANDFMT_SHORT: \
		INT( ITYPE, signed short, IM_CLIP_SHORT ); \
		break; \
	case IM_BANDFMT_UINT: \
		INT( ITYPE, unsigned int, IM_CLIP_NONE ); \
		break; \
	case IM_BANDFMT_INT: \
		INT( ITYPE, signed int, IM_CLIP_NONE ); \
		break; \
	case IM_BANDFMT_FLOAT: \
		FLOAT( ITYPE, float ); \
		break; \
	case IM_BANDFMT_DOUBLE: \
		FLOAT( ITYPE, double ); \
		break; \
	case IM_BANDFMT_COMPLEX: \
		COMPLEX( ITYPE, float ); \
		break; \
	case IM_BANDFMT_DPCOMPLEX: \
		COMPLEX( ITYPE, double ); \
		break; \
	default: \
		assert( 0 ); \
	} \
}

/* Clip a small area.
 */
static int
clip_gen( REGION *or, ClipSequence *seq, IMAGE *in, Clip *clip )
{	
	REGION *ir = seq->ir;
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int sz = IM_REGION_N_ELEMENTS( or );
	int x, y;

	if( im_prepare( ir, r ) )
		return( -1 );

	for( y = to; y < bo; y++ ) {
		switch( clip->in->BandFmt ) { 
		case IM_BANDFMT_UCHAR: 
			BAND_SWITCH_INNER( unsigned char,
				IM_CLIP_INT_INT, IM_CLIP_REAL_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		case IM_BANDFMT_CHAR: 
			BAND_SWITCH_INNER( signed char,
				IM_CLIP_INT_INT, IM_CLIP_REAL_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		case IM_BANDFMT_USHORT: 
			BAND_SWITCH_INNER( unsigned short,
				IM_CLIP_INT_INT, IM_CLIP_REAL_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		case IM_BANDFMT_SHORT: 
			BAND_SWITCH_INNER( signed short,
				IM_CLIP_INT_INT, IM_CLIP_REAL_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		case IM_BANDFMT_UINT: 
			BAND_SWITCH_INNER( unsigned int,
				IM_CLIP_INT_INT, IM_CLIP_REAL_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		case IM_BANDFMT_INT: 
			BAND_SWITCH_INNER( signed int,
				IM_CLIP_INT_INT, IM_CLIP_REAL_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		case IM_BANDFMT_FLOAT: 
			BAND_SWITCH_INNER( float,
				IM_CLIP_FLOAT_INT, IM_CLIP_REAL_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		case IM_BANDFMT_DOUBLE: 
			BAND_SWITCH_INNER( double,
				IM_CLIP_FLOAT_INT, IM_CLIP_REAL_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		case IM_BANDFMT_COMPLEX: 
			BAND_SWITCH_INNER( float,
				IM_CLIP_COMPLEX_INT, IM_CLIP_COMPLEX_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		case IM_BANDFMT_DPCOMPLEX: 
			BAND_SWITCH_INNER( double,
				IM_CLIP_COMPLEX_INT, IM_CLIP_COMPLEX_FLOAT, 
				IM_CLIP_ANY_COMPLEX );
			break; 
		default: 
			assert( 0 ); 
		} 
	}

	return( 0 );
}

/* Clip to any format.
 */
int 
im_clip2fmt( IMAGE *in, IMAGE *out, int ofmt ) 
{
	Clip *clip;

	/* Check args.
	 */
        if( im_piocheck( in, out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_clip2fmt", _( "in must be uncoded" ) );
		return( -1 );
	}
	if( ofmt < 0 || ofmt > IM_BANDFMT_DPCOMPLEX ) {
		im_error( "im_clip2fmt", _( "ofmt out of range" ) );
		return( -1 );
	}

	/* Trivial case: fall back to im_copy().
	 */
	if( in->BandFmt == ofmt )
		return( im_copy( in, out ) );

	if( !(clip = clip_new( in, out, ofmt )) )
		return( -1 );

	/* Prepare output header.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->BandFmt = ofmt;
	out->Bbits = im_bits_of_fmt( ofmt );

	if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) ||
		im_generate( out, start_clip, clip_gen, stop_clip, in, clip ) )
		return( -1 );

	return( 0 );
}

/* Legacy clippers.
 */
int
im_clip( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_UCHAR ) );
}

int
im_clip2c( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_CHAR ) );
}

int
im_clip2us( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_USHORT ) );
}

int
im_clip2s( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_SHORT ) );
}

int
im_clip2ui( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_UINT ) );
}

int
im_clip2i( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_INT ) );
}

int
im_clip2f( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_FLOAT ) );
}

int
im_clip2d( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_DOUBLE ) );
}

int
im_clip2cm( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_COMPLEX ) );
}

int
im_clip2dcm( IMAGE *in, IMAGE *out )
{
	return( im_clip2fmt( in, out, IM_BANDFMT_DPCOMPLEX ) );
}
