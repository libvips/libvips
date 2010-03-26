/* @(#) Various functions relating to tone curve adjustment.
 * @(#) 
 * @(#) im_tone_build: generate tone curve for adjustment of LabQ image. LUT we
 * @(#) make is always 1024 elements, each element is a LabS L value.
 * @(#) 
 * @(#) Base parameters:
 * @(#) 
 * @(#) 	Lb	- black point
 * @(#) 	Lw	- white point	(both [0,100])
 * @(#) 
 * @(#) 	Ps	- shadow point
 * @(#) 	Pm	- mid-tone point
 * @(#) 	Ph	- highlight point
 * @(#) 
 * @(#) All 0-1, meaning max of shadow section of curve should be positioned
 * @(#) at Lb+Ps(Lw-Lb), etc. Suggest Lb, Lw should be set by histogram
 * @(#) analysis to 0.1% and 99.9%; Ps, Pm, Ph should be 0.2, 0.5, 0.8.
 * @(#) 
 * @(#) Main parameters:
 * @(#) 
 * @(#) 	S	- shadow adjustment factor (+/- 30)
 * @(#) 	M	- mid-tone adjustment factor (+/- 30)
 * @(#) 	H	- highlight adjustment factor (+/- 30)
 * @(#) 
 * @(#) Usage:
 * @(#) 
 * @(#) int 
 * @(#) im_tone_build( 
 * @(#) 	IMAGE *lut, 
 * @(#) 	double Lb, double Lw,
 * @(#) 	double Ps, double Pm, double Ph,
 * @(#) 	double S, double M, double H )
 * @(#)
 * @(#)  Returns 0 on success and -1 on error
 * @(#)
 * @(#) im_ismonotonic: test any LUT for monotonicity --- set out to non-zero
 * @(#) if lut is monotonic.
 * @(#)
 * @(#) Usage:
 * @(#) 
 * @(#) int 
 * @(#) im_ismonotonic( IMAGE *lut, int *out )
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 * @(#) im_tone_map: map just the L channel of a LabQ or LabS image through 
 * @(#) a LUT.
 * @(#)
 * @(#) Usage:
 * @(#) 
 * @(#) int 
 * @(#) im_tone_map( IMAGE *in, IMAGE *out, IMAGE *lut )
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 * @(#) im_tone_analyse: find the histogram of a LabS or LabQ image and use
 * @(#) that to set the Ln and Lw parameters of im_tone_build()
 * @(#)
 * @(#) Usage:
 * @(#) 
 * @(#) int 
 * @(#) im_tone_analyse( 
 * @(#) 	IMAGE *in, 
 * @(#) 	IMAGE *lut, 
 * @(#) 	double Ps, double Pm, double Ph,
 * @(#) 	double S, double M, double H )
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Author: John Cupitt
 * Written on: 18/7/1995
 * 17/9/96 JC
 *	- restrictions on Ps, Pm, Ph relaxed
 *	- restrictions on S, M, H relaxed
 * 25/7/01 JC
 *	- patched for im_extract_band() change
 * 11/7/04
 *	- generalised to im_tone_build_range() ... so you can use it for any
 *	  image, not just LabS
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

/* Parameters for tone curve formation.
 */
typedef struct {
	/* Parameters.
	 */
	double Lb, Lw;
	double Ps, Pm, Ph; 
	double S, M, H;

	/* Derived values.
	 */
	double Ls, Lm, Lh;
} ToneShape;

/* Calculate shadow curve.
 */
static double
shad( ToneShape *ts, double x )
{
	double x1 = (x - ts->Lb) / (ts->Ls - ts->Lb);
	double x2 = (x - ts->Ls) / (ts->Lm - ts->Ls);
	double out;

	if( x < ts->Lb )
		out = 0;
	else if( x < ts->Ls )
		out = 3.0 * x1 * x1 - 2.0 * x1 * x1 * x1;
	else if( x < ts->Lm )
		out = 1.0 - 3.0 * x2 * x2 + 2.0 * x2 * x2 * x2;
	else 
		out = 0;

	return( out );
}

/* Calculate mid-tone curve.
 */
static double
mid( ToneShape *ts, double x )
{
	double x1 = (x - ts->Ls) / (ts->Lm - ts->Ls);
	double x2 = (x - ts->Lm) / (ts->Lh - ts->Lm);
	double out;

	if( x < ts->Ls )
		out = 0;
	else if( x < ts->Lm )
		out = 3.0 * x1 * x1 - 2.0 * x1 * x1 * x1;
	else if( x < ts->Lh )
		out = 1.0 - 3.0 * x2 * x2 + 2.0 * x2 * x2 * x2;
	else 
		out = 0;

	return( out );
}

/* Calculate highlight curve.
 */
static double
high( ToneShape *ts, double x )
{
	double x1 = (x - ts->Lm) / (ts->Lh - ts->Lm);
	double x2 = (x - ts->Lh) / (ts->Lw - ts->Lh);
	double out;

	if( x < ts->Lm )
		out = 0;
	else if( x < ts->Lh )
		out = 3.0 * x1 * x1 - 2.0 * x1 * x1 * x1;
	else if( x < ts->Lw )
		out = 1.0 - 3.0 * x2 * x2 + 2.0 * x2 * x2 * x2;
	else 
		out = 0;

	return( out );
}

/* Generate a point on the tone curve. Everything is 0-100.
 */
static double
tone_curve( ToneShape *ts, double x )
{
	double out;

	out = x + 
		ts->S * shad( ts, x ) + ts->M * mid( ts, x ) + 
		ts->H * high( ts, x );
	
	return( out );
}

int 
im_tone_build_range( IMAGE *out, 
	int in_max, int out_max,
	double Lb, double Lw,
	double Ps, double Pm, double Ph, 
	double S, double M, double H )
{
	ToneShape *ts;
	unsigned short lut[65536];
	int i;

	/* Check args.
	 */
	if( !(ts = IM_NEW( out, ToneShape )) ||
		im_outcheck( out ) )
		return( -1 );
	if( in_max < 0 || in_max > 65535 ||
		out_max < 0 || out_max > 65535 ) {
		im_error( "im_tone_build", 
			"%s", _( "bad in_max, out_max parameters" ) );
		return( -1 );
	}
	if( Lb < 0 || Lb > 100 || Lw < 0 || Lw > 100 || Lb > Lw ) {
		im_error( "im_tone_build", 
			"%s", _( "bad Lb, Lw parameters" ) );
		return( -1 );
	}
	if( Ps < 0.0 || Ps > 1.0 ) {
		im_error( "im_tone_build", 
			"%s", _( "Ps not in range [0.0,1.0]" ) );
		return( -1 );
	}
	if( Pm < 0.0 || Pm > 1.0 ) {
		im_error( "im_tone_build", 
			"%s", _( "Pm not in range [0.0,1.0]" ) );
		return( -1 );
	}
	if( Ph < 0.0 || Ph > 1.0 ) {
		im_error( "im_tone_build", 
			"%s", _( "Ph not in range [0.0,1.0]" ) );
		return( -1 );
	}
	if( S < -30 || S > 30 ) {
		im_error( "im_tone_build", 
			"%s", _( "S not in range [-30,+30]" ) );
		return( -1 );
	}
	if( M < -30 || M > 30 ) {
		im_error( "im_tone_build", 
			"%s", _( "M not in range [-30,+30]" ) );
		return( -1 );
	}
	if( H < -30 || H > 30 ) {
		im_error( "im_tone_build", 
			"%s", _( "H not in range [-30,+30]" ) );
		return( -1 );
	}

	/* Note params.
	 */
	ts->Lb = Lb; 
	ts->Lw = Lw;
	ts->Ps = Ps; 
	ts->Pm = Pm; 
	ts->Ph = Ph;
	ts->S = S; 
	ts->M = M; 
	ts->H = H;

	/* Note derived params.
	 */
	ts->Ls = Lb + Ps * (Lw - Lb);
	ts->Lm = Lb + Pm * (Lw - Lb);
	ts->Lh = Lb + Ph * (Lw - Lb);

	/* Generate curve.
	 */
	for( i = 0; i <= in_max; i++ ) {
		int v = (out_max / 100.0) * 
			tone_curve( ts, 100.0 * i / in_max );

		if( v < 0 )
			v = 0;
		else if( v > out_max )
			v = out_max;
		
		lut[i] = v;
	}

	/* Make the output image.
	 */
	im_initdesc( out,
		in_max + 1, 1, 1, IM_BBITS_SHORT, IM_BANDFMT_USHORT, 
		IM_CODING_NONE, IM_TYPE_HISTOGRAM, 1.0, 1.0, 0, 0 );
	if( im_setupout( out ) )
		return( -1 );

	if( im_writeline( 0, out, (PEL *) lut ) )
		return( -1 );

	return( 0 );
}

int 
im_tone_build( IMAGE *out, 
	double Lb, double Lw,
	double Ps, double Pm, double Ph, 
	double S, double M, double H )
{
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_tone_build", "p" )) ||
		im_tone_build_range( t1, 1023, 32767,
			Lb, Lw, Ps, Pm, Ph, S, M, H ) ||
		im_clip2fmt( t1, out, IM_BANDFMT_SHORT ) )
		return( -1 );

	return( 0 );
}

/* Test a lut or histogram for monotonicity.
 */
int
im_ismonotonic( IMAGE *lut, int *out )
{
	IMAGE *t[2];
	INTMASK *mask;
	double m;

	if( im_check_hist( "im_ismonotonic", lut ) ||
		im_open_local_array( lut, t, 2, "im_ismonotonic", "p" ) )
		return( -1 );

	if( !(mask = im_local_imask( lut, 
		im_create_imaskv( "im_ismonotonic", 2, 1, 1, -1 ) )) )
		return( -1 );
	mask->offset = 128;
	if( lut->Xsize == 1 ) {
		if( !(mask = im_local_imask( lut, 
			im_rotate_imask90( mask, mask->filename ) )) )
			return( -1 );
	}

	/* We want >=128 everywhere, ie. no -ve transitions.
	 */
	if( im_conv( lut, t[0], mask ) ||
		im_moreeqconst( t[0], t[1], 128 ) ||
		im_min( t[1], &m ) )
		return( -1 );

	*out = m;

	return( 0 );
}

/* Map the L channel of a LabQ or LabS channel of an image through a LUT.
 */
int
im_tone_map( IMAGE *in, IMAGE *out, IMAGE *lut )
{
	IMAGE *t1 = im_open_local( out, "im_tone_map:1", "p" );
	IMAGE *t2 = im_open_local( out, "im_tone_map:2", "p" );
	IMAGE *t3 = im_open_local( out, "im_tone_map:3", "p" );
	IMAGE *t4 = im_open_local( out, "im_tone_map:4", "p" );
	IMAGE *t5 = im_open_local( out, "im_tone_map:5", "p" );
	IMAGE *t6 = im_open_local( out, "im_tone_map:6", "p" );
	IMAGE *t7 = im_open_local( out, "im_tone_map:7", "p" );
	IMAGE *t8 = im_open_local( out, "im_tone_map:8", "p" );
	IMAGE *imarray[3];

	if( !t1 || !t2 || !t3 || !t4 || !t5 || !t6 || !t7 ) 
		return( -1 );

	/* Need a 1024-point IM_BANDFMT_SHORT lut.
	 */
	if( lut->Xsize != 1 && lut->Ysize != 1 ) {
		im_error( "im_tone_map", 
			"%s", _( "not 1 by n or n by 1 image" ) );
		return( -1 );
	}
	if( lut->Xsize*lut->Ysize != 1024 || 
		lut->BandFmt != IM_BANDFMT_SHORT ) {
		im_error( "im_tone_map", 
			"%s", _( "not 1024-point IM_BANDFMT_SHORT lut" ) );
		return( -1 );
	}

	/* If in is IM_CODING_LABQ, unpack.
	 */
	if( in->Coding == IM_CODING_LABQ ) {
		if( im_LabQ2LabS( in, t1 ) )
			return( -1 );
	}
	else
		t1 = in;

	/* Should now be 3-band short.
	 */
	if( t1->Coding != IM_CODING_NONE || t1->BandFmt != IM_BANDFMT_SHORT || 
		t1->Bands != 3 ) {
		im_error( "im_tone_map", 
			"%s", _( "input not LabS or LabQ" ) );
		return( -1 );
	}

	/* Split into bands.
	 */
	if( im_extract_band( t1, t2, 0 ) || im_extract_band( t1, t3, 1 ) ||
		im_extract_band( t1, t4, 2 ) )
		return( -1 );

	/* Scale L down to 10 bits so we can use it to index LUT. And amke
	 * sure we have an unsigned type we can use for indexing.
	 */
	if( im_shiftright( t2, t8, 5 ) ||
		im_clip2fmt( t8, t5, IM_BANDFMT_USHORT ) )
		return( -1 );

	/* Replace L.
	 */
	if( im_maplut( t5, t6, lut ) )
		return( -1 );

	/* Recombine bands. If input was LabQ, repack.
	 */
	imarray[0] = t6; imarray[1] = t3; imarray[2] = t4;
	if( in->Coding == IM_CODING_LABQ ) {
		if( im_gbandjoin( imarray, t7, 3 ) ||
			im_LabS2LabQ( t7, out ) )
			return( -1 );
	}
	else {
		if( im_gbandjoin( imarray, out, 3 ) )
			return( -1 );
	}
	
	return( 0 );
}

/* Find histogram of in, and use that to set Lb, Lw levels.
 */
int 
im_tone_analyse( 
	IMAGE *in, 
	IMAGE *lut, 
	double Ps, double Pm, double Ph,
	double S, double M, double H )
{
	gint64 sum = in->Xsize * in->Ysize;
	int *p;
	int i, j;
	double Lb, Lw;

	IMAGE *t1 = im_open_local( lut, "im_tone_analyse:1", "p" );
	IMAGE *t2 = im_open_local( lut, "im_tone_analyse:2", "p" );
	IMAGE *t3 = im_open_local( lut, "im_tone_analyse:3", "p" );
	IMAGE *t4 = im_open_local( lut, "im_tone_analyse:4", "p" );
	IMAGE *t6 = im_open_local( lut, "im_tone_analyse:6", "p" );

	if( !t1 || !t2 || !t3 || !t4 || !t6 )
		return( -1 );

	/* If in is IM_CODING_LABQ, unpack.
	 */
	if( in->Coding == IM_CODING_LABQ ) {
		if( im_LabQ2LabS( in, t1 ) )
			return( -1 );
	}
	else
		t1 = in;

	/* Should now be 3-band short.
	 */
	if( t1->Coding != IM_CODING_NONE || t1->BandFmt != IM_BANDFMT_SHORT || 
		t1->Bands != 3 ) {
		im_error( "im_tone_analyse", 
			"%s", _( "input not LabS or LabQ" ) );
		return( -1 );
	}

	/* Extract and scale L.
	 */
	if( im_extract_band( t1, t2, 0 ) ||
		im_shiftright( t2, t3, 5 ) ||
		im_clip2fmt( t3, t4, IM_BANDFMT_USHORT ) )
		return( -1 );
	
	/* Take histogram, and make it a cumulative hist.
	 */
	if( im_histgr( t4, t6, -1 ) )
		return( -1 );

	/* Search for 0.1% mark.
	 */
	if( im_incheck( t6 ) )
		return( -1 );
	p = (int *) t6->data; 
	for( j = 0, i = 0; i < t6->Xsize; i++ ) {
		j += p[i];
		if( j > sum * (0.1 / 100.0) )
			break;
	}
	Lb = i / 10.24;

	/* Search for 99.9% mark.
	 */
	p = (int *) t6->data; 
	for( j = 0, i = t6->Xsize - 1; i > 0; i-- ) {
		j += p[i];
		if( j > sum * (0.1 / 100.0) )
			break;
	}
	Lw = i / 10.24;

	im_diag( "im_tone_analyse", "set Lb = %g, Lw = %g", Lb, Lw );

	return( im_tone_build( lut, Lb, Lw, Ps, Pm, Ph, S, M, H ) );
}
