/* Various functions relating to tone curve adjustment.
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
 * 26/3/10
 * 	- cleanups
 * 	- gtkdoc
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
#include <math.h>

#include <vips/vips.h>

/**
 * im_tone_map:
 * @in: input image
 * @out: output image
 * @lut: look-up table
 *
 * Map the first channel of @in through @lut. If @in is IM_CODING_LABQ, unpack
 * to LABS, map L and then repack. 
 *
 * @in should be a LABS or LABQ image for this to work
 * sensibly.
 *
 * See also: im_maplut().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_tone_map( IMAGE *in, IMAGE *out, IMAGE *lut )
{
	IMAGE *t[8];

	if( im_check_hist( "im_tone_map", lut ) ||
		im_open_local_array( out, t, 8, "im_tone_map", "p" ) )
		return( -1 );

	/* If in is IM_CODING_LABQ, unpack.
	 */
	if( in->Coding == IM_CODING_LABQ ) {
		if( im_LabQ2LabS( in, t[0] ) )
			return( -1 );
	}
	else
		t[0] = in;

	/* Split into bands.
	 */
	if( im_extract_band( t[0], t[1], 0 ) )
		return( -1 );
	if( t[0]->Bands > 1 ) {
		if( im_extract_bands( t[0], t[2], 1, t[0]->Bands - 1 ) )
			return( -1 );
	}

	/* Map L.
	 */
	if( im_maplut( t[1], t[3], lut ) )
		return( -1 );

	/* Recombine bands. 
	 */
	if( t[0]->Bands > 1 ) {
		if( im_bandjoin( t[3], t[2], t[4] ) )
			return( -1 );
	}
	else
		t[4] = t[3];

	/* If input was LabQ, repack.
	 */
	if( in->Coding == IM_CODING_LABQ ) {
		if( im_LabS2LabQ( t[4], t[5] ) )
			return( -1 );
	}
	else 
		t[5] = t[4];
	
	return( im_copy( t[4], out ) );
}

/**
 * im_tone_analyse:
 * @in: input image 
 * @out: output image 
 * @Ps: shadow point (eg. 0.2)
 * @Pm: mid-tone point (eg. 0.5)
 * @Ph: highlight point (eg. 0.8)
 * @S: shadow adjustment (+/- 30)
 * @M: mid-tone adjustment (+/- 30)
 * @H: highlight adjustment (+/- 30)
 *
 * As im_tone_build(), but analyse the histogram of @in and use it to
 * pick the 0.1% and 99.9% points for @Lb and @Lw.
 *
 * See also: im_tone_build().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_tone_analyse( 
	IMAGE *in, 
	IMAGE *out, 
	double Ps, double Pm, double Ph,
	double S, double M, double H )
{
	IMAGE *t[4];
	int low, high;
	double Lb, Lw;

	if( im_open_local_array( out, t, 4, "im_tone_map", "p" ) )
		return( -1 );

	/* If in is IM_CODING_LABQ, unpack.
	 */
	if( in->Coding == IM_CODING_LABQ ) {
		if( im_LabQ2LabS( in, t[0] ) )
			return( -1 );
	}
	else
		t[0] = in;

	/* Should now be 3-band short.
	 */
	if( im_check_uncoded( "im_tone_analyse", t[0] ) ||
		im_check_bands( "im_tone_analyse", t[0], 3 ) ||
		im_check_format( "im_tone_analyse", t[0], IM_BANDFMT_SHORT ) )
		return( -1 );

	if( im_extract_band( t[0], t[1], 0 ) ||
		im_clip2fmt( t[1], t[2], IM_BANDFMT_USHORT ) )
		return( -1 );

	if( im_mpercent( t[2], 0.1 / 100.0, &high ) ||
		im_mpercent( t[2], 99.9 / 100.0, &low ) )
		return( -1 );

	Lb = 100 * low / 32768;
	Lw = 100 * high / 32768;

	im_diag( "im_tone_analyse", "set Lb = %g, Lw = %g", Lb, Lw );

	return( im_tone_build( out, Lb, Lw, Ps, Pm, Ph, S, M, H ) );
}
