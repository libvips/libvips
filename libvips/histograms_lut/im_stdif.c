/* @(#) Functions which calculates statistical differenciating according to
 * @(#) the formula given in page 45 of the book "An intro to digital image
 * @(#) processing" by Wayne Niblack
 * @(#) 
 * @(#) At point (i,j) the output is given by the eqn:
 * @(#)
 * @(#) 	vout(i,j) = a*m0 +(1-a)*meanv + 
 * @(#) 		(vin(i,j) - meanv) * beta*sigma0/(sigma0+beta*stdv)
 * @(#)
 * @(#) Values a, m0, beta and sigma0 are entered 
 * @(#) meanv and stdv are the values calculated over a moving window
 * @(#) xwin and ywin are the sizes of the used window
 * @(#) The resultant coefficients are written as floats
 * @(#) in out which has a size of in
 * @(#)
 * @(#) int im_stdif(in, im, alpha, mean0, beta, sigma0, xwin, ywin)
 * @(#) IMAGE *in, *out;
 * @(#) int xwin, ywin;
 * @(#) double alpha, mean0, beta, sigma0;
 * @(#)
 * @(#) Returns 0 on sucess  and -1 on error.
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 
 * 6/8/93 JC
 *	- now works for odd window sizes
 *	- ANSIfication
 * 25/5/95 JC
 *	- new IM_ARRAY() macro
 * 25/1/96 JC
 *	- im_lhisteq() adapted to make new im_stdif()
 *	- now partial, plus rolling window
 *	- 5x faster, amazingly
 *	- works
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the input, not
 *	  the output
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

/* Hold global stuff here.
 */
typedef struct {
	int xwin, ywin;		/* Parameters */
	double a, m0, b, s0;
} StdifInfo;

/* stdif generate function.
 */
static int
stdif_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	StdifInfo *inf = (StdifInfo *) b;
	Rect irect;

	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int ri = IM_RECT_RIGHT(r);

	int x, y, i, j;
	int lsk;

	int coff;			/* Offset to move to centre of window */
	int npel = inf->xwin * inf->ywin;

	/* What part of ir do we need?
	 */
	irect.left = or->valid.left;
	irect.top = or->valid.top;
	irect.width = or->valid.width + inf->xwin;
	irect.height = or->valid.height + inf->ywin;
	if( im_prepare( ir, &irect ) )
		return( -1 );

	lsk = IM_REGION_LSKIP( ir );
	coff = lsk * (inf->ywin/2) + inf->xwin/2;

	for( y = to; y < bo; y++ ) {
		/* Get input and output pointers for this line.
		 */
		PEL *p = (PEL *) IM_REGION_ADDR( ir, le, y );
		PEL *q = (PEL *) IM_REGION_ADDR( or, le, y );
		PEL *p1, *p2;
		int sum = 0;
		int sum2 = 0;

		/* Precompute some factors.
		 */
		double f1 = inf->a * inf->m0;
		double f2 = 1.0 - inf->a;
		double f3 = inf->b * inf->s0;

		/* Find sum, sum of squares for the start of this line.
		 */
		for( p1 = p, j = 0; j < inf->ywin; j++, p1 += lsk )
			for( p2 = p1, i = 0; i < inf->xwin; i++, p2++ ) {
				int t = *p2;

				sum += t;
				sum2 += t * t;
			}

		/* Loop for output pels.
		 */
		for( x = le; x < ri; x++, p++ ) {
			/* Find stats.
			 */
			double mean = (double)sum / npel;
			double var = (double)sum2 / npel - (mean * mean);
			double sig = sqrt( var );

			/* Transform.
			 */
			double res = f1 + f2*mean + ((double) p[coff] - mean) * 
				(f3 / (inf->s0 + inf->b*sig));
			
			/* And write.
			 */
			if( res < 0.0 )
				*q++ = 0;
			else if( res >= 256.0 )
				*q++ = 255;
			else
				*q++ = res + 0.5;

			/* Adapt sums - remove the pels from the left hand
			 * column, add in pels for a new right-hand column.
			 */
			for( p1 = p, j = 0; j < inf->ywin; j++, p1 += lsk ) {
				int t1 = p1[0];
				int t2 = p1[inf->xwin];

				sum -= t1;
				sum2 -= t1 * t1;

				sum += t2;
				sum2 += t2 * t2;
			}
		}
	}

	return( 0 );
}

int 
im_stdif_raw( IMAGE *in, IMAGE *out, 
	double a, double m0, double b, double s0, 
	int xwin, int ywin )
{
	StdifInfo *inf;

	if( m0 < 0 || m0 > 255 || a < 0 || a > 1.0 || b < 0 || b > 2 || 
		s0 < 0 || s0 > 255 ) {
		im_error( "im_stdif", "%s", _( "parameters out of range" ) );
		return( -1 );
	}
	if( im_piocheck( in, out ) )
		return( -1 );
	if( in->BandFmt != IM_BANDFMT_UCHAR || 
		in->Bands != 1 || in->Coding != IM_CODING_NONE ) { 
		im_error( "im_stdif", "%s", 
			_( "one band uchar uncoded only" ) ); 
		return( -1 ); 
	}
	if( xwin > in->Xsize || ywin > in->Ysize ) {
		im_error( "im_stdif", "%s", _( "window too large" ) );
		return( -1 );
	}
	if( im_cp_desc( out, in ) ) 
		return( -1 );
	out->Xsize -= xwin;
	out->Ysize -= ywin;

	/* Save parameters.
	 */
	if( !(inf = IM_NEW( out, StdifInfo )) )
		return( -1 );
	inf->xwin = xwin;
	inf->ywin = ywin;
	inf->a = a;
	inf->m0 = m0;
	inf->b = b;
	inf->s0 = s0;

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
		return( -1 );

	/* Write the hist.
	 */
	if( im_generate( out,
		im_start_one, stdif_gen, im_stop_one, in, inf ) )
		return( -1 );

	return( 0 );
}

/* The above, with a border to make out the same size as in.
 */
int 
im_stdif( IMAGE *in, IMAGE *out, 
	double a, double m0, double b, double s0, 
	int xwin, int ywin )
{
	IMAGE *t1 = im_open_local( out, "im_stdif:1", "p" );

	if( !t1 || 
		im_embed( in, t1, 1, xwin / 2, ywin / 2, 
			in->Xsize + xwin - 1, 
			in->Ysize + ywin - 1 ) ||
		im_stdif_raw( t1, out, a, m0, b, s0, xwin, ywin ) )
		return( -1 );

	return( 0 );
}
