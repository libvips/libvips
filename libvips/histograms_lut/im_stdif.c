/* statistical difference 
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
 * 25/3/10
 * 	- gtkdoc
 * 	- small cleanups
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
	int npel = inf->xwin * inf->ywin;
	Rect *r = &or->valid;

	Rect irect;
	int x, y, i, j;
	int lsk;
	int centre;			/* Offset to move to centre of window */

	/* What part of ir do we need?
	 */
	irect.left = or->valid.left;
	irect.top = or->valid.top;
	irect.width = or->valid.width + inf->xwin;
	irect.height = or->valid.height + inf->ywin;
	if( im_prepare( ir, &irect ) )
		return( -1 );

	lsk = IM_REGION_LSKIP( ir );
	centre = lsk * (inf->ywin / 2) + inf->xwin / 2;

	for( y = 0; y < r->height; y++ ) {
		/* Get input and output pointers for this line.
		 */
		PEL *p = (PEL *) IM_REGION_ADDR( ir, r->left, r->top + y );
		PEL *q = (PEL *) IM_REGION_ADDR( or, r->left, r->top + y );

		/* Precompute some factors.
		 */
		double f1 = inf->a * inf->m0;
		double f2 = 1.0 - inf->a;
		double f3 = inf->b * inf->s0;

		PEL *p1;
		int sum;
		int sum2;

		/* Find sum, sum of squares for the start of this line.
		 */
		sum = 0;
		sum2 = 0;
		p1 = p;
		for( j = 0; j < inf->ywin; j++ ) {
			for( i = 0; i < inf->xwin; i++ ) {
				int t = p1[i];

				sum += t;
				sum2 += t * t;
			}

			p1 += lsk;
		}

		/* Loop for output pels.
		 */
		for( x = 0; x < r->width; x++ ) {
			/* Find stats.
			 */
			double mean = (double) sum / npel;
			double var = (double) sum2 / npel - (mean * mean);
			double sig = sqrt( var );

			/* Transform.
			 */
			double res = f1 + f2 * mean + 
				((double) p[centre] - mean) * 
				(f3 / (inf->s0 + inf->b * sig));

			/* And write.
			 */
			if( res < 0.0 )
				q[x] = 0;
			else if( res >= 256.0 )
				q[x] = 255;
			else
				q[x] = res + 0.5;

			/* Adapt sums - remove the pels from the left hand
			 * column, add in pels for a new right-hand column.
			 */
			p1 = p;
			for( j = 0; j < inf->ywin; j++ ) {
				int t1 = p1[0];
				int t2 = p1[inf->xwin];

				sum -= t1;
				sum2 -= t1 * t1;

				sum += t2;
				sum2 += t2 * t2;

				p1 += lsk;
			}

			p += 1;
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

	if( xwin > in->Xsize || 
		ywin > in->Ysize ) {
		im_error( "im_stdif", "%s", _( "window too large" ) );
		return( -1 );
	}
	if( xwin <= 0 || 
		ywin <= 0 ) {
		im_error( "im_lhisteq", "%s", _( "window too small" ) );
		return( -1 );
	}
	if( m0 < 0 || m0 > 255 || a < 0 || a > 1.0 || b < 0 || b > 2 || 
		s0 < 0 || s0 > 255 ) {
		im_error( "im_stdif", "%s", _( "parameters out of range" ) );
		return( -1 );
	}
	if( im_check_format( "im_stdif", in, IM_BANDFMT_UCHAR ) ||
		im_check_uncoded( "im_stdif", in ) ||
		im_check_mono( "im_stdif", in ) ||
		im_piocheck( in, out ) )
		return( -1 );
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

/**
 * im_stdif:
 * @in: input image
 * @out: output image
 * @a: weight of new mean
 * @m0: target mean
 * @b: weight of new deviation
 * @s0:target deviation
 * @xwin: width of region
 * @hwin: height of region
 *
 * im_stdif() preforms statistical differencing according to the formula
 * given in page 45 of the book "An Introduction to Digital Image 
 * Processing" by Wayne Niblack. This transformation emphasises the way in 
 * which a pel differs statistically from its neighbours. It is useful for 
 * enhancing low-contrast images with lots of detail, such as X-ray plates.
 *
 * At point (i,j) the output is given by the equation:
 *
 * vout(i,j) = @a * @m0 + (1 - @a) * meanv + 
 *       (vin(i,j) - meanv) * (@b * @s0) / (@s0 + @b * stdv)
 *
 * Values @a, @m0, @b and @s0 are entered, while meanv and stdv are the values
 * calculated over a moving window of size @xwin, @ywin centred on pixel (i,j). 
 * @m0 is the new mean, @a is the weight given to it. @s0 is the new standard 
 * deviation, @b is the weight given to it. 
 *
 * Try:
 *
 * vips im_stdif $VIPSHOME/pics/huysum.v fred.v 0.5 128 0.5 50 11 11
 *
 * The operation works on one-band uchar images only, and writes a one-band 
 * uchar image as its result. The output image has the same size as the 
 * input.
 *
 * See also: im_lhisteq().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_stdif( IMAGE *in, IMAGE *out, 
	double a, double m0, double b, double s0, 
	int xwin, int ywin )
{
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_stdif:1", "p" )) ||
		im_embed( in, t1, 1, xwin / 2, ywin / 2, 
			in->Xsize + xwin - 1, 
			in->Ysize + ywin - 1 ) ||
		im_stdif_raw( t1, out, a, m0, b, s0, xwin, ywin ) )
		return( -1 );

	return( 0 );
}
