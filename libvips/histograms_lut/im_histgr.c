/* @(#) im_histgr: make a histogram of an image and saves it into hist.
 * @(#) If input is uchar, output is 256 by 1 image of uint. If input is
 * @(#) ushort, output is max(image) + 1 by 1 image of uint. If bandno is
 * @(#) zero, then output is has same number of bands as input, with each
 * @(#) band being a separate histogram. Otherwise, bandno selects a band
 * @(#) to find the histogram of.
 * @(#) 
 * @(#) Usage:
 * @(#) int im_histgr(image, hist, bandno)
 * @(#) IMAGE *image, *hist;
 * @(#) int bandno;
 * @(#)
 * @(#)  Returns 0 on success and -1 on error
 *
 * Copyright: 1990, 1991, N. Dessipris.
 *
 * Author: Nicos Dessipris.
 * Written on: 09/07/1990
 * Modified on : 11/03/1991
 * 19/7/93 JC
 *	- test for Coding type added
 * 26/10/94 JC
 *	- rewritten for ANSI
 *	- now does USHORT too
 *	- 5 x faster!
 * 2/6/95 JC
 *	- rewritten for partials
 * 3/3/01 JC
 *	- tiny speed ups
 * 21/1/07
 * 	- number bands from zero
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
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Accumulate a histogram in one of these.
 */
typedef struct {
	int bands;		/* Number of bands in output */
	int which;		/* If one band in out, which band of input */
	int size;		/* Length of bins */
	int mx;			/* Maximum value we have seen */
	unsigned int **bins;	/* All the bins! */
} Histogram;

/* Build a Histogram.
 */
static Histogram *
build_hist( IMAGE *out, int bands, int which, int size )
{
	int i;
	Histogram *hist = IM_NEW( out, Histogram );

	if( !hist || !(hist->bins = IM_ARRAY( out, bands, unsigned int * )) )
		return( NULL );
	for( i = 0; i < bands; i++ ) {
		if( !(hist->bins[i] = IM_ARRAY( out, size, unsigned int )) )
			return( NULL );
		memset( hist->bins[i], 0, size * sizeof( unsigned int ) );
	}

	hist->bands = bands;
	hist->which = which;
	hist->size = size;
	hist->mx = 0;

	return( hist );
}

/* Build a sub-hist, based on the main hist.
 */
static void *
build_subhist( IMAGE *out, void *a, void *b )
{
	Histogram *mhist = (Histogram *) a;

	return( (void *) 
		build_hist( out, mhist->bands, mhist->which, mhist->size ) );
}

/* Join a sub-hist onto the main hist.
 */
static int
merge_subhist( void *seq, void *a, void *b )
{
	Histogram *shist = (Histogram *) seq;
	Histogram *mhist = (Histogram *) a;
	int i, j;

	g_assert( shist->bands == mhist->bands && shist->size == mhist->size );

	/* Add on sub-data.
	 */
	mhist->mx = IM_MAX( mhist->mx, shist->mx );
	for( i = 0; i < mhist->bands; i++ )
		for( j = 0; j < mhist->size; j++ )
			mhist->bins[i][j] += shist->bins[i][j];

	/* Blank out sub-hist to make sure we can't add it again.
	 */
	shist->mx = 0;
	for( i = 0; i < shist->bands; i++ )
		shist->bins[i] = NULL;
	
	return( 0 );
}

/* Histogram of all bands of a uchar image.
 */
static int
find_uchar_hist( REGION *reg, void *seq, void *a, void *b )
{
	Histogram *hist = (Histogram *) seq;
	Rect *r = &reg->valid;
	IMAGE *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int nb = im->Bands;
	int x, y, z;

	/* Accumulate!
	 */
	for( y = to; y < bo; y++ ) {
		PEL *p = (PEL *) IM_REGION_ADDR( reg, le, y );
		int i;

		for( i = 0, x = 0; x < r->width; x++ )
			for( z = 0; z < nb; z++, i++ )
				hist->bins[z][p[i]]++;
	}

	/* Note the maximum.
	 */
	hist->mx = 255;

	return( 0 );
}

/* Histogram of a selected band of a uchar image.
 */
static int
find_uchar_hist_extract( REGION *reg, void *seq, void *a, void *b )
{
	Histogram *hist = (Histogram *) seq;
	Rect *r = &reg->valid;
	IMAGE *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	unsigned int *bins = hist->bins[0];
	int nb = im->Bands;
	int max = r->width * nb;
	int x, y;

	/* Accumulate!
	 */
	for( y = to; y < bo; y++ ) {
		PEL *p = (PEL *) IM_REGION_ADDR( reg, le, y );

		for( x = hist->which; x < max; x += nb ) 
			bins[p[x]]++;
	}

	/* Note the maximum.
	 */
	hist->mx = 255;

	return( 0 );
}

/* Histogram of all bands of a ushort image.
 */
static int
find_ushort_hist( REGION *reg, void *seq, void *a, void *b )
{
	Histogram *hist = (Histogram *) seq;
	Rect *r = &reg->valid;
	IMAGE *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int mx = hist->mx;
	int nb = im->Bands;
	int x, y, z;

	/* Accumulate!
	 */
	for( y = to; y < bo; y++ ) {
		unsigned short *p = (unsigned short *) 
			IM_REGION_ADDR( reg, le, y );
		int i;

		for( i = 0, x = 0; x < r->width; x++ )
			for( z = 0; z < nb; z++, i++ ) {
				int v = p[i];

				/* Adjust maximum.
				 */
				if( v > mx )
					mx = v;

				hist->bins[z][v]++;
			}
	}

	/* Note the maximum.
	 */
	hist->mx = mx;

	return( 0 );
}

/* Histogram of all bands of a ushort image.
 */
static int
find_ushort_hist_extract( REGION *reg, void *seq, void *a, void *b )
{
	Histogram *hist = (Histogram *) seq;
	Rect *r = &reg->valid;
	IMAGE *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int mx = hist->mx;
	unsigned int *bins = hist->bins[0];
	int nb = im->Bands;
	int max = nb * r->width;
	int x, y;

	/* Accumulate!
	 */
	for( y = to; y < bo; y++ ) {
		unsigned short *p = (unsigned short *) 
			IM_REGION_ADDR( reg, le, y ) + hist->which;

		for( x = hist->which; x < max; x += nb ) {
			int v = p[x];

			/* Adjust maximum.
			 */
			if( v > mx )
				mx = v;

			bins[v]++;
		}
	}

	/* Note the maximum.
	 */
	hist->mx = mx;

	return( 0 );
}

int 
im_histgr( IMAGE *in, IMAGE *out, int bandno )
{
	int size;		/* Length of hist */
	int bands;		/* Number of bands in output */
	Histogram *mhist;
	im_generate_fn scanfn;
	int i, j;
	unsigned int *obuffer, *q;

	/* Check images. PIO from in, WIO to out.
	 */
	if( im_pincheck( in ) || im_outcheck( out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE ) {
		im_error( "im_histgr", "%s", _( "uncoded images only" ) );
		return( -1 );
	}

	/* Find the range of pixel values we must handle.
	 */
	if( in->Bbits == IM_BBITS_BYTE && in->BandFmt == IM_BANDFMT_UCHAR ) 
		size = 256;
	else if( in->Bbits == IM_BBITS_SHORT && 
		in->BandFmt == IM_BANDFMT_USHORT )
		size = 65536;
	else {
		im_error( "im_histgr", "%s", _( "input not uchar or ushort" ) );
		return( -1 );
	}

	/* How many output bands?
	 */
	if( bandno > in->Bands || bandno < -1 ) {
		im_error( "im_histgr", "%s", _( "bad band parameter" ) );
		return( -1 );
	}
	if( bandno == -1 ) 
		bands = in->Bands;
	else 
		bands = 1;

	/* Build main hist we accumulate data in.
	 */
	if( !(mhist = build_hist( out, bands, bandno, size )) )
		return( -1 );

	/* Select scan function.
	 */
	if( in->BandFmt == IM_BANDFMT_UCHAR && bandno == -1 ) 
		scanfn = find_uchar_hist;
	else if( in->BandFmt == IM_BANDFMT_UCHAR )
		scanfn = find_uchar_hist_extract;
	else if( in->BandFmt == IM_BANDFMT_USHORT && bandno == -1 )
		scanfn = find_ushort_hist;
	else
		scanfn = find_ushort_hist_extract;

	/* Accumulate data.
	 */
	if( im_iterate( in, 
		build_subhist, scanfn, merge_subhist, mhist, NULL ) )
		return( -1 );

	/* Make the output image.
	 */
	if( im_cp_desc( out, in ) ) 
		return( -1 );
	im_initdesc( out,
		mhist->mx + 1, 1, bands, IM_BBITS_INT, IM_BANDFMT_UINT, 
		IM_CODING_NONE, IM_TYPE_HISTOGRAM, 1.0, 1.0, 0, 0 );
	if( im_setupout( out ) )
		return( -1 );

	/* Interleave for output.
	 */
	if( !(obuffer = IM_ARRAY( out, 
		IM_IMAGE_N_ELEMENTS( out ), unsigned int )) )
		return( -1 );
	for( q = obuffer, j = 0; j < out->Xsize; j++ )
		for( i = 0; i < out->Bands; i++ )
			*q++ = mhist->bins[i][j];

	/* Write interleaved buffer into hist.
	 */
	if( im_writeline( 0, out, (PEL *) obuffer ) )
		return( -1 );

	return( 0 );
}
