/* find histograms
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
 * 24/3/10
 * 	- gtkdoc
 * 	- small cleanups
 * 25/1/12
 * 	- cast @in to u8/u16.
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

#include <vips/vips.h>

/* Accumulate a histogram in one of these.
 */
typedef struct {
	int bands;		/* Number of bands in output */
	int which;		/* If one band in out, which band of input */
	int size;		/* Length of bins */
	int mx;			/* Maximum value we have seen */
	unsigned int **bins;	/* All the bins! */
} Histogram;

typedef struct _VipsHistFind {
	VipsStatistic parent_instance;

	VipsImage *in;
	int band;

	/* Main image histogram. Subhists accumulate to this.
	 */
	Histogram *hist;
} VipsHistFind;

typedef VipsStatisticClass VipsHistFindClass;

G_DEFINE_TYPE( VipsHistFind, vips_hist_find, VIPS_TYPE_STATISTIC );

/* Build a Histogram.
 */
static Histogram *
histogram_new( VipsImage *out, int bands, int which, int size )
{
	Histogram *hist;
	int i;

	if( !(hist = VIPS_NEW( out, Histogram )) ||
		!(hist->bins = VIPS_ARRAY( out, bands, unsigned int * )) )
		return( NULL );

	for( i = 0; i < bands; i++ ) {
		if( !(hist->bins[i] = VIPS_ARRAY( out, size, unsigned int )) )
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
vips_hist_find_start( VipsImage *out, void *a, void *b )
{
	VipsHistFind *hist_find = (VipsHistFind *) a;
	Histogram *hist = hist_find->hist;

	return( (void *) 
		histogram_new( out, hist->bands, hist->which, hist->size ) );
}

/* Join a sub-hist onto the main hist.
 */
static int
vips_hist_find_stop( void *seq, void *a, void *b )
{
	Histogram *sub_hist = (Histogram *) seq;
	VipsHistFind *hist_find = (VipsHistFind *) a;
	Histogram *hist = hist_find->hist; 

	int i, j;

	g_assert( sub_hist->bands == hist->bands && 
		sub_hist->size == hist->size );

	/* Add on sub-data.
	 */
	hist->mx = VIPS_MAX( hist->mx, sub_hist->mx );
	for( i = 0; i < hist->bands; i++ )
		for( j = 0; j < hist->size; j++ )
			hist->bins[i][j] += sub_hist->bins[i][j];

	/* Blank out sub-hist to make sure we can't add it again.
	 */
	sub_hist->mx = 0;
	for( i = 0; i < sub_hist->bands; i++ )
		sub_hist->bins[i] = NULL;

	return( 0 );
}

/* Histogram of all bands of a uchar image.
 */
static int
vips_hist_find_uchar_hist( VipsRegion *reg, 
	void *seq, void *a, void *b, gboolean *stop )
{
	Histogram *hist = (Histogram *) seq;
	VipsRect *r = &reg->valid;
	VipsImage *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);
	int nb = im->Bands;

	int x, y, z;

	/* Accumulate!
	 */
	for( y = to; y < bo; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( reg, le, y );
		int i;

		for( i = 0, x = 0; x < r->width; x++ )
			for( z = 0; z < nb; z++, i++ )
				hist->bins[z][p[i]] += 1;
	}

	/* Note the maximum.
	 */
	hist->mx = 255;

	return( 0 );
}

/* Histogram of a selected band of a uchar image.
 */
static int
vips_hist_find_uchar_hist_extract( VipsRegion *reg, 
	void *seq, void *a, void *b, gboolean *stop )
{
	Histogram *hist = (Histogram *) seq;
	VipsRect *r = &reg->valid;
	VipsImage *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);
	unsigned int *bins = hist->bins[0];
	int nb = im->Bands;
	int max = r->width * nb;

	int x, y;

	/* Accumulate!
	 */
	for( y = to; y < bo; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( reg, le, y );

		for( x = hist->which; x < max; x += nb ) 
			bins[p[x]] += 1;
	}

	/* Note the maximum.
	 */
	hist->mx = 255;

	return( 0 );
}

/* Histogram of all bands of a ushort image.
 */
static int
vips_hist_find_ushort_hist( VipsRegion *reg, 
	void *seq, void *a, void *b, gboolean *stop )
{
	Histogram *hist = (Histogram *) seq;
	VipsRect *r = &reg->valid;
	VipsImage *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);
	int mx = hist->mx;
	int nb = im->Bands;

	int x, y, z;

	/* Accumulate!
	 */
	for( y = to; y < bo; y++ ) {
		unsigned short *p = (unsigned short *) 
			VIPS_REGION_ADDR( reg, le, y );
		int i;

		for( i = 0, x = 0; x < r->width; x++ )
			for( z = 0; z < nb; z++, i++ ) {
				int v = p[i];

				/* Adjust maximum.
				 */
				if( v > mx )
					mx = v;

				hist->bins[z][v] += 1;
			}
	}

	/* Note the maximum.
	 */
	hist->mx = mx;

	return( 0 );
}

/* Histogram of one band of a ushort image.
 */
static int
vips_hist_find_ushort_hist_extract( VipsRegion *reg, 
	void *seq, void *a, void *b, gboolean *stop )
{
	Histogram *hist = (Histogram *) seq;
	VipsRect *r = &reg->valid;
	VipsImage *im = reg->im;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);
	int mx = hist->mx;
	unsigned int *bins = hist->bins[0];
	int nb = im->Bands;
	int max = nb * r->width;

	int x, y;

	/* Accumulate!
	 */
	for( y = to; y < bo; y++ ) {
		unsigned short *p = (unsigned short *) 
			VIPS_REGION_ADDR( reg, le, y ) + hist->which;

		for( x = hist->which; x < max; x += nb ) {
			int v = p[x];

			/* Adjust maximum.
			 */
			if( v > mx )
				mx = v;

			bins[v] += 1;
		}
	}

	/* Note the maximum.
	 */
	hist->mx = mx;

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT
#define UI VIPS_FORMAT_UINT

/* Type mapping: go to uchar or ushort.
 */
static int bandfmt_histgr[10] = {
/* UC   C  US   S  UI   I   F   X  D   DX */
   UC, UC, US, US, US, US, US, US, US, US
};

/**
 * im_histgr:
 * @in: input image
 * @out: output image
 * @bandno: band to equalise
 *
 * Find the histogram of @in. Find the histogram for band @bandno (producing a
 * one-band histogram), or for all bands (producing an n-band histogram) if 
 * @bandno is -1. 
 *
 * @in is cast to u8 or u16. @out is always u32.
 *
 * See also: im_hist_indexed(), im_histeq().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_histgr( VipsImage *in, VipsImage *out, int bandno )
{
	VipsImage *t;
	int size;		/* Length of hist */
	int bands;		/* Number of bands in output */
	Histogram *mhist;
	VipsGenerateFn scanfn;
	int i, j;
	unsigned int *obuffer, *q;

	/* Check images. PIO from in, WIO to out.
	 */
	if( im_check_uncoded( "im_histgr", in ) || 
		im_check_bandno( "im_histgr", in, bandno ) ||
		im_pincheck( in ) || 
		im_outcheck( out ) )
		return( -1 );

	/* Cast in to u8/u16.
	 */
	if( !(t = im_open_local( out, "im_histgr", "p" )) ||
		im_clip2fmt( in, t, bandfmt_histgr[in->BandFmt] ) )
		return( -1 );
	in = t;

	/* Find the range of pixel values we must handle.
	 */
	size = in->BandFmt == VIPS_FORMAT_UCHAR ? 256 : 65536;

	/* How many output bands?
	 */
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
	if( in->BandFmt == VIPS_FORMAT_UCHAR && bandno == -1 ) 
		scanfn = vips_hist_find_uchar_hist;
	else if( in->BandFmt == VIPS_FORMAT_UCHAR )
		scanfn = vips_hist_find_uchar_hist_extract;
	else if( in->BandFmt == VIPS_FORMAT_USHORT && bandno == -1 )
		scanfn = vips_hist_find_ushort_hist;
	else
		scanfn = vips_hist_find_ushort_hist_extract;

	/* Accumulate data.
	 */
	if( vips_sink( in, 
		vips_hist_find_start, scanfn, vips_hist_find_stop, 
		mhist, NULL ) )
		return( -1 );

	/* Make the output image.
	 */
	if( im_cp_desc( out, in ) ) 
		return( -1 );
	im_initdesc( out,
		mhist->mx + 1, 1, bands, VIPS_FORMAT_UINT, 
		VIPS_CODING_NONE, VIPS_TYPE_HISTOGRAM, 1.0, 1.0, 0, 0 );
	if( im_setupout( out ) )
		return( -1 );

	/* Interleave for output.
	 */
	if( !(obuffer = VIPS_ARRAY( out, 
		VIPS_IMAGE_N_ELEMENTS( out ), unsigned int )) )
		return( -1 );
	for( q = obuffer, j = 0; j < out->Xsize; j++ )
		for( i = 0; i < out->Bands; i++ )
			*q++ = mhist->bins[i][j];

	/* Write interleaved buffer into hist.
	 */
	if( im_writeline( 0, out, (VipsPel *) obuffer ) )
		return( -1 );

	return( 0 );
}
