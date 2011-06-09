/* im_aconv ... approximate convolution
 *
 * This operation does an approximate convolution. 
 *
 * Author: John Cupitt & Nicolas Robidoux
 * Written on: 31/5/11
 * Modified on: 
 * 31/5/11
 *      - from im_aconvsep()
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

  See:

	http://incubator.quasimondo.com/processing/stackblur.pde

  This thing is a little like stackblur, but generalised to any 2D 
  convolution.

 */

/*

  TODO

timing:

$ time vips im_conv_f img_0075.jpg x2.v g2d201.con
real	11m58.769s
user	22m46.390s
sys	0m3.270s

$ time vips im_aconv img_0075.jpg x.v g2d201.con 10 10
boxes_new: min = 0, max = 1
boxes_new: depth = 0.1, n_layers = 10
boxes_new: generated 1130 boxes
boxes_new: clustering with thresh 10 ...
boxes_new: renumbering ...
boxes_new: after renumbering, 14 boxes remain
real	0m34.377s
user	1m0.440s
sys	0m0.370s

$ vips im_subtract x.v x2.v diff.v
$ vips im_abs diff.v abs.v
$ vips im_max abs.v
2.70833

	- can we use rolling averages for the vertical pass? 
	  we need to search for groups with the same band and adjacent row

	- clustering could be much faster

	- add more bandfmt

  	- are we handling mask offset correctly?

 */

/*
 */
#define DEBUG
#define VIPS_DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/vector.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Maximum number of boxes we can break the mask into.
 */
#define MAX_LINES (10000)

/* Get an (x,y) value from a mask.
 */
#define MASK( M, X, Y ) ((M)->coeff[(X) + (Y) * (M)->xsize])

/* A horizontal line in the mask.
 */
typedef struct _HLine {
	/* Start is the left-most pixel in the line, end is one beyond the
	 * right-most pixel. 
	 */
	int start;
	int end;

	/* The hlines have weights. weight 0 means this line is unused.
	 */
	int weight;
} HLine;

/* An element of a vline.
 */
typedef struct _VElement {
	/* band is the index into hline[] we add, row is the row we take 
	 * it from.
	 */
	int band;
	int row;

	/* Negative lobes are made with factor -1, we also common-up repeated
	 * additions of the same line.
	 */
	int factor;
} VElement;

/* A vline.
 */
typedef struct _VLine {
	int band;
	int factor;
	int start;
	int end;
} VLine;

/* A set of boxes. 
 */
typedef struct _Boxes {
	/* Copy of our arguments.
	 */
	IMAGE *in;
	IMAGE *out;
	DOUBLEMASK *mask;
	int n_layers;
	int cluster;

	int area;
	int rounding;

	/* The horizontal lines we gather. hline[3] writes to band 3 in the
	 * intermediate image.
	 */
	int n_hline;
	HLine hline[MAX_LINES];

	/* Scale and sum a set of hlines to make the final value. 
	 */
	int n_velement;
	VElement velement[MAX_LINES];

	/* And group those velements as vlines.
	 */
	int n_vline;
	VLine vline[MAX_LINES];
} Boxes;

/* Euclid's algorithm. Use this to common up mults.
 */
static int
gcd( int a, int b )
{
	if( b == 0 )
		return( abs( a ) );
	else
		return( gcd( b, a % b ) );
}

static void
boxes_start( Boxes *boxes, int x )
{
	boxes->hline[boxes->n_hline].start = x;
	boxes->hline[boxes->n_hline].weight = 1;
}

static int
boxes_end( Boxes *boxes, int x, int y, int factor )
{
	boxes->hline[boxes->n_hline].end = x;

	boxes->velement[boxes->n_velement].row = y;
	boxes->velement[boxes->n_velement].band = boxes->n_hline;
	boxes->velement[boxes->n_velement].factor = factor;

	if( boxes->n_hline >= MAX_LINES - 1 ) {
		vips_error( "im_aconv", "%s", _( "mask too complex" ) );
		return( -1 );
	}
	boxes->n_hline += 1;

	if( boxes->n_velement >= MAX_LINES - 1 ) {
		vips_error( "im_aconv", "%s", _( "mask too complex" ) );
		return( -1 );
	}
	boxes->n_velement += 1;

	return( 0 );
}

/* The 'distance' between a pair of hlines.
 */
static int
boxes_distance( Boxes *boxes, int a, int b )
{
	g_assert( boxes->hline[a].weight > 0 && boxes->hline[b].weight > 0 );

	return( abs( boxes->hline[a].start - boxes->hline[b].start ) + 
		abs( boxes->hline[a].end - boxes->hline[b].end ) ); 
}

/* Merge two hlines. Line b is deleted, and any refs to b in vlines updated to
 * point at a.
 */
static void
boxes_merge( Boxes *boxes, int a, int b )
{
	int i;

	/* Scale weights. 
	 */
	int fa = boxes->hline[a].weight;
	int fb = boxes->hline[b].weight;
	double w = (double) fb / (fa + fb);

	/* New endpoints.
	 */
	boxes->hline[a].start += w * 
		(boxes->hline[b].start - boxes->hline[a].start);
	boxes->hline[a].end += w * 
		(boxes->hline[b].end - boxes->hline[a].end);
	boxes->hline[a].weight += boxes->hline[b].weight;

	/* Update velement refs to b to refer to a instead.
	 */
	for( i = 0; i < boxes->n_velement; i++ )
		if( boxes->velement[i].band == b )
			boxes->velement[i].band = a;

	/* Mark b to be deleted.
	 */
	boxes->hline[b].weight = 0;
}

/* Find the closest pair of hlines, join them up if the distance is less than 
 * a threshold. Return non-zero if we made a change.
 */
static int
boxes_cluster( Boxes *boxes, int cluster )
{
	int i, j;
	int best, a, b;
	int acted;

	best = 9999999;

	for( i = 0; i < boxes->n_hline; i++ ) {
		if( boxes->hline[i].weight == 0 )
			continue;

		for( j = i + 1; j < boxes->n_hline; j++ ) {
			int d;

			if( boxes->hline[j].weight == 0 )
				continue;

			d = boxes_distance( boxes, i, j ); 
			if( d < best ) {
				best = d;
				a = i;
				b = j;
			}
		}
	}

	acted = 0;
	if( best < cluster ) {
		boxes_merge( boxes, a, b );
		acted = 1;
	}

	return( acted );
}

/* Renumber after clustering. We will have removed a lot of hlines ... shuffle
 * the rest down, adjust all the vline references.
 */
static void
boxes_renumber( Boxes *boxes )
{
	int i, j;

	j = 0;
	for( i = 0; i < boxes->n_hline; i++ ) 
		if( boxes->hline[i].weight == 0 ) 
			j++;
	printf( "%d weight 0 hlines\n", j );

	/* Loop for all zero-weight hlines.
	 */
	for( i = 0; i < boxes->n_hline; ) {
		if( boxes->hline[i].weight > 0 ) {
			i++;
			continue;
		}

		/* We move hlines i + 1 down, so we need to adjust all
		 * band[] refs to match.
		 */
		for( j = 0; j < boxes->n_velement; j++ )
			if( boxes->velement[j].band > i ) 
				boxes->velement[j].band -= 1;

		memmove( boxes->hline + i, boxes->hline + i + 1, 
			sizeof( HLine ) * (boxes->n_hline - i - 1) );
		boxes->n_hline -= 1;
	}
}

/* Sort by band, then factor, then row.
 */
static int
sortfn( const void *p1, const void *p2 )
{
	VElement *a = (VElement *) p1;
	VElement *b = (VElement *) p2;

	if( a->band != b->band )
		return( a->band - b->band );

	if( a->factor != b->factor )
		return( a->factor - b->factor );

	return( a->row - b->row );
}

static void
boxes_vline( Boxes *boxes )
{
	int y, z;

	/* Sort to get elements which could form a vline together.
	 */
	qsort( boxes->velement, boxes->n_velement, sizeof( VElement ), sortfn );

	boxes->n_vline = 0;
	for( y = 0; y < boxes->n_velement; ) {
		int n = boxes->n_vline;

		/* Start of a line.
		 */
		boxes->vline[n].band = boxes->velement[y].band;
		boxes->vline[n].factor = boxes->velement[y].factor;
		boxes->vline[n].start = boxes->velement[y].row;

		/* Search for the end of this line.
		 */
		for( z = y + 1; z < boxes->n_velement; z++ ) 
			if( boxes->velement[z].band != 
					boxes->vline[n].band ||
				boxes->velement[z].factor != 
					boxes->vline[n].factor ||
				boxes->velement[z].row != 
					boxes->vline[n].start + z - y )
				break;

		/* So the line ends at the previously examined element. We
		 * want 'end' to be one beyond that (non-inclusive).
		 */
		boxes->vline[n].end = boxes->velement[z - 1].row + 1;

		boxes->n_vline += 1;
		y = z;
	}
}

#ifdef DEBUG
static void
boxes_print( Boxes *boxes )
{
	int x, y;

	printf( "hlines:\n" );
	printf( "   n   b   r  f   w\n" );
	for( y = 0; y < boxes->n_velement; y++ ) {
		int b = boxes->velement[y].band;

		printf( "%4d %3d %3d %2d %3d ", 
			y, b, 
			boxes->velement[y].row, 
			boxes->velement[y].factor,
			boxes->hline[b].weight );
		for( x = 0; x < 45; x++ ) {
			int rx = x * (boxes->mask->xsize + 1) / 45;

			if( rx >= boxes->hline[b].start && 
				rx < boxes->hline[b].end )
				printf( "#" );
			else
				printf( " " );
		}
		printf( " %3d .. %3d\n", 
			boxes->hline[b].start, boxes->hline[b].end );
	}

	printf( "%d vlines:\n", boxes->n_vline );
	printf( "   n  b  f      s      e\n" );
	for( y = 0; y < boxes->n_vline; y++ ) 
		printf( "%4d %2d %2d == %3d .. %3d\n", y,
			boxes->vline[y].band, 
			boxes->vline[y].factor, 
			boxes->vline[y].start, 
			boxes->vline[y].end );

	printf( "area = %d\n", boxes->area );
	printf( "rounding = %d\n", boxes->rounding );
}
#endif /*DEBUG*/

/* Break a mask into boxes.
 */
static Boxes *
boxes_new( IMAGE *in, IMAGE *out, DOUBLEMASK *mask, int n_layers, int cluster )
{
	const int size = mask->xsize * mask->ysize;

	Boxes *boxes;
	double max;
	double min;
	double depth;
	double sum;
	int layers_above;
	int layers_below;
	int z, n, x, y;

	/* Check parameters.
	 */
	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_aconv", in ) ||
		vips_check_dmask( "im_aconv", mask ) ) 
		return( NULL );

	if( !(boxes = VIPS_NEW( out, Boxes )) )
		return( NULL );
	boxes->in = in;
	boxes->out = out;
	if( !(boxes->mask = (DOUBLEMASK *) im_local( out, 
		(im_construct_fn) im_dup_dmask,
		(im_callback_fn) im_free_dmask, mask, mask->filename, NULL )) )
		return( NULL );
	boxes->n_layers = n_layers;
	boxes->cluster = cluster;

	boxes->n_hline = 0;
	boxes->n_velement = 0;
	boxes->n_vline = 0;

	/* Find mask range. We must always include the zero axis in the mask.
	 */
	max = 0;
	min = 0;
	for( n = 0; n < size; n++ ) {
		max = IM_MAX( max, mask->coeff[n] );
		min = IM_MIN( min, mask->coeff[n] );
	}

	VIPS_DEBUG_MSG( "boxes_new: min = %g, max = %g\n", min, max );

	/* The zero axis must fall on a layer boundary. Estimate the
	 * depth, find n-lines-above-zero, get exact depth, then calculate a
	 * fixed n-lines which includes any negative parts.
	 */
	depth = (max - min) / n_layers;
	layers_above = ceil( max / depth );
	depth = max / layers_above;
	layers_below = floor( min / depth );
	n_layers = layers_above - layers_below;

	VIPS_DEBUG_MSG( "boxes_new: depth = %g, n_layers = %d\n", 
		depth, n_layers );

	/* For each layer, generate a set of lines which are inside the
	 * perimeter. Work down from the top.
	 */
	for( z = 0; z < n_layers; z++ ) {
		/* How deep we are into the mask, as a double we can test
		 * against. Add half the layer depth so we can easily find >50%
		 * mask elements.
		 */
		double z_ph = max - (1 + z) * depth + depth / 2;

		/* Odd, but we must avoid rounding errors that make us miss 0
		 * in the line above.
		 */
		int z_positive = z < layers_above;

		for( y = 0; y < mask->ysize; y++ ) {
			int inside;

			/* Start outside the perimeter.
			 */
			inside = 0;

			for( x = 0; x < mask->xsize; x++ ) {
				double coeff = MASK( mask, x, y );

				/* The vertical line from mask[x, y] to 0 is 
				 * inside. Is our current square (x, y) part 
				 * of that line?
				 */
				if( (z_positive && coeff >= z_ph) ||
					(!z_positive && coeff <= z_ph) ) {
					if( !inside ) {
						boxes_start( boxes, x );
						inside = 1;
					}
				}
				else {
					if( inside ) {
						boxes_end( boxes, x, y,
							z_positive ? 1 : -1 );
						inside = 0;
					}
				}
			}

			if( inside && 
				boxes_end( boxes, mask->xsize, y, 
					z_positive ? 1 : -1 ) )
				return( NULL );
		}
	}

	VIPS_DEBUG_MSG( "boxes_new: generated %d boxes\n", boxes->n_hline );
	boxes_print( boxes );

	VIPS_DEBUG_MSG( "boxes_new: clustering with thresh %d ...\n", 
		cluster ); 
	while( boxes_cluster( boxes, cluster ) )
		;
	VIPS_DEBUG_MSG( "boxes_new: renumbering ...\n" );
	boxes_renumber( boxes );
	VIPS_DEBUG_MSG( "boxes_new: after renumbering, %d hlines remain\n", 
		boxes->n_hline );

	VIPS_DEBUG_MSG( "boxes_new: forming vlines ...\n" );
	boxes_vline( boxes );
	VIPS_DEBUG_MSG( "boxes_new: found %d vlines\n", boxes->n_vline );

	/* Find the area of the lines.
	 */
	boxes->area = 0;
	for( y = 0; y < boxes->n_velement; y++ ) {
		int x = boxes->velement[y].band;

		boxes->area += boxes->velement[y].factor * 
			(boxes->hline[x].end - boxes->hline[x].start);
	}

	/* Strength reduction: if all lines are divisible by n, we can move
	 * that n out into the ->area factor. The aim is to produce as many
	 * factor 1 lines as we can and to reduce the chance of overflow.
	 */
	x = boxes->velement[0].factor;
	for( y = 1; y < boxes->n_velement; y++ ) 
		x = gcd( x, boxes->velement[y].factor );
	for( y = 0; y < boxes->n_velement; y++ ) 
		boxes->velement[y].factor /= x;
	boxes->area *= x;

	/* Find the area of the original mask.
	 */
	sum = 0;
	for( z = 0; z < size; z++ ) 
		sum += mask->coeff[z];

	boxes->area = rint( sum * boxes->area / mask->scale );
	boxes->rounding = (boxes->area + 1) / 2 + mask->offset * boxes->area;

#ifdef DEBUG
	boxes_print( boxes );
#endif /*DEBUG*/

	/* With 512x512 tiles, each hline requires 3mb of intermediate per
	 * thread ... 300 lines is about a gb per thread, ouch.
	 */
	if( boxes->n_hline > 150 ) {
		im_error( "im_aconv", "%s", _( "mask too complex" ) );
		return( NULL );
	}

	return( boxes );
}

/* Our sequence value.
 */
typedef struct {
	Boxes *boxes;

	REGION *ir;		/* Input region */

	/* For the horizontal pass, offsets for start and stop. For the
	 * vertical pass, just use just start to get the offsets to sum.
	 */
	int *start;		
	int *end;

	/* For the horizontal pass, the rolling sums. int for integer types, 
	 * double for floating point types.
	 */
	void *sum;		

	int last_stride;	/* Avoid recalcing offsets, if we can */
} AConvSequence;

/* Free a sequence value.
 */
static int
aconv_stop( void *vseq, void *a, void *b )
{
	AConvSequence *seq = (AConvSequence *) vseq;

	IM_FREEF( im_region_free, seq->ir );

	return( 0 );
}

/* Convolution start function.
 */
static void *
aconv_start( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	Boxes *boxes = (Boxes *) b;

	AConvSequence *seq;

	if( !(seq = IM_NEW( out, AConvSequence )) )
		return( NULL );

	/* Init!
	 */
	seq->boxes = boxes;
	seq->ir = im_region_create( in );

	/* n_velement should be the largest possible dimension.
	 */
	g_assert( boxes->n_velement >= boxes->n_hline );

	seq->start = IM_ARRAY( out, boxes->n_velement, int );
	seq->end = IM_ARRAY( out, boxes->n_velement, int );

	if( vips_band_format_isint( out->BandFmt ) )
		seq->sum = IM_ARRAY( out, boxes->n_velement, int );
	else
		seq->sum = IM_ARRAY( out, boxes->n_velement, double );
	seq->last_stride = -1;

	if( !seq->ir || !seq->start || !seq->end || !seq->sum ) {
		aconv_stop( seq, in, boxes );
		return( NULL );
	}

	return( seq );
}

#define CLIP_UCHAR( V ) \
G_STMT_START { \
	if( (V) < 0 ) \
		(V) = 0; \
	else if( (V) > UCHAR_MAX ) \
		(V) = UCHAR_MAX; \
} G_STMT_END

#define CLIP_CHAR( V ) \
G_STMT_START { \
	if( (V) < SCHAR_MIN ) \
		(V) = SCHAR_MIN; \
	else if( (V) > SCHAR_MAX ) \
		(V) = SCHAR_MAX; \
} G_STMT_END

#define CLIP_USHORT( V ) \
G_STMT_START { \
	if( (V) < 0 ) \
		(V) = 0; \
	else if( (V) > USHRT_MAX ) \
		(V) = USHRT_MAX; \
} G_STMT_END

#define CLIP_SHORT( V ) \
G_STMT_START { \
	if( (V) < SHRT_MIN ) \
		(V) = SHRT_MIN; \
	else if( (V) > SHRT_MAX ) \
		(V) = SHRT_MAX; \
} G_STMT_END

#define CLIP_NONE( V ) {}

/* The h and v loops are very similar, but also annoyingly different. Keep
 * them separate for easy debugging.
 */

/* Do horizontal masks ... we scan the mask along scanlines.
 */
static int
aconv_hgenerate( REGION *or, void *vseq, void *a, void *b )
{
	AConvSequence *seq = (AConvSequence *) vseq;
	IMAGE *in = (IMAGE *) a;
	Boxes *boxes = (Boxes *) b;

	REGION *ir = seq->ir;
	const int n_hline = boxes->n_hline;
	DOUBLEMASK *mask = boxes->mask;
	Rect *r = &or->valid;

	/* Double the bands (notionally) for complex.
	 */
	int bands = vips_band_format_iscomplex( in->BandFmt ) ? 
		2 * in->Bands : in->Bands;

	Rect s;
	int x, y, z, i;
	int istride;
	int ostride;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += mask->xsize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );

	istride = IM_IMAGE_SIZEOF_PEL( in ) / 
		IM_IMAGE_SIZEOF_ELEMENT( in );
	ostride = IM_IMAGE_SIZEOF_PEL( or->im ) / 
		IM_IMAGE_SIZEOF_ELEMENT( or->im );

        /* Init offset array. 
	 */
	if( seq->last_stride != istride ) {
		seq->last_stride = istride;

		for( z = 0; z < n_hline; z++ ) {
			seq->start[z] = boxes->hline[z].start * istride;
			seq->end[z] = boxes->hline[z].end * istride;
		}
	}

	for( y = 0; y < r->height; y++ ) { 
		switch( in->BandFmt ) {
		case IM_BANDFMT_UCHAR: 	

	for( i = 0; i < bands; i++ ) { 
		int *seq_sum = (int *) seq->sum; 

		PEL *p; 
		int *q; 

		p = i + (PEL *) IM_REGION_ADDR( ir, r->left, r->top + y ); 
		q = i * n_hline + 
			(int *) IM_REGION_ADDR( or, r->left, r->top + y ); 

		for( z = 0; z < n_hline; z++ ) { 
			seq_sum[z] = 0; 
			for( x = boxes->hline[z].start; 
				x < boxes->hline[z].end; x++ ) 
				seq_sum[z] += p[x * istride]; 
			q[z] = seq_sum[z]; 
		} 
		q += ostride; 

		for( x = 1; x < r->width; x++ ) {  
			for( z = 0; z < n_hline; z++ ) { 
				seq_sum[z] += p[seq->end[z]]; 
				seq_sum[z] -= p[seq->start[z]]; 
				q[z] = seq_sum[z]; 
			} 
			p += istride; 
			q += ostride; 
		} 
	} 

			break;

			/*
		case IM_BANDFMT_UCHAR: 	
			HCONV_INT( unsigned char, CLIP_UCHAR );
			break;

		case IM_BANDFMT_CHAR: 	
			HCONV_INT( signed char, CLIP_UCHAR );
			break;

		case IM_BANDFMT_USHORT: 	
			HCONV_INT( unsigned short, CLIP_USHORT );
			break;

		case IM_BANDFMT_SHORT: 	
			HCONV_INT( signed short, CLIP_SHORT );
			break;

		case IM_BANDFMT_UINT: 	
			HCONV_INT( unsigned int, CLIP_NONE );
			break;

		case IM_BANDFMT_INT: 	
			HCONV_INT( signed int, CLIP_NONE );
			break;

		case IM_BANDFMT_FLOAT: 	
			HCONV_FLOAT( float );
			break;

		case IM_BANDFMT_DOUBLE: 	
			HCONV_FLOAT( double );
			break;

		case IM_BANDFMT_COMPLEX: 	
			HCONV_FLOAT( float );
			break;

		case IM_BANDFMT_DPCOMPLEX: 	
			HCONV_FLOAT( double );
			break;
			 */

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

static int
aconv_horizontal( Boxes *boxes, IMAGE *in, IMAGE *out )
{
	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize -= boxes->mask->xsize - 1;
	if( out->Xsize <= 0 ) { 
		im_error( "im_aconv", "%s", _( "image too small for mask" ) );
		return( -1 );
	}
	out->Bands *= boxes->n_hline;
	out->BandFmt = vips_band_format_isfloat( in->BandFmt ) ?
		VIPS_FORMAT_DOUBLE : VIPS_FORMAT_INT;

	if( im_demand_hint( out, IM_SMALLTILE, in, NULL ) ||
		im_generate( out, 
			aconv_start, aconv_hgenerate, aconv_stop, in, boxes ) )
		return( -1 );

	out->Xoffset = -boxes->mask->xsize / 2;
	out->Yoffset = -boxes->mask->ysize / 2;

	return( 0 );
}

/* Do vertical masks ... we scan the mask down columns of pixels. Copy-paste
 * from above with small changes.
 */
static int
aconv_vgenerate( REGION *or, void *vseq, void *a, void *b )
{
	AConvSequence *seq = (AConvSequence *) vseq;
	IMAGE *in = (IMAGE *) a;
	Boxes *boxes = (Boxes *) b;

	REGION *ir = seq->ir;
	const int n_velement = boxes->n_velement;
	DOUBLEMASK *mask = boxes->mask;
	Rect *r = &or->valid;

	/* Double the width (notionally) for complex.
	 */
	int sz = vips_band_format_iscomplex( in->BandFmt ) ? 
		2 * IM_REGION_N_ELEMENTS( or ) : IM_REGION_N_ELEMENTS( or );

	Rect s;
	int x, y, z;
	int istride;
	int ostride;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.height += mask->ysize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );

	istride = IM_REGION_LSKIP( ir ) / 
		IM_IMAGE_SIZEOF_ELEMENT( in );
	ostride = IM_REGION_LSKIP( or ) / 
		IM_IMAGE_SIZEOF_ELEMENT( boxes->out );

        /* Init offset array. 
	 */
	if( seq->last_stride != istride ) {
		seq->last_stride = istride;

		for( z = 0; z < n_velement; z++ ) 
			seq->start[z] = boxes->velement[z].band + 
				boxes->velement[z].row * istride;
	}

	switch( boxes->in->BandFmt ) {
	case IM_BANDFMT_UCHAR: 	

	for( x = 0; x < sz; x++ ) { 
		int *p; 
		PEL *q; 
		int sum; 

		p = x * boxes->n_hline + 
			(int *) IM_REGION_ADDR( ir, r->left, r->top ); 
		q = x + (PEL *) IM_REGION_ADDR( or, r->left, r->top ); 

		for( y = 0; y < r->height; y++ ) { 
			sum = 0; 
			for( z = 0; z < n_velement; z++ ) 
				sum += boxes->velement[z].factor * 
					p[seq->start[z]];
			p += istride;
			sum = (sum + boxes->rounding) / boxes->area; 
			CLIP_UCHAR( sum ); 
			*q = sum;
			q += ostride;
		}
	}

		break;

	/*
	case IM_BANDFMT_UCHAR: 	
		VCONV_INT( unsigned char, CLIP_UCHAR );
		break;

	case IM_BANDFMT_CHAR: 	
		VCONV_INT( signed char, CLIP_UCHAR );
		break;

	case IM_BANDFMT_USHORT: 	
		VCONV_INT( unsigned short, CLIP_USHORT );
		break;

	case IM_BANDFMT_SHORT: 	
		VCONV_INT( signed short, CLIP_SHORT );
		break;

	case IM_BANDFMT_UINT: 	
		VCONV_INT( unsigned int, CLIP_NONE );
		break;

	case IM_BANDFMT_INT: 	
		VCONV_INT( signed int, CLIP_NONE );
		break;

	case IM_BANDFMT_FLOAT: 	
		VCONV_FLOAT( float );
		break;

	case IM_BANDFMT_DOUBLE: 	
		VCONV_FLOAT( double );
		break;

	case IM_BANDFMT_COMPLEX: 	
		VCONV_FLOAT( float );
		break;

	case IM_BANDFMT_DPCOMPLEX: 	
		VCONV_FLOAT( double );
		break;
		 */

	default:
		g_assert( 0 );
	}

	return( 0 );
}

static int
aconv_vertical( Boxes *boxes, IMAGE *in, IMAGE *out )
{
	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Ysize -= boxes->mask->ysize - 1;
	if( out->Ysize <= 0 ) {
		im_error( "im_aconv", "%s", _( "image too small for mask" ) );
		return( -1 );
	}
	out->Bands = boxes->in->Bands;
	out->BandFmt = boxes->in->BandFmt;

	if( im_demand_hint( out, IM_SMALLTILE, in, NULL ) ||
		im_generate( out, 
			aconv_start, aconv_vgenerate, aconv_stop, in, boxes ) )
		return( -1 );

	out->Xoffset = -boxes->mask->xsize / 2;
	out->Yoffset = -boxes->mask->ysize / 2;

	return( 0 );
}

/**
 * im_aconv:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 * @n_layers: number of layers for approximation
 * @cluster: cluster lines closer than this distance
 *
 * Perform an approximate convolution of @in with @mask.
 *
 * The output image 
 * always has the same #VipsBandFmt as the input image. 
 *
 * Larger values for @n_layers give more accurate
 * results, but are slower. As @n_layers approaches the mask radius, the
 * accuracy will become close to exact convolution and the speed will drop to 
 * match. For many large masks, such as Gaussian, @n_layers need be only 10% of
 * this value and accuracy will still be good.
 *
 * Smaller values of @cluster will give more accurate results, but be slower
 * and use more memory. 10% of the mask radius is a good rule of thumb.
 *
 * See also: im_convsep_f(), im_create_dmaskv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_aconv( IMAGE *in, IMAGE *out, DOUBLEMASK *mask, int n_layers, int cluster )
{
	IMAGE *t[2];
	Boxes *boxes;

	if( !(boxes = boxes_new( in, out, mask, n_layers, cluster )) ||
		im_open_local_array( out, t, 2, "im_aconv", "p" ) )
		return( -1 );

	/*
	 */
	if( im_embed( in, t[0], 1, mask->xsize / 2, mask->ysize / 2, 
		in->Xsize + mask->xsize - 1, in->Ysize + mask->ysize - 1 ) ||
		aconv_horizontal( boxes, t[0], t[1] ) ||
		aconv_vertical( boxes, t[1], out ) )
		return( -1 );

	/* For testing .. just try one direction.
	if( aconv_horizontal( boxes, in, t[0] ) ||
		aconv_vertical( boxes, t[0], out ) )
		return( -1 );
	 */

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}

