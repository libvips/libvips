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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

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
real	5m3.359s
user	9m34.700s
sys	0m1.500s

$ time vips im_aconv img_0075.jpg x.v g2d201.con 10 10
real	0m3.151s
user	0m5.640s
sys	0m0.100s

$ vips im_subtract x.v x2.v diff.v
$ vips im_abs diff.v abs.v
$ vips im_max abs.v
2.70833

  	- are we handling mask offset correctly?

 */

/*
#define DEBUG
#define VIPS_DEBUG
 */

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

/* Maximum number of boxes we can break the mask into.
 */
#define MAX_LINES (10000)

/* The number of edges we consider at once in clustering. Higher values are
 * faster, but risk pushing up average error in the result.
 */
#define MAX_EDGES (1000)

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

/* For clustering. A pair of hlines and their distance. An edge in a graph.
 */
typedef struct _Edge {
	/* The index into boxes->hline[].
	 */
	int a;
	int b;

	/* The distance between them, see boxes_distance().
	 */
	int d;
} Edge;

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
	 * intermediate image. max_line is the length of the longest hline:
	 * over 256 and we need to use an int intermediate for 8-bit images.
	 */
	int n_hline;
	HLine hline[MAX_LINES];
	int max_line;

	/* During clustering, the top few edges we are considering.
	 */
	Edge edge[MAX_EDGES];

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

#ifdef DEBUG
static void
boxes_hprint( Boxes *boxes )
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
}

static void
boxes_vprint( Boxes *boxes )
{
	int y;

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
	printf( "max_line = %d\n", boxes->max_line );
}
#endif /*DEBUG*/

/* Break the mask into a set of lines.
 */
static int
boxes_break( Boxes *boxes )
{
	DOUBLEMASK *mask = boxes->mask;
	const int size = mask->xsize * mask->ysize;

	double max;
	double min;
	double depth;
	int layers_above;
	int layers_below;
	int z, n, x, y;

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
	depth = (max - min) / boxes->n_layers;
	layers_above = VIPS_CEIL( max / depth );
	depth = max / layers_above;
	layers_below = VIPS_FLOOR( min / depth );

	boxes->n_layers = layers_above - layers_below;

	VIPS_DEBUG_MSG( "boxes_new: depth = %g, n_layers = %d\n", 
		depth, boxes->n_layers );

	/* For each layer, generate a set of lines which are inside the
	 * perimeter. Work down from the top.
	 */
	for( z = 0; z < boxes->n_layers; z++ ) {
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
						if( boxes_end( boxes, x, y,
							z_positive ? 1 : -1 ) )
							return( -1 );
						inside = 0;
					}
				}
			}

			if( inside && 
				boxes_end( boxes, mask->xsize, y, 
					z_positive ? 1 : -1 ) )
				return( -1 );
		}
	}

#ifdef DEBUG
	VIPS_DEBUG_MSG( "boxes_new: generated %d boxes\n", boxes->n_hline );
	boxes_hprint( boxes );
#endif /*DEBUG*/

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

static int
edge_sortfn( const void *p1, const void *p2 )
{
	Edge *a = (Edge *) p1;
	Edge *b = (Edge *) p2;

	return( a->d - b->d );
}

/* Cluster in batches. Return non-zero if we merged some lines.
 *
 * This is not as accurate as rescanning the whole space on every merge, but
 * it's far faster.
 */
static int
boxes_cluster2( Boxes *boxes, int cluster )
{
	int i, j, k;
	int worst;
	int worst_i;
	int merged;

	for( i = 0; i < MAX_EDGES; i++ ) {
		boxes->edge[i].a = -1;
		boxes->edge[i].b = -1;
		boxes->edge[i].d = 99999;
	}
	worst_i = 0;
	worst = boxes->edge[worst_i].d;

	for( i = 0; i < boxes->n_hline; i++ ) {
		if( boxes->hline[i].weight == 0 )
			continue;

		for( j = i + 1; j < boxes->n_hline; j++ ) {
			int distance;

			if( boxes->hline[j].weight == 0 )
				continue;

			distance = boxes_distance( boxes, i, j ); 
			if( distance < worst ) {
				boxes->edge[worst_i].a = i;
				boxes->edge[worst_i].b = j;
				boxes->edge[worst_i].d = distance;

				worst_i = 0;
				worst = boxes->edge[worst_i].d;
				for( k = 0; k < MAX_EDGES; k++ )
					if( boxes->edge[k].d > worst ) {
						worst = boxes->edge[k].d;
						worst_i = k;
					}
			}
		}
	}

	/* Sort to get closest first.
	 */
	qsort( boxes->edge, MAX_EDGES, sizeof( Edge ), edge_sortfn );

	/*
	printf( "edges:\n" );
	printf( "  n   a   b  d:\n" );
	for( i = 0; i < MAX_EDGES; i++ )
		printf( "%2i) %3d %3d %3d\n", i, 
			boxes->edge[i].a, boxes->edge[i].b, boxes->edge[i].d );
	 */

	/* Merge from the top down.
	 */
	merged = 0;
	for( k = 0; k < MAX_EDGES; k++ ) {
		Edge *edge = &boxes->edge[k];

		if( edge->d > cluster )
			break;

		/* Has been removed, see loop below.
		 */
		if( edge->a == -1 )
			continue;

		boxes_merge( boxes, edge->a, edge->b );
		merged = 1;

		/* Nodes a and b have vanished or been moved. Remove any edges
		 * which refer to them from the edge list,
		 */
		for( i = k; i < MAX_EDGES; i++ ) {
			Edge *edgei = &boxes->edge[i];

			if( edgei->a == edge->a ||
				edgei->b == edge->a ||
				edgei->a == edge->b ||
				edgei->b == edge->b )
				edgei->a = -1;
		}
	}

	return( merged );
}

/* Renumber after clustering. We will have removed a lot of hlines ... shuffle
 * the rest down, adjust all the vline references.
 */
static void
boxes_renumber( Boxes *boxes )
{
	int i, j;

	VIPS_DEBUG_MSG( "boxes_renumber: renumbering ...\n" );

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

	VIPS_DEBUG_MSG( "boxes_renumber: ... %d hlines remain\n", 
		boxes->n_hline );
}

/* Sort by band, then factor, then row.
 */
static int
velement_sortfn( const void *p1, const void *p2 )
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

	VIPS_DEBUG_MSG( "boxes_vline: forming vlines ...\n" );

	/* Sort to get elements which could form a vline together.
	 */
	qsort( boxes->velement, boxes->n_velement, sizeof( VElement ), 
		velement_sortfn );

#ifdef DEBUG
	boxes_hprint( boxes );
#endif /*DEBUG*/

	/* If two lines have the same row and band, we can join them and knock
	 * up the factor instead.
	 */
	for( y = 0; y < boxes->n_velement; y++ ) {
		for( z = y + 1; z < boxes->n_velement; z++ )
			if( boxes->velement[z].band != 
				boxes->velement[y].band ||
				boxes->velement[z].row != 
					boxes->velement[y].row )
				break;

		boxes->velement[y].factor = z - y;
		memmove( boxes->velement + y + 1, boxes->velement + z,
			sizeof( VElement ) * (boxes->n_velement - z) );
		boxes->n_velement -= z - y - 1;
	}

#ifdef DEBUG
	printf( "after commoning up, %d velement remain\n", boxes->n_velement );
	boxes_hprint( boxes );
#endif /*DEBUG*/

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

	VIPS_DEBUG_MSG( "boxes_vline: found %d vlines\n", boxes->n_vline );
}

/* Break a mask into boxes.
 */
static Boxes *
boxes_new( IMAGE *in, IMAGE *out, DOUBLEMASK *mask, int n_layers, int cluster )
{
	const int size = mask->xsize * mask->ysize;

	Boxes *boxes;
	double sum;
	int x, y, z;

	/* Check parameters.
	 */
	if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_aconv", in ) ||
		vips_check_dmask( "im_aconv", mask ) ) 
		return( NULL );

	boxes = VIPS_NEW( out, Boxes );
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

	/* Break into a set of hlines.
	 */
	if( boxes_break( boxes ) )
		return( NULL );

	/* Cluster to find groups of lines.
	 */
	VIPS_DEBUG_MSG( "boxes_new: clustering with thresh %d ...\n", cluster );
	while( boxes_cluster2( boxes, cluster ) )
		;

	/* Renumber to remove holes created by clustering.
	 */
	boxes_renumber( boxes );

	/* Find a set of vlines for the remaining hlines.
	 */
	boxes_vline( boxes );

	/* Find the area of the lines and the length of the longest hline.
	 */
	boxes->area = 0;
	boxes->max_line = 0;
	for( y = 0; y < boxes->n_velement; y++ ) {
		x = boxes->velement[y].band;
		z = boxes->hline[x].end - boxes->hline[x].start;

		boxes->area += boxes->velement[y].factor * z;
		if( z > boxes->max_line )
			boxes->max_line = z;
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
	boxes_hprint( boxes );
	boxes_vprint( boxes );
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

	/* Offsets for start and stop. 
	 */
	int *start;		
	int *end;

	int last_stride;	/* Avoid recalcing offsets, if we can */

	/* The rolling sums. int for integer types, double for floating point 
	 * types.
	 */
	void *sum;		
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
	g_assert( boxes->n_velement >= boxes->n_vline );

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

/* The h and v loops are very similar, but also annoyingly different. Keep
 * them separate for easy debugging.
 */

#define HCONV( IN, OUT ) \
G_STMT_START { \
	for( i = 0; i < bands; i++ ) { \
		OUT *seq_sum = (OUT *) seq->sum; \
		\
		IN *p; \
		OUT *q; \
		\
		p = i + (IN *) IM_REGION_ADDR( ir, r->left, r->top + y ); \
		q = i * n_hline + \
			(OUT *) IM_REGION_ADDR( or, r->left, r->top + y ); \
		\
		for( z = 0; z < n_hline; z++ ) { \
			seq_sum[z] = 0; \
			for( x = boxes->hline[z].start; \
				x < boxes->hline[z].end; x++ ) \
				seq_sum[z] += p[x * istride]; \
			q[z] = seq_sum[z]; \
		} \
		q += ostride; \
		\
		for( x = 1; x < r->width; x++ ) {  \
			for( z = 0; z < n_hline; z++ ) { \
				seq_sum[z] += p[seq->end[z]]; \
				seq_sum[z] -= p[seq->start[z]]; \
				q[z] = seq_sum[z]; \
			} \
			p += istride; \
			q += ostride; \
		} \
	} \
} G_STMT_END

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
			if( boxes->max_line > 256 )
				HCONV( unsigned char, unsigned int );
			else
				HCONV( unsigned char, unsigned short );
			break;

		case IM_BANDFMT_CHAR: 	
			if( boxes->max_line > 256 )
				HCONV( signed char, signed int );
			else
				HCONV( signed char, signed short );
			break;

		case IM_BANDFMT_USHORT: 	
			HCONV( unsigned short, unsigned int );
			break;

		case IM_BANDFMT_SHORT: 	
			HCONV( signed short, signed int );
			break;

		case IM_BANDFMT_UINT: 	
			HCONV( unsigned int, unsigned int );
			break;

		case IM_BANDFMT_INT: 	
			HCONV( signed int, signed int );
			break;

		case IM_BANDFMT_FLOAT: 	
			HCONV( float, float );
			break;

		case IM_BANDFMT_DOUBLE: 	
			HCONV( double, double );
			break;

		case IM_BANDFMT_COMPLEX: 	
			HCONV( float, float );
			break;

		case IM_BANDFMT_DPCOMPLEX: 	
			HCONV( double, double );
			break;

		default:
			g_assert_not_reached();
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

	/* Short u?char lines can use u?short intermediate.
	 */
	if( vips_band_format_isuint( in->BandFmt ) )
		out->BandFmt = boxes->max_line < 256 ? 
			IM_BANDFMT_USHORT : IM_BANDFMT_UINT;
	else if( vips_band_format_isint( in->BandFmt ) )
		out->BandFmt = boxes->max_line < 256 ? 
			IM_BANDFMT_SHORT : IM_BANDFMT_INT;

	if( im_demand_hint( out, IM_SMALLTILE, in, NULL ) ||
		im_generate( out, 
			aconv_start, aconv_hgenerate, aconv_stop, in, boxes ) )
		return( -1 );

	out->Xoffset = -boxes->mask->xsize / 2;
	out->Yoffset = -boxes->mask->ysize / 2;

	return( 0 );
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

#define VCONV( ACC, IN, OUT, CLIP ) \
G_STMT_START { \
	for( x = 0; x < sz; x++ ) { \
		ACC *seq_sum = (ACC *) seq->sum; \
		\
		IN *p; \
		OUT *q; \
		ACC sum; \
		\
		p = x * boxes->n_hline + \
			(IN *) IM_REGION_ADDR( ir, r->left, r->top ); \
		q = x + (OUT *) IM_REGION_ADDR( or, r->left, r->top ); \
		\
		sum = 0; \
		for( z = 0; z < n_vline; z++ ) { \
			seq_sum[z] = 0; \
			for( k = boxes->vline[z].start; \
				k < boxes->vline[z].end; k++ ) \
				seq_sum[z] += p[k * istride + \
					boxes->vline[z].band]; \
			sum += boxes->vline[z].factor * seq_sum[z]; \
		} \
		sum = (sum + boxes->rounding) / boxes->area; \
		CLIP( sum ); \
		*q = sum; \
		q += ostride; \
		\
		for( y = 1; y < r->height; y++ ) { \
			sum = 0;\
			for( z = 0; z < n_vline; z++ ) { \
				seq_sum[z] += p[seq->end[z]]; \
				seq_sum[z] -= p[seq->start[z]]; \
				sum += boxes->vline[z].factor * seq_sum[z]; \
			} \
			p += istride; \
			sum = (sum + boxes->rounding) / boxes->area; \
			CLIP( sum ); \
			*q = sum; \
			q += ostride; \
		} \
	} \
} G_STMT_END

/* Do vertical masks ... we scan the mask down columns of pixels. 
 */
static int
aconv_vgenerate( REGION *or, void *vseq, void *a, void *b )
{
	AConvSequence *seq = (AConvSequence *) vseq;
	IMAGE *in = (IMAGE *) a;
	Boxes *boxes = (Boxes *) b;

	REGION *ir = seq->ir;
	const int n_vline = boxes->n_vline;
	DOUBLEMASK *mask = boxes->mask;
	Rect *r = &or->valid;

	/* Double the width (notionally) for complex.
	 */
	int sz = vips_band_format_iscomplex( in->BandFmt ) ? 
		2 * IM_REGION_N_ELEMENTS( or ) : IM_REGION_N_ELEMENTS( or );

	Rect s;
	int x, y, z, k;
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

		for( z = 0; z < n_vline; z++ ) {
			seq->start[z] = boxes->vline[z].band + 
				boxes->vline[z].start * istride;
			seq->end[z] = boxes->vline[z].band + 
				boxes->vline[z].end * istride;
		}
	}

	switch( boxes->in->BandFmt ) {
	case IM_BANDFMT_UCHAR: 	
		if( boxes->max_line > 256 )
			VCONV( unsigned int, \
				unsigned int, unsigned char, CLIP_UCHAR );
		else
			VCONV( unsigned int, \
				unsigned short, unsigned char, CLIP_UCHAR );
		break;

	case IM_BANDFMT_CHAR: 	
		if( boxes->max_line > 256 )
			VCONV( signed int, \
				signed int, signed char, CLIP_UCHAR );
		else
			VCONV( signed int, \
				signed short, signed char, CLIP_UCHAR );
		break;

	case IM_BANDFMT_USHORT: 	
		VCONV( unsigned int, \
			unsigned int, unsigned short, CLIP_USHORT );
		break;

	case IM_BANDFMT_SHORT: 	
		VCONV( signed int, signed int, signed short, CLIP_SHORT );
		break;

	case IM_BANDFMT_UINT: 	
		VCONV( unsigned int, unsigned int, unsigned int, CLIP_NONE );
		break;

	case IM_BANDFMT_INT: 	
		VCONV( signed int, signed int, signed int, CLIP_NONE );
		break;

	case IM_BANDFMT_FLOAT: 	
		VCONV( float, float, float, CLIP_NONE );
		break;

	case IM_BANDFMT_DOUBLE: 	
		VCONV( double, double, double, CLIP_NONE );
		break;

	case IM_BANDFMT_COMPLEX: 	
		VCONV( float, float, float, CLIP_NONE );
		break;

	case IM_BANDFMT_DPCOMPLEX: 	
		VCONV( double, double, double, CLIP_NONE );
		break;

	default:
		g_assert_not_reached();
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
 * always has the same #VipsBandFormat as the input image. 
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
	if( aconv_horizontal( boxes, in, out ) )
		return( -1 );
	 */

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}

