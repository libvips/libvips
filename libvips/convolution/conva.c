/* conva ... approximate convolution
 *
 * This operation does an approximate convolution. 
 *
 * Author: John Cupitt & Nicolas Robidoux
 * Written on: 31/5/11
 * Modified on: 
 * 31/5/11
 *      - from im_aconvsep()
 * 10/7/16
 * 	- redone as a class
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

	- could we do better with an h and a v cumulativization image? we might 
	not need the huge intermediate we have now, since any line sum an be 
	found with simple indexing

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
#include <vips/internal.h>

#include "pconvolution.h"

/* Maximum number of boxes we can break the mask into. Don't have this too
 * high, it'll make the instance huge, and gobject has a 64kb limit. 
 */
#define MAX_LINES (1000)

/* The number of edges we consider at once in clustering. Higher values are
 * faster, but risk pushing up average error in the result.
 */
#define MAX_EDGES (1000)

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
typedef struct {
	VipsConvolution parent_instance;

	VipsImage *iM;

	int layers;
	int cluster;

	int area;
	int rounding;
	int offset;

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

} VipsConva;

typedef VipsConvolutionClass VipsConvaClass;

G_DEFINE_TYPE( VipsConva, vips_conva, VIPS_TYPE_CONVOLUTION );

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
vips_conva_hline_start( VipsConva *conva, int x )
{
	conva->hline[conva->n_hline].start = x;
	conva->hline[conva->n_hline].weight = 1;
}

static int
vips_conva_hline_end( VipsConva *conva, int x, int y, int factor )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( conva );

	conva->hline[conva->n_hline].end = x;

	conva->velement[conva->n_velement].row = y;
	conva->velement[conva->n_velement].band = conva->n_hline;
	conva->velement[conva->n_velement].factor = factor;

	if( conva->n_hline >= MAX_LINES - 1 ) {
		vips_error( class->nickname, "%s", _( "mask too complex" ) );
		return( -1 );
	}
	conva->n_hline += 1;

	if( conva->n_velement >= MAX_LINES - 1 ) {
		vips_error( class->nickname, "%s", _( "mask too complex" ) );
		return( -1 );
	}
	conva->n_velement += 1;

	return( 0 );
}

#ifdef DEBUG
static void
vips_conva_hprint( VipsConva *conva )
{
	int x, y;

	printf( "hlines:\n" );
	printf( "   n   b   r  f   w\n" );
	for( y = 0; y < conva->n_velement; y++ ) {
		int b = conva->velement[y].band;

		printf( "%4d %3d %3d %2d %3d ", 
			y, b, 
			conva->velement[y].row, 
			conva->velement[y].factor,
			conva->hline[b].weight );
		for( x = 0; x < 45; x++ ) {
			int rx = x * (conva->iM->Xsize + 1) / 45;

			if( rx >= conva->hline[b].start && 
				rx < conva->hline[b].end )
				printf( "#" );
			else
				printf( " " );
		}
		printf( " %3d .. %3d\n", 
			conva->hline[b].start, conva->hline[b].end );
	}
}

static void
vips_conva_vprint( VipsConva *conva )
{
	int y;

	printf( "%d vlines:\n", conva->n_vline );
	printf( "   n  b  f      s      e\n" );
	for( y = 0; y < conva->n_vline; y++ ) 
		printf( "%4d %2d %2d == %3d .. %3d\n", y,
			conva->vline[y].band, 
			conva->vline[y].factor, 
			conva->vline[y].start, 
			conva->vline[y].end );

	printf( "area = %d\n", conva->area );
	printf( "rounding = %d\n", conva->rounding );
	printf( "offset = %d\n", conva->offset );
	printf( "max_line = %d\n", conva->max_line );
}
#endif /*DEBUG*/

/* Break the mask into a set of lines.
 */
static int
vips_conva_decompose_lines( VipsConva *conva )
{
	VipsImage *iM = conva->iM;
	const int size = iM->Xsize * iM->Ysize;
	double *coeff = VIPS_MATRIX( iM, 0, 0 ); 

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
		max = VIPS_MAX( max, coeff[n] );
		min = VIPS_MIN( min, coeff[n] );
	}

	VIPS_DEBUG_MSG( "vips_conva_decompose: min = %g, max = %g\n", min, max );

	/* The zero axis must fall on a layer boundary. Estimate the
	 * depth, find n-lines-above-zero, get exact depth, then calculate a
	 * fixed n-lines which includes any negative parts.
	 */
	depth = (max - min) / conva->layers;
	layers_above = VIPS_CEIL( max / depth );
	depth = max / layers_above;
	layers_below = VIPS_FLOOR( min / depth );
	conva->layers = layers_above - layers_below;

	VIPS_DEBUG_MSG( "vips_conva_decompose: depth = %g, layers = %d\n", 
		depth, conva->layers );

	/* For each layer, generate a set of lines which are inside the
	 * perimeter. Work down from the top.
	 */
	for( z = 0; z < conva->layers; z++ ) {
		/* How deep we are into the mask, as a double we can test
		 * against. Add half the layer depth so we can easily find >50%
		 * mask elements.
		 */
		double z_ph = max - (1 + z) * depth + depth / 2;

		/* Odd, but we must avoid rounding errors that make us miss 0
		 * in the line above.
		 */
		int z_positive = z < layers_above;

		for( y = 0; y < iM->Ysize; y++ ) {
			int inside;

			/* Start outside the perimeter.
			 */
			inside = 0;

			for( x = 0; x < iM->Xsize; x++ ) {
				double c = coeff[x + y * iM->Xsize];

				/* The vertical line from mask[x, y] to 0 is 
				 * inside. Is our current square (x, y) part 
				 * of that line?
				 */
				if( (z_positive && c >= z_ph) ||
					(!z_positive && c <= z_ph) ) {
					if( !inside ) {
						vips_conva_hline_start( conva,
							x );
						inside = 1;
					}
				}
				else {
					if( inside ) {
						if( vips_conva_hline_end( conva,
							x, y, 
							z_positive ? 1 : -1 ) )
							return( -1 );
						inside = 0;
					}
				}
			}

			if( inside && 
				vips_conva_hline_end( conva, 
					iM->Xsize, y, z_positive ? 1 : -1 ) )
				return( -1 );
		}
	}

#ifdef DEBUG
	VIPS_DEBUG_MSG( "vips_conva_decompose: generated %d boxes\n", 
		conva->n_hline );
	vips_conva_hprint( conva );
#endif /*DEBUG*/

	return( 0 );
}

/* The 'distance' between a pair of hlines.
 */
static int
vips_conva_distance( VipsConva *conva, int a, int b )
{
	g_assert( conva->hline[a].weight > 0 && conva->hline[b].weight > 0 );

	return( abs( conva->hline[a].start - conva->hline[b].start ) + 
		abs( conva->hline[a].end - conva->hline[b].end ) ); 
}

/* Merge two hlines. Line b is deleted, and any refs to b in vlines updated to
 * point at a.
 */
static void
vips_conva_merge( VipsConva *conva, int a, int b )
{
	int i;

	/* Scale weights. 
	 */
	int fa = conva->hline[a].weight;
	int fb = conva->hline[b].weight;
	double w = (double) fb / (fa + fb);

	/* New endpoints.
	 */
	conva->hline[a].start += w * 
		(conva->hline[b].start - conva->hline[a].start);
	conva->hline[a].end += w * 
		(conva->hline[b].end - conva->hline[a].end);
	conva->hline[a].weight += conva->hline[b].weight;

	/* Update velement refs to b to refer to a instead.
	 */
	for( i = 0; i < conva->n_velement; i++ )
		if( conva->velement[i].band == b )
			conva->velement[i].band = a;

	/* Mark b to be deleted.
	 */
	conva->hline[b].weight = 0;
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
vips_conva_cluster2( VipsConva *conva )
{
	int i, j, k;
	int worst;
	int worst_i;
	int merged;

	for( i = 0; i < MAX_EDGES; i++ ) {
		conva->edge[i].a = -1;
		conva->edge[i].b = -1;
		conva->edge[i].d = 99999;
	}
	worst_i = 0;
	worst = conva->edge[worst_i].d;

	for( i = 0; i < conva->n_hline; i++ ) {
		if( conva->hline[i].weight == 0 )
			continue;

		for( j = i + 1; j < conva->n_hline; j++ ) {
			int distance;

			if( conva->hline[j].weight == 0 )
				continue;

			distance = vips_conva_distance( conva, i, j ); 
			if( distance < worst ) {
				conva->edge[worst_i].a = i;
				conva->edge[worst_i].b = j;
				conva->edge[worst_i].d = distance;

				worst_i = 0;
				worst = conva->edge[worst_i].d;
				for( k = 0; k < MAX_EDGES; k++ )
					if( conva->edge[k].d > worst ) {
						worst = conva->edge[k].d;
						worst_i = k;
					}
			}
		}
	}

	/* Sort to get closest first.
	 */
	qsort( conva->edge, MAX_EDGES, sizeof( Edge ), edge_sortfn );

	/*
	printf( "edges:\n" );
	printf( "  n   a   b  d:\n" );
	for( i = 0; i < MAX_EDGES; i++ )
		printf( "%2i) %3d %3d %3d\n", i, 
			conva->edge[i].a, conva->edge[i].b, conva->edge[i].d );
	 */

	/* Merge from the top down.
	 */
	merged = 0;
	for( k = 0; k < MAX_EDGES; k++ ) {
		Edge *edge = &conva->edge[k];

		if( edge->d > conva->cluster )
			break;

		/* Has been removed, see loop below.
		 */
		if( edge->a == -1 )
			continue;

		vips_conva_merge( conva, edge->a, edge->b );
		merged = 1;

		/* Nodes a and b have vanished or been moved. Remove any edges
		 * which refer to them from the edge list,
		 */
		for( i = k; i < MAX_EDGES; i++ ) {
			Edge *edgei = &conva->edge[i];

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
vips_conva_renumber( VipsConva *conva )
{
	int i, j;

	VIPS_DEBUG_MSG( "vips_conva_renumber: renumbering ...\n" );

	/* Loop for all zero-weight hlines.
	 */
	for( i = 0; i < conva->n_hline; ) {
		if( conva->hline[i].weight > 0 ) {
			i++;
			continue;
		}

		/* We move hlines i + 1 down, so we need to adjust all
		 * band[] refs to match.
		 */
		for( j = 0; j < conva->n_velement; j++ )
			if( conva->velement[j].band > i ) 
				conva->velement[j].band -= 1;

		memmove( conva->hline + i, conva->hline + i + 1, 
			sizeof( HLine ) * (conva->n_hline - i - 1) );
		conva->n_hline -= 1;
	}

	VIPS_DEBUG_MSG( "boxes_renumber: ... %d hlines remain\n", 
		conva->n_hline );
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
vips_conva_vline( VipsConva *conva )
{
	int y, z;

	VIPS_DEBUG_MSG( "vips_conva_vline: forming vlines ...\n" );

	/* Sort to get elements which could form a vline together.
	 */
	qsort( conva->velement, conva->n_velement, sizeof( VElement ), 
		velement_sortfn );

#ifdef DEBUG
	vips_conva_hprint( conva );
#endif /*DEBUG*/

	/* If two lines have the same row and band, we can join them and knock
	 * up the factor instead.
	 */
	for( y = 0; y < conva->n_velement; y++ ) {
		for( z = y + 1; z < conva->n_velement; z++ )
			if( conva->velement[z].band != 
				conva->velement[y].band ||
				conva->velement[z].row != 
					conva->velement[y].row )
				break;

		conva->velement[y].factor = z - y;
		memmove( conva->velement + y + 1, conva->velement + z,
			sizeof( VElement ) * (conva->n_velement - z) );
		conva->n_velement -= z - y - 1;
	}

#ifdef DEBUG
	printf( "after commoning up, %d velement remain\n", conva->n_velement );
	vips_conva_hprint( conva );
#endif /*DEBUG*/

	conva->n_vline = 0;
	for( y = 0; y < conva->n_velement; ) {
		int n = conva->n_vline;

		/* Start of a line.
		 */
		conva->vline[n].band = conva->velement[y].band;
		conva->vline[n].factor = conva->velement[y].factor;
		conva->vline[n].start = conva->velement[y].row;

		/* Search for the end of this line.
		 */
		for( z = y + 1; z < conva->n_velement; z++ ) 
			if( conva->velement[z].band != 
					conva->vline[n].band ||
				conva->velement[z].factor != 
					conva->vline[n].factor ||
				conva->velement[z].row != 
					conva->vline[n].start + z - y )
				break;

		/* So the line ends at the previously examined element. We
		 * want 'end' to be one beyond that (non-inclusive).
		 */
		conva->vline[n].end = conva->velement[z - 1].row + 1;

		conva->n_vline += 1;
		y = z;
	}

	VIPS_DEBUG_MSG( "vips_conva_vline: found %d vlines\n", conva->n_vline );
}

/* Break a mask into boxes.
 */
static int
vips_conva_decompose_boxes( VipsConva *conva )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( conva );
	VipsImage *iM = conva->iM;
	double *coeff = VIPS_MATRIX( iM, 0, 0 ); 
	const int size = iM->Xsize * iM->Ysize;
	double scale = vips_image_get_scale( iM ); 
	double offset = vips_image_get_offset( iM ); 

	double sum;
	int x, y, z;

	/* Break into a set of hlines.
	 */
	if( vips_conva_decompose_lines( conva ) )
		return( -1 );

	/* Cluster to find groups of lines.
	 */
	VIPS_DEBUG_MSG( "vips_conva_decompose_boxes: "
		"clustering with thresh %d ...\n", conva->cluster );
	while( vips_conva_cluster2( conva ) )
		;

	/* Renumber to remove holes created by clustering.
	 */
	vips_conva_renumber( conva );

	/* Find a set of vlines for the remaining hlines.
	 */
	vips_conva_vline( conva );

	/* Find the area of the lines and the length of the longest hline.
	 */
	conva->area = 0;
	conva->max_line = 0;
	for( y = 0; y < conva->n_velement; y++ ) {
		x = conva->velement[y].band;
		z = conva->hline[x].end - conva->hline[x].start;

		conva->area += conva->velement[y].factor * z;
		if( z > conva->max_line )
			conva->max_line = z;
	}

	/* Strength reduction: if all lines are divisible by n, we can move
	 * that n out into the ->area factor. The aim is to produce as many
	 * factor 1 lines as we can and to reduce the chance of overflow.
	 */
	x = conva->velement[0].factor;
	for( y = 1; y < conva->n_velement; y++ ) 
		x = gcd( x, conva->velement[y].factor );
	for( y = 0; y < conva->n_velement; y++ ) 
		conva->velement[y].factor /= x;
	conva->area *= x;

	/* Find the area of the original mask.
	 */
	sum = 0;
	for( z = 0; z < size; z++ ) 
		sum += coeff[z];

	conva->area = VIPS_RINT( sum * conva->area / scale );
	conva->rounding = (conva->area + 1) / 2;
	conva->offset = offset;

#ifdef DEBUG
	vips_conva_hprint( conva );
	vips_conva_vprint( conva );
#endif /*DEBUG*/

	/* With 512x512 tiles, each hline requires 3mb of intermediate per
	 * thread ... 300 lines is about a gb per thread, ouch.
	 */
	if( conva->n_hline > 150 ) {
		vips_error( class->nickname, "%s", _( "mask too complex" ) );
		return( -1 );
	}

	return( 0 );
}

/* Our sequence value.
 */
typedef struct {
	VipsConva *conva;

	VipsRegion *ir;		/* Input region */

	/* Offsets for start and stop. 
	 */
	int *start;		
	int *end;

	int last_stride;	/* Avoid recalcing offsets, if we can */

	/* The rolling sums. int for integer types, double for floating point 
	 * types.
	 */
	void *sum;		
} VipsConvaSeq;

/* Free a sequence value.
 */
static int
vips_conva_stop( void *vseq, void *a, void *b )
{
	VipsConvaSeq *seq = (VipsConvaSeq *) vseq;

	VIPS_UNREF( seq->ir );

	return( 0 );
}

/* Convolution start function.
 */
static void *
vips_conva_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsConva *conva = (VipsConva *) b;

	VipsConvaSeq *seq;

	seq = VIPS_NEW( out, VipsConvaSeq );
	seq->conva = conva;
	seq->ir = vips_region_new( in );

	/* n_velement should be the largest possible dimension.
	 */
	g_assert( conva->n_velement >= conva->n_hline );
	g_assert( conva->n_velement >= conva->n_vline );

	seq->start = VIPS_ARRAY( out, conva->n_velement, int );
	seq->end = VIPS_ARRAY( out, conva->n_velement, int );

	if( vips_band_format_isint( out->BandFmt ) )
		seq->sum = VIPS_ARRAY( out, conva->n_velement, int );
	else
		seq->sum = VIPS_ARRAY( out, conva->n_velement, double );
	seq->last_stride = -1;

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
		p = i + (IN *) VIPS_REGION_ADDR( ir, r->left, r->top + y ); \
		q = i * n_hline + \
			(OUT *) VIPS_REGION_ADDR( or, r->left, r->top + y ); \
		\
		for( z = 0; z < n_hline; z++ ) { \
			seq_sum[z] = 0; \
			for( x = conva->hline[z].start; \
				x < conva->hline[z].end; x++ ) \
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
vips_conva_hgenerate( VipsRegion *or, void *vseq, 
	void *a, void *b, gboolean *stop )
{
	VipsConvaSeq *seq = (VipsConvaSeq *) vseq;
	VipsImage *in = (VipsImage *) a;
	VipsConva *conva = (VipsConva *) b;

	VipsRegion *ir = seq->ir;
	const int n_hline = conva->n_hline;
	VipsImage *iM = conva->iM;
	VipsRect *r = &or->valid;

	/* Double the bands (notionally) for complex.
	 */
	int bands = vips_band_format_iscomplex( in->BandFmt ) ? 
		2 * in->Bands : in->Bands;

	VipsRect s;
	int x, y, z, i;
	int istride;
	int ostride;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += iM->Xsize - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	istride = VIPS_IMAGE_SIZEOF_PEL( in ) / 
		VIPS_IMAGE_SIZEOF_ELEMENT( in );
	ostride = VIPS_IMAGE_SIZEOF_PEL( or->im ) / 
		VIPS_IMAGE_SIZEOF_ELEMENT( or->im );

        /* Init offset array. 
	 */
	if( seq->last_stride != istride ) {
		seq->last_stride = istride;

		for( z = 0; z < n_hline; z++ ) {
			seq->start[z] = conva->hline[z].start * istride;
			seq->end[z] = conva->hline[z].end * istride;
		}
	}

	for( y = 0; y < r->height; y++ ) { 
		switch( in->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			if( conva->max_line > 256 )
				HCONV( unsigned char, unsigned int );
			else
				HCONV( unsigned char, unsigned short );
			break;

		case VIPS_FORMAT_CHAR: 	
			if( conva->max_line > 256 )
				HCONV( signed char, signed int );
			else
				HCONV( signed char, signed short );
			break;

		case VIPS_FORMAT_USHORT: 	
			HCONV( unsigned short, unsigned int );
			break;

		case VIPS_FORMAT_SHORT: 	
			HCONV( signed short, signed int );
			break;

		case VIPS_FORMAT_UINT: 	
			HCONV( unsigned int, unsigned int );
			break;

		case VIPS_FORMAT_INT: 	
			HCONV( signed int, signed int );
			break;

		case VIPS_FORMAT_FLOAT: 	
			HCONV( float, float );
			break;

		case VIPS_FORMAT_DOUBLE: 	
			HCONV( double, double );
			break;

		case VIPS_FORMAT_COMPLEX: 	
			HCONV( float, float );
			break;

		case VIPS_FORMAT_DPCOMPLEX: 	
			HCONV( double, double );
			break;

		default:
			g_assert_not_reached();
		}
	}

	return( 0 );
}

static int
vips_conva_horizontal( VipsConva *conva, VipsImage *in, VipsImage **out )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( conva );

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	*out = vips_image_new(); 
	if( vips_image_pipelinev( *out, 
		VIPS_DEMAND_STYLE_SMALLTILE, in, NULL ) )
		return( -1 );

	(*out)->Xsize -= conva->iM->Xsize - 1;
	if( (*out)->Xsize <= 0 ) { 
		vips_error( class->nickname, 
			"%s", _( "image too small for mask" ) );
		return( -1 );
	}
	(*out)->Bands *= conva->n_hline;

	/* Short u?char lines can use u?short intermediate.
	 */
	if( vips_band_format_isuint( in->BandFmt ) )
		(*out)->BandFmt = conva->max_line < 256 ? 
			VIPS_FORMAT_USHORT : VIPS_FORMAT_UINT;
	else if( vips_band_format_isint( in->BandFmt ) )
		(*out)->BandFmt = conva->max_line < 256 ? 
			VIPS_FORMAT_SHORT : VIPS_FORMAT_INT;

	if( vips_image_generate( *out, 
		vips_conva_start, vips_conva_hgenerate, vips_conva_stop, 
		in, conva ) )
		return( -1 );

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
		p = x * conva->n_hline + \
			(IN *) VIPS_REGION_ADDR( ir, r->left, r->top ); \
		q = x + (OUT *) VIPS_REGION_ADDR( or, r->left, r->top ); \
		\
		sum = 0; \
		for( z = 0; z < n_vline; z++ ) { \
			seq_sum[z] = 0; \
			for( k = conva->vline[z].start; \
				k < conva->vline[z].end; k++ ) \
				seq_sum[z] += p[k * istride + \
					conva->vline[z].band]; \
			sum += conva->vline[z].factor * seq_sum[z]; \
		} \
		sum = (sum + conva->rounding) / conva->area + conva->offset; \
		CLIP( sum ); \
		*q = sum; \
		q += ostride; \
		\
		for( y = 1; y < r->height; y++ ) { \
			sum = 0;\
			for( z = 0; z < n_vline; z++ ) { \
				seq_sum[z] += p[seq->end[z]]; \
				seq_sum[z] -= p[seq->start[z]]; \
				sum += conva->vline[z].factor * seq_sum[z]; \
			} \
			p += istride; \
			sum = (sum + conva->rounding) / conva->area + \
				conva->offset; \
			CLIP( sum ); \
			*q = sum; \
			q += ostride; \
		} \
	} \
} G_STMT_END

/* Do vertical masks ... we scan the mask down columns of pixels. 
 */
static int
vips_conva_vgenerate( VipsRegion *or, void *vseq, 
	void *a, void *b, gboolean *stop )
{
	VipsConvaSeq *seq = (VipsConvaSeq *) vseq;
	VipsImage *in = (VipsImage *) a;
	VipsConva *conva = (VipsConva *) b;
	VipsConvolution *convolution = (VipsConvolution *) conva;

	VipsRegion *ir = seq->ir;
	const int n_vline = conva->n_vline;
	VipsImage *iM = conva->iM;
	VipsRect *r = &or->valid;

	/* Double the width (notionally) for complex.
	 */
	int sz = vips_band_format_iscomplex( in->BandFmt ) ? 
		2 * VIPS_REGION_N_ELEMENTS( or ) : VIPS_REGION_N_ELEMENTS( or );

	VipsRect s;
	int x, y, z, k;
	int istride;
	int ostride;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.height += iM->Ysize - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	istride = VIPS_REGION_LSKIP( ir ) / 
		VIPS_IMAGE_SIZEOF_ELEMENT( in );
	ostride = VIPS_REGION_LSKIP( or ) / 
		VIPS_IMAGE_SIZEOF_ELEMENT( convolution->out );

        /* Init offset array. 
	 */
	if( seq->last_stride != istride ) {
		seq->last_stride = istride;

		for( z = 0; z < n_vline; z++ ) {
			seq->start[z] = conva->vline[z].band + 
				conva->vline[z].start * istride;
			seq->end[z] = conva->vline[z].band + 
				conva->vline[z].end * istride;
		}
	}

	switch( convolution->in->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	
		if( conva->max_line > 256 )
			VCONV( unsigned int, \
				unsigned int, unsigned char, CLIP_UCHAR );
		else
			VCONV( unsigned int, \
				unsigned short, unsigned char, CLIP_UCHAR );
		break;

	case VIPS_FORMAT_CHAR: 	
		if( conva->max_line > 256 )
			VCONV( signed int, \
				signed int, signed char, CLIP_CHAR );
		else
			VCONV( signed int, \
				signed short, signed char, CLIP_CHAR );
		break;

	case VIPS_FORMAT_USHORT: 	
		VCONV( unsigned int, \
			unsigned int, unsigned short, CLIP_USHORT );
		break;

	case VIPS_FORMAT_SHORT: 	
		VCONV( signed int, signed int, signed short, CLIP_SHORT );
		break;

	case VIPS_FORMAT_UINT: 	
		VCONV( unsigned int, unsigned int, unsigned int, CLIP_NONE );
		break;

	case VIPS_FORMAT_INT: 	
		VCONV( signed int, signed int, signed int, CLIP_NONE );
		break;

	case VIPS_FORMAT_FLOAT: 	
		VCONV( float, float, float, CLIP_NONE );
		break;

	case VIPS_FORMAT_DOUBLE: 	
		VCONV( double, double, double, CLIP_NONE );
		break;

	case VIPS_FORMAT_COMPLEX: 	
		VCONV( float, float, float, CLIP_NONE );
		break;

	case VIPS_FORMAT_DPCOMPLEX: 	
		VCONV( double, double, double, CLIP_NONE );
		break;

	default:
		g_assert_not_reached();
	}

	return( 0 );
}

static int
vips_conva_vertical( VipsConva *conva, VipsImage *in, VipsImage **out )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( conva );
	VipsConvolution *convolution = (VipsConvolution *) conva;

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	*out = vips_image_new(); 
	if( vips_image_pipelinev( *out, 
		VIPS_DEMAND_STYLE_SMALLTILE, in, NULL ) )
		return( -1 );

	(*out)->Ysize -= conva->iM->Ysize - 1;
	if( (*out)->Ysize <= 0 ) { 
		vips_error( class->nickname, 
			"%s", _( "image too small for mask" ) );
		return( -1 );
	}
	(*out)->Bands = convolution->in->Bands;
	(*out)->BandFmt = convolution->in->BandFmt;

	if( vips_image_generate( *out, 
		vips_conva_start, vips_conva_vgenerate, vips_conva_stop, 
		in, conva ) )
		return( -1 );

	return( 0 );
}

static int
vips_conva_build( VipsObject *object )
{
	VipsConvolution *convolution = (VipsConvolution *) object;
	VipsConva *conva = (VipsConva *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_conva_parent_class )->build( object ) )
		return( -1 );

	/* An int version of our mask.
	 */
	if( vips__image_intize( convolution->M, &t[0] ) )
		return( -1 );
	conva->iM = t[0]; 

	in = convolution->in;

	if( vips_conva_decompose_boxes( conva ) )
	       return( -1 ); 	

	g_object_set( conva, "out", vips_image_new(), NULL ); 
	if( 
		vips_embed( in, &t[1], 
			t[0]->Xsize / 2, 
			t[0]->Ysize / 2, 
			in->Xsize + t[0]->Xsize - 1, 
			in->Ysize + t[0]->Ysize - 1,
			"extend", VIPS_EXTEND_COPY,
			NULL ) ||
		vips_conva_horizontal( conva, t[1], &t[2] ) ||
		vips_conva_vertical( conva, t[2], &t[3] ) ||
		vips_image_write( t[3], convolution->out ) )
		return( -1 );

	convolution->out->Xoffset = 0;
	convolution->out->Yoffset = 0;

	return( 0 );
}

static void
vips_conva_class_init( VipsConvaClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "conva";
	object_class->description = _( "approximate integer convolution" );
	object_class->build = vips_conva_build;

	VIPS_ARG_INT( class, "layers", 104, 
		_( "Layers" ), 
		_( "Use this many layers in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsConva, layers ), 
		1, 1000, 5 ); 

	VIPS_ARG_INT( class, "cluster", 105, 
		_( "Cluster" ), 
		_( "Cluster lines closer than this in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsConva, cluster ), 
		1, 100, 1 ); 

}

static void
vips_conva_init( VipsConva *conva )
{
        conva->layers = 5;
        conva->cluster = 1;
}

/**
 * vips_conva:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @layers: %gint, number of layers for approximation
 * * @cluster: %gint, cluster lines closer than this distance
 *
 * Perform an approximate integer convolution of @in with @mask.
 * This is a low-level operation, see 
 * vips_conv() for something more convenient. 
 *
 * The output image 
 * always has the same #VipsBandFormat as the input image. 
 * Elements of @mask are converted to
 * integers before convolution.
 *
 * Larger values for @layers give more accurate
 * results, but are slower. As @layers approaches the mask radius, the
 * accuracy will become close to exact convolution and the speed will drop to 
 * match. For many large masks, such as Gaussian, @layers need be only 10% of
 * this value and accuracy will still be good.
 *
 * Smaller values of @cluster will give more accurate results, but be slower
 * and use more memory. 10% of the mask radius is a good rule of thumb.
 *
 * See also: vips_conv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_conva( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
{
	va_list ap;
	int result;

	va_start( ap, mask );
	result = vips_call_split( "conva", ap, in, out, mask );
	va_end( ap );

	return( result );
}

