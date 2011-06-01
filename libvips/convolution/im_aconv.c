/* im_aconv ... approximate convolution
 *
 * This operation does an approximate, seperable convolution. 
 *
 * Author: John Cupitt & Nicolas Robidoux
 * Written on: 31/5/11
 * Modified on: 
 * 31/5/11
 *      - from im_conv()
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

/* Show sample pixels as they are transformed.
#define DEBUG_PIXELS
 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/vector.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Maximum number of lines we can break the mask into.
 */
#define MAX_LINES (1000)

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

/* A set of lines.
 */
typedef struct _Lines {
	/* Copy of our arguments.
	 */
	IMAGE *in;
	IMAGE *out;
	DOUBLEMASK *mask;
	int n_lines;

	int area;
	int rounding;

	/* Start is the left-most pixel in the line, end is one beyond the
	 * right-most pixel.
	 */
	int n_lines;
	int start[MAX_LINES];
	int end[MAX_LINES];
	int factor[MAX_LINES];
} Lines;

static void
line_start( Lines *lines, int x, int factor )
{
	lines->start[lines->n_lines] = x;
	lines->factor[lines->n_lines] = factor;
}

static int
line_end( Lines *lines, int x )
{
	lines->end[lines->n_lines] = x;
	lines->n_lines += 1;

	if( lines->n_lines >= MAX_LINES ) {
		vips_error( "im_aconv", "%s", _( "mask too complex" ) );
		return( -1 );
	}

	return( 0 );
}

/* Break a mask into lines.
 */
static Lines *
lines_new( IMAGE *in, IMAGE *out, DOUBLEMASK *mask, int n_lines )
{
	const int width = mask->xsize * mask->ysize;

	Lines *lines;
	double max;
	double min;
	double depth;
	int lines_above;
	int lines_below;
	int z, n, x;

	/* Check parameters.
	 */
	if( vips_image_pio_input( in ) ||
		vips_image_pio_output( out ) ||
		vips_check_uncoded( "im_aconv", in ) ||
		vips_check_dmask_1d( "im_aconv", mask ) ) 
		return( NULL );

	if( !(lines = VIPS_NEW( out, Lines )) )
		return( NULL );
	lines->in = in;
	lines->out = out;
	if( !(lines->mask = (DOUBLEMASK *) im_local( out, 
		(im_construct_fn) im_dup_dmask,
		(im_callback_fn) im_free_dmask, mask, mask->filename, NULL )) )
		return( NULL );
	lines->n_lines = n_lines;
	lines->n_lines = 0;

	VIPS_DEBUG_MSG( "lines_new: breaking into %d lines ...\n", n_lines );

	/* Find mask range. We must always include the zero axis in the mask.
	 */
	max = 0;
	min = 0;
	for( x = 0; x < width; x++ ) {
		if( mask->coeff[x] > max )
			max = mask->coeff[x];
		if( mask->coeff[x] < min )
			min = mask->coeff[x];
	}

	/* The zero axis must fall on a layer boundary. Estimate the
	 * depth, find n-lines-above-zero, get exact depth, then calculate a
	 * fixed n-lines which includes any negative parts.
	 */
	depth = (max - min) / n_lines;
	lines_above = ceil( max / depth );
	depth = max / lines_above;
	lines_below = floor( min / depth );
	n_lines = lines_above - lines_below;

	VIPS_DEBUG_MSH( "depth = %g, n_lines = %d\n", depth, n_lines );

	/* For each layer, generate a set of lines which are inside the
	 * perimeter. Work down from the top.
	 */
	for( z = 0; z < n_lines; z++ ) {
		double y = max - (1 + z) * depth;

		/* Odd, but we must avoid rounding errors that make us miss 0
		 * in the line above.
		 */
		int y_positive = z < lines_above;

		int inside;

		/* Start outside the perimeter.
		 */
		inside = 0;

		for( x = 0; x < width; x++ ) {
			/* The vertical line from mask[z] to 0 is inside. Is
			 * our current square (x, y) part of that line?
			 */
			if( (y_positive && mask->coeff[x] > y + depth / 2) ||
				(!y_positive && mask->coeff[x] < y + depth / 2) ) {
				/* (x, y) is inside.
				 */
				if( !inside ) {
					line_start( lines, 
						x, y_positive ? 1 : -1 );
					inside = 1;
				}
			}
			else {
				/* (x, y) is outside.
				 */
				if( inside ) {
					if( line_end( lines, x ) )
						return( NULL );
					inside = 0;
				}
			}
		}

		if( inside && 
			line_end( lines, mask->xsize - 1 ) )
			return( NULL );
	}

	/* Can we common up any lines? Search for lines with identical
	 * start/end.
	 */
	for( z = 0; z < lines->n_lines; z++ ) {
		for( n = z + 1; n < lines->n_lines; n++ ) {
			if( lines->start[z] == lines->start[n] &&
				lines->end[z] == lines->end[n] ) {
				lines->factor[z] += lines->factor[n];

				/* n can be deleted. Do this in a separate
				 * pass below.
				 */
				lines->factor[n] = 0;
			}
		}
	}

	/* Now we can remove all factor 0 lines.
	 */
	for( z = 0; z < lines->n_lines; z++ ) {
		if( lines->factor[z] == 0 ) {
			for( x = z; x < lines->n_lines; x++ ) {
				lines->start[x] = lines->start[x + 1];
				lines->end[x] = lines->end[x + 1];
				lines->factor[x] = lines->factor[x + 1];
			}
			lines->n_lines -= 1;
		}
	}

	/* Find the area of the lines.
	 */
	lines->area = 0;
	for( z = 0; z < lines->n_lines; z++ ) 
		lines->area += lines->factor[z] * 
			(lines->end[z] - lines->start[z]);

	/* Strength reduction: if all lines are divisible by n, we can move
	 * that n out into the ->area factor. The aim is to produce as many
	 * factor 1 lines as we can and to reduce the chance of overflow.
	 */
	x = lines->factor[0];
	for( z = 1; z < lines->n_lines; z++ ) 
		x = gcd( x, lines->factor[z] );
	for( z = 0; z < lines->n_lines; z++ ) 
		lines->factor[z] /= x;
	lines->area *= x;
	lines->rounding = (lines->area + 1) / 2;

	/* ASCII-art layer drawing.
	 */
	printf( "lines:\n" );
	for( z = 0; z < lines->n_lines; z++ ) {
		printf( "%3d - %2d x ", z, lines->factor[z] );
		for( x = 0; x < 55; x++ ) {
			int rx = x * width / 55;

			if( rx >= lines->start[z] && rx < lines->end[z] )
				printf( "#" );
			else
				printf( " " );
		}
		printf( " %3d .. %3d\n", lines->start[z], lines->end[z] );
	}
	printf( "area = %d\n", lines->area );
	printf( "rounding = %d\n", lines->rounding );

	return( lines );
}

/* Our sequence value.
 */
typedef struct {
	Lines *lines;
	REGION *ir;		/* Input region */

	int *start;		/* Offsets for start and stop */
	int *end;
	int last_bpl;		/* Avoid recalcing offsets, if we can */

	PEL **startp;		/* Pixel pointers */
	PEL **endp;
} LinesSequence;

/* Free a sequence value.
 */
static int
lines_stop( void *vseq, void *a, void *b )
{
	LinesSequence *seq = (LinesSequence *) vseq;

	IM_FREEF( im_region_free, seq->ir );

	return( 0 );
}

/* Convolution start function.
 */
static void *
lines_start( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	Lines *lines = (Lines *) b;
	DOUBLEMASK *mask = lines->mask;
	const int n_mask = mask->xsize * mask->ysize;

	LinesSequence *seq;

	if( !(seq = IM_NEW( out, LinesSequence )) )
		return( NULL );

	/* Init!
	 */
	seq->lines = lines;
	seq->ir = im_region_create( in );
	seq->start = IM_ARRAY( out, lines->n_lines, int );
	seq->end = IM_ARRAY( out, lines->n_lines, int );
	seq->startp = IM_ARRAY( out, lines->n_lines, PEL * );
	seq->endp = IM_ARRAY( out, lines->n_lines, PEL * );
	seq->last_bpl = -1;

	if( !seq->ir || 
		!seq->start || !seq->end || 
		!seq->startp || !seq->endp ) {
		lines_stop( seq, in, lines );
		return( NULL );
	}

	return( seq );
}

static int
lines_generate( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE *in = (IMAGE *) a;
	Lines *lines = (Lines *) b;
	const int n_lines = lines->n_lines;
	DOUBLEMASK *mask = lines->mask;
	Rect *r = &or->valid;

	Rect s;
	int x, y, z;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += mask->xsize - 1;
	s.height += mask->ysize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );

        /* Fill offset array. Only do this if the bpl has changed since the 
	 * previous im_prepare().
	 */
	if( seq->last_bpl != IM_REGION_LSKIP( ir ) ) {
		seq->last_bpl = IM_REGION_LSKIP( ir );

		for( z = 0; z < n_lines; z++ ) {
			x = mask->xsize == 1 ? 1 : lines->start[z];
			y = mask->ysize == 1 ? 1 : lines->start[z];
			seq->start[z] = 
				IM_REGION_ADDR( ir, x + r->left, y + r->top ) -
				IM_REGION_ADDR( ir, r->left, r->top );

			x = mask->xsize == 1 ? 1 : lines->end[z];
			y = mask->ysize == 1 ? 1 : lines->end[z];
			seq->end[z] = 
				IM_REGION_ADDR( ir, x + r->left, y + r->top ) -
				IM_REGION_ADDR( ir, r->left, r->top );
		}
	}

	for( y = 0; y < r->height; y++ ) { 
		PEL *q = (PEL *) IM_REGION_ADDR( or, r->left, r->top + y ); 
		PEL *p = (PEL *) IM_REGION_ADDR( ir, le, y ); 

		/* Init pts for this line of PELs.
		 */
                for( z = 0; z < n_lines; z++ ) {
                        seq->startp[z] = p + seq->start[z];
                        seq->endp[z] = p + seq->end[z];
		}

		switch( in->BandFmt ) {
		case IM_BANDFMT_UCHAR: 	
{
	int sum;
	int line_sum[1000];

	/* Fill the lines ready to scan.
	 */
	sum = 0;
	for( z = 0; z < lines->n_lines; z++ ) {
		line_sum[z] = 0;
		for( x = seq->startp[z]; x < lines->end[z]; x++ )
			line_sum[z] += p[x];
		sum += lines->factor[z] * line_sum[z];
	}
	q[0] = CLIPUC( (sum + lines->rounding) / lines->area );

	for( x = 1; x < len; x++ ) { 
		sum = 0;
		for( z = 0; z < lines->n_lines; z++ ) {
			line_sum[z] += p[lines->end[z]];
			line_sum[z] -= p[lines->start[z]];
			sum += lines->factor[z] * line_sum[z];
		}
		p += 1;
		q[x] = CLIPUC( (sum + lines->rounding) / lines->area );
	}  
}
			break;

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
}

static int
aconv_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask, int n_layers )
{
	Lines *lines;

#ifdef DEBUG
	printf( "im_conv_raw: starting with matrix:\n" );
	im_print_imask( mask );
#endif /*DEBUG*/

	if( !(lines = lines_new( in, out, mask, n_layers )) )
		return( -1 );

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize -= mask->xsize - 1;
	out->Ysize -= mask->ysize - 1;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_error( "im_conv", "%s", _( "image too small for mask" ) );
		return( -1 );
	}

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) ||
		im_generate( out, 
			lines_start, lines_generate, lines_stop, in, lines ) )
		return( -1 );

	out->Xoffset = -mask->xsize / 2;
	out->Yoffset = -mask->ysize / 2;

	return( 0 );
}

/**
 * im_aconv:
 * @in: input image
 * @out: output image
 * @mask: convolution mask
 * @n_layers: number of layers for approximation
 *
 * Perform a separable convolution of @in with @mask using approximate
 * convolution. 
 *
 * The mask must be 1xn or nx1 elements. 
 * The output image 
 * always has the same #VipsBandFmt as the input image. 
 *
 * The image is convolved twice: once with @mask and then again with @mask 
 * rotated by 90 degrees. 
 *
 * Larger values for @n_layers give more accurate
 * results, but are slower. As @n_layers approaches the mask radius, the
 * accuracy will become close to exact convolution and the speed will drop to 
 * match. For many large masks, such as Gaussian, @n_layers can be only 10% of
 * this value and accuracy will still be good.
 *
 * See also: im_convsep_f(), im_create_dmaskv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_aconv( IMAGE *in, IMAGE *out, DOUBLEMASK *mask, int n_layers )
{
	IMAGE *t[2];
	const int n_mask = mask->xsize * mask->ysize;
	DOUBLEMASK *rmask;

	if( vips_image_new_array( out, t, 2 ) ||
		!(rmask = (DOUBLEMASK *) im_local( out, 
		(im_construct_fn) im_dup_dmask,
		(im_callback_fn) im_free_dmask, mask, mask->filename, NULL )) )
		return( -1 );

	rmask->xsize = mask->ysize;
	rmask->ysize = mask->xsize;

	if( im_embed( in, t[0], 1, n_mask / 2, n_mask / 2, 
		in->Xsize + n_mask - 1, in->Ysize + n_mask - 1 ) ||
		aconv_raw( t[0], t[1], mask, n_layers ) ||
		aconv_raw( t[1], out, rmask, n_layers ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}

