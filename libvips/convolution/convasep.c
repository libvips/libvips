/* convasep ... separable approximate convolution
 *
 * This operation does an approximate, seperable convolution. 
 *
 * Author: John Cupitt & Nicolas Robidoux
 * Written on: 31/5/11
 * Modified on: 
 * 31/5/11
 *      - from im_conv()
 * 5/7/16
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

  This thing is a little like stackblur, but generalised to any separable 
  mask.

 */

/*

  TODO

	- how about making a cumulative image and then subtracting points in 
	  that, rather than keeping a set of running totals

	  faster?

	  we could then use orc to write a bit of code to implement this set 
	  of lines

	  stackoverflow has an algorithm for cumulativization using SIMD and 
	  threads, see that font rasterization with rust piece on medium by 
	  ralph levien

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
#include <stdlib.h>
#include <limits.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/vector.h>
#include <vips/debug.h>
#include <vips/internal.h>

#include "pconvolution.h"

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

typedef struct {
	VipsConvolution parent_instance;

	int layers;

	int divisor;
	int rounding;
	int offset;

	/* The "width" of the mask, ie. n for our 1xn or nx1 argument, plus 
	 * an int version of our mask. 
	 */
	int width;
	VipsImage *iM;

	/* The mask broken into a set of lines.
	 *
	 * Start is the left-most pixel in the line, end is one beyond the
	 * right-most pixel.
	 */
	int n_lines;
	int start[MAX_LINES];
	int end[MAX_LINES];
	int factor[MAX_LINES];
} VipsConvasep;

typedef VipsConvolutionClass VipsConvasepClass;

G_DEFINE_TYPE( VipsConvasep, vips_convasep, VIPS_TYPE_CONVOLUTION );

static void
vips_convasep_line_start( VipsConvasep *convasep, int x, int factor )
{
	convasep->start[convasep->n_lines] = x;
	convasep->factor[convasep->n_lines] = factor;
}

static int
vips_convasep_line_end( VipsConvasep *convasep, int x )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( convasep );

	convasep->end[convasep->n_lines] = x;

	if( convasep->n_lines >= MAX_LINES - 1 ) {
		vips_error( class->nickname, "%s", _( "mask too complex" ) );
		return( -1 );
	}
	convasep->n_lines += 1;

	return( 0 );
}

/* Break a mask into lines.
 */
static int
vips_convasep_decompose( VipsConvasep *convasep )
{
	VipsImage *iM = convasep->iM;
	double *coeff = (double *) VIPS_IMAGE_ADDR( iM, 0, 0 );
	double scale = vips_image_get_scale( iM ); 
	double offset = vips_image_get_offset( iM ); 

	double max;
	double min;
	double depth;
	double sum;
	double area;
	int layers;
	int layers_above;
	int layers_below;
	int z, n, x;

	VIPS_DEBUG_MSG( "vips_convasep_decompose: "
		"breaking into %d layers ...\n", convasep->layers );

	/* Find mask range. We must always include the zero axis in the mask.
	 */
	max = 0;
	min = 0;
	for( x = 0; x < convasep->width; x++ ) {
		if( coeff[x] > max )
			max = coeff[x];
		if( coeff[x] < min )
			min = coeff[x];
	}

	/* The zero axis must fall on a layer boundary. Estimate the
	 * depth, find n-lines-above-zero, get exact depth, then calculate a
	 * fixed n-lines which includes any negative parts.
	 */
	depth = (max - min) / convasep->layers;
	layers_above = ceil( max / depth );
	depth = max / layers_above;
	layers_below = floor( min / depth );
	layers = layers_above - layers_below;

	VIPS_DEBUG_MSG( "depth = %g, layers = %d\n", depth, layers );

	/* For each layer, generate a set of lines which are inside the
	 * perimeter. Work down from the top.
	 */
	for( z = 0; z < layers; z++ ) {
		double y = max - (1 + z) * depth;

		/* y plus half depth ... ie. the layer midpoint.
		 */
		double y_ph = y + depth / 2;

		/* Odd, but we must avoid rounding errors that make us miss 0
		 * in the line above.
		 */
		int y_positive = z < layers_above;

		int inside;

		/* Start outside the perimeter.
		 */
		inside = 0;

		for( x = 0; x < convasep->width; x++ ) {
			/* The vertical line from mask[z] to 0 is inside. Is
			 * our current square (x, y) part of that line?
			 */
			if( (y_positive && coeff[x] >= y_ph) ||
				(!y_positive && coeff[x] <= y_ph) ) {
				if( !inside ) {
					vips_convasep_line_start( convasep, x, 
						y_positive ? 1 : -1 );
					inside = 1;
				}
			}
			else if( inside ) {
				if( vips_convasep_line_end( convasep, x ) )
					return( -1 );
				inside = 0;
			}
		}

		if( inside && 
			vips_convasep_line_end( convasep, convasep->width ) )
			return( -1 );
	}

	/* Can we common up any lines? Search for lines with identical
	 * start/end.
	 */
	for( z = 0; z < convasep->n_lines; z++ ) {
		for( n = z + 1; n < convasep->n_lines; n++ ) {
			if( convasep->start[z] == convasep->start[n] &&
				convasep->end[z] == convasep->end[n] ) {
				convasep->factor[z] += convasep->factor[n];

				/* n can be deleted. Do this in a separate
				 * pass below.
				 */
				convasep->factor[n] = 0;
			}
		}
	}

	/* Now we can remove all factor 0 lines.
	 */
	for( z = 0; z < convasep->n_lines; z++ ) {
		if( convasep->factor[z] == 0 ) {
			for( x = z; x < convasep->n_lines; x++ ) {
				convasep->start[x] = convasep->start[x + 1];
				convasep->end[x] = convasep->end[x + 1];
				convasep->factor[x] = convasep->factor[x + 1];
			}
			convasep->n_lines -= 1;
		}
	}

	/* Find the area of the lines.
	 */
	area = 0;
	for( z = 0; z < convasep->n_lines; z++ ) 
		area += convasep->factor[z] * 
			(convasep->end[z] - convasep->start[z]);

	/* Strength reduction: if all lines are divisible by n, we can move
	 * that n out into the ->area factor. The aim is to produce as many
	 * factor 1 lines as we can and to reduce the chance of overflow.
	 */
	x = convasep->factor[0];
	for( z = 1; z < convasep->n_lines; z++ ) 
		x = gcd( x, convasep->factor[z] );
	for( z = 0; z < convasep->n_lines; z++ ) 
		convasep->factor[z] /= x;
	area *= x;

	/* Find the area of the original mask.
	 */
	sum = 0;
	for( z = 0; z < convasep->width; z++ ) 
		sum += coeff[z];

	convasep->divisor = VIPS_RINT( sum * area / scale );
	if( convasep->divisor == 0 )
		convasep->divisor = 1;
	convasep->rounding = (convasep->divisor + 1) / 2;
	convasep->offset = offset;

#ifdef DEBUG
	/* ASCII-art layer drawing.
	 */
	printf( "lines:\n" );
	for( z = 0; z < convasep->n_lines; z++ ) {
		printf( "%3d - %2d x ", z, convasep->factor[z] );
		for( x = 0; x < 55; x++ ) {
			int rx = x * (convasep->width + 1) / 55;

			if( rx >= convasep->start[z] && rx < convasep->end[z] )
				printf( "#" );
			else
				printf( " " );
		}
		printf( " %3d .. %3d\n", convasep->start[z], convasep->end[z] );
	}
	printf( "divisor = %d\n", convasep->divisor );
	printf( "rounding = %d\n", convasep->rounding );
	printf( "offset = %d\n", convasep->offset );
#endif /*DEBUG*/

	return( 0 );
}

/* Our sequence value.
 */
typedef struct {
	VipsConvasep *convasep;

	VipsRegion *ir;		/* Input region */

	int *start;		/* Offsets for start and stop */
	int *end;

	/* The sums for each line. int for integer types, double for floating
	 * point types.
	 */
	int *isum;		
	double *dsum;		

	int last_stride;	/* Avoid recalcing offsets, if we can */
} VipsConvasepSeq;

/* Free a sequence value.
 */
static int
vips_convasep_stop( void *vseq, void *a, void *b )
{
	VipsConvasepSeq *seq = (VipsConvasepSeq *) vseq;

	VIPS_UNREF( seq->ir );
	VIPS_FREE( seq->start );
	VIPS_FREE( seq->end );
	VIPS_FREE( seq->isum );
	VIPS_FREE( seq->dsum );

	return( 0 );
}

/* Convolution start function.
 */
static void *
vips_convasep_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (IMAGE *) a;
	VipsConvasep *convasep = (VipsConvasep *) b;

	VipsConvasepSeq *seq;

	if( !(seq = VIPS_NEW( out, VipsConvasepSeq )) )
		return( NULL );

	/* Init!
	 */
	seq->convasep = convasep;
	seq->ir = vips_region_new( in );
	seq->start = VIPS_ARRAY( NULL, convasep->n_lines, int );
	seq->end = VIPS_ARRAY( NULL, convasep->n_lines, int );
	seq->isum = NULL;
	seq->dsum = NULL;
	if( vips_band_format_isint( out->BandFmt ) )
		seq->isum = VIPS_ARRAY( NULL, convasep->n_lines, int );
	else
		seq->dsum = VIPS_ARRAY( NULL, convasep->n_lines, double );
	seq->last_stride = -1;

	if( !seq->ir || 
		!seq->start || 
		!seq->end || 
		(!seq->isum && !seq->dsum) ) {
		vips_convasep_stop( seq, in, convasep );
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

#define HCONV_INT( TYPE, CLIP ) { \
	for( i = 0; i < bands; i++ ) { \
		int *isum = seq->isum; \
		\
		TYPE *q; \
		TYPE *p; \
		int sum; \
		\
		p = i + (TYPE *) VIPS_REGION_ADDR( ir, r->left, r->top + y ); \
		q = i + (TYPE *) VIPS_REGION_ADDR( or, r->left, r->top + y ); \
		\
		sum = 0; \
		for( z = 0; z < n_lines; z++ ) { \
			isum[z] = 0; \
			for( x = seq->start[z]; x < seq->end[z]; x += istride ) \
				isum[z] += p[x]; \
			sum += convasep->factor[z] * isum[z]; \
		} \
		\
		/* Don't add offset ... we only want to do that once, do it on \
		 * the vertical pass. \
		 */ \
		sum = (sum + convasep->rounding) / convasep->divisor; \
		CLIP( sum ); \
		*q = sum; \
		q += ostride; \
		\
		for( x = 1; x < r->width; x++ ) {  \
			sum = 0; \
			for( z = 0; z < n_lines; z++ ) { \
				isum[z] += p[seq->end[z]]; \
				isum[z] -= p[seq->start[z]]; \
				sum += convasep->factor[z] * isum[z]; \
			} \
			p += istride; \
			sum = (sum + convasep->rounding) / convasep->divisor; \
			CLIP( sum ); \
			*q = sum; \
			q += ostride; \
		} \
	} \
}

#define HCONV_FLOAT( TYPE ) { \
	for( i = 0; i < bands; i++ ) { \
		double *dsum = seq->dsum; \
		\
		TYPE *q; \
		TYPE *p; \
		double sum; \
		\
		p = i + (TYPE *) VIPS_REGION_ADDR( ir, r->left, r->top + y ); \
		q = i + (TYPE *) VIPS_REGION_ADDR( or, r->left, r->top + y ); \
		\
		sum = 0; \
		for( z = 0; z < n_lines; z++ ) { \
			dsum[z] = 0; \
			for( x = seq->start[z]; x < seq->end[z]; x += istride ) \
				dsum[z] += p[x]; \
			sum += convasep->factor[z] * dsum[z]; \
		} \
		\
		/* Don't add offset ... we only want to do that once, do it on \
		 * the vertical pass. \
		 */ \
		sum = sum / convasep->divisor; \
		*q = sum; \
		q += ostride; \
		\
		for( x = 1; x < r->width; x++ ) {  \
			sum = 0; \
			for( z = 0; z < n_lines; z++ ) { \
				dsum[z] += p[seq->end[z]]; \
				dsum[z] -= p[seq->start[z]]; \
				sum += convasep->factor[z] * dsum[z]; \
			} \
			p += istride; \
			sum = sum / convasep->divisor; \
			*q = sum; \
			q += ostride; \
		} \
	} \
}

/* Do horizontal masks ... we scan the mask along scanlines.
 */
static int
vips_convasep_generate_horizontal( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsConvasepSeq *seq = (VipsConvasepSeq *) vseq;
	VipsImage *in = (VipsImage *) a;
	VipsConvasep *convasep = (VipsConvasep *) b;
	VipsConvolution *convolution = (VipsConvolution *) convasep;

	VipsRegion *ir = seq->ir;
	const int n_lines = convasep->n_lines;
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
	s.width += convasep->width - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	/* Stride can be different for the vertical case, keep this here for
	 * ease of direction change.
	 */
	istride = VIPS_IMAGE_SIZEOF_PEL( in ) / 
		VIPS_IMAGE_SIZEOF_ELEMENT( in );
	ostride = VIPS_IMAGE_SIZEOF_PEL( convolution->out ) / 
		VIPS_IMAGE_SIZEOF_ELEMENT( convolution->out );

        /* Init offset array. 
	 */
	if( seq->last_stride != istride ) {
		seq->last_stride = istride;

		for( z = 0; z < n_lines; z++ ) {
			seq->start[z] = convasep->start[z] * istride;
			seq->end[z] = convasep->end[z] * istride;
		}
	}

	for( y = 0; y < r->height; y++ ) { 
		switch( in->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			HCONV_INT( unsigned char, CLIP_UCHAR );
			break;

		case VIPS_FORMAT_CHAR: 	
			HCONV_INT( signed char, CLIP_CHAR );
			break;

		case VIPS_FORMAT_USHORT: 	
			HCONV_INT( unsigned short, CLIP_USHORT );
			break;

		case VIPS_FORMAT_SHORT: 	
			HCONV_INT( signed short, CLIP_SHORT );
			break;

		case VIPS_FORMAT_UINT: 	
			HCONV_INT( unsigned int, CLIP_NONE );
			break;

		case VIPS_FORMAT_INT: 	
			HCONV_INT( signed int, CLIP_NONE );
			break;

		case VIPS_FORMAT_FLOAT: 	
		case VIPS_FORMAT_COMPLEX: 	
			HCONV_FLOAT( float );
			break;

		case VIPS_FORMAT_DOUBLE: 	
		case VIPS_FORMAT_DPCOMPLEX: 	
			HCONV_FLOAT( double );
			break;

		default:
			g_assert_not_reached();
		}
	}

	return( 0 );
}

#define VCONV_INT( TYPE, CLIP ) { \
	for( x = 0; x < sz; x++ ) { \
		int *isum = seq->isum; \
		\
		TYPE *q; \
		TYPE *p; \
		int sum; \
		\
		p = x + (TYPE *) VIPS_REGION_ADDR( ir, r->left, r->top ); \
		q = x + (TYPE *) VIPS_REGION_ADDR( or, r->left, r->top ); \
		\
		sum = 0; \
		for( z = 0; z < n_lines; z++ ) { \
			isum[z] = 0; \
			for( y = seq->start[z]; y < seq->end[z]; y += istride ) \
				isum[z] += p[y]; \
			sum += convasep->factor[z] * isum[z]; \
		} \
		sum = (sum + convasep->rounding) / convasep->divisor + \
			convasep->offset; \
		CLIP( sum ); \
		*q = sum; \
		q += ostride; \
		\
		for( y = 1; y < r->height; y++ ) { \
			sum = 0; \
			for( z = 0; z < n_lines; z++ ) { \
				isum[z] += p[seq->end[z]]; \
				isum[z] -= p[seq->start[z]]; \
				sum += convasep->factor[z] * isum[z]; \
			} \
			p += istride; \
			sum = (sum + convasep->rounding) / convasep->divisor + \
				convasep->offset; \
			CLIP( sum ); \
			*q = sum; \
			q += ostride; \
		} \
	} \
}

#define VCONV_FLOAT( TYPE ) { \
	for( x = 0; x < sz; x++ ) { \
		double *dsum = seq->dsum; \
		\
		TYPE *q; \
		TYPE *p; \
		double sum; \
		\
		p = x + (TYPE *) VIPS_REGION_ADDR( ir, r->left, r->top ); \
		q = x + (TYPE *) VIPS_REGION_ADDR( or, r->left, r->top ); \
		\
		sum = 0; \
		for( z = 0; z < n_lines; z++ ) { \
			dsum[z] = 0; \
			for( y = seq->start[z]; y < seq->end[z]; y += istride ) \
				dsum[z] += p[y]; \
			sum += convasep->factor[z] * dsum[z]; \
		} \
		sum = sum / convasep->divisor + convasep->offset; \
		*q = sum; \
		q += ostride; \
		\
		for( y = 1; y < r->height; y++ ) { \
			sum = 0; \
			for( z = 0; z < n_lines; z++ ) { \
				dsum[z] += p[seq->end[z]]; \
				dsum[z] -= p[seq->start[z]]; \
				sum += convasep->factor[z] * dsum[z]; \
			} \
			p += istride; \
			sum = sum / convasep->divisor + convasep->offset; \
			*q = sum; \
			q += ostride; \
		} \
	} \
}

/* Do vertical masks ... we scan the mask down columns of pixels. Copy-paste
 * from above with small changes.
 */
static int
vips_convasep_generate_vertical( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsConvasepSeq *seq = (VipsConvasepSeq *) vseq;
	VipsImage *in = (VipsImage *) a;
	VipsConvasep *convasep = (VipsConvasep *) b;
	VipsConvolution *convolution = (VipsConvolution *) convasep;

	VipsRegion *ir = seq->ir;
	const int n_lines = convasep->n_lines;
	VipsRect *r = &or->valid;

	/* Double the width (notionally) for complex.
	 */
	int sz = vips_band_format_iscomplex( in->BandFmt ) ? 
		2 * VIPS_REGION_N_ELEMENTS( or ) : VIPS_REGION_N_ELEMENTS( or );

	VipsRect s;
	int x, y, z;
	int istride;
	int ostride;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.height += convasep->width - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

	/* Stride can be different for the vertical case, keep this here for
	 * ease of direction change.
	 */
	istride = VIPS_REGION_LSKIP( ir ) / VIPS_IMAGE_SIZEOF_ELEMENT( in );
	ostride = VIPS_REGION_LSKIP( or ) / 
		VIPS_IMAGE_SIZEOF_ELEMENT( convolution->out );

        /* Init offset array. 
	 */
	if( seq->last_stride != istride ) {
		seq->last_stride = istride;

		for( z = 0; z < n_lines; z++ ) {
			seq->start[z] = convasep->start[z] * istride;
			seq->end[z] = convasep->end[z] * istride;
		}
	}

	switch( in->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 	
		VCONV_INT( unsigned char, CLIP_UCHAR );
		break;

	case VIPS_FORMAT_CHAR: 	
		VCONV_INT( signed char, CLIP_CHAR );
		break;

	case VIPS_FORMAT_USHORT: 	
		VCONV_INT( unsigned short, CLIP_USHORT );
		break;

	case VIPS_FORMAT_SHORT: 	
		VCONV_INT( signed short, CLIP_SHORT );
		break;

	case VIPS_FORMAT_UINT: 	
		VCONV_INT( unsigned int, CLIP_NONE );
		break;

	case VIPS_FORMAT_INT: 	
		VCONV_INT( signed int, CLIP_NONE );
		break;

	case VIPS_FORMAT_FLOAT: 	
	case VIPS_FORMAT_COMPLEX: 	
		VCONV_FLOAT( float );
		break;

	case VIPS_FORMAT_DOUBLE: 	
	case VIPS_FORMAT_DPCOMPLEX: 	
		VCONV_FLOAT( double );
		break;

	default:
		g_assert_not_reached();
	}

	return( 0 );
}

static int
vips_convasep_pass( VipsConvasep *convasep, 
	VipsImage *in, VipsImage **out, VipsDirection direction )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( convasep );

	VipsGenerateFn gen;

	*out = vips_image_new(); 
	if( vips_image_pipelinev( *out, 
		VIPS_DEMAND_STYLE_SMALLTILE, in, NULL ) )
		return( -1 );

	if( direction == VIPS_DIRECTION_HORIZONTAL ) { 
		(*out)->Xsize -= convasep->width - 1;
		gen = vips_convasep_generate_horizontal;
	}
	else {
		(*out)->Ysize -= convasep->width - 1;
		gen = vips_convasep_generate_vertical;
	}

	if( (*out)->Xsize <= 0 || 
		(*out)->Ysize <= 0 ) {
		vips_error( class->nickname, 
			"%s", _( "image too small for mask" ) );
		return( -1 );
	}

	if( vips_image_generate( *out, 
		vips_convasep_start, gen, vips_convasep_stop, in, convasep ) )
		return( -1 );

	return( 0 );
}

static int 
vips_convasep_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsConvolution *convolution = (VipsConvolution *) object;
	VipsConvasep *convasep = (VipsConvasep *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	VipsImage *in;

	if( VIPS_OBJECT_CLASS( vips_convasep_parent_class )->build( object ) )
		return( -1 );

	if( vips_check_separable( class->nickname, convolution->M ) ) 
                return( -1 );

	/* An int version of our mask.
	 */
	if( vips__image_intize( convolution->M, &t[3] ) )
		return( -1 );
	convasep->iM = t[3]; 
	convasep->width = convasep->iM->Xsize * convasep->iM->Ysize;
	in = convolution->in;

	if( vips_convasep_decompose( convasep ) )
		return( -1 ); 

	g_object_set( convasep, "out", vips_image_new(), NULL ); 
	if( 
		vips_embed( in, &t[0], 
			convasep->width / 2, 
			convasep->width / 2, 
			in->Xsize + convasep->width - 1, 
			in->Ysize + convasep->width - 1,
			"extend", VIPS_EXTEND_COPY,
			NULL ) ||
		vips_convasep_pass( convasep, 
			t[0], &t[1], VIPS_DIRECTION_HORIZONTAL ) ||
		vips_convasep_pass( convasep, 
			t[1], &t[2], VIPS_DIRECTION_VERTICAL ) ||
		vips_image_write( t[2], convolution->out ) )
		return( -1 );

	convolution->out->Xoffset = 0;
	convolution->out->Yoffset = 0;

	vips_reorder_margin_hint( convolution->out,
		convolution->M->Xsize * convolution->M->Ysize );

	return( 0 );
}

static void
vips_convasep_class_init( VipsConvasepClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "convasep";
	object_class->description = 
		_( "approximate separable integer convolution" );
	object_class->build = vips_convasep_build;

	VIPS_ARG_INT( class, "layers", 104, 
		_( "Layers" ), 
		_( "Use this many layers in approximation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsConvasep, layers ), 
		1, 1000, 5 ); 

}

static void
vips_convasep_init( VipsConvasep *convasep )
{
        convasep->layers = 5;
	convasep->n_lines = 0;
}

/**
 * vips_convasep:
 * @in: input image
 * @out: output image
 * @mask: convolve with this mask
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @layers: %gint, number of layers for approximation
 *
 * Approximate separable integer convolution. This is a low-level operation, see 
 * vips_convsep() for something more convenient. 
 *
 * The image is convolved twice: once with @mask and then again with @mask 
 * rotated by 90 degrees. 
 * @mask must be 1xn or nx1 elements. 
 * Elements of @mask are converted to
 * integers before convolution.
 *
 * Larger values for @layers give more accurate
 * results, but are slower. As @layers approaches the mask radius, the
 * accuracy will become close to exact convolution and the speed will drop to 
 * match. For many large masks, such as Gaussian, @layers need be only 10% of
 * this value and accuracy will still be good.
 *
 * The output image 
 * always has the same #VipsBandFormat as the input image. 
 *
 * See also: vips_convsep().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_convasep( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
{
	va_list ap;
	int result;

	va_start( ap, mask );
	result = vips_call_split( "convasep", ap, in, out, mask );
	va_end( ap );

	return( result );
}

