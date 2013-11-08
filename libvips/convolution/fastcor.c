/* fastcor
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 15/03/1991
 * 20/2/95 JC
 *	- ANSIfied
 *	- in1 and in2 swapped, to match order for im_spcor
 *	- memory leaks fixed
 * 21/2/95 JC
 * 	- partialed
 *	- speed-ups
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the output
 *	- sets Xoffset / Yoffset
 * 8/3/06 JC
 *	- use im_embed() with edge stretching on the input, not the output
 *	- calculate sum of squares of differences, rather than abs of
 *	  difference
 * 3/2/10
 * 	- gtkdoc
 * 	- cleanups
 * 7/11/13
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

#include "pconvolution.h"
#include "correlation.h"

typedef VipsCorrelationClass VipsFastcor;
typedef VipsCorrelationClass VipsFastcorClass;

G_DEFINE_TYPE( VipsFastcor, vips_fastcor, VIPS_TYPE_CORRELATION );

#define CORR_INT( TYPE ) { \
	for( y = 0; y < r->height; y++ ) { \
		unsigned int *q = (unsigned int *) \
			VIPS_REGION_ADDR( out, r->left, r->top + y ); \
		\
		for( x = 0; x < r->width; x++ ) \
			for( b = 0; b < bands; b++ ) {  \
				TYPE *p1 = (TYPE *) ref->data; \
				TYPE *p2 = (TYPE *) VIPS_REGION_ADDR( in,  \
					r->left + x, r->top + y ); \
				\
				unsigned int sum; \
				\
				sum = 0; \
				for( j = 0; j < ref->Ysize; j++ ) { \
					for( i = b; i < sz; i += bands ) { \
						int t = p1[i] - p2[i]; \
						\
						sum += t * t; \
					} \
					\
					p1 += sz; \
					p2 += lsk; \
				} \
				\
				*q++ = sum; \
			} \
	} \
}

#define CORR_FLOAT( TYPE ) { \
	for( y = 0; y < r->height; y++ ) { \
		TYPE *q = (TYPE *) \
			VIPS_REGION_ADDR( out, r->left, r->top + y ); \
		\
		for( x = 0; x < r->width; x++ ) \
			for( b = 0; b < bands; b++ ) {  \
				TYPE *p1 = (TYPE *) ref->data; \
				TYPE *p2 = (TYPE *) VIPS_REGION_ADDR( in,  \
					r->left + x, r->top + y ); \
				\
				TYPE sum; \
				\
				sum = 0; \
				for( j = 0; j < ref->Ysize; j++ ) { \
					for( i = b; i < sz; i += bands ) { \
						TYPE t = p1[i] - p2[i]; \
						\
						sum += t * t; \
					} \
					\
					p1 += sz; \
					p2 += lsk; \
				} \
				\
				*q++ = sum; \
			} \
	} \
}

static void
vips_fastcor_correlation( VipsCorrelation *correlation,
	VipsRegion *in, VipsRegion *out )
{
	VipsRect *r = &out->valid;
	VipsImage *ref = correlation->ref_ready;
	int bands = vips_band_format_iscomplex( ref->BandFmt ) ? 
		ref->Bands * 2 : ref->Bands; 
	int sz = ref->Xsize * bands; 
	int lsk = VIPS_REGION_LSKIP( in ); 

	int x, y, i, j, b;

        switch( vips_image_get_format( ref ) ) {
        case VIPS_FORMAT_CHAR: 	
		CORR_INT( signed char ); 
		break; 

        case VIPS_FORMAT_UCHAR:	
		CORR_INT( unsigned char ); 
		break; 

        case VIPS_FORMAT_SHORT:	
		CORR_INT( signed short ); 
		break; 

        case VIPS_FORMAT_USHORT:
		CORR_INT( unsigned short ); 
		break; 

        case VIPS_FORMAT_INT: 	
		CORR_INT( signed int ); 
		break; 

        case VIPS_FORMAT_UINT: 	
		CORR_INT( unsigned int ); 
		break; 

        case VIPS_FORMAT_FLOAT:	
        case VIPS_FORMAT_COMPLEX: 
		CORR_FLOAT( float ); 
		break; 

        case VIPS_FORMAT_DOUBLE: 
        case VIPS_FORMAT_DPCOMPLEX: 
		CORR_FLOAT( double ); 
		break;

        default:
		g_assert( 0 );
        }
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

/* Type promotion for multiplication. Sign and value preserving. Make sure 
 * these match the case statement in multiply_buffer() above.
 */
static int vips_fastcor_format_table[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   UI, UI, UI, UI, UI, UI,F, X, D, DX
};

static void
vips_fastcor_class_init( VipsFastcorClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsCorrelationClass *cclass = VIPS_CORRELATION_CLASS( class );

	object_class->nickname = "fastcor";
	object_class->description = _( "fast correlation" );

	cclass->format_table = vips_fastcor_format_table;
	cclass->correlation = vips_fastcor_correlation;
}

static void
vips_fastcor_init( VipsFastcor *fastcor )
{
}

/**
 * vips_fastcor:
 * @in: input image
 * @ref: reference image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Calculate a fast correlation surface.
 *
 * @ref is placed at every position in @in and the sum of squares of
 * differences calculated. 
 *
 * The output
 * image is the same size as the input. Extra input edge pixels are made by 
 * copying the existing edges outwards. 
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The output type is uint if both inputs are integer, float if both are float
 * or complex, and double if either is double or double complex. 
 * In other words, the output type is just large enough to hold the whole
 * range of possible values.
 *
 * See also: vips_spcor().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_fastcor( VipsImage *in, VipsImage *ref, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "fastcor", ap, in, ref, out );
	va_end( ap );

	return( result );
}
