/* spcor
 *
 * Copyright: 1990, N. Dessipris; 2006, 2007 Nottingham Trent University.
 *
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 
 * 20/2/95 JC
 *	- updated
 *	- ANSIfied, a little
 * 21/2/95 JC
 *	- rewritten
 *	- partialed 
 *	- speed-ups
 *	- new correlation coefficient (see above), from Niblack "An
 *	  Introduction to Digital Image Processing", Prentice/Hall, pp 138.
 * 4/9/97 JC
 *	- now does short/ushort as well
 * 13/2/03 JC
 *	- oops, could segv for short images
 * 14/4/04 JC
 *	- sets Xoffset / Yoffset
 * 8/3/06 JC
 *	- use im_embed() with edge stretching on the input, not the output
 *
 * 2006-10-24 tcv
 *      - add im_spcor2
 *
 * 2007-11-12 tcv
 *      - make im_spcor a wrapper selecting either im__spcor or im__spcor2
 * 2008-09-09 JC
 * 	- roll back the windowed version for now, it has some tile edge effects
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

typedef struct _VipsSpcor {
	VipsCorrelation parent_instance;

	/* Per-band mean of ref images.
	 */
	double *rmean;

	/* Per band sqrt(sumij (ref(i,j)-mean(ref))^2) 
	 */
	double *c1;
} VipsSpcor; 

typedef VipsCorrelationClass VipsSpcorClass;

G_DEFINE_TYPE( VipsSpcor, vips_spcor, VIPS_TYPE_CORRELATION );

static int
vips_spcor_pre_generate( VipsCorrelation *correlation )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( correlation );
	VipsSpcor *spcor = (VipsSpcor *) correlation;
	VipsImage *ref = correlation->ref_ready;
	int bands = ref->Bands;
	VipsImage **b = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( spcor ), bands );
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( spcor ), 2 );
	VipsImage **b2 = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( spcor ), bands );

	int i; 
	double *offset;
	double *scale;

	if( vips_check_noncomplex( class->nickname, ref ) )
		return( -1 ); 

	/* Per-band mean.
	 */
	if( !(spcor->rmean = VIPS_ARRAY( spcor, bands, double )) ||
		!(spcor->c1 = VIPS_ARRAY( spcor, bands, double )) )
		return( -1 ); 
	for( i = 0; i < bands; i++ ) 
		if( vips_extract_band( ref, &b[i], i, NULL ) ||
			vips_avg( b[i], &spcor->rmean[i], NULL ) )
			return( -1 );

	/* Per band sqrt(sumij (ref(i,j)-mean(ref))^2) 
	 */
	if( !(offset = VIPS_ARRAY( spcor, bands, double )) ||
		!(scale = VIPS_ARRAY( spcor, bands, double )) )
		return( -1 ); 
	for( i = 0; i < bands; i++ ) {
		offset[i] = -spcor->rmean[i];
		scale[i] = 1.0;
	}
	if( vips_linear( ref, &t[0], scale, offset, bands, NULL ) ||
		vips_multiply( t[0], t[0], &t[1], NULL ) )
		return( -1 ); 
	for( i = 0; i < bands; i++ ) 
		if( vips_extract_band( t[1], &b2[i], i, NULL ) ||
			vips_avg( b2[i], &spcor->c1[i], NULL ) )
			return( -1 );
	for( i = 0; i < bands; i++ ) {
		spcor->c1[i] *= ref->Xsize * ref->Ysize;
		spcor->c1[i] = sqrt( spcor->c1[i] );
	}

	return( 0 );
}

#define LOOP( IN ) { \
	IN *r1 = ((IN *) ref->data) + b; \
	IN *p1 = ((IN *) p) + b; \
	int in_lsk = lsk / sizeof( IN ); \
	IN *r1a; \
	IN *p1a; \
 	\
	/* Mean of area of in corresponding to ref. \
	 */ \
	p1a = p1; \
	sum1 = 0.0; \
	for( j = 0; j < ref->Ysize; j++ ) { \
		for( i = 0; i < sz; i += bands ) \
			sum1 += p1a[i]; \
		p1a += in_lsk;  \
	} \
	imean = sum1 / VIPS_IMAGE_N_PELS( ref ); \
 	\
	/* Calculate sum-of-squares-of-differences for this window on \
	 * in, and also sum-of-products-of-differences from mean. \
	 */ \
	p1a = p1; \
	r1a = r1; \
	sum2 = 0.0; \
	sum3 = 0.0; \
	for( j = 0; j < ref->Ysize; j++ ) { \
		for( i = 0; i < sz; i += bands ) { \
			/* Reference pel, and input pel. \
			 */ \
			IN ip = p1a[i]; \
			IN rp = r1a[i]; \
			\
			/* Accumulate sum-of-squares-of- \
			 * differences for input image. \
			 */ \
			double t = ip - imean; \
			sum2 += t * t; \
			\
			/* Accumulate product-of-difference from mean. \
			 */ \
			sum3 += (rp - spcor->rmean[b]) * (ip - imean); \
		} \
		\
		p1a += in_lsk; \
		r1a += sz; \
	} \
}

static void
vips_spcor_correlation( VipsCorrelation *correlation,
	VipsRegion *in, VipsRegion *out )
{
	VipsSpcor *spcor = (VipsSpcor *) correlation;
	VipsRect *r = &out->valid;
	VipsImage *ref = correlation->ref_ready;
	int bands = vips_band_format_iscomplex( ref->BandFmt ) ? 
		ref->Bands * 2 : ref->Bands; 
	int sz = ref->Xsize * bands; 
	int lsk = VIPS_REGION_LSKIP( in ); 

	int x, y, b, j, i;

	double imean;
	double sum1;
	double sum2, sum3;
	double c2, cc;

	for( y = 0; y < r->height; y++ ) {
		float *q = (float *) 
			VIPS_REGION_ADDR( out, r->left, r->top + y );

		for( x = 0; x < r->width; x++ ) {
			VipsPel *p = 
				VIPS_REGION_ADDR( in, r->left + x, r->top + y );

			for( b = 0; b < bands; b++ ) { 
				switch( vips_image_get_format( ref ) ) {
				case VIPS_FORMAT_UCHAR:	
					LOOP( unsigned char ); 
					break;

				case VIPS_FORMAT_CHAR:	
					LOOP( signed char ); 
					break;

				case VIPS_FORMAT_USHORT: 
					LOOP( unsigned short ); 
					break;

				case VIPS_FORMAT_SHORT:	
					LOOP( signed short ); 
					break;

				case VIPS_FORMAT_UINT: 	
					LOOP( unsigned int ); 
					break; 

				case VIPS_FORMAT_INT: 	
					LOOP( signed int ); 
					break; 

				case VIPS_FORMAT_FLOAT:	
				case VIPS_FORMAT_COMPLEX: 
					LOOP( float ); 
					break; 

				case VIPS_FORMAT_DOUBLE: 
				case VIPS_FORMAT_DPCOMPLEX: 
					LOOP( double ); 
					break;

				default:
					g_assert( 0 );
					return; 
				}

				c2 = sqrt( sum2 );
				cc = sum3 / (spcor->c1[b] * c2);

				*q++ = cc;
			}
		}
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

static int vips_spcor_format_table[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   F,  F,  F,  F,  F,  F, F, F, F, F
};

static void
vips_spcor_class_init( VipsSpcorClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsCorrelationClass *cclass = VIPS_CORRELATION_CLASS( class );

	object_class->nickname = "spcor";
	object_class->description = _( "spatial correlation" );

	cclass->format_table = vips_spcor_format_table;
	cclass->pre_generate = vips_spcor_pre_generate;
	cclass->correlation = vips_spcor_correlation;
}

static void
vips_spcor_init( VipsSpcor *spcor )
{
}

/**
 * vips_spcor:
 * @in: input image
 * @ref: reference image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Calculate a correlation surface.
 *
 * @ref is placed at every position in @in and the correlation coefficient
 * calculated. The output
 * image is always float.
 *
 * The output
 * image is the same size as the input. Extra input edge pixels are made by 
 * copying the existing edges outwards. 
 *
 * The correlation coefficient is calculated as:
 *
 * |[
 *          sumij (ref(i,j)-mean(ref))(inkl(i,j)-mean(inkl))
 * c(k,l) = ------------------------------------------------
 *          sqrt(sumij (ref(i,j)-mean(ref))^2) *
 *                      sqrt(sumij (inkl(i,j)-mean(inkl))^2)
 * ]|
 *
 * where inkl is the area of @in centred at position (k,l).
 *
 * from Niblack "An Introduction to Digital Image Processing", 
 * Prentice/Hall, pp 138.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The output image is always float, unless either of the two inputs is
 * double, in which case the output is also double.
 *
 * See also: vips_fastcor().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_spcor( VipsImage *in, VipsImage *ref, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "spcor", ap, in, ref, out );
	va_end( ap );

	return( result );
}
