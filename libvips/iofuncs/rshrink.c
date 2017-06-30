/* Shrink VipsRegions by x2
 * 
 * 21/6/17
 * 	- from region.c, this was becoming too large
 * 	- add a lanczos3 version
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/debug.h>

/* Generate area @target in @to using pixels in @from. 
 *
 * VIPS_CODING_LABQ only.
 */
static void
vips_region_shrink_labpack( VipsRegion *from, VipsRegion *to, VipsRect *target )
{
	int ls = VIPS_REGION_LSKIP( from );

	int x, y;

	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			target->left * 2, (target->top + y) * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, 
			target->left, target->top + y );

		/* Ignore the extra bits for speed.
		 */
		for( x = 0; x < target->width; x++ ) {
			signed char *sp = (signed char *) p;
			unsigned char *up = (unsigned char *) p;

			int l = up[0] + up[4] + 
				up[ls] + up[ls + 4];
			int a = sp[1] + sp[5] + 
				sp[ls + 1] + sp[ls + 5];
			int b = sp[2] + sp[6] + 
				sp[ls + 2] + sp[ls + 6];

			q[0] = (l + 2) >> 2;
			q[1] = a >> 2;
			q[2] = b >> 2;
			q[3] = 0;

			q += 4;
			p += 8;
		}
	}
}

#define SHRINK_INT( TYPE ) { \
	TYPE *tp = (TYPE *) p; \
	TYPE *tq = (TYPE *) q; \
	\
	for( x = 0; x < target->width; x++ ) { \
 		\
		for( z = 0; z < nb; z++ ) { \
			int tot = tp[z] + tp[z + nb] + \
				tp[z + ls] + tp[z + nb + ls]; \
			\
			tq[z] = (tot + 2) >> 2; \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		tp += nb << 1; \
		tq += nb; \
	} \
}

#define SHRINK_FLOAT( TYPE ) { \
	TYPE *tp = (TYPE *) p; \
	TYPE *tq = (TYPE *) q; \
	\
	for( x = 0; x < target->width; x++ ) { \
		for( z = 0; z < nb; z++ ) { \
			double tot = tp[z] + tp[z + nb] + \
				tp[z + ls] + tp[z + nb + ls]; \
			\
			tq[z] = tot / 4; \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		tp += nb << 1; \
		tq += nb; \
	} \
}

/* Generate area @target in @to using pixels in @from. Non-complex.
 */
static void
vips_region_shrink_uncoded( VipsRegion *from, VipsRegion *to, VipsRect *target )
{
	int ls = VIPS_REGION_LSKIP( from );
	int nb = from->im->Bands;

	int x, y, z;

	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			target->left * 2, (target->top + y) * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, 
			target->left, target->top + y );

		/* Process this line of pels.
		 */
		switch( from->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:	
			SHRINK_INT( unsigned char );  break; 
		case VIPS_FORMAT_CHAR:	
			SHRINK_INT( signed char );  break; 
		case VIPS_FORMAT_USHORT:	
			SHRINK_INT( unsigned short );  break; 
		case VIPS_FORMAT_SHORT:	
			SHRINK_INT( signed short );  break; 
		case VIPS_FORMAT_UINT:	
			SHRINK_INT( unsigned int );  break; 
		case VIPS_FORMAT_INT:	
			SHRINK_INT( signed int );  break; 
		case VIPS_FORMAT_FLOAT:	
			SHRINK_FLOAT( float );  break; 
		case VIPS_FORMAT_DOUBLE:	
			SHRINK_FLOAT( double );  break; 

		default:
			g_assert_not_reached();
		}
	}
}

/* No point having an int path, this will always be horribly slow.
 */
#define SHRINK_ALPHA( TYPE ) { \
	TYPE *tp = (TYPE *) p; \
	TYPE *tq = (TYPE *) q; \
	\
	for( x = 0; x < target->width; x++ ) { \
		/* Make the input alphas. \
		 */ \
		double a1 = tp[nb - 1]; \
		double a2 = tp[nb + nb - 1]; \
		double a3 = tp[ls + nb - 1]; \
		double a4 = tp[ls + nb + nb - 1]; \
		\
		/* Output alpha. \
		 */ \
		double a = (a1 + a2 + a3 + a4) / 4.0; \
		\
		if( a == 0 ) { \
			for( z = 0; z < nb; z++ ) \
				tq[z] = 0; \
		} \
		else { \
			for( z = 0; z < nb - 1; z++ ) \
				tq[z] = (a1 * tp[z] + a2 * tp[z + nb] + \
					 a3 * tp[z] + a4 * tp[z + nb]) / \
					(4.0 * a); \
			tq[z] = a; \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		tp += nb << 1; \
		tq += nb; \
	} \
}

/* Generate area @target in @to using pixels in @from. Non-complex. Use the
 * last band as alpha.
 */
static void
vips_region_shrink_alpha( VipsRegion *from, VipsRegion *to, VipsRect *target )
{
	int ls = VIPS_REGION_LSKIP( from );
	int nb = from->im->Bands;

	int x, y, z;

	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			target->left * 2, (target->top + y) * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, 
			target->left, target->top + y );

		/* Process this line of pels.
		 */
		switch( from->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:	
			SHRINK_ALPHA( unsigned char ); break; 
		case VIPS_FORMAT_CHAR:	
			SHRINK_ALPHA( signed char ); break; 
		case VIPS_FORMAT_USHORT:	
			SHRINK_ALPHA( unsigned short ); break; 
		case VIPS_FORMAT_SHORT:	
			SHRINK_ALPHA( signed short ); break; 
		case VIPS_FORMAT_UINT:	
			SHRINK_ALPHA( unsigned int ); break; 
		case VIPS_FORMAT_INT:	
			SHRINK_ALPHA( signed int ); break; 
		case VIPS_FORMAT_FLOAT:	
			SHRINK_ALPHA( float ); break; 
		case VIPS_FORMAT_DOUBLE:	
			SHRINK_ALPHA( double ); break; 

		default:
			g_assert_not_reached();
		}
	}
}

/**
 * vips_region_shrink:
 * @from: source region 
 * @to: destination region 
 * @target: #VipsRect of pixels you need to copy
 *
 * Write the pixels @target in @to from the x2 larger area in @from.
 * Non-complex uncoded images and LABQ only. Images with alpha (see
 * vips_image_hasalpha()) shrink with pixels scaled by alpha to avoid fringing.
 *
 * See also: vips_region_shrink_lanczos3(), vips_region_copy().
 */
int
vips_region_shrink( VipsRegion *from, VipsRegion *to, VipsRect *target )
{
	VipsImage *image = from->im;

	if( vips_check_coding_noneorlabq( "vips_region_shrink", image ) )
		return( -1 );

	if( from->im->Coding == VIPS_CODING_NONE ) {
		if( vips_check_noncomplex(  "vips_region_shrink", image ) )
			return( -1 );

		if( vips_image_hasalpha( image ) ) 
			vips_region_shrink_alpha( from, to, target );
		else
			vips_region_shrink_uncoded( from, to, target );
	}
	else
		vips_region_shrink_labpack( from, to, target );

	return( 0 );
}

/* Lanczos3 values for a x2 reduce generated by reduceh.cpp. 
 */
#define SHRINK_INT_LANCZOS3_VER( TYPE, MN, MX ) { \
	TYPE * restrict tp = (TYPE *) p; \
	TYPE * restrict tq = (TYPE *) q; \
	\
	for( x = 0; x < in_cols; x++ ) { \
		int tot = 50 * tp[0] + \
			-277 * tp[2 * ls] + \
			1248 * tp[4 * ls] + \
			2054 * tp[5 * ls] + \
			1248 * tp[6 * ls] + \
			-277 * tp[8 * ls] + \
			  50 * tp[10 * ls]; \
		\
		tot = (tot + 2048) >> 12; \
		tq[x] = VIPS_CLIP( MN, tot, MX ); \
		\
		tp += 1; \
	} \
}

#define SHRINK_FLOAT_LANCZOS3_VER( TYPE ) { \
	TYPE * restrict tp = (TYPE *) p; \
	TYPE * restrict tq = (TYPE *) q; \
	\
	for( x = 0; x < in_cols; x++ ) { \
		tq[x] = 0.0121933 * tp[0] + \
		       -0.0677406 * tp[2 * ls] + \
                        0.3048330 * tp[4 * ls] + \
                        0.5014290 * tp[5 * ls] + \
                        0.3048330 * tp[6 * ls] + \
                       -0.0677406 * tp[8 * ls] + \
                        0.0121933 * tp[10 * ls]; \
		\
		tp += 1; \
	} \
}

#define SHRINK_INT_LANCZOS3_HOR( TYPE, MN, MX ) { \
	TYPE * restrict tp = (TYPE *) p; \
	TYPE * restrict tq = (TYPE *) q; \
	\
	for( x = 0; x < target->width; x++ ) { \
		for( z = 0; z < nb; z++ ) { \
			int tot = 50 * tp[0] + \
				-277 * tp[2 * nb] + \
				1248 * tp[4 * nb] + \
				2054 * tp[5 * nb] + \
				1248 * tp[6 * nb] + \
				-277 * tp[8 * nb] + \
				  50 * tp[10 * nb]; \
			\
			tot = (tot + 2048) >> 12; \
			tq[z] = VIPS_CLIP( MN, tot, MX ); \
			\
			tp += 1; \
		} \
		\
		tp += nb; \
		tq += nb; \
	} \
}

#define SHRINK_FLOAT_LANCZOS3_HOR( TYPE ) { \
	TYPE * restrict tp = (TYPE *) p; \
	TYPE * restrict tq = (TYPE *) q; \
	\
	for( x = 0; x < target->width; x++ ) { \
		for( z = 0; z < nb; z++ ) { \
			tq[z] = 0.0121933 * tp[0] + \
			       -0.0677406 * tp[2 * nb] + \
			        0.3048330 * tp[4 * nb] + \
			        0.5014290 * tp[5 * nb] + \
			        0.3048330 * tp[6 * nb] + \
			       -0.0677406 * tp[8 * nb] + \
			        0.0121933 * tp[10 * nb]; \
			\
			tp += 1; \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		tp += nb; \
		tq += nb; \
	} \
}

/* Generate area @target in @to using pixels in @from. Non-complex.
 */
static void
vips_region_shrink_uncoded_lanczos3( VipsRegion *from, VipsRegion *to, 
	VipsRect *target, int margin )
{
	int ls = VIPS_REGION_LSKIP( from );
	int es = VIPS_IMAGE_SIZEOF_ELEMENT( from->im );
	int nb = from->im->Bands;

	/* Number of columns of elements in the input for the first vertical
	 * shrink.
	 */
	int in_cols = nb * (2 * target->width + 10);

	VipsPel *intermediate;
	int x, y, z;

	/* We shrink in two orthogonal passes, so we need to keep the results
	 * of the vertical shrink in an intermediate. 
	 *
	 * We try hard in the rest of vips to avoid malloc()/free() on the
	 * main path, but it seems unavoidable here, and it's going to be slow
	 * anyway. 
	 */
	intermediate = g_malloc( target->height * in_cols * es );

	/* Vertical first, since that is simple to auto-vectorise.
	 */
	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			(target->left - margin) * 2,
			(target->top - margin + y) * 2 );
		VipsPel *q = intermediate + y * in_cols * es;

		switch( from->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:	
			SHRINK_INT_LANCZOS3_VER( unsigned char, 
				0, UCHAR_MAX );  
			break; 

		case VIPS_FORMAT_CHAR:	
			SHRINK_INT_LANCZOS3_VER( signed char, 
				SCHAR_MIN, SCHAR_MAX );  
			break; 

		case VIPS_FORMAT_USHORT:	
			SHRINK_INT_LANCZOS3_VER( unsigned short, 
				0, USHRT_MAX );  
			break; 

		case VIPS_FORMAT_SHORT:	
			SHRINK_INT_LANCZOS3_VER( signed short, 
				SHRT_MIN, SHRT_MAX );  
			break; 

		case VIPS_FORMAT_UINT:	
			SHRINK_FLOAT_LANCZOS3_VER( unsigned int );  
			break; 

		case VIPS_FORMAT_INT:	
			SHRINK_FLOAT_LANCZOS3_VER( signed int );  
			break; 

		case VIPS_FORMAT_FLOAT:	
			SHRINK_FLOAT_LANCZOS3_VER( float );  
			break; 

		case VIPS_FORMAT_DOUBLE:	
			SHRINK_FLOAT_LANCZOS3_VER( double );  
			break; 

		default:
			g_assert_not_reached();
		}
	}

	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = intermediate + y * in_cols * es;
		VipsPel *q = VIPS_REGION_ADDR( to, 
			target->left, target->top + y );

		switch( from->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:	
			SHRINK_INT_LANCZOS3_HOR( unsigned char, 
				0, UCHAR_MAX );  
			break; 

		case VIPS_FORMAT_CHAR:	
			SHRINK_INT_LANCZOS3_HOR( signed char, 
				SCHAR_MIN, SCHAR_MAX );  
			break; 

		case VIPS_FORMAT_USHORT:	
			SHRINK_INT_LANCZOS3_HOR( unsigned short, 
				0, USHRT_MAX );  
			break; 

		case VIPS_FORMAT_SHORT:	
			SHRINK_INT_LANCZOS3_HOR( signed short, 
				SHRT_MIN, SHRT_MAX );  
			break; 

		case VIPS_FORMAT_UINT:	
			SHRINK_FLOAT_LANCZOS3_HOR( unsigned int );  
			break; 

		case VIPS_FORMAT_INT:	
			SHRINK_FLOAT_LANCZOS3_HOR( signed int );  
			break; 

		case VIPS_FORMAT_FLOAT:	
			SHRINK_FLOAT_LANCZOS3_HOR( float );  
			break; 

		case VIPS_FORMAT_DOUBLE:	
			SHRINK_FLOAT_LANCZOS3_HOR( double );  
			break; 

		default:
			g_assert_not_reached();
		}
	}

	g_free( intermediate ); 
}

/**
 * vips_region_shrink_lanczos3:
 * @from: source region 
 * @to: destination region 
 * @target: #VipsRect of @to to write
 * @margin: @target is offset by this much in @to
 *
 * Write to the pixels in @target in @to using the in @from as the source.
 * @target includes a margin of @margin pixels. Non-complex uncoded images 
 * only. No alpha handling. 
 *
 * We need a margin, since we want to be able to have some space in the output
 * at the left/top so we can call this function repeatedly.
 *
 * See also: vips_region_shrink(), vips_region_copy().
 */
int
vips_region_shrink_lanczos3( VipsRegion *from, VipsRegion *to, 
	VipsRect *target, int margin )
{
	VipsImage *image = from->im;

	VipsRect source;

	if( vips_check_noncomplex( "vips_region_shrink_lanczos3", image ) )
		return( -1 );

	/* Lanczos3 is 11x11.
	 */
	source.left = (target->left - margin) * 2;
	source.top = (target->top - margin) * 2;
	source.width = target->width * 2 + 10;
	source.height = target->height * 2 + 10;
	if( !vips_rect_includesrect( &from->valid, &source ) ) {
		printf( "argh not enough pixels!!\n" );
		return( -1 ); 
	}

	vips_region_shrink_uncoded_lanczos3( from, to, target, margin );

	return( 0 );
}

