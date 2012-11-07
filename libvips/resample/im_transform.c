/* Resample an image.
 * Original code from Reimar Lenz,
 * Adapted by Lars Raffelt for many bands,
 * VIPSified by JC ... other numeric types, partial output
 *
 * 7/11/12
 * 	- reworked again for vips8
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
#define DEBUG
#define DEBUG_GEOMETRY
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <math.h>

#include <vips/vips.h>

/* **************************************************************************
/@ imtranf.c
/@
/@      ALGORITHM
/@
/@      x',y' = coordinates of srcim
/@      x,y   = coordinates of dstim
/@
/@
/@      x = x' + srcvec[0]                     : order 0     image shift only
/@             + srcvec[2]x'   + srcvec[4]y'   : order 1     + affine transf.
/@             + srcvec[6]x'y'                 : order 2     + bilinear transf.
/@             + srcvec[8]x'x' + srcvec[10]y'y': order 3     + quadratic transf.
/@
/@      y = y' + srcvec[1]
/@             + srcvec[3]x'   + srcvec[5]y'
/@             + srcvec[7]x'y'
/@             + srcvec[9]x'x' + srcvec[11]y'y'
/@
/@
/@
/@
************************************************************************/

/* Inner bilinear interpolation loop. Integer types.
 */
#define IPOL_INNERI( TYPE ) { \
	TYPE *from = (TYPE *) p; \
	TYPE *to = (TYPE *) q; \
	int i; \
	\
	for( i = 0; i < bands; i++ ) { \
		double value = f1 * from[t2 + t4 + i] + \
			f2 * from[t2 + t5 + i] + \
			f3 * from[t3 + t4 + i] + \
			f4 * from[t3 + t5 + i]; \
		to[ix++] = (int) (value + 0.5); \
	} \
}

/* Inner bilinear interpolation loop. Float types.
 */
#define IPOL_INNERF( TYPE ) { \
	TYPE *from = (TYPE *) p; \
	TYPE *to = (TYPE *) q; \
	int i; \
	\
	for( i = 0; i < bands; i++ ) { \
		double value = f1 * from[t2 + t4 + i] + \
			f2 * from[t2 + t5 + i] + \
			f3 * from[t3 + t4 + i] + \
			f4 * from[t3 + t5 + i]; \
		to[ix++] = value; \
	} \
}

#define TYPE_SWITCH_IPOL \
	switch( bandfmt ) { \
	case IM_BANDFMT_UCHAR:	IPOL_INNERI( unsigned char ); break; \
	case IM_BANDFMT_USHORT:	IPOL_INNERI( unsigned short ); break; \
	case IM_BANDFMT_UINT:	IPOL_INNERI( unsigned int ); break; \
	case IM_BANDFMT_CHAR:	IPOL_INNERI( signed char ); break; \
	case IM_BANDFMT_SHORT:	IPOL_INNERI( signed short ); break; \
	case IM_BANDFMT_INT:	IPOL_INNERI( signed int ); break; \
	case IM_BANDFMT_FLOAT:	IPOL_INNERF( float ); break; \
	case IM_BANDFMT_DOUBLE:	IPOL_INNERF( double ); break; \
 	\
	default: \
		g_assert( 0 ); \
		/*NOTREACHED*/ \
	}

/* 2-way interpolation, integer types.
 */
#define IPOL2_INNERI( TYPE ) { \
	TYPE *from = (TYPE *) p; \
	TYPE *to = (TYPE *) q; \
	int i; \
	\
	for( i = 0; i < bands; i++ ) { \
		double value = f1 * from[t1 + i] + f2 * from[t2 + i]; \
		to[ix++] = (int) (value + 0.5); \
	} \
}

/* 2-way interpolation, float types.
 */
#define IPOL2_INNERF( TYPE ) { \
	TYPE *from = (TYPE *) p; \
	TYPE *to = (TYPE *) q; \
	int i; \
	\
	for( i = 0; i < bands; i++ ) { \
		double value = f1 * from[t1 + i] + f2 * from[t2 + i]; \
		to[ix++] = value; \
	} \
}

#define TYPE_SWITCH_IPOL2 \
	switch( bandfmt ) { \
	case IM_BANDFMT_UCHAR:	IPOL2_INNERI( unsigned char ); break; \
	case IM_BANDFMT_USHORT:	IPOL2_INNERI( unsigned short ); break; \
	case IM_BANDFMT_UINT:	IPOL2_INNERI( unsigned int ); break; \
	case IM_BANDFMT_CHAR:	IPOL2_INNERI( signed char ); break; \
	case IM_BANDFMT_SHORT:	IPOL2_INNERI( signed short ); break; \
	case IM_BANDFMT_INT:	IPOL2_INNERI( signed int ); break; \
	case IM_BANDFMT_FLOAT:	IPOL2_INNERF( float ); break; \
	case IM_BANDFMT_DOUBLE:	IPOL2_INNERF( double ); break; \
 	\
	default: \
		g_assert( 0 ); \
		/*NOTREACHED*/ \
	}

#define NN_INNER( TYPE ) { \
	TYPE *from = (TYPE *) p; \
	TYPE *to = (TYPE *) q; \
	int i; \
	\
	for( i = 0; i < bands; i++ ) \
		to[ix++] = from[t1 + i];\
}

#define TYPE_SWITCH_NN \
	switch( bandfmt ) { \
	case IM_BANDFMT_UCHAR:		NN_INNER( unsigned char ); break; \
	case IM_BANDFMT_USHORT:		NN_INNER( unsigned short ); break; \
	case IM_BANDFMT_UINT:		NN_INNER( unsigned int ); break; \
	case IM_BANDFMT_CHAR:		NN_INNER( signed char ); break; \
	case IM_BANDFMT_SHORT:		NN_INNER( signed short ); break; \
	case IM_BANDFMT_INT:		NN_INNER( signed int ); break; \
	case IM_BANDFMT_FLOAT:		NN_INNER( float ); break; \
	case IM_BANDFMT_DOUBLE:		NN_INNER( double ); break; \
 	\
	default: \
		g_assert( 0 ); \
		/*NOTREACHED*/ \
	}

/* Keep run state here.
 */
typedef struct {
	IMAGE *in;		/* From here */
	IMAGE *out;		/* To here */
	DOUBLEMASK *vec;	/* This transform */

	int order;
} ImtranInfo;

static int
transform_gen( REGION *out, void *seq, void *a, void *b )
{
	const IMAGE *in = (IMAGE *) a;
	const ImtranInfo *it = (ImtranInfo *) b;

	double *vec = it->vec->coeff;

	int sizex = in->Xsize;
	int sizey = in->Ysize;
	int bands = in->Bands;
	int bandfmt = in->BandFmt;

	const int sizex1 = sizex - 1;
	const int sizey1 = sizey - 1;

	int xlow = out->valid.left;
	int ylow = out->valid.top;
	int xhigh = IM_RECT_RIGHT( &out->valid );
	int yhigh = IM_RECT_BOTTOM( &out->valid );

	PEL *p = (PEL *) in->data;
	PEL *q;

	int xi, yi;		/* input coordinates, srcimage  */
	int xi1, yi1;		/* 1 + input coordinates */
	int xo, yo;		/* output coordinates, dstimage */
	int ix;			/* pointer auf Zielbild */
	double fxi, fyi; 	/* input coordinates */
	double frx, fry;      	/* fractinal part of input coord. */
	double frx1, fry1; 	/* 1.0 - fract. part of input coord. */
	double dx, dy;        	/* xo derivative of input coord. */
	double ddx, ddy;      	/* 2nd xo derivative of input coord. */

	for( yo = ylow; yo < yhigh; yo++ ) {
		fxi = xlow + vec[0];                /* order 0 */
		fyi = yo + vec[1];    
		dx  = 1.0;
		dy  = 0.0;

		switch( it->order ) {
		case 3: 
			fxi += vec[10] * yo * yo + vec[8] * xlow * xlow;
			fyi += vec[11] * yo * yo + vec[9] * xlow * xlow;
			dx  += vec[8];
			ddx  = vec[8] * 2.0;
			dy  += vec[9];
			ddy  = vec[9] * 2.0;

		case 2: 
			fxi += vec[6] * xlow * yo;
			fyi += vec[7] * xlow * yo;
			dx  += vec[6] * yo;
			dy  += vec[7] * yo;

		case 1: fxi += vec[4] * yo + vec[2] * xlow;
			fyi += vec[5] * yo + vec[3] * xlow;
			dx  += vec[2];
			dy  += vec[3];
			break;
		default:
		    printf("transform_nowrap_ipol: order out of range\n");
		    return(-7);
		}

		q = (PEL *) IM_REGION_ADDR( out, xlow, yo );

		/*  7 | 8 | 1 */
		/*  --+---+-- */
		/*  6 | 0 | 2 */
		/*  --+---+-- */
		/*  5 | 4 | 3 */
		/* 0 Orginalbild */

		for( ix = 0, xo = xlow; xo < xhigh; xo++ ) {
			int t1, t2, t3, t4, t5;
			double f1, f2, f3, f4;

			if( fxi < 0 ) {
				if( fyi < 0 ) {                                  /* 7 */
					t1 = 0;

					TYPE_SWITCH_NN;
				}
				else if( fyi >= sizey1 ) {                       /* 5 */
					t1 = sizey1*sizex*bands;
					
					TYPE_SWITCH_NN;
				}
				else {                                          /* 6 */
					yi  = fyi;
					yi1 = yi + 1;

					t1 = yi*sizex*bands;
					t2 = yi1*sizex*bands;
					f1 = yi1 - fyi;
					f2 = fyi - yi;

					TYPE_SWITCH_IPOL2;
				}
			}
			else if( fxi >= sizex1 ) {
				if( fyi < 0 ) {                                         /* 1 */
					t1 = sizex1*bands;
					
					TYPE_SWITCH_NN;
				}
				else if( fyi >= sizey1 ) {                            /* 3 */
					t1 = sizex1*bands+sizex*sizey1*bands;

					TYPE_SWITCH_NN;
				}
				else {                                                /* 2 */
					yi  = fyi;
					yi1 = yi + 1;

					t1 = sizex1*bands+yi*sizex*bands;
					t2 = sizex1*bands+yi1*sizex*bands;
					f1 = yi1 - fyi;
					f2 = fyi - yi;

					TYPE_SWITCH_IPOL2;
				}
			}
			else {
				if( fyi < 0 ) {                             /* 8 */
					xi  = fxi;
					xi1 = xi + 1;

					t1 = xi*bands;
					t2 = xi1*bands;
					f1 = xi1 - fxi;
					f2 = fxi - xi;

					TYPE_SWITCH_IPOL2;
				}
				else if( fyi >= sizey1 ) { 			/* 4 */
					xi  = fxi;
					xi1 = xi + 1;

					t1 = xi*bands+sizey1*sizex*bands;
					t2 = xi1*bands+sizey1*sizex*bands;
					f1 = xi1 - fxi;
					f2 = fxi - xi;

					TYPE_SWITCH_IPOL2;
				}
				else {                                    /* 0 */
					xi   = fxi;
					frx  = fxi - xi;
					frx1 = 1.0 - frx;
					yi   = fyi;
					fry  = fyi - yi;
					fry1 = 1.0 - fry;
					xi1  = xi+1;
					yi1  = yi+1;

					t1 = sizex*bands;
					t2 = yi*t1;
					t3 = yi1*t1;
					t4 = xi*bands;
					t5 = xi1*bands;
					f1 = frx1*fry1;
					f2 = frx*fry1;
					f3 = frx1*fry;
					f4 = frx*fry;

					/* Inner ipol stuff.
					 */
					TYPE_SWITCH_IPOL;
				}
			}

			fxi += dx;
			fyi += dy;
			if( it->order > 2 ) {
				dx += ddx;
				dy += ddy;
			}
		}
	}

	return( 0 );
}

int
im_transform2( IMAGE *in, IMAGE *out, DOUBLEMASK *vec )
{
	ImtranInfo *it;
	int order;

        /* Check args.
         */
        if( im_incheck( in ) || im_poutcheck( out ) )
                return( -1 );
        if( in->Coding != IM_CODING_NONE || im_iscomplex( in ) ) {
                im_errormsg( "im_transform: uncoded non-complex only" );
                return( -1 );
        }
	if( vec->xsize != 2 ) {
		im_errormsg( "im_transform: mask width not 2" );
		return( -1 );
	} 
        switch( vec->ysize ) {
	case 1: order = 0; break;
	case 3: order = 1; break;
	case 4: order = 2; break;
	case 6: order = 3; break;
	default:
		im_errormsg( "im_transform: mask height not 1, 3, 4 or 6" );
		return( -1 );
	} 
        if( im_cp_desc( out, in ) )
                return( -1 );

	if( !(it = IM_NEW( out, ImtranInfo )) )
		return( -1 );
	it->in = in;
	it->out = out;
	it->vec = NULL;
	it->order = order;

        /* Take a copy of vec.
         */
        if( !(it->vec = im_dup_dmask( vec, "conv_mask" )) )
                return( -1 );
        if( im_add_close_callback( out, 
		(im_callback_fn) im_free_dmask, it->vec, NULL ) ) {
                im_free_dmask( it->vec );
                return( -1 );
        }

	/* Don't mind ... partial output only.
	 */
        if( im_demand_hint( out, IM_ANY, in, NULL ) )
                return( -1 );

        /* Generate!
         */
        if( im_generate( out, 
		NULL, transform_gen, NULL, in, it ) )
                return( -1 );

        return( 0 );
}
