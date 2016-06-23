/* convf
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris & Kirk Martinez
 * Written on: 29/04/1991
 * Modified on: 19/05/1991
 * 8/7/93 JC
 *      - adapted for partial v2
 *      - memory leaks fixed
 *      - ANSIfied
 * 12/7/93 JC
 *	- adapted im_convbi() to im_convbf()
 * 7/10/94 JC
 *	- new IM_ARRAY() macro
 *	- evalend callbacks
 *	- more typedef
 * 9/3/01 JC
 *	- redone from im_conv() 
 * 27/7/01 JC
 *	- rejects masks with scale == 0
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the input, not
 *	  the output
 *	- sets Xoffset / Yoffset
 * 11/11/05
 * 	- simpler inner loop avoids gcc4 bug 
 * 12/11/09
 * 	- only rebuild the buffer offsets if bpl changes
 * 	- tiny speedups and cleanups
 * 	- add restrict, though it doesn't seem to help gcc
 * 	- add mask-all-zero check
 * 13/11/09
 * 	- rename as im_conv_f() to make it easier for vips.c to make the
 * 	  overloaded version
 * 3/2/10
 * 	- gtkdoc
 * 	- more cleanups
 * 1/10/10
 * 	- support complex (just double the bands)
 * 29/10/10
 * 	- get rid of im_convsep_f(), just call this twice, no longer worth
 * 	  keeping two versions
 * 15/10/11 Nicolas
 * 	- handle offset correctly in seperable convolutions
 * 26/1/16 Lovell Fuller
 * 	- remove Duff for a 25% speedup
 * 23/6/16
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
#include <stdlib.h>
#include <limits.h>

#include <vips/vips.h>

#include "pconvolution.h"

typedef struct {
	VipsConvolution parent_instance;

	/* We make a smaller version of the mask with the zeros squeezed out.
	 */
	int nnz;		/* Number of non-zero mask elements */
	double *coeff;		/* Array of non-zero mask coefficients */
	int *coeff_pos;		/* Index of each nnz element in mask->coeff */
} VipsConvf;

typedef VipsConvolutionClass VipsConvfClass;

G_DEFINE_TYPE( VipsConvf, vips_convf, VIPS_TYPE_CONVOLUTION );

/* Our sequence value.
 */
typedef struct {
	VipsConvf *convf;
	VipsRegion *ir;		/* Input region */

	int *offsets;		/* Offsets for each non-zero matrix element */
	VipsPel **pts;		/* Per-non-zero mask element image pointers */

	int last_bpl;		/* Avoid recalcing offsets, if we can */
} VipsConvfSequence;

/* Free a sequence value.
 */
static int
vips_convf_stop( void *vseq, void *a, void *b )
{
	VipsConvfSequence *seq = (VipsConvfSequence *) vseq;

	VIPS_UNREF( seq->ir );

	return( 0 );
}

/* Convolution start function.
 */
static void *
vips_convf_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsConvf *convf = (VipsConvf *) b;
	VipsConvfSequence *seq;

	if( !(seq = VIPS_NEW( out, VipsConvfSequence )) )
		return( NULL );

	seq->convf = convf;
	seq->ir = NULL;
	seq->pts = NULL;
	seq->last_bpl = -1;

	seq->ir = vips_region_new( in );
	if( !(seq->offsets = VIPS_ARRAY( out, convf->nnz, int )) ||
		!(seq->pts = VIPS_ARRAY( out, convf->nnz, VipsPel * )) ) {
		vips_convf_stop( seq, in, convf );
		return( NULL );
	}

	return( (void *) seq );
}

#define CONV_FLOAT( ITYPE, OTYPE ) { \
	ITYPE ** restrict p = (ITYPE **) seq->pts; \
	OTYPE * restrict q = (OTYPE *) VIPS_REGION_ADDR( or, le, y ); \
	\
	for( x = 0; x < sz; x++ ) {  \
		double sum; \
		int i; \
		\
		sum = 0; \
		for ( i = 0; i < nnz; i++ ) \
			sum += t[i] * p[i][x]; \
 		\
		sum = (sum / scale) + offset; \
		\
		q[x] = sum;  \
	}  \
} 

/* Convolve!
 */
static int
vips_convf_gen( REGION *or, void *vseq, void *a, void *b, gboolean *stop )
{
	VipsConvfSequence *seq = (VipsConvfSequence *) vseq;
	VipsConvf *convf = (VipsConvf *) b;
	VipsConvolution *convolution = (VipsConvolution *) convf;
	VipsImage *M = convolution->M;
	double scale = vips_image_get_scale( M ); 
	double offset = vips_image_get_offset( M ); 
	VipsImage *in = (VipsImage *) a;
	VipsRegion *ir = seq->ir;
	double * restrict t = convf->coeff; 
	const int nnz = convf->nnz;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );
	int sz = VIPS_REGION_N_ELEMENTS( or ) * 
		(vips_band_format_iscomplex( in->BandFmt ) ? 2 : 1);

	VipsRect s;
	int x, y, z, i;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += M->Xsize - 1;
	s.height += M->Ysize - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

        /* Fill offset array. Only do this if the bpl has changed since the 
	 * previous vips_region_prepare().
	 */
	if( seq->last_bpl != VIPS_REGION_LSKIP( ir ) ) {
		seq->last_bpl = VIPS_REGION_LSKIP( ir );

		for( i = 0; i < nnz; i++ ) {
			z = convf->coeff_pos[i];
			x = z % M->Xsize;
			y = z / M->Xsize;

			seq->offsets[i] = 
				VIPS_REGION_ADDR( ir, x + le, y + to ) -
				VIPS_REGION_ADDR( ir, le, to );
		}
	}

	for( y = to; y < bo; y++ ) { 
		/* Init pts for this line of PELs.
		 */
		for( z = 0; z < nnz; z++ )
			seq->pts[z] = seq->offsets[z] +
				VIPS_REGION_ADDR( ir, le, y ); 

		switch( in->BandFmt ) {
		case VIPS_FORMAT_UCHAR: 	
			CONV_FLOAT( unsigned char, float ); 
			break;

		case VIPS_FORMAT_CHAR:   
			CONV_FLOAT( signed char, float ); 
			break;

		case VIPS_FORMAT_USHORT: 
			CONV_FLOAT( unsigned short, float ); 
			break;

		case VIPS_FORMAT_SHORT:  
			CONV_FLOAT( signed short, float ); 
			break;

		case VIPS_FORMAT_UINT:   
			CONV_FLOAT( unsigned int, float ); 
			break;

		case VIPS_FORMAT_INT:    
			CONV_FLOAT( signed int, float ); 
			break;

		case VIPS_FORMAT_FLOAT:  
		case VIPS_FORMAT_COMPLEX:  
			CONV_FLOAT( float, float ); 
			break;

		case VIPS_FORMAT_DOUBLE: 
		case VIPS_FORMAT_DPCOMPLEX:  
			CONV_FLOAT( double, double ); 
			break;

		default:
			g_assert_not_reached();
		}
	}

	return( 0 );
}

static int
vips_convf_build( VipsObject *object )
{
	VipsConvolution *convolution = (VipsConvolution *) object;
	VipsConvf *convf = (VipsConvf *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 4 );

	VipsImage *in;
	VipsImage *M;
	double *coeff;
	int ne;
        int i;

	if( VIPS_OBJECT_CLASS( vips_convf_parent_class )->build( object ) )
		return( -1 );

	M = convolution->M;
	coeff = (double *) VIPS_IMAGE_ADDR( M, 0, 0 );
	ne = M->Xsize * M->Ysize;
        if( !(convf->coeff = VIPS_ARRAY( object, ne, double )) ||
        	!(convf->coeff_pos = VIPS_ARRAY( object, ne, int )) )
                return( -1 );

        /* Find non-zero mask elements.
         */
        for( i = 0; i < ne; i++ )
                if( coeff[i] ) {
			convf->coeff[convf->nnz] = coeff[i];
			convf->coeff_pos[convf->nnz] = i;
			convf->nnz += 1;
		}

	/* Was the whole mask zero? We must have at least 1 element in there:
	 * set it to zero.
	 */
	if( convf->nnz == 0 ) {
		convf->coeff[0] = 0;
		convf->coeff_pos[0] = 0;
		convf->nnz = 1;
	}

	in = convolution->in;

	if( vips_embed( in, &t[0], 
		M->Xsize / 2, M->Ysize / 2, 
		in->Xsize + M->Xsize - 1, in->Ysize + M->Ysize - 1,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[0]; 

	g_object_set( convf, "out", vips_image_new(), NULL ); 
	if( vips_image_pipelinev( convolution->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, in, NULL ) )
		return( -1 );

	convolution->out->Xoffset = 0;
	convolution->out->Yoffset = 0;

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( vips_bandfmt_isint( in->BandFmt ) ) 
		convolution->out->BandFmt = IM_BANDFMT_FLOAT;
	convolution->out->Xsize -= M->Xsize - 1;
	convolution->out->Ysize -= M->Ysize - 1;

	if( vips_image_generate( convolution->out, 
		vips_convf_start, vips_convf_gen, vips_convf_stop, in, convf ) )
		return( -1 );

	convolution->out->Xoffset = -M->Xsize / 2;
	convolution->out->Yoffset = -M->Ysize / 2;

	return( 0 );
}

static void
vips_convf_class_init( VipsConvfClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "convf";
	object_class->description = _( "float convolution operation" );
	object_class->build = vips_convf_build;
}

static void
vips_convf_init( VipsConvf *convf )
{
        convf->nnz = 0;
        convf->coeff = NULL;
        convf->coeff_pos = NULL;
}

/**
 * vips_convf:
 * @in: input image
 * @out: output image
 * @mask: convolve with this mask
 * @...: %NULL-terminated list of optional named arguments
 *
 * Convolution. This is a low-level operation, see vips_conv() for something
 * more convenient. 
 *
 * Perform a convolution of @in with @mask.
 * Each output pixel is
 * calculated as sigma[i]{pixel[i] * mask[i]} / scale + offset, where scale
 * and offset are part of @mask. 
 *
 * The convolution is performed with floating-point arithmetic. The output image 
 * is always #VIPS_FORMAT_FLOAT unless @in is #VIPS_FORMAT_DOUBLE, in which case
 * @out is also #VIPS_FORMAT_DOUBLE. 
 *
 * See also: vips_conv().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_convf( VipsImage *in, VipsImage **out, VipsImage *mask, ... )
{
	va_list ap;
	int result;

	va_start( ap, mask );
	result = vips_call_split( "convf", ap, in, out, mask );
	va_end( ap );

	return( result );
}

