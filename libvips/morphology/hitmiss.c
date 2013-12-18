/* morphological operators
 *
 * 19/9/95 JC
 *	- rewritten
 * 6/7/99 JC
 *	- small tidies
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the input, not
 *	  the output
 *	- sets Xoffset / Yoffset
 * 21/4/08
 * 	- only rebuild the buffer offsets if bpl changes
 * 	- small cleanups
 * 25/10/10
 * 	- start again from the Orc'd im_conv
 * 29/10/10
 * 	- use VipsVector
 * 	- do erode as well 
 * 7/11/10
 * 	- gtk-doc
 * 	- do (!=0) to make uchar, if we're not given uchar
 * 28/6/13
 * 	- oops, fix !=0 code
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
#include <limits.h>

#include <vips/vips.h>
#include <vips/vector.h>

/* The two operators we implement. They are more hit-miss, really.
 */
typedef enum {
	ERODE,
	DILATE
} MorphOp;

/* We can't run more than this many passes. Larger than this and we
 * fall back to C.
 */
#define MAX_PASS (10)

/* A pass with a vector. 
 */
typedef struct {
	int first;		/* The index of the first mask coff we use */
	int last;		/* The index of the last mask coff we use */

	int r;			/* Set previous result in this var */

        /* The code we generate for this section of this mask. 
	 */
        VipsVector *vector;
} Pass;

/* Our parameters.
 */
typedef struct {
	IMAGE *in;
	IMAGE *out;
	INTMASK *mask;		/* Copy of mask arg */
	MorphOp op;

	/* The passes we generate for this mask.
	 */
	int n_pass;	
	Pass pass[MAX_PASS];
} Morph;

static void
pass_free( Morph *morph )
{
	int i;

	for( i = 0; i < morph->n_pass; i++ )
		IM_FREEF( vips_vector_free, morph->pass[i].vector );
	morph->n_pass = 0;
}

static int
morph_close( Morph *morph )
{
	IM_FREEF( im_free_imask, morph->mask );
	pass_free( morph );

        return( 0 );
}

#define TEMP( N, S ) vips_vector_temporary( v, N, S )
#define SCANLINE( N, P, S ) vips_vector_source_scanline( v, N, P, S )
#define CONST( N, V, S ) vips_vector_constant( v, N, V, S )
#define ASM2( OP, A, B ) vips_vector_asm2( v, OP, A, B )
#define ASM3( OP, A, B, C ) vips_vector_asm3( v, OP, A, B, C )

/* Generate code for a section of the mask. first is the index we start
 * at, we set last to the index of the last one we use before we run 
 * out of intermediates / constants / parameters / sources or mask
 * coefficients.
 *
 * 0 for success, -1 on error.
 */
static int
pass_compile_section( Pass *pass, Morph *morph, gboolean first_pass )
{
	INTMASK *mask = morph->mask;
	const int n_mask = mask->xsize * mask->ysize; 

	VipsVector *v;
	char offset[256];
	char source[256];
	char zero[256];
	char one[256];
	int i;

	pass->vector = v = vips_vector_new( "morph", 1 );

	/* The value we fetch from the image, the accumulated sum.
	 */
	TEMP( "value", 1 );
	TEMP( "sum", 1 );

	CONST( zero, 0, 1 );
	CONST( one, 255, 1 );

	/* Init the sum. If this is the first pass, it's a constant. If this
	 * is a later pass, we have to init the sum from the result 
	 * of the previous pass. 
	 */
	if( first_pass ) {
		if( morph->op == DILATE )
			ASM2( "copyb", "sum", zero );
		else
			ASM2( "copyb", "sum", one );
	}
	else {
		/* "r" is the result of the previous pass. 
		 */
		pass->r = vips_vector_source_name( v, "r", 1 );
		ASM2( "loadb", "sum", "r" );
	}

	for( i = pass->first; i < n_mask; i++ ) {
		int x = i % mask->xsize;
		int y = i / mask->xsize;

		/* Exclude don't-care elements.
		 */
		if( mask->coeff[i] == 128 )
			continue;

		/* The source. sl0 is the first scanline in the mask.
		 */
		SCANLINE( source, y, 1 );

		/* The offset, only for non-first-columns though.
		 */
		if( x > 0 ) {
			CONST( offset, morph->in->Bands * x, 1 );
			ASM3( "loadoffb", "value", source, offset );
		}
		else
			ASM2( "loadb", "value", source );

		/* Join to our sum. If the mask element is zero, we have to
		 * add an extra negate.
		 */
		if( morph->op == DILATE ) {
			if( !mask->coeff[i] ) 
				ASM3( "xorb", "value", "value", one );
			ASM3( "orb", "sum", "sum", "value" );
		}
		else {
			if( !mask->coeff[i] ) 
				ASM3( "andnb", "sum", "sum", "value" );
			else
				ASM3( "andb", "sum", "sum", "value" );
		}

		if( vips_vector_full( v ) )
			break;
	}

	pass->last = i;

	ASM2( "copyb", "d1", "sum" );

	if( !vips_vector_compile( v ) ) 
		return( -1 );

#ifdef DEBUG
	printf( "done matrix coeffs %d to %d\n", pass->first, pass->last );
	vips_vector_print( v );
#endif /*DEBUG*/

	return( 0 );
}

/* Generate a set of passes.
 */
static int
pass_compile( Morph *morph )
{
	INTMASK *mask = morph->mask;
	const int n_mask = mask->xsize * mask->ysize; 

	int i;
	Pass *pass;

#ifdef DEBUG
	printf( "morph: generating vector code\n" );
#endif /*DEBUG*/

	/* Generate passes until we've used up the whole mask.
	 */
	for( i = 0;;) {
		/* Skip any don't-care coefficients at the start of the mask 
		 * region.
		 */
		for( ; i < n_mask && mask->coeff[i] == 128; i++ )
			;
		if( i == n_mask )
			break;

		/* Allocate space for another pass.
		 */
		if( morph->n_pass == MAX_PASS ) 
			return( -1 );
		pass = &morph->pass[morph->n_pass];
		morph->n_pass += 1;

		pass->first = i;
		pass->last = i;
		pass->r = -1;

		if( pass_compile_section( pass, morph, morph->n_pass == 1 ) )
			return( -1 );
		i = pass->last + 1;

		if( i >= n_mask )
			break;
	}

	return( 0 );
}

static Morph *
morph_new( IMAGE *in, IMAGE *out, INTMASK *mask, MorphOp op )
{
	const int n_mask = mask->xsize * mask->ysize; 

        Morph *morph;
        int i;

	/* If in is not uchar, do (!=0) to make a uchar image.
	 */
	if( in->BandFmt != IM_BANDFMT_UCHAR ) {
		IMAGE *t;

		if( !(t = im_open_local( out, "morph_new", "p" )) ||
			im_notequalconst( in, t, 0 ) )
			return( NULL );

		in = t;
	}

	if( im_piocheck( in, out ) ||
		im_check_uncoded( "morph", in ) ||
		im_check_format( "morph", in, IM_BANDFMT_UCHAR ) ||
		im_check_imask( "morph", mask ) ) 
		return( NULL );
	for( i = 0; i < n_mask; i++ )
		if( mask->coeff[i] != 0 && 
			mask->coeff[i] != 128 &&
			mask->coeff[i] != 255 ) {
			im_error( "morph", 
				_( "bad mask element (%d "
				"should be 0, 128 or 255)" ), 
				mask->coeff[i] );
			return( NULL );
		}

        if( !(morph = IM_NEW( out, Morph )) )
                return( NULL );

        morph->in = in;
        morph->out = out;
        morph->mask = NULL;
        morph->op = op;

        morph->n_pass = 0;
	for( i = 0; i < MAX_PASS; i++ )
		morph->pass[i].vector = NULL;

        if( im_add_close_callback( out, 
		(im_callback_fn) morph_close, morph, NULL ) ||
        	!(morph->mask = im_dup_imask( mask, "morph" )) )
                return( NULL );

	/* Generate code for this mask / image, if possible.
	 */
	if( vips_vector_isenabled() ) {
		if( pass_compile( morph ) )
			pass_free( morph );
	}

        return( morph );
}

/* Our sequence value.
 */
typedef struct {
	Morph *morph;
	REGION *ir;		/* Input region */

	int *soff;		/* Offsets we check for set */
	int ss;			/* ... and number we check for set */
	int *coff;		/* Offsets we check for clear */
	int cs;			/* ... and number we check for clear */

	int last_bpl;		/* Avoid recalcing offsets, if we can */

	/* In vector mode we need a pair of intermediate buffers to keep the 
	 * results of each pass in.
	 */
	void *t1;
	void *t2;
} MorphSequence;

/* Free a sequence value.
 */
static int
morph_stop( void *vseq, void *a, void *b )
{
	MorphSequence *seq = (MorphSequence *) vseq;

	IM_FREEF( im_region_free, seq->ir );
	IM_FREE( seq->t1 );
	IM_FREE( seq->t2 );

	return( 0 );
}

/* Morph start function.
 */
static void *
morph_start( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	Morph *morph = (Morph *) b;
	int n_mask = morph->mask->xsize * morph->mask->ysize;
	int sz = IM_IMAGE_N_ELEMENTS( in );

	MorphSequence *seq;

	if( !(seq = IM_NEW( out, MorphSequence )) )
		return( NULL );

	/* Init!
	 */
	seq->morph = morph;
	seq->ir = NULL;
	seq->soff = NULL;
	seq->ss = 0;
	seq->coff = NULL;
	seq->cs = 0;
	seq->last_bpl = -1;
	seq->t1 = NULL;
	seq->t2 = NULL;

	/* Attach region and arrays.
	 */
	seq->ir = im_region_create( in );
	seq->soff = IM_ARRAY( out, n_mask, int );
	seq->coff = IM_ARRAY( out, n_mask, int );
	seq->t1 = IM_ARRAY( NULL, sz, VipsPel );
	seq->t2 = IM_ARRAY( NULL, sz, VipsPel );
	if( !seq->ir || !seq->soff || !seq->coff || !seq->t1 || !seq->t2  ) {
		morph_stop( seq, in, NULL );
		return( NULL );
	}

	return( seq );
}

/* Dilate!
 */
static int
dilate_gen( REGION *or, void *vseq, void *a, void *b )
{
	MorphSequence *seq = (MorphSequence *) vseq;
	Morph *morph = (Morph *) b;
	INTMASK *mask = morph->mask;
	REGION *ir = seq->ir;

	int *soff = seq->soff;
	int *coff = seq->coff;

	Rect *r = &or->valid;
	Rect s;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM( r );
	int sz = IM_REGION_N_ELEMENTS( or );

	int *t;

	int x, y;
	int result, i;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += mask->xsize - 1;
	s.height += mask->ysize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );

#ifdef DEBUG
	printf( "dilate_gen: preparing %dx%d@%dx%d pixels\n", 
		s.width, s.height, s.left, s.top );
#endif /*DEBUG*/

	/* Scan mask, building offsets we check when processing. Only do this
	 * if the bpl has changed since the previous im_prepare().
	 */
	if( seq->last_bpl != IM_REGION_LSKIP( ir ) ) {
		seq->last_bpl = IM_REGION_LSKIP( ir );

		seq->ss = 0;
		seq->cs = 0;
		for( t = mask->coeff, y = 0; y < mask->ysize; y++ )
			for( x = 0; x < mask->xsize; x++, t++ )
				switch( *t ) {
				case 255:
					soff[seq->ss++] = 
						IM_REGION_ADDR( ir, 
							x + le, y + to ) - 
						IM_REGION_ADDR( ir, le, to );
					break;

				case 128:
					break;

				case 0:
					coff[seq->cs++] = 
						IM_REGION_ADDR( ir, 
							x + le, y + to ) - 
						IM_REGION_ADDR( ir, le, to );
					break;

				default:
					g_assert( 0 );
				}
	}

	/* Dilate!
	 */
	for( y = to; y < bo; y++ ) {
		VipsPel *p = IM_REGION_ADDR( ir, le, y );
		VipsPel *q = IM_REGION_ADDR( or, le, y );

		/* Loop along line.
		 */
		for( x = 0; x < sz; x++, q++, p++ ) {
			/* Search for a hit on the set list.
			 */
			result = 0;
			for( i = 0; i < seq->ss; i++ )
				if( p[soff[i]] ) {
					/* Found a match! 
					 */
					result = 255;
					break;
				}

			/* No set pixels ... search for a hit in the clear
			 * pixels.
			 */
			if( !result )
				for( i = 0; i < seq->cs; i++ )
					if( !p[coff[i]] ) {
						/* Found a match! 
						 */
						result = 255;
						break;
					}

			*q = result;

		}
	}

	return( 0 );
}

/* Erode!
 */
static int
erode_gen( REGION *or, void *vseq, void *a, void *b )
{
	MorphSequence *seq = (MorphSequence *) vseq;
	Morph *morph = (Morph *) b;
	INTMASK *mask = morph->mask;
	REGION *ir = seq->ir;

	int *soff = seq->soff;
	int *coff = seq->coff;

	Rect *r = &or->valid;
	Rect s;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int sz = IM_REGION_N_ELEMENTS( or );

	int *t;

	int x, y;
	int result, i;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += mask->xsize - 1;
	s.height += mask->ysize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );

#ifdef DEBUG
	printf( "erode_gen: preparing %dx%d@%dx%d pixels\n", 
		s.width, s.height, s.left, s.top );
#endif /*DEBUG*/

	/* Scan mask, building offsets we check when processing. Only do this
	 * if the bpl has changed since the previous im_prepare().
	 */
	if( seq->last_bpl != IM_REGION_LSKIP( ir ) ) {
		seq->last_bpl = IM_REGION_LSKIP( ir );

		seq->ss = 0;
		seq->cs = 0;
		for( t = mask->coeff, y = 0; y < mask->ysize; y++ )
			for( x = 0; x < mask->xsize; x++, t++ )
				switch( *t ) {
				case 255:
					soff[seq->ss++] = 
						IM_REGION_ADDR( ir, 
							x + le, y + to ) - 
						IM_REGION_ADDR( ir, le, to );
					break;

				case 128:
					break;

				case 0:
					coff[seq->cs++] = 
						IM_REGION_ADDR( ir, 
							x + le, y + to ) - 
						IM_REGION_ADDR( ir, le, to );
					break;

				default:
					g_assert( 0 );
				}
	}

	/* Erode!
	 */
	for( y = to; y < bo; y++ ) {
		VipsPel *p = IM_REGION_ADDR( ir, le, y );
		VipsPel *q = IM_REGION_ADDR( or, le, y );

		/* Loop along line.
		 */
		for( x = 0; x < sz; x++, q++, p++ ) {
			/* Check all set pixels are set.
			 */
			result = 255;
			for( i = 0; i < seq->ss; i++ )
				if( !p[soff[i]] ) {
					/* Found a mismatch! 
					 */
					result = 0;
					break;
				}

			/* Check all clear pixels are clear.
			 */
			if( result )
				for( i = 0; i < seq->cs; i++ )
					if( p[coff[i]] ) {
						result = 0;
						break;
					}

			*q = result;
		}
	}
	
	return( 0 );
}

/* The vector codepath.
 */
static int
morph_vector_gen( REGION *or, void *vseq, void *a, void *b )
{
	MorphSequence *seq = (MorphSequence *) vseq;
	Morph *morph = (Morph *) b;
	INTMASK *mask = morph->mask;
	REGION *ir = seq->ir;
	Rect *r = &or->valid;
	int sz = IM_REGION_N_ELEMENTS( or );

	Rect s;
	int y, j;
	VipsExecutor executor[MAX_PASS];

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += mask->xsize - 1;
	s.height += mask->ysize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );

#ifdef DEBUG
	printf( "morph_vector_gen: preparing %dx%d@%dx%d pixels\n", 
		s.width, s.height, s.left, s.top );
#endif /*DEBUG*/

	for( j = 0; j < morph->n_pass; j++ ) 
		vips_executor_set_program( &executor[j], 
			morph->pass[j].vector, sz );

	for( y = 0; y < r->height; y++ ) { 
		for( j = 0; j < morph->n_pass; j++ ) {
			void *d;

			/* The last pass goes to the output image,
			 * intermediate passes go to t2.
			 */
			if( j == morph->n_pass - 1 )
				d = IM_REGION_ADDR( or, r->left, r->top + y );
			else 
				d = seq->t2;

			vips_executor_set_scanline( &executor[j], 
				ir, r->left, r->top + y );
			vips_executor_set_array( &executor[j],
				morph->pass[j].r, seq->t1 );
			vips_executor_set_destination( &executor[j], d );
			vips_executor_run( &executor[j] );

			IM_SWAP( void *, seq->t1, seq->t2 );
		}
	}

	return( 0 );
}

/* Morph an image.
 */
static int
morphology( IMAGE *in, IMAGE *out, INTMASK *mask, MorphOp op )
{
	Morph *morph;
	im_generate_fn generate;

	/* Check parameters.
	 */
	if( !(morph = morph_new( in, out, mask, op )) )
		return( -1 );

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( im_cp_desc( morph->out, morph->in ) )
		return( -1 );
	morph->out->Xsize -= morph->mask->xsize - 1;
	morph->out->Ysize -= morph->mask->ysize - 1;
	if( morph->out->Xsize <= 0 || 
		morph->out->Ysize <= 0 ) {
		im_error( "morph", "%s", _( "image too small for mask" ) );
		return( -1 );
	}

	if( morph->n_pass ) {
		generate = morph_vector_gen;

#ifdef DEBUG
		printf( "morph_vector_gen: %d passes\n", morph->n_pass );
#endif /*DEBUG*/
	}
	else if( morph->op == DILATE )
		generate = dilate_gen;
	else
		generate = erode_gen;

	if( im_demand_hint( morph->out, IM_SMALLTILE, morph->in, NULL ) ||
		im_generate( morph->out, 
			morph_start, generate, morph_stop, morph->in, morph ) )
		return( -1 );

	morph->out->Xoffset = -morph->mask->xsize / 2;
	morph->out->Yoffset = -morph->mask->ysize / 2;

	return( 0 );
}

/* Keep the _raw versions for compat.
 */
int
im_dilate_raw( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	return( morphology( in, out, mask, DILATE ) );
}

int
im_erode_raw( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	return( morphology( in, out, mask, ERODE ) );
}

int 
im_dilate( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *t1 = im_open_local( out, "im_dilate:1", "p" );

	if( !t1 || 
		im_embed( in, t1, 1, mask->xsize / 2, mask->ysize / 2, 
			in->Xsize + mask->xsize - 1, 
			in->Ysize + mask->ysize - 1 ) ||
		morphology( t1, out, mask, DILATE ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}

int 
im_erode( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	IMAGE *t1 = im_open_local( out, "im_erode:1", "p" );

	if( !t1 || 
		im_embed( in, t1, 1, mask->xsize / 2, mask->ysize / 2, 
			in->Xsize + mask->xsize - 1, 
			in->Ysize + mask->ysize - 1 ) ||
		morphology( t1, out, mask, ERODE ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
