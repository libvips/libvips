/* morphology
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
 * 23/10/13	
 * 	- from vips_conv()
 * 25/2/20 kleisauke
 * 	- rewritten as a class
 * 	- merged with hitmiss
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <vips/vips.h>
#include <vips/vector.h>
#include <vips/debug.h>
#include <vips/internal.h>

#include "pmorphology.h"

/* We can't run more than this many passes. Larger than this and we
 * fall back to C.
 * TODO: Could this be raised to 20? Just like convi.
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

/** 
 * VipsOperationMorphology:
 * @VIPS_OPERATION_MORPHOLOGY_ERODE: true if all set
 * @VIPS_OPERATION_MORPHOLOGY_DILATE: true if one set
 *
 * More like hit-miss, really. 
 *
 * See also: vips_morph().
 */

typedef struct {
	VipsMorphology parent_instance;

	VipsImage *out;
	VipsImage *mask;
	VipsOperationMorphology morph;

	/* @mask cast ready for processing.
	 */
	VipsImage *M;

	int n_point;		/* w * h for our matrix */

	int *coeff;			/* Mask coefficients */

	/* The passes we generate for this mask.
	 */
	int n_pass;	
	Pass pass[MAX_PASS];
} VipsMorph;

typedef VipsMorphologyClass VipsMorphClass;

G_DEFINE_TYPE( VipsMorph, vips_morph, VIPS_TYPE_MORPHOLOGY );

/* Our sequence value.
 */
typedef struct {
	VipsMorph *morph;
	VipsRegion *ir;		/* Input region */

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
} VipsMorphSequence;

static void
vips_morph_compile_free( VipsMorph *morph )
{
	int i;

	for( i = 0; i < morph->n_pass; i++ )
		VIPS_FREEF( vips_vector_free, morph->pass[i].vector );
	morph->n_pass = 0;
}

static void
vips_morph_dispose( GObject *gobject )
{
	VipsMorph *morph = (VipsMorph *) gobject;

#ifdef DEBUG
	printf( "vips_morph_dispose: " );
	vips_object_print_name( VIPS_OBJECT( gobject ) );
	printf( "\n" );
#endif /*DEBUG*/

	vips_morph_compile_free( morph ); 

	G_OBJECT_CLASS( vips_morph_parent_class )->dispose( gobject );
}

/* Free a sequence value.
 */
static int
vips_morph_stop( void *vseq, void *a, void *b )
{
	VipsMorphSequence *seq = (VipsMorphSequence *) vseq;

	VIPS_UNREF( seq->ir );
	VIPS_FREE( seq->t1 );
	VIPS_FREE( seq->t2 );

	return( 0 );
}

/* Morph start function.
 */
static void *
vips_morph_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsMorph *morph = (VipsMorph *) b;

	VipsMorphSequence *seq;

	if( !(seq = VIPS_NEW( out, VipsMorphSequence )) )
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

	seq->ir = vips_region_new( in );

	/* C mode.
	 */
	seq->soff = VIPS_ARRAY( out, morph->n_point, int );
	seq->coff = VIPS_ARRAY( out, morph->n_point, int );

	if( !seq->soff || 
		!seq->coff ) {
		vips_morph_stop( seq, in, morph );
		return( NULL );
	}

	/* Vector mode.
	 */
	if( morph->n_pass ) {
		seq->t1 = VIPS_ARRAY( NULL, 
			VIPS_IMAGE_N_ELEMENTS( in ), VipsPel );
		seq->t2 = VIPS_ARRAY( NULL, 
			VIPS_IMAGE_N_ELEMENTS( in ), VipsPel );

		if( !seq->t1 || 
			!seq->t2 ) {
			vips_morph_stop( seq, in, morph );
			return( NULL );
		}
	}

	return( seq );
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
vips_morph_compile_section( VipsMorph *morph, Pass *pass, gboolean first_pass )
{
	VipsMorphology *morphology = (VipsMorphology *) morph;
	VipsImage *M = morph->M;

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
		if( morph->morph == VIPS_OPERATION_MORPHOLOGY_DILATE )
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

	for( i = pass->first; i < morph->n_point; i++ ) {
		int x = i % M->Xsize;
		int y = i / M->Xsize;

		/* Exclude don't-care elements.
		 */
		if( morph->coeff[i] == 128 )
			continue;

		/* The source. sl0 is the first scanline in the mask.
		 */
		SCANLINE( source, y, 1 );

		/* The offset, only for non-first-columns though.
		 */
		if( x > 0 ) {
			CONST( offset, morphology->in->Bands * x, 1 );
			ASM3( "loadoffb", "value", source, offset );
		}
		else
			ASM2( "loadb", "value", source );

		/* Join to our sum. If the mask element is zero, we have to
		 * add an extra negate.
		 */
		if( morph->morph == VIPS_OPERATION_MORPHOLOGY_DILATE ) {
			if( !morph->coeff[i] ) 
				ASM3( "xorb", "value", "value", one );
			ASM3( "orb", "sum", "sum", "value" );
		}
		else {
			if( !morph->coeff[i] ) {
				/* You'd think we could use andnb, but it
				 * fails on some machines with some orc
				 * versions :( 
				 */
				ASM3( "xorb", "value", "value", one );
				ASM3( "andb", "sum", "sum", "value" );
			}
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
vips_morph_compile( VipsMorph *morph )
{
	int i;
	Pass *pass;

#ifdef DEBUG
	printf( "vips_morph_compile: generating vector code\n" );
#endif /*DEBUG*/

	/* Generate passes until we've used up the whole mask.
	 */
	for( i = 0;;) {
		/* Skip any don't-care coefficients at the start of the mask 
		 * region.
		 */
		for( ; i < morph->n_point && morph->coeff[i] == 128; i++ )
			;
		if( i == morph->n_point )
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

		if( vips_morph_compile_section( morph, pass, morph->n_pass == 1 ) )
			return( -1 );
		i = pass->last + 1;

		if( i >= morph->n_point )
			break;
	}

	return( 0 );
}

/* Dilate!
 */
static int
vips_dilate_gen( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsMorphSequence *seq = (VipsMorphSequence *) vseq;
	VipsMorph *morph = (VipsMorph *) b;
	VipsImage *M = morph->M;
	VipsRegion *ir = seq->ir;

	int *soff = seq->soff;
	int *coff = seq->coff;

	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );
	int sz = VIPS_REGION_N_ELEMENTS( or );

	VipsRect s;
	int x, y;
	int *t;
	int result, i;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += M->Xsize - 1;
	s.height += M->Ysize - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

#ifdef DEBUG_VERBOSE
	printf( "vips_dilate_gen: preparing %dx%d@%dx%d pixels\n", 
		s.width, s.height, s.left, s.top );
#endif /*DEBUG_VERBOSE*/

	/* Scan mask, building offsets we check when processing. Only do this
	 * if the bpl has changed since the previous vips_region_prepare().
	 */
	if( seq->last_bpl != VIPS_REGION_LSKIP( ir ) ) {
		seq->last_bpl = VIPS_REGION_LSKIP( ir );

		seq->ss = 0;
		seq->cs = 0;
		for( t = morph->coeff, y = 0; y < M->Ysize; y++ )
			for( x = 0; x < M->Xsize; x++, t++ )
				switch( *t ) {
				case 255:
					soff[seq->ss++] =
						VIPS_REGION_ADDR( ir, 
							x + le, y + to ) -
						VIPS_REGION_ADDR( ir, le, to );
					break;

				case 128:
					break;

				case 0:
					coff[seq->cs++] =
						VIPS_REGION_ADDR( ir, 
							x + le, y + to ) -
						VIPS_REGION_ADDR( ir, le, to );
					break;

				default:
					g_assert_not_reached();
				}
	}

	/* Dilate!
	 */
	for( y = to; y < bo; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir, le, y );
		VipsPel *q = VIPS_REGION_ADDR( or, le, y );

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
vips_erode_gen( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsMorphSequence *seq = (VipsMorphSequence *) vseq;
	VipsMorph *morph = (VipsMorph *) b;
	VipsImage *M = morph->M;
	VipsRegion *ir = seq->ir;

	int *soff = seq->soff;
	int *coff = seq->coff;

	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );
	int sz = VIPS_REGION_N_ELEMENTS( or );

	VipsRect s;
	int x, y;
	int *t;
	int result, i;

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += M->Xsize - 1;
	s.height += M->Ysize - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

#ifdef DEBUG_VERBOSE
	printf( "vips_erode_gen: preparing %dx%d@%dx%d pixels\n", 
		s.width, s.height, s.left, s.top );
#endif /*DEBUG_VERBOSE*/

	/* Scan mask, building offsets we check when processing. Only do this
	 * if the bpl has changed since the previous vips_region_prepare().
	 */
	if( seq->last_bpl != VIPS_REGION_LSKIP( ir ) ) {
		seq->last_bpl = VIPS_REGION_LSKIP( ir );

		seq->ss = 0;
		seq->cs = 0;
		for( t = morph->coeff, y = 0; y < M->Ysize; y++ )
			for( x = 0; x < M->Xsize; x++, t++ )
				switch( *t ) {
				case 255:
					soff[seq->ss++] =
						VIPS_REGION_ADDR( ir, 
							x + le, y + to ) -
						VIPS_REGION_ADDR( ir, le, to );
					break;

				case 128:
					break;

				case 0:
					coff[seq->cs++] =
						VIPS_REGION_ADDR( ir, 
							x + le, y + to ) -
						VIPS_REGION_ADDR( ir, le, to );
					break;

				default:
					g_assert_not_reached();
				}
	}

	/* Erode!
	 */
	for( y = to; y < bo; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( ir, le, y );
		VipsPel *q = VIPS_REGION_ADDR( or, le, y );

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
vips_morph_gen_vector( VipsRegion *or, 
	void *vseq, void *a, void *b, gboolean *stop )
{
	VipsMorphSequence *seq = (VipsMorphSequence *) vseq;
	VipsMorph *morph = (VipsMorph *) b;
	VipsImage *M = morph->M;
	VipsRegion *ir = seq->ir;
	VipsRect *r = &or->valid;
	int sz = VIPS_REGION_N_ELEMENTS( or );

	VipsRect s;
	int y, j;
	VipsExecutor executor[MAX_PASS];

	/* Prepare the section of the input image we need. A little larger
	 * than the section of the output image we are producing.
	 */
	s = *r;
	s.width += M->Xsize - 1;
	s.height += M->Ysize - 1;
	if( vips_region_prepare( ir, &s ) )
		return( -1 );

#ifdef DEBUG_VERBOSE
	printf( "vips_morph_gen_vector: preparing %dx%d@%dx%d pixels\n", 
		s.width, s.height, s.left, s.top );
#endif /*DEBUG_VERBOSE*/

	for( j = 0; j < morph->n_pass; j++ ) 
		vips_executor_set_program( &executor[j], 
			morph->pass[j].vector, sz );

	VIPS_GATE_START( "vips_morph_gen_vector: work" ); 

	for( y = 0; y < r->height; y++ ) { 
		for( j = 0; j < morph->n_pass; j++ ) {
			void *d;

			/* The last pass goes to the output image,
			 * intermediate passes go to t2.
			 */
			if( j == morph->n_pass - 1 )
				d = VIPS_REGION_ADDR( or, r->left, r->top + y );
			else 
				d = seq->t2;

			vips_executor_set_scanline( &executor[j], 
				ir, r->left, r->top + y );
			vips_executor_set_array( &executor[j],
				morph->pass[j].r, seq->t1 );
			vips_executor_set_destination( &executor[j], d );
			vips_executor_run( &executor[j] );

			VIPS_SWAP( void *, seq->t1, seq->t2 );
		}
	}

	VIPS_GATE_STOP( "vips_morph_gen_vector: work" ); 

	VIPS_COUNT_PIXELS( or, "vips_morph_gen_vector" ); 

	return( 0 );
}

static int
vips_morph_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsMorphology *morphology = (VipsMorphology *) object;
	VipsMorph *morph = (VipsMorph *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 5 );

	VipsImage *in;
	VipsImage *M;
	VipsGenerateFn generate;
	double *coeff;
	int i;

	if( VIPS_OBJECT_CLASS( vips_morph_parent_class )->build( object ) )
		return( -1 );

	in = morphology->in;

	/* Unpack for processing.
	 */
	if( vips_image_decode( in, &t[0] ) )
		return( -1 );
	in = t[0];

	if( vips_check_matrix( class->nickname, morph->mask, &t[1] ) )
		return( -1 ); 
	morph->M = M = t[1];
	morph->n_point = M->Xsize * M->Ysize;

	if( vips_embed( in, &t[2], 
		M->Xsize / 2, M->Ysize / 2, 
		in->Xsize + M->Xsize - 1, in->Ysize + M->Ysize - 1,
		"extend", VIPS_EXTEND_COPY,
		NULL ) )
		return( -1 );
	in = t[2]; 

	/* Make sure we are uchar.
	 */
	if( vips_cast( in, &t[3], VIPS_FORMAT_UCHAR, NULL ) )
		return( -1 );
	in = t[3];

	/* Make an int version of our mask.
	 */
	if( vips__image_intize( M, &t[4] ) )
		return( -1 ); 
	M = t[4];

	coeff = VIPS_MATRIX( M, 0, 0 ); 
	if( !(morph->coeff = VIPS_ARRAY( object, morph->n_point, int )) )
		return( -1 );

	for( i = 0; i < morph->n_point; i++ ) {
		if( coeff[i] != 0 && 
			coeff[i] != 128 &&
			coeff[i] != 255 ) {
			vips_error( class->nickname, 
				_( "bad mask element (%f "
				"should be 0, 128 or 255)" ),
				coeff[i] );
			return( -1 );
		}
		morph->coeff[i] = coeff[i];
	}

	/* Default to the C path.
	 */
	generate = morph->morph == VIPS_OPERATION_MORPHOLOGY_DILATE
		? vips_dilate_gen : vips_erode_gen;

	/* Generate code for this mask / image, if possible.
	 */
	if( vips_vector_isenabled() ) {
		if( !vips_morph_compile( morph ) ) {
			generate = vips_morph_gen_vector;
			g_info( "morph: using vector path" ); 
		}
		else
			vips_morph_compile_free( morph );
	}

	g_object_set( morph, "out", vips_image_new(), NULL ); 
	if( vips_image_pipelinev( morph->out, 
		VIPS_DEMAND_STYLE_SMALLTILE, in, NULL ) )
		return( -1 );

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	morph->out->Xsize -= M->Xsize - 1;
	morph->out->Ysize -= M->Ysize - 1;

	if( vips_image_generate( morph->out, 
		vips_morph_start, generate, vips_morph_stop, in, morph ) )
		return( -1 );

	morph->out->Xoffset = -M->Xsize / 2;
	morph->out->Yoffset = -M->Ysize / 2;

	vips_reorder_margin_hint( morph->out, morph->n_point );

	return( 0 );
}

static void
vips_morph_class_init( VipsMorphClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	gobject_class->dispose = vips_morph_dispose;

	object_class->nickname = "morph";
	object_class->description = _( "morphology operation" );
	object_class->build = vips_morph_build;

	VIPS_ARG_IMAGE( class, "out", 10, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMorph, out ) );

	VIPS_ARG_IMAGE( class, "mask", 20, 
		_( "Mask" ), 
		_( "Input matrix image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMorph, mask ) );

	VIPS_ARG_ENUM( class, "morph", 103, 
		_( "Morphology" ), 
		_( "Morphological operation to perform" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsMorph, morph ), 
		VIPS_TYPE_OPERATION_MORPHOLOGY, 
			VIPS_OPERATION_MORPHOLOGY_ERODE ); 

}

static void
vips_morph_init( VipsMorph *morph )
{
	morph->morph = VIPS_OPERATION_MORPHOLOGY_ERODE;
	morph->coeff = NULL;
}

/**
 * vips_morph: (method)
 * @in: input image
 * @out: (out): output image
 * @mask: morphology with this mask
 * @morph: operation to perform
 * @...: %NULL-terminated list of optional named arguments
 *
 * Performs a morphological operation on @in using @mask as a
 * structuring element. 
 *
 * The image should have 0 (black) for no object and 255
 * (non-zero) for an object. Note that this is the reverse of the usual
 * convention for these operations, but more convenient when combined with the
 * boolean operators. The output image is the same
 * size as the input image: edge pxels are made by expanding the input image
 * as necessary.
 *
 * Mask coefficients can be either 0 (for object) or 255 (for background) 
 * or 128 (for do not care).  The origin of the mask is at location
 * (m.xsize / 2, m.ysize / 2), integer division.  All algorithms have been 
 * based on the book "Fundamentals of Digital Image Processing" by A. Jain, 
 * pp 384-388, Prentice-Hall, 1989. 
 *
 * For #VIPS_OPERATION_MORPHOLOGY_ERODE, 
 * the whole mask must match for the output pixel to be
 * set, that is, the result is the logical AND of the selected input pixels.
 *
 * For #VIPS_OPERATION_MORPHOLOGY_DILATE, 
 * the output pixel is set if any part of the mask 
 * matches, that is, the result is the logical OR of the selected input pixels.
 *
 * See the boolean operations vips_andimage(), vips_orimage() and 
 * vips_eorimage() 
 * for analogues of the usual set difference and set union operations.
 *
 * Operations are performed using the processor's vector unit,
 * if possible. Disable this with --vips-novector or VIPS_NOVECTOR.
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_morph( VipsImage *in, VipsImage **out, VipsImage *mask, 
	VipsOperationMorphology morph, ... )
{
	va_list ap;
	int result;

	va_start( ap, morph );
	result = vips_call_split( "morph", ap, in, out, mask, morph );
	va_end( ap );

	return( result );
}
