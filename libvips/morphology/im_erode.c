/* @(#) Function which erodes a binary VASARI format picture with a mask.
 * @(#) The mask coefficients are either 255 (object) or 0 (bk) or 128 (any).
 * @(#) Input image are binary images with either 0 or 255 values, one channel 
 * @(#) only. The program erodes a white object on a black background.
 * @(#) The center of the mask is at location (m->xsize/2, m->ysize/2)
 * @(#) integer division. The mask is expected to have an odd width and
 * @(#) height.
 * @(#)
 * @(#) int im_erode(in, out, m)
 * @(#) IMAGE *in, *out;
 * @(#) INTMASK *m;
 * @(#)
 * @(#) Returns either 0 (sucess) or -1 (fail)
 *
 * 19/9/95 JC
 *	- rewrite
 * 6/7/99 JC
 *	- checks and small tidies
 * 7/4/04 
 *	- now uses im_embed() with edge stretching on the input, not
 *	  the output
 *	- sets Xoffset / Yoffset
 * 21/4/08
 * 	- only rebuild the buffer offsets if bpl changes
 * 	- small cleanups
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Our sequence value.
 */
typedef struct {
	REGION *ir;		/* Input region */

	int *soff;		/* Offsets we check for set */
	int ss;			/* ... and number we check for set */
	int *coff;		/* Offsets we check for clear */
	int cs;			/* ... and number we check for clear */
	int last_bpl;		/* Avoid recalcing offsets, if we can */
} SeqInfo;

/* Stop function.
 */
static int
erode_stop( void *vseq, void *a, void *b )
{
	SeqInfo *seq = (SeqInfo *) vseq;

	IM_FREEF( im_region_free, seq->ir );

	return( 0 );
}

/* Start function.
 */
static void *
erode_start( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	INTMASK *msk = (INTMASK *) b;
	SeqInfo *seq;
	int sz = msk->xsize * msk->ysize;

	if( !(seq = IM_NEW( out, SeqInfo )) )
		return( NULL );

	/* Init!
	 */
	seq->ir = NULL;
	seq->soff = NULL;
	seq->ss = 0;
	seq->coff = NULL;
	seq->cs = 0;
	seq->last_bpl = -1;

	/* Attach region and arrays.
	 */
	seq->ir = im_region_create( in );
	seq->soff = IM_ARRAY( out, sz, int );
	seq->coff = IM_ARRAY( out, sz, int );
	if( !seq->ir || !seq->soff || !seq->coff ) {
		erode_stop( seq, in, NULL );
		return( NULL );
	}

	return( (void *) seq );
}

/* Erode!
 */
static int
erode_gen( REGION *or, void *vseq, void *a, void *b )
{
	SeqInfo *seq = (SeqInfo *) vseq;
	INTMASK *msk = (INTMASK *) b;
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
	s.width += msk->xsize - 1;
	s.height += msk->ysize - 1;
	if( im_prepare( ir, &s ) )
		return( -1 );

#ifdef DEBUG
	printf( "erode_gen: preparing %dx%d pixels\n", s.width, s.height );
#endif /*DEBUG*/

	/* Scan mask, building offsets we check when processing. Only do this
	 * if the bpl has changed since the previous im_prepare().
	 */
	if( seq->last_bpl != IM_REGION_LSKIP( ir ) ) {
		seq->last_bpl = IM_REGION_LSKIP( ir );

		seq->ss = 0;
		seq->cs = 0;
		for( t = msk->coeff, y = 0; y < msk->ysize; y++ )
			for( x = 0; x < msk->xsize; x++, t++ )
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
					im_error( "im_erode", 
						_( "bad mask element (%d "
						"should be 0, 128 or 255)" ), 
						*t );
					return( -1 ); 
				}
	}

	/* Erode!
	 */
	for( y = to; y < bo; y++ ) {
		PEL *p = (PEL *) IM_REGION_ADDR( ir, le, y );
		PEL *q = (PEL *) IM_REGION_ADDR( or, le, y );

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

/* Erode an image.
 */
int
im_erode_raw( IMAGE *in, IMAGE *out, INTMASK *m )
{
	INTMASK *msk;

	/* Check mask has odd number of elements in width and height.
	 */
	if( m->xsize < 1 || !(m->xsize & 0x1) ||
		m->ysize < 1 || !(m->ysize & 0x1) ) {
		im_error( "im_erode", "%s", _( "mask size not odd" ) ); 
		return( -1 ); 
	}

	/* Standard checks.
	 */
	if( im_piocheck( in, out ) ) 
		return( -1 ); 
	if( in->Coding != IM_CODING_NONE || in->Bbits != 8 || 
		in->BandFmt != IM_BANDFMT_UCHAR ) {
		im_error( "im_erode", "%s", _( "1-band uchar uncoded only" ) );
		return( -1 );
	}
	if( im_cp_desc( out, in ) ) 
		return( -1 ); 

	/* Prepare output. Consider a 7x7 mask and a 7x7 image --- the output
	 * would be 1x1.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Xsize -= m->xsize - 1;
	out->Ysize -= m->ysize - 1;
	if( out->Xsize <= 0 || out->Ysize <= 0 ) {
		im_error( "im_erode", "%s", _( "image too small for mask" ) );
		return( -1 );
	}

	/* Take a copy of m.
	 */
	if( !(msk = im_dup_imask( m, "conv_mask" )) )
		return( -1 );
	if( im_add_close_callback( out, 
		(im_callback_fn) im_free_imask, msk, NULL ) ) {
		im_free_imask( msk );
		return( -1 );
	}

	/* Set demand hints. FATSTRIP is good for us, as THINSTRIP will cause
	 * too many recalculations on overlaps.
	 */
	if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
		return( -1 );

	/* Generate! 
	 */
	if( im_generate( out, erode_start, erode_gen, erode_stop, in, msk ) )
		return( -1 );

	out->Xoffset = -m->xsize / 2;
	out->Yoffset = -m->ysize / 2;

	return( 0 );
}

/* The above, with a border to make out the same size as in.
 */
int 
im_erode( IMAGE *in, IMAGE *out, INTMASK *m )
{
	IMAGE *t1 = im_open_local( out, "im_erode:1", "p" );

	if( !t1 || 
		im_embed( in, t1, 1, m->xsize / 2, m->ysize / 2, 
			in->Xsize + m->xsize - 1, 
			in->Ysize + m->ysize - 1 ) ||
		im_erode_raw( t1, out, m ) )
		return( -1 );

	out->Xoffset = 0;
	out->Yoffset = 0;

	return( 0 );
}
