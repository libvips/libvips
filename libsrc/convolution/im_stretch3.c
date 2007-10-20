/* Function to stretch an image by 3%, and displace in x and y. Cubic
 * interpolation with a seperable mask. Displacements are:
 *
 *	0 <= xdisp < 1.0.
 *	0 <= ydisp < 1.0.
 *
 * Each horizontal block of 33 pixels is stretched to 34.
 *
 * Written by Ahmed Abbood
 * August-1994
 *
 * Any unsigned short image. Output image is 3 pixels smaller because of
 * convolution, but x is larger by 3%:
 *
 *	out->Xsize = 34*(in->Xsize / 33) + in->Xsize%33 - 3;
 *	out->Ysize = in->Ysize - 3;
 *
 * 20/10/95 JC
 *	- was not freeing regions correctly
 *	- tidied up
 * 29/3/96 JC
 *	- completely rewritten ... now produces correct result, and is 2x
 *	  faster
 * 18/9/97 JC
 *	- added to VIPS library as im_stretch3
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Data for the cubic interpolation function.
 */
typedef struct {
	IMAGE *in;
	double dx, dy;

	int xoff, yoff;		/* Mask we start with for this disp. */
	int mask[34][4];	/* Fixed-point masks for each output pixel */
} StretchInfo;

/* Per-thread info.
 */
typedef struct seq_info {
	StretchInfo *sin;
	REGION *ir;
	unsigned short *buf;
	int lsk;
} SeqInfo;

static int
stretch_stop( void *vseq, void *a, void *b )
{
	SeqInfo *seq = (SeqInfo *) vseq;

	IM_FREEF( im_region_free, seq->ir );

	return( 0 );
}

static void *
stretch_start( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	StretchInfo *sin = (StretchInfo *) b;
	SeqInfo *seq;

        if( !(seq = IM_NEW( out, SeqInfo )) )
		return( NULL );

        seq->sin = sin;
	seq->ir = im_region_create( in );
	seq->lsk = IM_IMAGE_N_ELEMENTS( out );
        seq->buf = IM_ARRAY( out, 4*seq->lsk, unsigned short );

        if( !seq->buf || !seq->ir ) {
		stretch_stop( seq, NULL, NULL );
        	return( NULL );
	}

	return( (void *)seq );
}

/* Stretch a line of pels into a line in the buffer.
 */
static void
make_xline( StretchInfo *sin, 
	unsigned short *p, unsigned short *q, int w, int m )
{
	int bands = sin->in->Bands;
	int tot;
	int x, b;

	/* Offsets for subsequent pixels.
	 */
	int o1 = 1*bands;
	int o2 = 2*bands;
	int o3 = 3*bands;

	for( x = 0; x < w; x++ ) {
		int *mask = &sin->mask[m][0];
		unsigned short *p1 = p;

		/* Loop for this pel.
		 */
		for( b = 0; b < bands; b++ ) {
			tot = p1[0]*mask[0] + p1[o1]*mask[1] + 
				p1[o2]*mask[2] + p1[o3]*mask[3];
			tot = IM_MAX( 0, tot );
			p1++;
			*q++ = (tot + 16384) >> 15;
		}

		/* Move to next mask.
		 */
		m++;
		if( m == 34 )
			/* Back to mask 0, reuse this input pel.
			 */
			m = 0;
		else
			/* Move to next input pel.
			 */
			p += bands;
	}
}

/* As above, but do the vertical resample. lsk is how much we add to move down
 * a line in p, boff is [0,1,2,3] for which buffer line is mask[3].
 */
static void
make_yline( StretchInfo *sin, int lsk, int boff, 
	unsigned short *p, unsigned short *q, int w, int m )
{
	int bands = sin->in->Bands;
	int we = w * bands;
	int *mask = &sin->mask[m][0];
	int tot;
	int x;

	/* Offsets for subsequent pixels. Down a line each time.
	 */
	int o0 = lsk*boff;
	int o1 = lsk*((boff + 1) % 4);
	int o2 = lsk*((boff + 2) % 4);
	int o3 = lsk*((boff + 3) % 4);

	for( x = 0; x < we; x++ ) {
		tot = p[o0]*mask[0] + p[o1]*mask[1] + 
			p[o2]*mask[2] + p[o3]*mask[3];
		tot = IM_MAX( 0, tot );
		p++;
		*q++ = (tot + 16384) >> 15;
	}
}

static int
stretch_gen( REGION *or, void *vseq, void *a, void *b )
{ 
	SeqInfo *seq = (SeqInfo *) vseq;
	StretchInfo *sin = (StretchInfo *) b;
	REGION *ir = seq->ir;
	Rect *r = &or->valid;
	Rect r1;
	int x, y;

	/* What mask do we start with?
	 */
	int xstart = (r->left + sin->xoff) % 34;

	/* What part of input do we need for this output? 
	 */
	r1.left = r->left - (r->left + sin->xoff) / 34;
	r1.top = r->top;
	x = IM_RECT_RIGHT( r );
	x = x - (x + sin->xoff) / 34 + 3;
	r1.width = x - r1.left;
	r1.height = r->height + 3;
        if( im_prepare( ir, &r1 ) )
        	return( -1 );
	
	/* Fill the first three lines of the buffer.
	 */
	for( y = 0; y < 3; y++ ) {
		unsigned short *p = (unsigned short *) 
			IM_REGION_ADDR( ir, r1.left, y + r1.top );
		unsigned short *q = seq->buf + seq->lsk*y;

		make_xline( sin, p, q, r->width, xstart );
	}

	/* Loop for subsequent lines: stretch a new line of x pels, and
	 * interpolate a line of output from the 3 previous xes plus this new
	 * one.
	 */
	for( y = 0; y < r->height; y++ ) {
		/* Next line of fresh input pels.
		 */
		unsigned short *p = (unsigned short *) 
			IM_REGION_ADDR( ir, r1.left, y + r1.top + 3 );

		/* Next line we fill in the buffer.
		 */
		int boff = (y + 3)%4;
		unsigned short *q = seq->buf + boff*seq->lsk;

		/* Line we write in output.
		 */
		unsigned short *q1 = (unsigned short *) 
			IM_REGION_ADDR( or, r->left, y + r->top );

		/* Process this new xline.
		 */
		make_xline( sin, p, q, r->width, xstart );

		/* Generate new output line.
		 */
		make_yline( sin, seq->lsk, boff, 
			seq->buf, q1, r->width, sin->yoff );
	}

	return( 0 );
}

int
im_stretch3( IMAGE *in, IMAGE *out, double dx, double dy )
{
	StretchInfo *sin;
	int i;
 
        /* Check our args. 
	 */
        if( in->Coding != IM_CODING_NONE || in->BandFmt != IM_BANDFMT_USHORT ) {
        	im_error( "im_stretch3", _( "not uncoded unsigned short" ) );
        	return( -1 );
        }
	if( dx < 0 || dx >= 1.0 || dy < 0 || dy >= 1.0 ) {
		im_error( "im_stretch3", 
			_( "displacements out of range [0,1)" ) );
		return( -1 );
	}
	if( im_piocheck( in, out ) )
		return( -1 );

        /* Prepare the output image.
	 */
        if( im_cp_desc( out, in ) )
		return( -1 );
 	out->Xsize = 34*(in->Xsize / 33) + in->Xsize%33 - 3;
        out->Ysize = in->Ysize - 3;

        if( im_demand_hint( out, IM_FATSTRIP, in, NULL ) )
        	return( -1 );

        if( !(sin = IM_NEW( out, StretchInfo )) )
        	return( -1 );

	/* Save parameters.
	 */
	sin->in = in;
	sin->dx = dx;
	sin->dy = dy;

	/* Generate masks.
	 */
        for( i = 0; i < 34; i++ ) {
        	double d = (34.0 - i)/34.0;

		double y0 = 2.0*d*d - d - d*d*d;
		double y1 = 1.0 - 2.0*d*d + d*d*d;
		double y2 = d + d*d - d*d*d;
		double y3 = -d*d + d*d*d;

		sin->mask[i][0] = IM_RINT( y0 * 32768 );
		sin->mask[i][1] = IM_RINT( y1 * 32768 );
		sin->mask[i][2] = IM_RINT( y2 * 32768 );
		sin->mask[i][3] = IM_RINT( y3 * 32768 );
	}

	/* Which mask do we start with to apply these offsets?
	 */
	sin->xoff = (dx * 33.0) + 0.5;
	sin->yoff = (dy * 33.0) + 0.5;

        if( im_generate( out, 
		stretch_start, stretch_gen, stretch_stop, in, sin ) )
        	return( -1 );

	return( 0 );
}
