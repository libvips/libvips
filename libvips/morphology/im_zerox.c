/* detect zero-crossings
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 12/02/1990
 * Modified on : 
 * 1/2/95 JC
 *	- rewritten for PIO
 *	- some bugs removed
 * 11/5/06
 * 	- small clean ups
 * 11/11/10
 * 	- small cleanups
 * 	- gtkdoc
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define LOOP( TYPE ) { \
	for( i = 0; i < ne; i++ ) { \
		TYPE p1 = ((TYPE *)p)[i]; \
		TYPE p2 = ((TYPE *)p)[i + ba]; \
		\
		if( flag == 1 && p1 > 0 && p2 <= 0 ) \
			q[i] = 255; \
		else if( flag == -1 && p1 < 0 && p2 >= 0 ) \
			q[i] = 255; \
		else \
			q[i] = 0; \
	} \
}

/* Zerox generate function.
 */
static int
zerox_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE *in = (IMAGE *) a;
	int flag = GPOINTER_TO_INT( b );
	Rect irect;
	Rect *r = &or->valid;

	/* Range of pixels we loop over. 
	 */
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM( r );
	int ba = in->Bands;
	int ne = ba * r->width;

	int i, y;

	/* We need to be able to see one pixel to the right. 
	 */
	irect.top = r->top;
	irect.left = r->left;
	irect.width = r->width + 1;
	irect.height = r->height;
	if( im_prepare( ir, &irect ) )
		return( -1 );
	
	for( y = to; y < bo; y++ ) {
		PEL *p = (PEL *) IM_REGION_ADDR( ir, le, y );
		PEL *q = (PEL *) IM_REGION_ADDR( or, le, y );

		switch( in->BandFmt ) {
		case IM_BANDFMT_CHAR:           LOOP( signed char ); break;
		case IM_BANDFMT_SHORT:          LOOP( signed short ); break;
		case IM_BANDFMT_INT:            LOOP( signed int ); break;
		case IM_BANDFMT_FLOAT:          LOOP( float ); break;
		case IM_BANDFMT_DOUBLE:         LOOP( double ); break;

		default:
			g_assert( 0 );
		}
	}

	return( 0 );
} 

/**
 * im_zerox:
 * @in: input image
 * @out: output image
 * @sign: detect positive or negative zero crossings
 *
 * im_zerox() detects the positive or negative zero crossings @in, 
 * depending on @sign. If @sign is -1, negative zero crossings are returned,
 * if @sign is 1, positive zero crossings are returned.
 *
 * The output image is byte with zero crossing set to 255 and all other values
 * set to zero. Input can have any number of channels, and be any non-complex 
 * type.
 *
 * See also: im_conv(), im_rot90.
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_zerox( IMAGE *in, IMAGE *out, int sign )
{
	IMAGE *t1;

	if( flag != -1 && flag != 1 ) {
		im_error( "im_zerox", "%s", _( "flag not -1 or 1" ) );
		return( -1 );
	}
	if( in->Xsize < 2 ) {
		im_error( "im_zerox", "%s", _( "image too narrow" ) );
		return( -1 );
	}
	if( !(t1 = im_open_local( out, "im_zerox" , "p" )) ||
		im_piocheck( in, t1 ) ||
		im_check_uncoded( "im_zerox", in ) ||
		im_check_noncomplex( "im_zerox", in ) )
		return( -1 );
	if( vips_bandfmt_isuint( in->BandFmt ) )
		/* Unsigned type, therefore there will be no zero-crossings.
		 */
		return( im_black( out, in->Xsize, in->Ysize, in->Bands ) );

	/* Force output to be BYTE. Output is narrower than input by 1 pixel.
	 */
	if( im_cp_desc( t1, in ) )
		return( -1 );
	t1->BandFmt = IM_BANDFMT_UCHAR;
	t1->Xsize -= 1;

	/* Set hints - THINSTRIP is ok with us.
	 */
	if( im_demand_hint( t1, IM_THINSTRIP, NULL ) )
		return( -1 );

	/* Generate image.
	 */
	if( im_generate( t1, im_start_one, zerox_gen, im_stop_one, 
		in, GINT_TO_POINTER( flag ) ) )
		return( -1 );

	/* Now embed it in a larger image.
	 */
	if( im_embed( t1, out, 0, 0, 0, in->Xsize, in->Ysize ) )
		return( -1 );

	return( 0 );
}
