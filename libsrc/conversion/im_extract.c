/* @(#) Function to extract a portion of a Vasari format picture.
 * @(#) Function im_extract() assumes that the imin image
 * @(#) is either memory mapped or in the buffer pimin->data.
 * @(#)
 * @(#) int im_extract(pimin, pimout, pbox)
 * @(#) IMAGE *pimin, *pimout;
 * @(#) IMAGE_BOX *pbox;
 * @(#)
 * @(#) All functions return 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, J. Cupitt
 *
 * Author: J. Cupitt
 * Written on: 12/02/1990
 * Modified on: 4/6/92, J.Cupitt
 *	- speed up! why wasn't this done before? Why am I stupid?
 *	- layout, messages fixed
 * now extracts IM_CODING_LABQ to IM_CODING_LABQ file: K.Martinez 1/7/93
 * 2/7/93 JC
 *	- adapted for partial v2
 *	- ANSIfied
 * 7/7/93 JC
 *	- behaviour for IM_CODING_LABQ fixed
 *	- better messages
 * 7/10/94 JC
 *	- new IM_NEW()
 * 22/2/95 JC
 *	- new use of im_region_region()
 * 6/7/98 JC
 *	- im_extract_area() and im_extract_band() added
 * 11/7/01 JC
 *	- im_extract_band() now numbers from zero
 * 7/11/01 JC
 *	- oh what pain, im_extract now numbers bands from zero as well
 * 6/9/02 JC
 *	- zero xoff/yoff for extracted area
 * 14/4/04 JC
 *	- nope, -ve the origin
 * 17/7/04
 *	- added im_extract_bands(), remove many bands from image
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Extract one or more bands ... get number of output bands from
 * or->im->Bands.
 */
static int
extract_band( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE_BOX *box = (IMAGE_BOX *) b;
	Rect *r = &or->valid;
	int le = r->left;
	int ri = IM_RECT_RIGHT(r);
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int es = IM_IMAGE_SIZEOF_ELEMENT( ir->im );	
	int ipel = IM_IMAGE_SIZEOF_PEL( ir->im );
	int opel = IM_IMAGE_SIZEOF_PEL( or->im );
	Rect iarea;
	char *p, *q;
	int x, y, z;

	/* Ask for input we need.
	 */
	iarea = or->valid;
	iarea.left += box->xstart;
	iarea.top += box->ystart;
	if( im_prepare( ir, &iarea ) )
		return( -1 );

	for( y = to; y < bo; y++ ) {
		p = IM_REGION_ADDR( ir, le + box->xstart, y + box->ystart ) +
			box->chsel * es;
		q = IM_REGION_ADDR( or, le, y );

		for( x = le; x < ri; x++ ) {
			for( z = 0; z < opel; z++ )
				q[z] = p[z];

			p += ipel;
			q += opel;
		}
	}

	return( 0 );
}

/* Extract an area. Can just use pointers.
 */
static int
extract_area( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	IMAGE_BOX *box = (IMAGE_BOX *) b;
	Rect iarea;

	/* Ask for input we need. Translate from demand in or's space to
	 * demand in ir's space.
	 */
	iarea = or->valid;
	iarea.left += box->xstart;
	iarea.top += box->ystart;
	if( im_prepare( ir, &iarea ) )
		return( -1 );

	/* Attach or to ir.
	 */
	if( im_region_region( or, ir, &or->valid, iarea.left, iarea.top ) )
		return( -1 );
	
	return( 0 );
}

/* Extract an area and bands from an image. 
 */
int
im_extract_areabands( IMAGE *in, IMAGE *out, 
	int left, int top, int width, int height, int band, int nbands )
{      
	IMAGE_BOX *box;

	if( im_piocheck( in, out ) )
		return( -1 );
        if( band < 0 || nbands < 1 || band + nbands > in->Bands ) {
                im_error( "im_extract_areabands", 
                        "%s", _( "band selection out of range" ) );
                return( -1 );
        }
	if( left + width > in->Xsize ||
		top + height > in->Ysize ||
		left < 0 || top < 0 ||
		width <= 0 || height <= 0 ) {
		im_error( "im_extract_areabands", 
			"%s", _( "bad extract area" ) );
		return( -1 );
	}
        if( in->Coding != IM_CODING_NONE ) {
		if( in->Coding != IM_CODING_LABQ ) {
			im_error( "im_extract_areabands", 
				"%s", _( "unknown coding" ) );
			return( -1 );
		}

		/* We only do area extract for coding == labq.
		 */
		if( band != 0 || nbands != in->Bands ) {
			im_error( "im_extract_areabands", 
				"%s", _( "can only extract areas from LABQ" ) );
			return( -1 );
		}
        }

        /* Set up the output header.  
         */
        if( im_cp_desc( out, in ) ) 
                 return( -1 );
        out->Bands = nbands;
        out->Xsize = width;
        out->Ysize = height;
        if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
                return( -1 );
        if( !(box = IM_NEW( out, IMAGE_BOX )) )
                return( -1 );
        box->xstart = left;
        box->ystart = top;
        box->xsize = width;
        box->ysize = height;
        box->chsel = band;
 
 	/* Extracting all bands is a special case ... we can do it with
	 * pointers.
	 */
	if( band == 0 && nbands == in->Bands ) {
		if( im_generate( out, 
			im_start_one, extract_area, im_stop_one, in, box ) )
			return( -1 );
	}
	else {
		if( im_generate( out, 
			im_start_one, extract_band, im_stop_one, in, box ) )
			return( -1 );
 	}
 
        out->Xoffset = -left;
        out->Yoffset = -top;

        return( 0 );
}

/* Legacy interface.
 */
int
im_extract( IMAGE *in, IMAGE *out, IMAGE_BOX *box )
{	
	if( box->chsel == -1 )
		return( im_extract_areabands( in, out, 
			box->xstart, box->ystart, box->xsize, box->ysize,
			0, in->Bands ) );
	else
		return( im_extract_areabands( in, out, 
			box->xstart, box->ystart, box->xsize, box->ysize,
			box->chsel, 1 ) );
}

/* Convenience functions.
 */
int
im_extract_area( IMAGE *in, IMAGE *out, 
	int left, int top, int width, int height )
{
	return( im_extract_areabands( in, out, 
		left, top, width, height, 0, in->Bands ) );
}

int
im_extract_bands( IMAGE *in, IMAGE *out, int chsel, int nbands )
{
	return( im_extract_areabands( in, out, 
		0, 0, in->Xsize, in->Ysize, chsel, nbands ) );
}

int
im_extract_band( IMAGE *in, IMAGE *out, int chsel )
{
	return( im_extract_bands( in, out, chsel, 1 ) ); 
}
