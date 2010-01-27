/* @(#) Creates a IM_BANDFMT_FLOAT grey level image of a specified size. Range is
 * @(#) always [0,1].
 * @(#)
 * @(#) Usage: 
 * @(#) 
 * @(#) int 
 * @(#) im_fgrey( image, xsize, ysize )
 * @(#) IMAGE *image;
 * @(#) int xsize, ysize;
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/02/1990
 * Modified on:
 * 22/7/93 JC
 *	- im_outcheck() added
 *	- externs removed
 * 8/2/95 JC
 *	- ANSIfied
 *	- im_fgrey() made from im_grey()
 * 31/8/95 JC
 *	- now makes [0,1], rather than [0,256)
 *	- im_grey() now defined in terms of im_fgrey()
 * 2/3/98 JC
 *	- partialed
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

/* Generate function.
 */
static int
fgrey_gen( REGION *or, void *seq, void *a, void *b )
{
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int iwm = or->im->Xsize - 1;

	int x, y;

	for( y = 0; y < r->height; y++ ) {
		float *q = (float *) IM_REGION_ADDR( or, le, y + to );

		for( x = 0; x < r->width; x++ )
			q[x] = (float) (x + le) / iwm;
	}

	return( 0 );
}

/* Make a one band grey ramp image.
 */
int
im_fgrey( IMAGE *out, const int xsize, const int ysize )
{
	/* Check args.
	 */
	if( xsize <=0 || ysize <= 0 ) { 
		im_error( "im_fgrey", "%s", _( "bad size" ) ); 
		return( -1 ); 
	}
	if( im_poutcheck( out ) )
		return( -1 );

	/* Set image.
	 */
	im_initdesc( out, xsize, ysize, 1, IM_BBITS_FLOAT, IM_BANDFMT_FLOAT, 
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0 );

	/* Set hints - ANY is ok with us.
	 */
	if( im_demand_hint( out, IM_ANY, NULL ) )
		return( -1 );
	
	/* Generate image.
	 */
	if( im_generate( out, NULL, fgrey_gen, NULL, NULL, NULL ) )
		return( -1 );

	return( 0 );
}

/* As above, but make a IM_BANDFMT_UCHAR [0-255] image.
 */
int
im_grey( IMAGE *image, const int xsize, const int ysize )
{
	IMAGE *t1 = im_open_local( image, "im_grey:1", "p" );
	IMAGE *t2 = im_open_local( image, "im_grey:2", "p" );

	if( !t1 || !t2 )
		return( -1 );

	/* Change range to [0,255].
	 */
	if( im_fgrey( t1, xsize, ysize ) || 
		im_lintra( 255.0, t1, 0.0, t2 ) ||
		im_clip2fmt( t2, image, IM_BANDFMT_UCHAR ) )
		return( -1 );

	return( 0 );
}
