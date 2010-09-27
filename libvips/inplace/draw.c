/* base class for drawing operations
 *
 * 27/9/10
 *	- from im_draw_circle()
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

#include <string.h>

#include <vips/vips.h>

#include "draw.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Fill a scanline between points x1 and x2 inclusive. x1 < x2.
 */
void 
im__draw_scanline( Draw *draw, int y, int x1, int x2 )
{
	PEL *mp;
	int i;
	int len;

	g_assert( x1 <= x2 );

	if( y < 0 || y > draw->im->Ysize )
		return;
	if( x1 < 0 && x2 < 0 )
		return;
	if( x1 > draw->im->Xsize && x2 > draw->im->Xsize )
		return;
	x1 = IM_CLIP( 0, x1, draw->im->Xsize - 1 );
	x2 = IM_CLIP( 0, x2, draw->im->Xsize - 1 );

	mp = (PEL *) IM_IMAGE_ADDR( draw->im, x1, y );
	len = x2 - x1 + 1;

	for( i = 0; i < len; i++ ) {
		im__draw_pel( draw, mp );
		mp += draw->psize;
	}
}

void
im__draw_free( Draw *draw )
{
	IM_FREE( draw->ink );
}

Draw *
im__draw_init( Draw *draw, IMAGE *im, PEL *ink )
{
	if( im_rwcheck( im ) )
		return( NULL );

	draw->im = im;
	draw->ink = NULL;

	draw->lsize = IM_IMAGE_SIZEOF_LINE( im );
	draw->psize = IM_IMAGE_SIZEOF_PEL( im );
	draw->noclip = FALSE;

	if( ink ) {
		if( !(draw->ink = (PEL *) im_malloc( NULL, draw->psize )) ) 
			return( NULL );
		memcpy( draw->ink, ink, draw->psize );
	}

	return( draw );
}
