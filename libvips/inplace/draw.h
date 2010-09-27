/* base class for drawing operations
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

/* Our state.
 */
typedef struct _Draw {
	/* Parameters.
	 */
	IMAGE *im;		/* Draw here */
	PEL *ink;		/* Copy of ink param */

	/* Derived stuff.
	 */
	size_t lsize;
	size_t psize;

	/* If the object to draw is entirely within the image, we have a 
	 * faster noclip path.
	 */
	gboolean noclip;
} Draw;

#define DRAW(X) ((Draw *)(X))

static inline void
im__draw_pel( Draw *draw, PEL *q )
{
 	int j;

	/* Faster than memcopy() for n < about 20.
	 */
	for( j = 0; j < draw->psize; j++ ) 
		q[j] = draw->ink[j];
}

/* Paint, with clip.
 */
static inline void 
im__draw_pel_clip( Draw *draw, int x, int y )
{
	if( x < 0 || x >= draw->im->Xsize )
		return;
	if( y < 0 || y >= draw->im->Ysize )
		return;

	im__draw_pel( draw, (PEL *) IM_IMAGE_ADDR( draw->im, x, y ) );
}

/* Is p painted?
 */
static inline gboolean
im__draw_painted( Draw *draw, PEL *p )
{
 	int j;

	for( j = 0; j < draw->psize; j++ ) 
		if( p[j] != draw->ink[j] ) 
			break;

	return( j == draw->psize );
}

void im__draw_scanline( Draw *draw, int y, int x1, int x2 );
void im__draw_free( Draw *draw );
Draw *im__draw_init( Draw *draw, IMAGE *im, PEL *ink );
