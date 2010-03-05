/* Definitions for partial image regions.
 *
 * J.Cupitt, 8/4/93
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

#ifndef IM_REGION_H
#define IM_REGION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Sub-area of image.
 */
typedef struct _REGION {
	/*< public >*/
	/* Users may read these two fields.
	 */
	IMAGE *im;		/* Link back to parent image */
	Rect valid;		/* Area of parent we can see */

	/* The rest of REGION is private.
	 */
	/*< private >*/
	RegionType type;	/* What kind of attachment */
	char *data;		/* Off here to get data */
	int bpl;		/* Bytes-per-line for data */
	void *seq;		/* Sequence we are using to fill region */

	/* The thread that made this region. Used to assert() test that
	 * regions are not being shared between threads.
	 */
	GThread *thread;

	/* Ref to the window we use for this region, if any.
	 */
	im_window_t *window;

	/* Ref to the buffer we use for this region, if any.
	 */
	im_buffer_t *buffer;

	/* The image this region is on has changed and caches need to be
	 * dropped.
	 */
	gboolean invalid;	
} REGION;

REGION *im_region_create( IMAGE *im );
void im_region_free( REGION *reg );

int im_region_buffer( REGION *reg, Rect *r );
int im_region_image( REGION *reg, Rect *r );
int im_region_region( REGION *reg, REGION *to, Rect *r, int x, int y );
int im_region_equalsregion( REGION *reg1, REGION *reg2 );
int im_region_position( REGION *reg1, int x, int y );

void im_region_paint( REGION *reg, Rect *r, int value );
void im_region_black( REGION *reg );

/* Macros on REGIONs.
 *	IM_REGION_LSKIP()		add to move down line
 *	IM_REGION_N_ELEMENTS()		number of elements across region
 *	IM_REGION_SIZEOF_LINE()		sizeof width of region
 *	IM_REGION_ADDR()		address of pixel in region
 */
#define IM_REGION_LSKIP(R) \
	((size_t)((R)->bpl))
#define IM_REGION_N_ELEMENTS(R) \
	((size_t)((R)->valid.width * (R)->im->Bands))
#define IM_REGION_SIZEOF_LINE(R) \
	((size_t)((R)->valid.width * IM_IMAGE_SIZEOF_PEL((R)->im)))

/* If DEBUG is defined, add bounds checking.
 */
#ifdef DEBUG
#define IM_REGION_ADDR(B,X,Y) \
	( (im_rect_includespoint( &(B)->valid, (X), (Y) ))? \
	  ((B)->data + ((Y) - (B)->valid.top) * IM_REGION_LSKIP(B) + \
	  ((X) - (B)->valid.left) * IM_IMAGE_SIZEOF_PEL((B)->im)): \
	  (fprintf( stderr, \
		"IM_REGION_ADDR: point out of bounds, " \
		"file \"%s\", line %d\n" \
		"(point x=%d, y=%d\n" \
		" should have been within Rect left=%d, top=%d, " \
		"width=%d, height=%d)\n", \
		__FILE__, __LINE__, \
		(X), (Y), \
		(B)->valid.left, \
		(B)->valid.top, \
		(B)->valid.width, \
		(B)->valid.height ), abort(), (char *) NULL) \
	)
#else /*DEBUG*/
#define IM_REGION_ADDR(B,X,Y) \
	((B)->data + \
	((Y)-(B)->valid.top) * IM_REGION_LSKIP(B) + \
	((X)-(B)->valid.left) * IM_IMAGE_SIZEOF_PEL((B)->im))
#endif /*DEBUG*/

#define IM_REGION_ADDR_TOPLEFT(B)   ( (B)->data )

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_REGION_H*/
