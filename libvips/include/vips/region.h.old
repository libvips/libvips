/* Definitions for partial image regions.
 *
 * J.Cupitt, 8/4/93
 *
 * 2/3/11
 * 	- move to GObject
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

#ifndef VIPS_REGION_H
#define VIPS_REGION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Sub-area of image.
 */
typedef struct _VipsRegion {
	/*< public >*/
	/* Users may read these two fields.
	 */
	VipsImage *im;		/* Link back to parent image */
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
} VipsRegion;

void vips_region_free( VipsRegion *region );
VipsRegion *vips_region_new( VipsImage *im );
void vips_region_print( VipsRegion *region, VipsBuf *buf );

int vips_region_buffer( VipsRegion *reg, Rect *r );
int vips_region_image( VipsRegion *reg, Rect *r );
int vips_region_region( VipsRegion *reg, VipsRegion *dest, 
	Rect *r, int x, int y );
int vips_region_equalsregion( VipsRegion *reg1, VipsRegion *reg2 );
int vips_region_position( VipsRegion *reg, int x, int y );

void vips_region_paint( VipsRegion *reg, Rect *r, int value );
void vips_region_black( VipsRegion *reg );
void vips_region_copy( VipsRegion *reg, VipsRegion *dest, 
	Rect *r, int x, int y );

int vips_region_prepare( VipsRegion *reg, Rect *r );
int vips_region_prepare_to( VipsRegion *reg, 
	VipsRegion *dest, Rect *r, int x, int y );
int vips_region_prepare_many( VipsRegion **reg, Rect *r );

/* Macros on REGIONs.
 *	VIPS_REGION_LSKIP()		add to move down line
 *	VIPS_REGION_N_ELEMENTS()	number of elements across region
 *	VIPS_REGION_SIZEOF_LINE()	sizeof width of region
 *	VIPS_REGION_ADDR()		address of pixel in region
 */
#define VIPS_REGION_LSKIP( R ) \
	((size_t)((R)->bpl))
#define VIPS_REGION_N_ELEMENTS( R ) \
	((size_t)((R)->valid.width * (R)->im->Bands))
#define VIPS_REGION_SIZEOF_LINE( R ) \
	((size_t)((R)->valid.width * VIPS_IMAGE_SIZEOF_PEL( (R)->im) ))

/* If DEBUG is defined, add bounds checking.
 */
#ifdef DEBUG
#define VIPS_REGION_ADDR( R, X, Y ) \
	( (im_rect_includespoint( &(R)->valid, (X), (Y) ))? \
	  ((R)->data + ((Y) - (R)->valid.top) * VIPS_REGION_LSKIP(R) + \
	  ((X) - (R)->valid.left) * VIPS_IMAGE_SIZEOF_PEL((R)->im)): \
	  (fprintf( stderr, \
		"VIPS_REGION_ADDR: point out of bounds, " \
		"file \"%s\", line %d\n" \
		"(point x=%d, y=%d\n" \
		" should have been within Rect left=%d, top=%d, " \
		"width=%d, height=%d)\n", \
		__FILE__, __LINE__, \
		(X), (Y), \
		(R)->valid.left, \
		(R)->valid.top, \
		(R)->valid.width, \
		(R)->valid.height ), abort(), (char *) NULL) \
	)
#else /*DEBUG*/
#define VIPS_REGION_ADDR( R, X, Y ) \
	((R)->data + \
	((Y)-(R)->valid.top) * VIPS_REGION_LSKIP( R ) + \
	((X)-(R)->valid.left) * VIPS_IMAGE_SIZEOF_PEL( (R)->im ))
#endif /*DEBUG*/

#define VIPS_REGION_ADDR_TOPLEFT( R ) ((R)->data)

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_REGION_H*/
