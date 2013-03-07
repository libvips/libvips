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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_REGION_H
#define VIPS_REGION_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_TYPE_REGION (vips_region_get_type())
#define VIPS_REGION( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_REGION, VipsRegion ))
#define VIPS_REGION_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_REGION, VipsRegionClass))
#define VIPS_IS_REGION( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_REGION ))
#define VIPS_IS_REGION_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_REGION ))
#define VIPS_REGION_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_REGION, VipsRegionClass ))

/* Sub-area of image.
 */
typedef struct _VipsRegion {
	VipsObject parent_object;

	/*< public >*/
	/* Users may read these two fields.
	 */
	VipsImage *im;		/* Link back to parent image */
	VipsRect valid;		/* Area of parent we can see */

	/* The rest of VipsRegion is private.
	 */
	/*< private >*/
	RegionType type;	/* What kind of attachment */
	VipsPel *data;		/* Off here to get data */
	int bpl;		/* Bytes-per-line for data */
	void *seq;		/* Sequence we are using to fill region */

	/* The thread that made this region. Used to assert() test that
	 * regions are not being shared between threads.
	 */
	GThread *thread;

	/* Ref to the window we use for this region, if any.
	 */
	VipsWindow *window;

	/* Ref to the buffer we use for this region, if any.
	 */
	VipsBuffer *buffer;

	/* The image this region is on has changed and caches need to be
	 * dropped.
	 */
	gboolean invalid;	
} VipsRegion;

typedef struct _VipsRegionClass {
	VipsObjectClass parent_class;

} VipsRegionClass;

GType vips_region_get_type( void );

VipsRegion *vips_region_new( VipsImage *image );

int vips_region_buffer( VipsRegion *reg, VipsRect *r );
int vips_region_image( VipsRegion *reg, VipsRect *r );
int vips_region_region( VipsRegion *reg, VipsRegion *dest, 
	VipsRect *r, int x, int y );
int vips_region_equalsregion( VipsRegion *reg1, VipsRegion *reg2 );
int vips_region_position( VipsRegion *reg, int x, int y );

void vips_region_paint( VipsRegion *reg, VipsRect *r, int value );
void vips_region_paint_pel( VipsRegion *reg, VipsRect *r, VipsPel *ink );
void vips_region_black( VipsRegion *reg );
void vips_region_copy( VipsRegion *reg, VipsRegion *dest, 
	VipsRect *r, int x, int y );

int vips_region_prepare( VipsRegion *reg, VipsRect *r );
int vips_region_prepare_to( VipsRegion *reg, 
	VipsRegion *dest, VipsRect *r, int x, int y );
int vips_region_prepare_many( VipsRegion **reg, VipsRect *r );

/* Macros on VipsRegion.
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
	( (vips_rect_includespoint( &(R)->valid, (X), (Y) ))? \
	  ((R)->data + ((Y) - (R)->valid.top) * VIPS_REGION_LSKIP(R) + \
	  ((X) - (R)->valid.left) * VIPS_IMAGE_SIZEOF_PEL((R)->im)): \
	  (fprintf( stderr, \
		"VIPS_REGION_ADDR: point out of bounds, " \
		"file \"%s\", line %d\n" \
		"(point x=%d, y=%d\n" \
		" should have been within VipsRect left=%d, top=%d, " \
		"width=%d, height=%d)\n", \
		__FILE__, __LINE__, \
		(X), (Y), \
		(R)->valid.left, \
		(R)->valid.top, \
		(R)->valid.width, \
		(R)->valid.height ), abort(), (VipsPel *) NULL) \
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
