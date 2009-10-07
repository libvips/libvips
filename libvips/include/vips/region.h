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
} REGION;

REGION *im_region_create( IMAGE *im );
void im_region_free( REGION *reg );

int im_region_buffer( REGION *reg, Rect *r );
int im_region_image( REGION *reg, Rect *r );
int im_region_region( REGION *reg, REGION *to, Rect *r, int x, int y );
int im_region_equalsregion( REGION *reg1, REGION *reg2 );
int im_region_position( REGION *reg1, int x, int y );

/* IMAGE functions which use regions. 
 */
int im_prepare( REGION *reg, Rect *r );
int im_prepare_to( REGION *reg, REGION *dest, Rect *r, int x, int y );

typedef void *(*im_start_fn)( IMAGE *, void *, void * );
typedef int (*im_generate_fn)( REGION *, void *, void *, void *);
typedef int (*im_stop_fn)( void *, void *, void * );

void *im_start_one( IMAGE *out, void *in, void *dummy );
int im_stop_one( void *seq, void *dummy1, void *dummy2 );
void *im_start_many( IMAGE *out, void *in, void *dummy );
int im_stop_many( void *seq, void *dummy1, void *dummy2 );
IMAGE **im_allocate_input_array( IMAGE *out, ... )
	__attribute__((sentinel));

int im_generate( IMAGE *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b
);
int im_iterate( IMAGE *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b
);

int im_demand_hint( IMAGE *im, im_demand_type hint, ... )
	__attribute__((sentinel));
int im_demand_hint_array( IMAGE *im, im_demand_type hint, IMAGE **in );

void im_free_region_array( REGION **regs );
REGION **im_allocate_region_array( IMAGE *im, int count );

/* Buffer processing.
 */
typedef void (*im_wrapone_fn)( void *in, void *out, int width,
	void *a, void *b );
int im_wrapone( IMAGE *in, IMAGE *out,
	im_wrapone_fn fn, void *a, void *b );

typedef void (*im_wraptwo_fn)( void *in1, void *in2, void *out, 
        int width, void *a, void *b );
int im_wraptwo( IMAGE *in1, IMAGE *in2, IMAGE *out,
	im_wraptwo_fn fn, void *a, void *b );

typedef void (*im_wrapmany_fn)( void **in, void *out, int width,
	void *a, void *b );
int im_wrapmany( IMAGE **in, IMAGE *out,
	im_wrapmany_fn fn, void *a, void *b );

/* Macros on REGIONs.
 *	IM_REGION_LSKIP()		add to move down line
 *	IM_REGION_N_ELEMENTS()		number of elements across region
 *	IM_REGION_SIZEOF_LINE()		sizeof width of region
 *	IM_REGION_ADDR()		address of pixel in region
 */
#define IM_REGION_LSKIP(R) ((R)->bpl)
#define IM_REGION_N_ELEMENTS(R) ((R)->valid.width*(R)->im->Bands)
#define IM_REGION_SIZEOF_LINE(R) \
	((R)->valid.width * IM_IMAGE_SIZEOF_PEL((R)->im))

/* If DEBUG is defined, add bounds checking.
 */
#ifdef DEBUG
#define IM_REGION_ADDR(B,X,Y) \
	( (im_rect_includespoint( &(B)->valid, (X), (Y) ))? \
	  ((B)->data + ((Y) - (B)->valid.top)*IM_REGION_LSKIP(B) + \
	  ((X) - (B)->valid.left)*IM_IMAGE_SIZEOF_PEL((B)->im)): \
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
