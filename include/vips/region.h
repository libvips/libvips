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

/* Profiling madness only, who cares about portability.
 */
#ifdef TIME_THREAD
#include <sys/time.h>
#endif /*TIME_THREAD*/

/* Per-thread buffer cache. Held in a GPrivate.
 */
typedef struct im__buffer_cache_t {
	GHashTable *hash;	/* Hash to im_buffer_cache_list_t* */
	GThread *thread;	/* Just for sanity checking */
} im_buffer_cache_t;

/* Per-image buffer cache. Hash to this from im_buffer_cache_t.
 * We can't store the GSList directly in the hash table, as GHashTable lacks an
 * update operation and we'd need to _remove() and _insert() on every list
 * operation.
 */
typedef struct im__buffer_cache_list_t {
	GSList *buffers;	/* GSList of im_buffer_t* */
	GThread *thread;	/* Just for sanity checking */
	IMAGE *im;
	im_buffer_cache_t *cache;
} im_buffer_cache_list_t;

/* What we track for each pixel buffer. 
 */
typedef struct {
	int ref_count;		/* # of regions referencing us */
	IMAGE *im;		/* IMAGE we are attached to */

	Rect area;		/* Area this pixel buffer covers */
	gboolean done;		/* Calculated and in cache */
	im_buffer_cache_t *cache;
	gboolean invalid;	/* Needs to be recalculated */
	char *buf;		/* Private malloc() area */
	size_t bsize;		/* Size of private malloc() */
} im_buffer_t;

/* Region types.
 */
typedef enum region_type {
	IM_REGION_NONE,
	IM_REGION_BUFFER,	/* a pixel buffer */
	IM_REGION_OTHER_REGION, /* memory on another region */
	IM_REGION_OTHER_IMAGE,	/* memory on another image */
	IM_REGION_WINDOW	/* mmap() buffer on fd on another image */
} RegionType;

/* Sub-area of image.
 */
typedef struct region_struct {
	/* Users may read these two fields.
	 */
	IMAGE *im;		/* Link back to parent image */
	Rect valid;		/* Area of parent we can see */

	/* The rest of REGION is private.
	 */
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

/* Private to iofuncs: the size of the `tiles' requested by im_generate()
 * when acting as a data sink.
 */
#define IM__TILE_WIDTH (64)
#define IM__TILE_HEIGHT (64)

/* The height of the strips for the other two request styles.
 */
#define IM__THINSTRIP_HEIGHT (1)
#define IM__FATSTRIP_HEIGHT (16)

/* Functions on regions.
 */
void im__region_take_ownership( REGION *reg );
void im__region_check_ownership( REGION *reg );
void im__region_no_ownership( REGION *reg );

REGION *im_region_create( IMAGE *im );
void im_region_free( REGION *reg );
int im_region_buffer( REGION *reg, Rect *r );
int im_region_image( REGION *reg, Rect *r );
int im_region_region( REGION *reg, REGION *to, Rect *r, int x, int y );
int im_region_equalsregion( REGION *reg1, REGION *reg2 );
int im_region_position( REGION *reg1, int x, int y );
typedef int (*im_region_fill_fn)( REGION *, void * );
int im_region_fill( REGION *reg, Rect *r, im_region_fill_fn fn, void *a );

void im_region_print( REGION *region );

/* IMAGE functions which use regions. 
 */
typedef void *(*im_start_fn)( IMAGE *, void *, void * );
typedef int (*im_generate_fn)( REGION *, void *, void *, void *);
typedef int (*im_stop_fn)( void *, void *, void * );
int im_prepare( REGION *reg, Rect *r );
int im_prepare_many( REGION **reg, Rect *r );
int im_prepare_to( REGION *reg, REGION *dest, Rect *r, int x, int y );
int im_generate( IMAGE *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b
);
int im_iterate( IMAGE *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b
);
void im__copy_region( REGION *reg, REGION *dest, Rect *r, int x, int y );

/* Convenience functions for im_generate()/im_iterate().
 */
void *im_start_one( IMAGE *out, void *in, void *dummy );
int im_stop_one( void *seq, void *dummy1, void *dummy2 );
void *im_start_many( IMAGE *out, void *in, void *dummy );
int im_stop_many( void *seq, void *dummy1, void *dummy2 );
IMAGE **im_allocate_input_array( IMAGE *out, ... );
int im_demand_hint( IMAGE *im, im_demand_type hint, ... )
	__attribute__((sentinel));
int im_demand_hint_array( IMAGE *im, im_demand_type hint, IMAGE **in );
void im_free_region_array( REGION **regs );
REGION **im_allocate_region_array( IMAGE *im, int count );
void im__find_demand_size( IMAGE *im, int *pw, int *ph );

/* Buffer processing.
 */
typedef void (*im_wrapone_fn)( void *in, void *out, int width,
	void *a, void *b );
typedef void (*im_wraptwo_fn)( void *in1, void *in2, void *out, 
        int width, void *a, void *b );
typedef void (*im_wrapmany_fn)( void **in, void *out, int width,
	void *a, void *b );

int im_wrapone( IMAGE *in, IMAGE *out,
	im_wrapone_fn fn, void *a, void *b );
int im_wraptwo( IMAGE *in1, IMAGE *in2, IMAGE *out,
	im_wraptwo_fn fn, void *a, void *b );
int im_wrapmany( IMAGE **in, IMAGE *out,
	im_wrapmany_fn fn, void *a, void *b );

/* Internal VIPS functions shared by partials.
 */
int im__call_start( REGION *reg );
void im__call_stop( REGION *reg );

/* window manager.
 */
im_window_t *im_window_ref( IMAGE *im, int top, int height );
int im_window_unref( im_window_t *window );
void im_window_print( im_window_t *window );

/* buffer manager.
 */
void im_buffer_done( im_buffer_t *buffer );
void im_buffer_undone( im_buffer_t *buffer );
void im_buffer_unref( im_buffer_t *buffer );
im_buffer_t *im_buffer_ref( IMAGE *im, Rect *area );
im_buffer_t *im_buffer_unref_ref( im_buffer_t *buffer, IMAGE *im, Rect *area );
void im_buffer_print( im_buffer_t *buffer );
void im_invalidate( IMAGE *im );

/* Only define if IM_ENABLE_DEPRECATED is set.
 */
#ifdef IM_ENABLE_DEPRECATED

/* Compatibilty macros ... delete soon. See below for the new names.
 */

/* Macros on REGIONs.
 *	lskip()		add to move down line
 *	nele()		number of elements across region
 *	rsize()		sizeof width of region
 *	addr()		address of pixel in region
 */
#define lskip(B) ((B)->bpl)
#define nele(B) ((B)->valid.width*(B)->im->Bands)
#define rsize(B) ((B)->valid.width*psize((B)->im))

/* addr() is special: if DEBUG is defined, make an addr() with bounds checking.
 */
#ifdef DEBUG
#define addr(B,X,Y) \
	( (im_rect_includespoint( &(B)->valid, (X), (Y) ))? \
	  ((B)->data + ((Y) - (B)->valid.top)*lskip(B) + \
	  ((X) - (B)->valid.left)*psize((B)->im)): \
	  (fprintf( stderr, \
		"addr: point out of bounds, file \"%s\", line %d\n" \
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
#define addr(B,X,Y) ((B)->data + ((Y)-(B)->valid.top)*lskip(B) + \
	((X)-(B)->valid.left)*psize((B)->im))
#endif /*DEBUG*/

#endif /*IM_ENABLE_DEPRECATED*/

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
