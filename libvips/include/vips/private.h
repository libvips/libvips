/* Declarations which are public-facing, but private. See internal.h for
 * declarations which are only used internally by vips and which are not
 * externally visible.
 *
 * 6/7/09
 * 	- from vips.h
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

#ifndef IM_PRIVATE_H
#define IM_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define IM_SPARE (8)

/* Private to iofuncs: the minimum number of scanlines we add above and below 
 * the window as a margin for slop.
 */
#define IM__WINDOW_MARGIN_PIXELS (128)

/* Private to iofuncs: add at least this many bytes above and below the window. 
 * There's no point mapping just a few KB of a small image.
 */
#define IM__WINDOW_MARGIN_BYTES (1024 * 1024 * 10)

/* sizeof() a VIPS header on disc.
 */
#define IM_SIZEOF_HEADER (64)

typedef unsigned char PEL;			/* useful datum		*/

/* Types of image descriptor we may have. The type field is advisory only: it
 * does not imply that any fields in IMAGE have valid data.
 */
typedef enum {
	VIPS_IMAGE_NONE,		/* no type set */
	VIPS_IMAGE_SETBUF,		/* malloced memory array */
	VIPS_IMAGE_SETBUF_FOREIGN,	/* memory array, don't free on close */
	VIPS_IMAGE_OPENIN,		/* input from fd with a window */
	VIPS_IMAGE_MMAPIN,		/* memory mapped input file */
	VIPS_IMAGE_MMAPINRW,		/* memory mapped read/write file */
	VIPS_IMAGE_OPENOUT,		/* output to fd */
	VIPS_IMAGE_PARTIAL		/* partial image */
} VipsImageType;

/* What we track for each mmap window. Have a list of these on an openin
 * IMAGE.
 */
typedef struct {
	int ref_count;		/* # of regions referencing us */
	struct _VipsImage *im;	/* IMAGE we are attached to */

	int top; 		/* Area of image we have mapped, in pixels */
	int height;
	char *data;		/* First pixel of line 'top' */

	PEL *baseaddr;		/* Base of window */
	size_t length;		/* Size of window */
} im_window_t;

/* window manager.
 */
im_window_t *im_window_ref( struct _VipsImage *im, int top, int height );
int im_window_unref( im_window_t *window );
void im_window_print( im_window_t *window );

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
	struct _VipsImage *im;
	im_buffer_cache_t *cache;
} im_buffer_cache_list_t;

/* What we track for each pixel buffer. 
 */
typedef struct im__buffer_t {
	int ref_count;		/* # of regions referencing us */
	struct _VipsImage *im;	/* IMAGE we are attached to */

	Rect area;		/* Area this pixel buffer covers */
	gboolean done;		/* Calculated and in cache */
	im_buffer_cache_t *cache;
	char *buf;		/* Private malloc() area */
	size_t bsize;		/* Size of private malloc() */
} im_buffer_t;

void im_buffer_done( im_buffer_t *buffer );
void im_buffer_undone( im_buffer_t *buffer );
void im_buffer_unref( im_buffer_t *buffer );
im_buffer_t *im_buffer_new( struct _VipsImage *im, Rect *area );
im_buffer_t *im_buffer_ref( struct _VipsImage *im, Rect *area );
im_buffer_t *im_buffer_unref_ref( im_buffer_t *buffer, 
	struct _VipsImage *im, Rect *area );
void im_buffer_print( im_buffer_t *buffer );

/* Sections of region.h that are private to VIPS.
 */

/* Region types.
 */
typedef enum region_type {
	IM_REGION_NONE,
	IM_REGION_BUFFER,	/* a pixel buffer */
	IM_REGION_OTHER_REGION, /* memory on another region */
	IM_REGION_OTHER_IMAGE,	/* memory on another image */
	IM_REGION_WINDOW	/* mmap() buffer on fd on another image */
} RegionType;

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
struct _REGION;
void im__region_take_ownership( struct _REGION *reg );
void im__region_check_ownership( struct _REGION *reg );
void im__region_no_ownership( struct _REGION *reg );

void im__copy_region( struct _REGION *reg, struct _REGION *dest, Rect *r, int x, int y );
void im__find_demand_size( struct _VipsImage *im, int *pw, int *ph );

int im__call_start( struct _REGION *reg );
void im__call_stop( struct _REGION *reg );

typedef int (*im_region_fill_fn)( struct _REGION *, void * );
int im_region_fill( struct _REGION *reg, Rect *r, im_region_fill_fn fn, void *a );
void im_region_print( struct _REGION *region );

int im_prepare_many( struct _REGION **reg, Rect *r );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_PRIVATE_H*/
