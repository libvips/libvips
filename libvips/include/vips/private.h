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

#ifndef VIPS_PRIVATE_H
#define VIPS_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define VIPS_SPARE (8)

/* Private to iofuncs: the minimum number of scanlines we add above and below 
 * the window as a margin for slop.
 */
#define VIPS__WINDOW_MARGIN_PIXELS (128)

/* Private to iofuncs: add at least this many bytes above and below the window. 
 * There's no point mapping just a few KB of a small image.
 */
#define VIPS__WINDOW_MARGIN_BYTES (1024 * 1024 * 10)

/* sizeof() a VIPS header on disc.
 */
#define VIPS_SIZEOF_HEADER (64)

typedef unsigned char PEL;			/* useful datum		*/

/* What we track for each mmap window. Have a list of these on an openin
 * VipsImage.
 */
typedef struct {
	int ref_count;		/* # of regions referencing us */
	struct _VipsImage *im;	/* VipsImage we are attached to */

	int top; 		/* Area of image we have mapped, in pixels */
	int height;
	PEL *data;		/* First pixel of line 'top' */

	void *baseaddr;		/* Base of window */
	size_t length;		/* Size of window */
} VipsWindow;

/* window manager.
 */
VipsWindow *vips_window_ref( struct _VipsImage *im, int top, int height );
int vips_window_unref( VipsWindow *window );
void vips_window_print( VipsWindow *window );

/* Per-thread buffer cache. Held in a GPrivate.
 */
typedef struct {
	GHashTable *hash;	/* Hash to VipsBufferCacheList* */
	GThread *thread;	/* Just for sanity checking */
} VipsBufferCache;

/* Per-image buffer cache. Hash to this from VipsBufferCache.
 * We can't store the GSList directly in the hash table, as GHashTable lacks an
 * update operation and we'd need to _remove() and _insert() on every list
 * operation.
 */
typedef struct {
	GSList *buffers;	/* GSList of VipsBuffer* */
	GThread *thread;	/* Just for sanity checking */
	struct _VipsImage *im;
	VipsBufferCache *cache;
} VipsBufferCacheList;

/* What we track for each pixel buffer. 
 */
typedef struct {
	int ref_count;		/* # of regions referencing us */
	struct _VipsImage *im;	/* VipsImage we are attached to */

	VipsRect area;		/* Area this pixel buffer covers */
	gboolean done;		/* Calculated and in cache */
	VipsBufferCache *cache;
	PEL *buf;		/* Private malloc() area */
	size_t bsize;		/* Size of private malloc() */
} VipsBuffer;

void vips_buffer_done( VipsBuffer *buffer );
void vips_buffer_undone( VipsBuffer *buffer );
void vips_buffer_unref( VipsBuffer *buffer );
VipsBuffer *vips_buffer_new( struct _VipsImage *im, VipsRect *area );
VipsBuffer *vips_buffer_ref( struct _VipsImage *im, VipsRect *area );
VipsBuffer *vips_buffer_unref_ref( VipsBuffer *buffer, 
	struct _VipsImage *im, VipsRect *area );
void vips_buffer_print( VipsBuffer *buffer );

/* Sections of region.h that are private to VIPS.
 */

/* Region types.
 */
typedef enum region_type {
	VIPS_REGION_NONE,
	VIPS_REGION_BUFFER,		/* A VipsBuffer */
	VIPS_REGION_OTHER_REGION, 	/* Memory on another region */
	VIPS_REGION_OTHER_IMAGE,	/* Memory on another image */
	VIPS_REGION_WINDOW		/* A VipsWindow on fd */
} RegionType;

/* Private to iofuncs: the size of the `tiles' requested by 
 * vips_image_generate() when acting as a data sink.
 */
#define VIPS__TILE_WIDTH (128)
#define VIPS__TILE_HEIGHT (128)

/* The height of the strips for the other two request styles.
 */
#define VIPS__THINSTRIP_HEIGHT (1)
#define VIPS__FATSTRIP_HEIGHT (16)

/* Functions on regions.
 */
struct _VipsRegion;
void vips__region_take_ownership( struct _VipsRegion *reg );
void vips__region_check_ownership( struct _VipsRegion *reg );
void vips__region_no_ownership( struct _VipsRegion *reg );

int vips__region_start( struct _VipsRegion *reg );
void vips__region_stop( struct _VipsRegion *reg );

typedef int (*VipsRegionFillFn)( struct _VipsRegion *, void * );
int vips_region_fill( struct _VipsRegion *reg, 
	VipsRect *r, VipsRegionFillFn fn, void *a );

int vips__image_wio_output( struct _VipsImage *image );
int vips__image_pio_output( struct _VipsImage *image );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_PRIVATE_H*/
