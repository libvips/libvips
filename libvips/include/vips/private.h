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

/* Private to iofuncs: the image size above which we switch from
 * mmap()-whole-image behaviour to mmap()-window, plus window margins.
 */
#define IM__MMAP_LIMIT (1024*1024*30)
#define IM__WINDOW_MARGIN (128)

/* sizeof() a VIPS header on disc.
 */
#define IM_SIZEOF_HEADER (64)

typedef unsigned char PEL;			/* useful datum		*/

/* Types of image descriptor we may have. The type field is advisory only: it
 * does not imply that any fields in IMAGE have valid data.
 */
typedef enum {
	IM_NONE,		/* no type set */
	IM_SETBUF,		/* malloced memory array */
	IM_SETBUF_FOREIGN,	/* memory array, don't free on close */
	IM_OPENIN,		/* input from fd */
	IM_MMAPIN,		/* memory mapped input file */
	IM_MMAPINRW,		/* memory mapped read/write file */
	IM_OPENOUT,		/* output to fd */
	IM_PARTIAL		/* partial image */
} im_desc_type;

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
im_window_t *im_window_ref( IMAGE *im, int top, int height );
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
	gboolean invalid;	/* Needs to be recalculated */
	char *buf;		/* Private malloc() area */
	size_t bsize;		/* Size of private malloc() */
} im_buffer_t;

void im_buffer_done( im_buffer_t *buffer );
void im_buffer_undone( im_buffer_t *buffer );
void im_buffer_unref( im_buffer_t *buffer );
im_buffer_t *im_buffer_ref( struct _VipsImage *im, Rect *area );
im_buffer_t *im_buffer_unref_ref( im_buffer_t *buffer, 
	struct _VipsImage *im, Rect *area );
void im_buffer_print( im_buffer_t *buffer );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_PRIVATE_H*/
