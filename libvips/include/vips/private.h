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

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_PRIVATE_H*/
