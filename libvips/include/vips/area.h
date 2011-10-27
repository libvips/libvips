/* area.h
 *
 * 27/10/11
 * 	- from header.h
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

#ifndef VIPS_AREA_H
#define VIPS_AREA_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Also used for eg. vips_local() and friends.
 */
typedef int (*VipsCallbackFn)( void *a, void *b );

/* A ref-counted area of memory. Can hold arrays of things as well.
 */
typedef struct _VipsArea {
	void *data;
	size_t length;		/* 0 if not known */

	/* If this area represents an array, the number of elements in the
	 * array. Equal to length / sizeof(element).
	 */
	int n;

	/*< private >*/

	/* Reference count.
	 */
	int count;

	/* Things like ICC profiles need their own free functions.
	 */
	VipsCallbackFn free_fn;

	/* If we are holding an array (for exmaple, an array of double), the
	 * GType of the elements and their size. 0 for not known.
	 *
	 * n is always length / sizeof_type, we keep it as a member for
	 * convenience.
	 */
	GType type;
	size_t sizeof_type;
} VipsArea;

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_AREA_H*/
