/* Thread eval for VIPS.
 *
 * 29/9/99 JC
 *	- from thread.h
 * 17/3/10
 * 	- from threadgroup
 * 	- rework with a simpler distributed work allocation model
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

#ifndef IM_THREADPOOL_H
#define IM_THREADPOOL_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/semaphore.h>

/* The per-thread state we expose. Allocate functions can use these members to
 * communicate with work functions.
 */
typedef struct _VipsThreadState {
	/* This region is created and destroyed by the threadpool for the
	 * worker. 
	 */
	REGION *reg;		

	/* The rest are neither used nor set, do what you like with them.
	 */
	Rect pos;
	int x, y;
        void *d, *e, *f; 	
} VipsThreadState;

/* A work allocate function. This is run single-threaded by a worker to
 * set up a new work unit. 
 * Return non-zero for errors. Set *stop for "no more work to do"
 */
typedef int (*VipsThreadpoolAllocate)( VipsThreadState *state,
	void *a, void *b, void *c, gboolean *stop );

/* A work function. This does a unit of work (eg. processing a tile or
 * whatever). Return non-zero for errors. 
 */
typedef int (*VipsThreadpoolWork)( VipsThreadState *state, 
	void *a, void *b, void *c );

/* A progress function. This is run by the main thread once for every
 * allocation. Return an error to kill computation early.
 */
typedef int (*VipsThreadpoolProgress)( void *a, void *b, void *c );

int vips_threadpool_run( VipsImage *im, 
	VipsThreadpoolAllocate allocate, 
	VipsThreadpoolWork work,
	VipsThreadpoolProgress progress,
	void *a, void *b, void *c );
void vips_get_tile_size( VipsImage *im, 
	int *tile_width, int *tile_height, int *nlines );

typedef int (*VipsRegionWrite)( REGION *region, Rect *area, void *a, void *b );
int vips_discsink( VipsImage *im, 
	VipsRegionWrite write_fn, void *a, void *b );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_THREADPOOL_H*/
