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

/* What we track for each thread in the pool.
 */
typedef struct {
	/* All private.
	 */
	/*< private >*/
	REGION *reg;		/* Region this thread operates on */
	struct _VipsTreadPool *pool; /* Pool we are part of */

        GThread *thread;  	/* Thread for this region */
        im_semaphore_t go;   	/* Thread waits here to start work */
	int kill;		/* Set this to make thread exit */
	int error;		/* Set by thread if work fn fails */

	REGION *oreg;		/* If part of an inplace threadgroup, */
	Rect pos;		/* Where this thread should write */
	int x, y;		/* Its result */

        void *a, *b, *c; 	/* User arguments to work fns */

#ifdef TIME_THREAD
	hrtime_t *btime, *etime;
	int tpos;
#endif /*TIME_THREAD*/
} VipsThread;

/* A work function. This does a unit of work (eg. processing a tile or
 * whatever).
 */
typedef int (*VipsThreadPoolWork)( VipsThread *thr,
	REGION *, void *, void *, void * );

/* A work allocate function. This is run single-threaded by a worker to
 * set up a new work unit.
 */
typedef void (*VipsThreadPoolAllocate)( VipsThread *thr );

/* What we track for a group of threads working together.
 */
typedef struct _VipsThreadPool {
	/* All private.
	 */
	/*< private >*/
	IMAGE *im;		/* Image we are calculating */
	int pw, ph;		/* Tile size */
	int nlines;		/* Scanlines-at-once we prefer for iteration */

	/* Do a unit of work (runs in parallel) and allocate a unit of work
	 * (serial). Plus the mutex we use to serialize work allocation.
	 */
	VipsThreadPoolWork work;
	VipsThreadPoolAllocate allocate;
	GMutex *allocate_lock;

	int nthr;		/* Number of threads in group */
	im_thread_t **thr;	/* Threads */

	/* The caller blocks here until the last worker is done.
	 */
	im_semaphore_t *main;	

	int kill;		/* Set this to stop threadgroup early */
	int progress;		/* Set this to get eval progress feedback */
} VipsThreadPool;

/* Thread pool functions.
 */
VipsThreadPool *vips_thread_pool_new( IMAGE *im );
int vips_thread_pool_free( VipsThreadPool *pool );
void vips_thread_pool_run( VipsThreadPool *pool );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_THREADPOOL_H*/
