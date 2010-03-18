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
	struct _VipsThreadpool *pool; /* Pool we are part of */

	REGION *reg;		/* Region this thread operates on */

        GThread *thread;  	/* Thread for this region */
	gboolean kill;		/* Set this to make thread kill itself */
	gboolean stop;		/* Set this to make thread stop work */
	gboolean error;		/* Set by thread if work fn fails */

	REGION *oreg;		/* If part of an inplace pool, */
	Rect pos;		/* Where this thread should write */
	int x, y;		/* Its result */

        void *a, *b, *c; 	/* User arguments to work fns */

#ifdef TIME_THREAD
	double *btime, *etime;
	int tpos;
#endif /*TIME_THREAD*/
} VipsThread;

/* A work function. This does a unit of work (eg. processing a tile or
 * whatever).
 */
typedef int (*VipsThreadpoolWork)( VipsThread *thr,
	REGION *, void *, void *, void * );

/* A work allocate function. This is run single-threaded by a worker to
 * set up a new work unit. Return TRUE if computation is all done.
 */
typedef gboolean (*VipsThreadpoolAllocate)( VipsThread *thr );

/* What we track for a group of threads working together.
 */
typedef struct _VipsThreadpool {
	/* All private.
	 */
	/*< private >*/
	IMAGE *im;		/* Image we are calculating */
	int pw, ph;		/* Tile size */
	int nlines;		/* Scanlines-at-once we prefer for iteration */

	/* Do a unit of work (runs in parallel) and allocate a unit of work
	 * (serial). Plus the mutex we use to serialize work allocation.
	 */
	VipsThreadpoolAllocate allocate;
	VipsThreadpoolWork work;
	GMutex *allocate_lock;
        void *a, *b, *c; 	/* User arguments to work / allocate */

	int nthr;		/* Number of threads in pool */
	VipsThread **thr;	/* Threads */

	/* The caller blocks here until all threads finish.
	 */
	im_semaphore_t finish;	

	gboolean kill;		/* Set to stop eval early */
	gboolean stop;		/* Set on normal end of computation */
	gboolean progress;	/* Set this to get eval progress feedback */

	/* Set this if the pool has been shut down. We sometimes need to allow
	 * double-frees.
	 */
	gboolean zombie;
} VipsThreadpool;

int vips_threadpool_run( VipsImage *im, 
	VipsThreadpoolAllocate allocate, VipsThreadpoolWork work,
	void *a, void *b, void *c );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_THREADPOOL_H*/
