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

        GThread *thread;  	/* Thread for this region */

	/* Set this to ask the thread to exit.
	 */
	gboolean exit;	

	/* Set by the thread if work or allocate return an error.
	 */
	gboolean error;	

	/* Thread state for the worker and allocate. Handy for communication.
	 * The region is created and destroyed by the threadpool for the
	 * worker.
	 */
	REGION *reg;		
	Rect pos;
	int x, y;
        void *a, *b, *c; 	

#ifdef TIME_THREAD
	double *btime, *etime;
	int tpos;
#endif /*TIME_THREAD*/
} VipsThread;

/* A work allocate function. This is run single-threaded by a worker to
 * set up a new work unit. 
 * Return non-zero for errors. Set *stop for "no more work to do"
 */
typedef int (*VipsThreadpoolAllocate)( VipsThread *thr,
	void *a, void *b, void *c, gboolean *stop );

/* A work function. This does a unit of work (eg. processing a tile or
 * whatever). Return non-zero for errors. 
 */
typedef int (*VipsThreadpoolWork)( VipsThread *thr, REGION *reg, 
	void *a, void *b, void *c );

/* What we track for a group of threads working together.
 */
typedef struct _VipsThreadpool {
	/* All private.
	 */
	/*< private >*/
	VipsImage *im;		/* Image we are calculating */

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

	/* Set this to abort evaluation early with an error.
	 */
	gboolean kill;		

	/* Set by Allocate (via an arg) to indicate normal end of computation.
	 */
	gboolean stop;

	/* Set this if the pool has been shut down. We sometimes need to allow
	 * double-frees.
	 */
	gboolean zombie;
} VipsThreadpool;


int vips_threadpool_run( VipsImage *im, 
	VipsThreadpoolAllocate allocate, VipsThreadpoolWork work,
	void *a, void *b, void *c );
void vips_get_tile_size( VipsImage *im, 
	int *tile_width, int *tile_height, int *nlines );

extern int im__wbuffer2;

int im_wbuffer2( VipsImage *im, im_wbuffer_fn write_fn, void *a, void *b );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_THREADPOOL_H*/
