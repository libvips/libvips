/* Thread eval for VIPS.
 *
 * 29/9/99 JC
 *	- from thread.h
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

#ifndef IM_THREADGROUP_H
#define IM_THREADGROUP_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/semaphore.h>

/* Stack size for each thread. We need to set this explicitly because some
 * systems have a very low default.

 	FIXME ...  should have an environment variable for this?

 */
#define IM__DEFAULT_STACK_SIZE (2 * 1024 * 1024)

/* What we track for each thread.
 */
typedef struct {
	/*< private >*/
	REGION *reg;		/* Region this thread operates on */
	struct im__threadgroup_t *tg; /* Thread group we are part of */

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
} im_thread_t;

/* A work function.
 */
typedef int (*im__work_fn)( im_thread_t *thr,
	REGION *, void *, void *, void * );

/* What we track for a group of threads working together.
 */
typedef struct im__threadgroup_t {
	/*< private >*/
	int zombie;		/* Set if has been freed */

	IMAGE *im;		/* Image we are calculating */
	int pw, ph;		/* Tile size */
	int nlines;		/* Scanlines-at-once we prefer for iteration */

	im__work_fn work;	/* Work fn for this threadgroup */

	int nthr;		/* Number of threads in group */
	im_thread_t **thr;	/* Threads */

	im_semaphore_t idle_sem;/* The number of idle threads */
	GSList *idle;		/* All the idle threads */
	GMutex *idle_lock;	
#ifdef DEBUG_HIGHWATER
	int nidle;		/* Number of idles */
	int min_idle;		/* How short idle got */
#endif /*DEBUG_HIGHWATER*/

	int kill;		/* Set this to stop threadgroup early */

	int progress;		/* Set this to get eval progress feedback */
} im_threadgroup_t;

void im_concurrency_set( int concurrency );
int im_concurrency_get( void );

/* Thread group functions.
 */
im_threadgroup_t *im_threadgroup_create( IMAGE *im );
int im_threadgroup_free( im_threadgroup_t *tg );
im_thread_t *im_threadgroup_get( im_threadgroup_t *tg );
void im_threadgroup_trigger( im_thread_t *thr );
void im_threadgroup_wait( im_threadgroup_t *tg );
int im_threadgroup_iserror( im_threadgroup_t *tg );

/* Threaded im_prepare()
 */
int im_prepare_thread( im_threadgroup_t *tg, REGION *oreg, Rect *r );

/* Threaded, double-buffered eval to file.
 */
typedef int (*im_wbuffer_fn)( REGION *region, Rect *area, void *a, void *b );
int im_wbuffer( im_threadgroup_t *tg, 
	im_wbuffer_fn write_fn, void *a, void *b );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_THREADGROUP_H*/
