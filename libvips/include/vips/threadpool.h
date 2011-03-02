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

/* Per-thread state. Allocate functions can use these members to
 * communicate with work functions.
 */

#define VIPS_TYPE_THREAD_STATE (vips_thread_state_get_type())
#define VIPS_THREAD_STATE( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_THREAD_STATE, VipsThreadState ))
#define VIPS_THREAD_STATE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_THREAD_STATE, VipsThreadStateClass))
#define VIPS_IS_THREAD_STATE( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_THREAD_STATE ))
#define VIPS_IS_THREAD_STATE_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_THREAD_STATE ))
#define VIPS_THREAD_STATE_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_THREAD_STATE, VipsThreadStateClass ))

typedef struct _VipsThreadState {
	VipsObject parent_object;

	/*< public >*/
	/* Image we run on.
	 */
	VipsImage *im;

	/* This region is created and destroyed by the threadpool for the
	 * use of the worker. 
	 */
	VipsRegion *reg;		

	/* Neither used nor set, do what you like with them.
	 */
	Rect pos;
	int x, y;

	/* The client data passed to the enclosing vips_threadpool_run().
	 */
        void *a;

} VipsThreadState;

typedef struct _VipsThreadStateClass {
	VipsObjectClass parent_class;
	/*< public >*/

} VipsThreadStateClass;

void *vips_thread_state_set( VipsObject *object, void *a, void *b );
GType vips_thread_state_get_type( void );

VipsThreadState *vips_thread_state_new( VipsImage *im, void *a );

/* Constructor for per-thread state.
 */
typedef VipsThreadState *(*VipsThreadStart)( VipsImage *im, void *a );

/* A work allocate function. This is run single-threaded by a worker to
 * set up a new work unit. 
 * Return non-zero for errors. Set *stop for "no more work to do"
 */
typedef int (*VipsThreadpoolAllocate)( VipsThreadState *state,
	void *a, gboolean *stop );

/* A work function. This does a unit of work (eg. processing a tile or
 * whatever). Return non-zero for errors. 
 */
typedef int (*VipsThreadpoolWork)( VipsThreadState *state, void *a );

/* A progress function. This is run by the main thread once for every
 * allocation. Return an error to kill computation early.
 */
typedef int (*VipsThreadpoolProgress)( void *a );

int vips_threadpool_run( VipsImage *im, 
	VipsThreadStart start, 
	VipsThreadpoolAllocate allocate, 
	VipsThreadpoolWork work,
	VipsThreadpoolProgress progress,
	void *a );
void vips_get_tile_size( VipsImage *im, 
	int *tile_width, int *tile_height, int *nlines );

typedef int (*VipsRegionWrite)( VipsRegion *region, Rect *area, void *a );
int vips_sink_disc( VipsImage *im, VipsRegionWrite write_fn, void *a );

typedef void *(*VipsStart)( VipsImage *out, void *a, void *b );
typedef int (*VipsGenerate)( VipsRegion *out, void *seq, void *a, void *b );
typedef int (*VipsStop)( void *seq, void *a, void *b );
int vips_sink( VipsImage *im, 
	VipsStart start, VipsGenerate generate, VipsStop stop,
	void *a, void *b );
int vips_sink_tile( VipsImage *im, 
	int tile_width, int tile_height,
	VipsStart start, VipsGenerate generate, VipsStop stop,
	void *a, void *b );

typedef void (*VipsSinkNotify)( VipsImage *im, Rect *rect, void *a );
int vips_sink_screen( VipsImage *in, VipsImage *out, VipsImage *mask,
	int tile_width, int tile_height, int max_tiles,
	int priority,
	VipsSinkNotify notify, void *a );

int vips_sink_memory( VipsImage *im );

void im__print_renders( void );

void im_concurrency_set( int concurrency );
int im_concurrency_get( void );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_THREADPOOL_H*/
