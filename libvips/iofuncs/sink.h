/* A sink that's not attached to anything, eg. find image average,
 * 
 * 28/3/10
 * 	- from im_iterate(), reworked for threadpool
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_SINK_H
#define VIPS_SINK_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#include <vips/vips.h>
#include <vips/thread.h>

/* Base for sink.c / sinkdisc.c / sinkmemory.c
 */
typedef struct _SinkBase {
	VipsImage *im;

	/* The position we're at in buf.
	 */
	int x;
	int y;

	/* The tilesize we've picked.
	 */
	int tile_width;
	int tile_height;
	int nlines;

	/* The number of pixels allocate has allocated. Used for progress
	 * feedback.
	 */
	guint64 processed;
} SinkBase;

/* Some function we can share.
 */
void vips_sink_base_init( SinkBase *sink_base, VipsImage *image );
VipsThreadState *vips_sink_thread_state_new( VipsImage *im, void *a );
int vips_sink_base_allocate( VipsThreadState *state, void *a, gboolean *stop );
int vips_sink_base_progress( void *a );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_SINK_H*/
