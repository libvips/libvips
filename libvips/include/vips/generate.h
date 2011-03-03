/* Definitions for partial image regions.
 *
 * J.Cupitt, 8/4/93
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

#ifndef IM_GENERATE_H
#define IM_GENERATE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

typedef void *(*im_start_fn)( IMAGE *out, void *a, void *b );
typedef int (*im_generate_fn)( VipsRegion *out, void *seq, void *a, void *b );
typedef int (*im_stop_fn)( void *seq, void *a, void *b );

void *im_start_one( IMAGE *out, void *a, void *b );
int im_stop_one( void *seq, void *a, void *b );
void *im_start_many( IMAGE *out, void *a, void *b );
int im_stop_many( void *seq, void *a, void *b );
IMAGE **im_allocate_input_array( IMAGE *out, ... )
	__attribute__((sentinel));

int im_generate( IMAGE *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b
);
int im_iterate( IMAGE *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b
);

int im_demand_hint_array( IMAGE *im, im_demand_type hint, IMAGE **in );
int im_demand_hint( IMAGE *im, im_demand_type hint, ... )
	__attribute__((sentinel));

/* Buffer processing.
 */
typedef void (*im_wrapone_fn)( void *in, void *out, int width,
	void *a, void *b );
int im_wrapone( IMAGE *in, IMAGE *out,
	im_wrapone_fn fn, void *a, void *b );

typedef void (*im_wraptwo_fn)( void *in1, void *in2, void *out, 
        int width, void *a, void *b );
int im_wraptwo( IMAGE *in1, IMAGE *in2, IMAGE *out,
	im_wraptwo_fn fn, void *a, void *b );

typedef void (*im_wrapmany_fn)( void **in, void *out, int width,
	void *a, void *b );
int im_wrapmany( IMAGE **in, IMAGE *out,
	im_wrapmany_fn fn, void *a, void *b );

/* Async rendering.
 */
int im_render_priority( IMAGE *in, IMAGE *out, IMAGE *mask,
	int width, int height, int max,
	int priority,
	void (*notify)( IMAGE *, Rect *, void * ), void *client );
int im_cache( IMAGE *in, IMAGE *out, int width, int height, int max );

int im_setupout( IMAGE *im );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_GENERATE_H*/
