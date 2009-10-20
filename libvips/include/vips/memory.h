/* memory utilities
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

#ifndef IM_MEMORY_H
#define IM_MEMORY_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define IM_NEW( IM, T ) ((T *) im_malloc( (IM), sizeof( T )))
#define IM_ARRAY( IM, N, T ) ((T *) im_malloc( (IM), (N) * sizeof( T )))

void *im_malloc( VipsImage *im, size_t sz );
int im_free( void * );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_MEMORY_H*/
