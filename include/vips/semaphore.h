/* Definitions for thread support.
 *
 * JC, 9/5/94
 * 30/7/99 RP, JC
 *	- reworked for posix/solaris threads
 * 28/9/99 JC
 *	- restructured, made part of public API
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

#ifndef IM_SEMAPHORE_H
#define IM_SEMAPHORE_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* Implement our own semaphores.
 */
typedef struct {
	char *name;
	int v;

	GMutex *mutex;
	GCond *cond;
} im_semaphore_t;

int im_semaphore_up( im_semaphore_t *s );
int im_semaphore_down( im_semaphore_t *s );
int im_semaphore_upn( im_semaphore_t *s, int n );
int im_semaphore_downn( im_semaphore_t *s, int n );
void im_semaphore_destroy( im_semaphore_t *s );
void im_semaphore_init( im_semaphore_t *s, int v, char *name );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*IM_SEMAPHORE_H*/
