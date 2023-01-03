/* Private include file ... if we've been configured without gthread, we need
 * to point the g_thread_*() and g_mutex_*() functions at our own stubs.
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

#ifndef VIPS_THREAD_H
#define VIPS_THREAD_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* We need wrappers over g_mutex_new(), it was replaced by g_mutex_init() in
 * glib 2.32+
 */
VIPS_API
GMutex *vips_g_mutex_new( void );
VIPS_API
void vips_g_mutex_free( GMutex * );

/* Same for GCond.
 */
VIPS_API
GCond *vips_g_cond_new( void );
VIPS_API
void vips_g_cond_free( GCond * );

/* ... and for GThread.
 */
VIPS_API
GThread *vips_g_thread_new( const char *, GThreadFunc, gpointer );

VIPS_API
gboolean vips_thread_isvips( void );

typedef struct _VipsThreadset VipsThreadset;
VipsThreadset *vips_threadset_new( int max_threads );
int vips_threadset_run( VipsThreadset *set, 
	const char *domain, GFunc func, gpointer data );
void vips_threadset_free( VipsThreadset *set );

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VIPS_THREAD_H*/
