/* Support for thread stuff.
 * 
 * JC & KM 9/5/94
 * Modified:
 * 28/11/94 JC
 *	- return(0) missing from tidy_thread_info()
 * 4/8/99 RP JC
 *	- reorganised for POSIX
 * 28/3/11
 * 	- moved to vips_ namespace
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

/* 
#define DEBUG_IO
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include <vips/vips.h>
#include <vips/thread.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

void
vips_semaphore_init( VipsSemaphore *s, int v, char *name )
{
	s->v = v;
	s->name = name;
#ifdef HAVE_THREADS
	s->mutex = g_mutex_new();
	s->cond = g_cond_new();
#endif /*HAVE_THREADS*/
}

void
vips_semaphore_destroy( VipsSemaphore *s )
{
#ifdef HAVE_THREADS
	VIPS_FREEF( g_mutex_free, s->mutex );
	VIPS_FREEF( g_cond_free, s->cond );
#endif /*HAVE_THREADS*/
}

/* Add n to the semaphore and signal any threads that are blocked waiting 
 * a change.
 */
int
vips_semaphore_upn( VipsSemaphore *s, int n )
{
	int value_after_op;

#ifdef HAVE_THREADS
	g_mutex_lock( s->mutex );
#endif /*HAVE_THREADS*/
	s->v += n;
	value_after_op = s->v;
#ifdef HAVE_THREADS
	g_mutex_unlock( s->mutex );
	g_cond_signal( s->cond );
#endif /*HAVE_THREADS*/

#ifdef DEBUG_IO
	printf( "vips_semaphore_upn(\"%s\",%d) = %d\n", 
		s->name, n, value_after_op );
	if( value_after_op > 1 )
		vips_error( "vips_semaphore_upn", "up over 1!" );
#endif /*DEBUG_IO*/

	return( value_after_op );
}

/* Increment the semaphore.
 */
int
vips_semaphore_up( VipsSemaphore *s )
{
	return( vips_semaphore_upn( s, 1 ) );
}

/* Wait for sem>n, then subtract n.
 */
int
vips_semaphore_downn( VipsSemaphore *s, int n )
{
	int value_after_op;

#ifdef HAVE_THREADS
	g_mutex_lock( s->mutex );
	while( s->v < n )
		g_cond_wait( s->cond, s->mutex );
#endif /*HAVE_THREADS*/
	s->v -= n;
	value_after_op = s->v;
#ifdef HAVE_THREADS
	g_mutex_unlock( s->mutex );
#endif /*HAVE_THREADS*/

#ifdef DEBUG_IO
	printf( "vips_semaphore_downn(\"%s\",%d): %d\n", 
		s->name, n, value_after_op );
#endif /*DEBUG_IO*/

	return( value_after_op );
}

/* Wait for sem > 0, then decrement.
 */
int
vips_semaphore_down( VipsSemaphore *s )
{
	return( vips_semaphore_downn( s, 1 ) );
}
