/* Create and reuse a set of OS threads.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <errno.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>
#include <vips/debug.h>

typedef struct _VipsThreadsetMember {
        /* The set we are part of.
         */
        VipsThreadset *set;

        /* The underlying glib thread object.
         */
        GThread *thread;

        /* The task the thread should run next, and the result it returned.
         */
        const char *domain;
	GFunc func; 
        void *data;
        void *user_data;

        /* The thread waits on this when it's free.
         */
        VipsSemaphore idle;

        /* Set by our controller to request exit.
         */
        gboolean kill;
} VipsThreadsetMember;

struct _VipsThreadset {
	GMutex *lock;

        /* All the VipsThreadsetMember we have created.
         */
        GSList *members;

        /* The set of currently idle threads.
         */
        GSList *free;
};

/* Set this GPrivate to indicate that this is a libvips worker.
 */
static GPrivate *is_worker_key = NULL;

static int vips_threadset_n_threads = 0;
static int vips_threadset_max_threads = 0;

/* The thread work function.
 */
static void *
vips_threadset_work( void *pointer )
{
        VipsThreadsetMember *member = (VipsThreadsetMember *) pointer;
        VipsThreadset *set = member->set;

        for(;;) {
                /* Wait to be given work.
                 */
                vips_semaphore_down( &member->idle );
                if( member->kill ||
                        !member->func ) 
                        break;

                /* If we're profiling, attach a prof struct to this thread.
                 */
                if( vips__thread_profile ) 
                        vips__thread_profile_attach( member->domain );

                /* Execute the task.
                 */
                member->func( member->data, member->user_data );

                /* Free any thread-private resources -- they will not be
                 * useful for the next task to use this thread.
                 */
                vips_thread_shutdown();

                member->domain = NULL;
                member->func = NULL;
                member->data = NULL;
                member->user_data = NULL;

                /* We are free ... back on the free list!
                 */
                g_mutex_lock( set->lock );
                set->free = g_slist_prepend( set->free, member );
                g_mutex_unlock( set->lock );
        }

        /* Kill has been requested. We leave this thread on the members 
         * list so it can be found and joined.
         */

        return( NULL );
}

/* TRUE if we are a vips worker thread. We sometimes manage resource allocation
 * differently for vips workers since we can cheaply free stuff on thread
 * termination.
 */
gboolean
vips_thread_isworker( void )
{
	return( g_private_get( is_worker_key ) != NULL );
}

/* Create a new idle member for the set.
 */
static VipsThreadsetMember *
vips_threadset_add( VipsThreadset *set )
{
        VipsThreadsetMember *member;
	GError *error = NULL;

        member = g_new0( VipsThreadsetMember, 1 );
        member->set = set;

	vips_semaphore_init( &member->idle, 0, "idle" );

	member->thread = g_thread_try_new( "libvips worker", 
                vips_threadset_work, member, &error );
	if( !member->thread ) {
		if( error ) 
			vips_g_error( &error ); 
		else
			vips_error( "vips_threadset_add", 
				"%s", _( "unable to create thread" ) );

                vips_semaphore_destroy( &member->idle );
                VIPS_FREE( member );

                return( NULL );
	}

	/* Set this to something (anything) to tag this thread as a vips 
	 * worker.
	 */
	g_private_set( is_worker_key, member );

        g_mutex_lock( set->lock );
        set->members = g_slist_prepend( set->members, member );
        vips_threadset_n_threads += 1;
        vips_threadset_max_threads = VIPS_MAX( vips_threadset_max_threads, 
                vips_threadset_n_threads );;
        g_mutex_unlock( set->lock );

        return( member );
}

VipsThreadset *
vips_threadset_new( void )
{
	static GPrivate private = { 0 }; 

        VipsThreadset *set;

	is_worker_key = &private;

        set = g_new0( VipsThreadset, 1 );
	set->lock = vips_g_mutex_new();

        return( set );
}

/* Execute a task in a thread. If there are no idle threads, create a new one.
 */
int
vips_threadset_run( VipsThreadset *set, 
        const char *domain, GFunc func, gpointer data, gpointer user_data )
{
        VipsThreadsetMember *member;

        /* Try to get an idle thread.
         */
        member = NULL;
        g_mutex_lock( set->lock );
        if( set->free ) {
                member = (VipsThreadsetMember *) set->free->data;
                set->free = g_slist_remove( set->free, member );
        }
        g_mutex_unlock( set->lock );

        /* None? Make a new idle but not free member.
         */
        if( !member )
                member = vips_threadset_add( set );

        /* Still nothing? Thread create has failed.
         */
        if( !member )
                return( -1 );

        /* Allocate the task and set it going.
         */
        member->domain = domain;
        member->func = func;
        member->data = data;
        member->user_data = user_data;
        vips_semaphore_up( &member->idle );

        return( 0 );
}

/* Kill a member.
 */
static void
vips_threadset_kill_member( VipsThreadsetMember *member )
{
        VipsThreadset *set = member->set;

        member->kill = TRUE;
        vips_semaphore_up( &member->idle );
        g_thread_join( member->thread );

	vips_semaphore_destroy( &member->idle );

        g_mutex_lock( set->lock );
        set->free = g_slist_remove( set->free, member );
        vips_threadset_n_threads += 1;
        g_mutex_unlock( set->lock );

        VIPS_FREE( member );
}

/* Wait for all pending tasks to finish and clean up.
 */
void
vips_threadset_free( VipsThreadset *set )
{
        /* Try to get and finish a thread.
         */
        for(;;) {
                VipsThreadsetMember *member;

                member = NULL;
                g_mutex_lock( set->lock );
                if( set->members ) {
                        member = (VipsThreadsetMember *) set->members->data;
                        set->members = g_slist_remove( set->members, member );
                }
                g_mutex_unlock( set->lock );

                if( !member )
                        break;

                vips_threadset_kill_member( member );
        }

	VIPS_FREEF( vips_g_mutex_free, set->lock );
	VIPS_FREE( set );
}
