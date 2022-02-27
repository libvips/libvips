/* gate.c --- thread profiling
 *
 * Written on: 18 nov 13
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

/* Very verbose.
#define VIPS_DEBUG_RED
 */

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#define VIPS_GATE_SIZE (1000)

/* A set of timing records. i is the index of the next slot we fill. 
 */
typedef struct _VipsThreadGateBlock {
	struct _VipsThreadGateBlock *prev;

	gint64 time[VIPS_GATE_SIZE];
	int i;
} VipsThreadGateBlock; 

/* What we track for each gate-name.
 */
typedef struct _VipsThreadGate {
	const char *name;
	VipsThreadGateBlock *start;
	VipsThreadGateBlock *stop;
} VipsThreadGate; 

/* One of these in per-thread private storage. 
 */

typedef struct _VipsThreadProfile {
	/*< private >*/

	const char *name;
	GThread *thread;
	GHashTable *gates;
	VipsThreadGate *memory;
} VipsThreadProfile; 

gboolean vips__thread_profile = FALSE;

static GPrivate *vips_thread_profile_key = NULL;

static FILE *vips__thread_fp = NULL;;

/**
 * vips_profile_set:
 * @profile: %TRUE to enable profile recording
 *
 * If set, vips will record profiling information, and dump it on program
 * exit. These profiles can be analysed with the `vipsprofile` program. 
 */
void
vips_profile_set( gboolean profile )
{
	vips__thread_profile = profile;
}

static void
vips_thread_gate_block_save( VipsThreadGateBlock *block, FILE *fp )
{
	int i;

	for( i = block->i - 1; i >= 0; i-- )
		fprintf( fp, "%" G_GINT64_FORMAT " ", block->time[i] );
	fprintf( fp, "\n" ); 
	if( block->prev )
		vips_thread_gate_block_save( block->prev, fp ); 
}

static void
vips_thread_profile_save_gate( VipsThreadGate *gate, FILE *fp )
{
	if( gate->start->i || 
		gate->start->prev ) { 
		fprintf( fp, "gate: %s\n", gate->name );
		fprintf( fp, "start:\n" );
		vips_thread_gate_block_save( gate->start, fp );
		fprintf( fp, "stop:\n" );
		vips_thread_gate_block_save( gate->stop, fp );
	}
}

static void
vips_thread_profile_save_cb( gpointer key, gpointer value, gpointer data )
{
	VipsThreadGate *gate = (VipsThreadGate *) value;
	FILE *fp = (FILE *) data;

	vips_thread_profile_save_gate( gate, fp ); 
}

static void
vips_thread_profile_save( VipsThreadProfile *profile )
{
	g_mutex_lock( vips__global_lock );

	VIPS_DEBUG_MSG( "vips_thread_profile_save: %s\n", profile->name ); 

	if( !vips__thread_fp ) { 
		vips__thread_fp = 
			vips__file_open_write( "vips-profile.txt", TRUE );
		if( !vips__thread_fp ) {
			g_mutex_unlock( vips__global_lock );
			g_warning( "unable to create profile log" ); 
			return;
		}

		printf( "recording profile in vips-profile.txt\n" );  
	}

	fprintf( vips__thread_fp, "thread: %s (%p)\n", profile->name, profile );
	g_hash_table_foreach( profile->gates, 
		vips_thread_profile_save_cb, vips__thread_fp );
	vips_thread_profile_save_gate( profile->memory, vips__thread_fp ); 

	g_mutex_unlock( vips__global_lock );
}

static void
vips_thread_gate_block_free( VipsThreadGateBlock *block )
{
	VIPS_FREEF( vips_thread_gate_block_free, block->prev );
	VIPS_FREE( block );
}

static void
vips_thread_gate_free( VipsThreadGate *gate )
{
	VIPS_FREEF( vips_thread_gate_block_free, gate->start );
	VIPS_FREEF( vips_thread_gate_block_free, gate->stop );
	VIPS_FREE( gate ); 
}

static void
vips_thread_profile_free( VipsThreadProfile *profile )
{
	VIPS_DEBUG_MSG( "vips_thread_profile_free: %s\n", profile->name ); 

	VIPS_FREEF( g_hash_table_destroy, profile->gates );
	VIPS_FREEF( vips_thread_gate_free, profile->memory );
	VIPS_FREE( profile );
}

void
vips__thread_profile_stop( void )
{
	if( vips__thread_profile ) 
		VIPS_FREEF( fclose, vips__thread_fp ); 
}

static void
vips__thread_profile_init_cb( VipsThreadProfile *profile )
{
	/* We only come here if vips_thread_shutdown() was not called for this
	 * thread. Do our best to clean up.
	 *
	 * GPrivate has stopped working, be careful not to touch that. 
	 *
	 * Don't try to save: we must free all mem before saving and we
	 * probably haven't done that because vips_thread_shutdown() has not
	 * been called. 
	 */
	if( vips__thread_profile ) 
		g_warning( "discarding unsaved state for thread %p --- "
			"call vips_thread_shutdown() for this thread",
			profile->thread ); 

	vips_thread_profile_free( profile );
}

static void *
vips__thread_profile_init( void *data )
{
	static GPrivate private = 
		G_PRIVATE_INIT( (GDestroyNotify) vips__thread_profile_init_cb );

	vips_thread_profile_key = &private;

	return( NULL );
}

static VipsThreadGate *
vips_thread_gate_new( const char *gate_name ) 
{
	VipsThreadGate *gate;

	gate = g_new( VipsThreadGate, 1 );
	gate->name = gate_name; 
	gate->start = g_new0( VipsThreadGateBlock, 1 );
	gate->stop = g_new0( VipsThreadGateBlock, 1 );

	return( gate );
}

void
vips__thread_profile_attach( const char *thread_name )
{
	static GOnce once = G_ONCE_INIT;

	VipsThreadProfile *profile;

	VIPS_ONCE( &once, vips__thread_profile_init, NULL );

	VIPS_DEBUG_MSG( "vips__thread_profile_attach: %s\n", thread_name ); 

	profile = g_new( VipsThreadProfile, 1 );
	profile->name = thread_name; 
	profile->gates = g_hash_table_new_full( 
		g_direct_hash, g_str_equal, 
		NULL, (GDestroyNotify) vips_thread_gate_free );
	profile->memory = vips_thread_gate_new( "memory" ); 
	g_private_replace( vips_thread_profile_key, profile );
}

static VipsThreadProfile *
vips_thread_profile_get( void )
{
	return( g_private_get( vips_thread_profile_key ) ); 
}

/* This usually happens automatically when a thread shuts down, see 
 * vips__thread_profile_init() where we set a GDestroyNotify, but will not
 * happen for the main thread. 
 *
 * Shut down any stats on the main thread with this, see vips_shutdown()
 */
void
vips__thread_profile_detach( void ) 
{
	VipsThreadProfile *profile;

	VIPS_DEBUG_MSG( "vips__thread_profile_detach:\n" ); 

	if( (profile = vips_thread_profile_get()) ) {
		if( vips__thread_profile ) 
			vips_thread_profile_save( profile ); 

		vips_thread_profile_free( profile );
		g_private_set( vips_thread_profile_key, NULL );
	}
}

static void
vips_thread_gate_block_add( VipsThreadGateBlock **block )
{
	VipsThreadGateBlock *new_block;

	new_block = g_new0( VipsThreadGateBlock, 1 );
	new_block->prev = *block;
	*block = new_block;
}

void
vips__thread_gate_start( const char *gate_name )
{
	VipsThreadProfile *profile;

	VIPS_DEBUG_MSG_RED( "vips__thread_gate_start: %s\n", gate_name ); 

	if( (profile = vips_thread_profile_get()) ) { 
		gint64 time = g_get_monotonic_time();

		VipsThreadGate *gate;

		if( !(gate = 
			g_hash_table_lookup( profile->gates, gate_name )) ) {
			gate = vips_thread_gate_new( gate_name );
			g_hash_table_insert( profile->gates, 
				(char *) gate_name, gate );
		}

		if( gate->start->i >= VIPS_GATE_SIZE )
			vips_thread_gate_block_add( &gate->start );

		gate->start->time[gate->start->i++] = time;

		VIPS_DEBUG_MSG_RED( "\t %" G_GINT64_FORMAT "\n", time ); 
	}
}

void
vips__thread_gate_stop( const char *gate_name )
{
	VipsThreadProfile *profile;

	VIPS_DEBUG_MSG_RED( "vips__thread_gate_stop: %s\n", gate_name ); 

	if( (profile = vips_thread_profile_get()) ) { 
		gint64 time = g_get_monotonic_time();

		VipsThreadGate *gate;

		if( !(gate = 
			g_hash_table_lookup( profile->gates, gate_name )) ) {
			gate = vips_thread_gate_new( gate_name );
			g_hash_table_insert( profile->gates, 
				(char *) gate_name, gate );
		}

		if( gate->stop->i >= VIPS_GATE_SIZE )
			vips_thread_gate_block_add( &gate->stop );

		gate->stop->time[gate->stop->i++] = time;

		VIPS_DEBUG_MSG_RED( "\t %" G_GINT64_FORMAT "\n", time ); 
	}
}

/* Record a malloc() or free(). Use -ve numbers for free.
 */
void
vips__thread_malloc_free( gint64 size )
{
	VipsThreadProfile *profile;

	VIPS_DEBUG_MSG_RED( "vips__thread_malloc_free: %zd\n", size ); 

#ifdef VIPS_DEBUG
	if( !(profile = vips_thread_profile_get()) ) 
		printf( "argh no block to record free() in!\n" ); 
#endif /*VIPS_DEBUG*/

	if( (profile = vips_thread_profile_get()) ) { 
		gint64 time = g_get_monotonic_time();
		VipsThreadGate *gate = profile->memory;

		if( gate->start->i >= VIPS_GATE_SIZE ) {
			vips_thread_gate_block_add( &gate->start );
			vips_thread_gate_block_add( &gate->stop );
		}

		gate->start->time[gate->start->i++] = time;
		gate->stop->time[gate->stop->i++] = size;
	}
}
