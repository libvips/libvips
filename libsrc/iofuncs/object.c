/* abstract base class for all vips objects
 *
 * Edited from nip's base class, 15/10/08
 */

/*

    Copyright (C) 1991-2003 The National Gallery

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Our signals. 
 */
enum {
	SIG_DESTROY,	/* End lifetime */
	SIG_CHANGED,	/* VipsObject has changed somehow */
	SIG_LAST
};

static GObjectClass *parent_class = NULL;

static guint vips_object_signals[SIG_LAST] = { 0 };

/* Don't emit "destroy" immediately, do it from the _dispose handler.
 */
void *
vips_object_destroy( VipsObject *vips_object )
{
#ifdef DEBUG
	printf( "vips_object_destroy: " );
	vips_object_print( vips_object );
#endif /*DEBUG*/

	if( !vips_object->in_destruction )
		g_object_run_dispose( G_OBJECT( vips_object ) );

	return( NULL );
}

void *
vips_object_changed( VipsObject *vips_object )
{
	g_return_val_if_fail( vips_object != NULL, NULL );
	g_return_val_if_fail( VIPS_IS_OBJECT( vips_object ), NULL );

#ifdef DEBUG
	printf( "vips_object_changed: " );
	vips_object_print( vips_object );
#endif /*DEBUG*/

	g_signal_emit( G_OBJECT( vips_object ), 
		vips_object_signals[SIG_CHANGED], 0 );

	return( NULL );
}

static void
vips_object_dispose( GObject *gobject )
{
	VipsObject *vips_object = VIPS_OBJECT( gobject );

#ifdef DEBUG
	printf( "vips_object_dispose: " );
	vips_object_print( vips_object );
#endif /*DEBUG*/

	if( !vips_object->in_destruction ) {
		vips_object->in_destruction = TRUE;
		g_signal_emit( G_OBJECT( vips_object ), 
			vips_object_signals[SIG_DESTROY], 0 );
		vips_object->in_destruction = FALSE;
	}

	G_OBJECT_CLASS( parent_class )->dispose( gobject );
}

static void
vips_object_finalize( GObject *gobject )
{
#ifdef DEBUG
	VipsObject *vips_object = VIPS_OBJECT( gobject );

	printf( "vips_object_finalize: " );
	vips_object_print( vips_object );
#endif /*DEBUG*/

	/* Unlike GTK, we allow floating objects to be finalized. Handy if a
	 * _new() fails. So don't assert( !vips_object->floating );
	 */

	G_OBJECT_CLASS( parent_class )->finalize( gobject );
}

static void
vips_object_real_destroy( VipsObject *vips_object )
{
}

static void
vips_object_real_changed( VipsObject *vips_object )
{
}

static void
vips_object_class_init( VipsObjectClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );

	parent_class = g_type_class_peek_parent( class );

	gobject_class->dispose = vips_object_dispose;
	gobject_class->finalize = vips_object_finalize;

	class->destroy = vips_object_real_destroy;
	class->changed = vips_object_real_changed;

	vips_object_signals[SIG_DESTROY] = g_signal_new( "destroy",
		G_TYPE_FROM_CLASS( gobject_class ),
		G_SIGNAL_RUN_CLEANUP | G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
		G_STRUCT_OFFSET( VipsObjectClass, destroy ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
	vips_object_signals[SIG_CHANGED] = g_signal_new( "changed",
		G_OBJECT_CLASS_TYPE( gobject_class ),
		G_SIGNAL_RUN_FIRST,
		G_STRUCT_OFFSET( VipsObjectClass, changed ),
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
}

static void
vips_object_init( VipsObject *vips_object )
{
#ifdef DEBUG
	printf( "vips_object_init: " );
	vips_object_print( vips_object );
#endif /*DEBUG*/

	vips_object->floating = TRUE;
	vips_object->in_destruction = FALSE;
}

GType
vips_object_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		static const GTypeInfo info = {
			sizeof( VipsObjectClass ),
			NULL,           /* base_init */
			NULL,           /* base_finalize */
			(GClassInitFunc) vips_object_class_init,
			NULL,           /* class_finalize */
			NULL,           /* class_data */
			sizeof( VipsObject ),
			32,             /* n_preallocs */
			(GInstanceInitFunc) vips_object_init,
		};

		type = g_type_register_static( G_TYPE_OBJECT, 
			"VipsObject", &info, 0 );
	}

	return( type );
}

void
vips_object_sink( VipsObject *vips_object )
{
	g_assert( VIPS_IS_OBJECT( vips_object ) ); 

	if( vips_object->floating ) {
		vips_object->floating = FALSE;
		g_object_unref( G_OBJECT( vips_object ) );
	}
}
