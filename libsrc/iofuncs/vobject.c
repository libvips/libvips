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
	SIG_CHANGED,	/* VObject has changed somehow */
	SIG_LAST
};

static GObjectClass *parent_class = NULL;

static guint vobject_signals[SIG_LAST] = { 0 };

/* Don't emit "destroy" immediately, do it from the _dispose handler.
 */
void *
vobject_destroy( VObject *vobject )
{
#ifdef DEBUG
	printf( "vobject_destroy: " );
	vobject_print( vobject );
#endif /*DEBUG*/

	if( !vobject->in_destruction )
		g_object_run_dispose( G_OBJECT( vobject ) );

	return( NULL );
}

void *
vobject_changed( VObject *vobject )
{
	g_return_val_if_fail( vobject != NULL, NULL );
	g_return_val_if_fail( IS_VOBJECT( vobject ), NULL );

#ifdef DEBUG
	printf( "vobject_changed: " );
	vobject_print( vobject );
#endif /*DEBUG*/

	g_signal_emit( G_OBJECT( vobject ), vobject_signals[SIG_CHANGED], 0 );

	return( NULL );
}

static void
vobject_dispose( GObject *gobject )
{
	VObject *vobject = VOBJECT( gobject );

#ifdef DEBUG
	printf( "vobject_dispose: " );
	vobject_print( vobject );
#endif /*DEBUG*/

	if( !vobject->in_destruction ) {
		vobject->in_destruction = TRUE;
		g_signal_emit( G_OBJECT( vobject ), 
			vobject_signals[SIG_DESTROY], 0 );
		vobject->in_destruction = FALSE;
	}

	G_OBJECT_CLASS( parent_class )->dispose( gobject );
}

static void
vobject_finalize( GObject *gobject )
{
#ifdef DEBUG
	VObject *vobject = VOBJECT( gobject );

	printf( "vobject_finalize: " );
	vobject_print( vobject );
#endif /*DEBUG*/

	/* Unlike GTK, we allow floating objects to be finalized. Handy if a
	 * _new() fails. So don't assert( !vobject->floating );
	 */

	G_OBJECT_CLASS( parent_class )->finalize( gobject );
}

static void
vobject_real_destroy( VObject *vobject )
{
}

static void
vobject_real_changed( VObject *vobject )
{
}

static void
vobject_class_init( VObjectClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );

	parent_class = g_type_class_peek_parent( class );

	gobject_class->dispose = vobject_dispose;
	gobject_class->finalize = vobject_finalize;

	class->destroy = vobject_real_destroy;
	class->changed = vobject_real_changed;

	vobject_signals[SIG_DESTROY] = g_signal_new( "destroy",
		G_TYPE_FROM_CLASS( gobject_class ),
		G_SIGNAL_RUN_CLEANUP | G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
		G_STRUCT_OFFSET( VObjectClass, destroy ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
	vobject_signals[SIG_CHANGED] = g_signal_new( "changed",
		G_OBJECT_CLASS_TYPE( gobject_class ),
		G_SIGNAL_RUN_FIRST,
		G_STRUCT_OFFSET( VObjectClass, changed ),
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
}

static void
vobject_init( VObject *vobject )
{
#ifdef DEBUG
	printf( "vobject_init: " );
	vobject_print( vobject );
#endif /*DEBUG*/

	vobject->floating = TRUE;
	vobject->in_destruction = FALSE;
}

GType
vobject_get_type( void )
{
	static GType vobject_type = 0;

	if( !vobject_type ) {
		static const GTypeInfo info = {
			sizeof( VObjectClass ),
			NULL,           /* base_init */
			NULL,           /* base_finalize */
			(GClassInitFunc) vobject_class_init,
			NULL,           /* class_finalize */
			NULL,           /* class_data */
			sizeof( VObject ),
			32,             /* n_preallocs */
			(GInstanceInitFunc) vobject_init,
		};

		vobject_type = g_type_register_static( G_TYPE_OBJECT, 
			"VObject", &info, 0 );
	}

	return( vobject_type );
}

void
vobject_sink( VObject *vobject )
{
	g_assert( IS_VOBJECT( vobject ) ); 

	if( vobject->floating ) {
		vobject->floating = FALSE;
		g_object_unref( G_OBJECT( vobject ) );
	}
}
