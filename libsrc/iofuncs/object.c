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
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Our signals. 
 */
enum {
	SIG_CHANGED,	/* VipsObject has changed somehow */
	SIG_LAST
};

static guint vips_object_signals[SIG_LAST] = { 0 };

G_DEFINE_ABSTRACT_TYPE( VipsObject, vips_object, G_TYPE_OBJECT );

void *
vips_object_changed( VipsObject *object )
{
	g_return_val_if_fail( object != NULL, NULL );
	g_return_val_if_fail( VIPS_IS_OBJECT( object ), NULL );

#ifdef DEBUG
	printf( "vips_object_changed: " );
	vips_object_print( object );
#endif /*DEBUG*/

	g_signal_emit( G_OBJECT( object ), 
		vips_object_signals[SIG_CHANGED], 0 );

	return( NULL );
}

void
vips_object_print_class( VipsObjectClass *class )
{
	im_buf_t buf;
	char str[1000];

	im_buf_init_static( &buf, str, 1000 );
	class->print_class( class, &buf );
	printf( "%s\n", im_buf_all( &buf ) );
}

void
vips_object_print( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	im_buf_t buf;
	char str[1000];

	vips_object_print_class( class );
	im_buf_init_static( &buf, str, 1000 );
	class->print( object, &buf );
	printf( "\n%s (%p)\n", im_buf_all( &buf ), object );
}

static void
vips_object_dispose( GObject *gobject )
{
#ifdef DEBUG
	VipsObject *object = VIPS_OBJECT( gobject );

	printf( "vips_object_dispose: " );
	vips_object_print( object );
#endif /*DEBUG*/

	G_OBJECT_CLASS( vips_object_parent_class )->dispose( gobject );
}

static void
vips_object_finalize( GObject *gobject )
{
	VipsObject *object = VIPS_OBJECT( gobject );

#ifdef DEBUG
	printf( "vips_object_finalize: " );
	vips_object_print( object );
#endif /*DEBUG*/

	IM_FREE( object->name );

	G_OBJECT_CLASS( vips_object_parent_class )->finalize( gobject );
}

static void
vips_object_real_changed( VipsObject *object )
{
#ifdef DEBUG
	VipsObject *object = VIPS_OBJECT( gobject );

	printf( "vips_object_real_changed: " );
	vips_object_print( object );
#endif /*DEBUG*/
}

static void
vips_object_real_print_class( VipsObjectClass *class, im_buf_t *buf )
{
	im_buf_appendf( buf, "%s", G_OBJECT_CLASS_NAME( class ) );
	if( class->nickname )
		im_buf_appendf( buf, " (%s)", class->nickname );
	if( class->description )
		im_buf_appendf( buf, ", %s", class->description );
}

static void
vips_object_real_print( VipsObject *object, im_buf_t *buf )
{
	if( object->name )
		im_buf_appendf( buf, "\"%s\"", object->name );
}

static void
vips_object_class_init( VipsObjectClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );

	gobject_class->dispose = vips_object_dispose;
	gobject_class->finalize = vips_object_finalize;

	class->changed = vips_object_real_changed;
	class->print_class = vips_object_real_print_class;
	class->print = vips_object_real_print;
	class->nickname = "object";
	class->description = _( "VIPS base class" );

	vips_object_signals[SIG_CHANGED] = g_signal_new( "changed",
		G_OBJECT_CLASS_TYPE( gobject_class ),
		G_SIGNAL_RUN_FIRST,
		G_STRUCT_OFFSET( VipsObjectClass, changed ),
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );
}

static void
vips_object_init( VipsObject *object )
{
#ifdef DEBUG
	printf( "vips_object_init: " );
	vips_object_print( object );
#endif /*DEBUG*/
}

void
vips_object_set_name( VipsObject *object, const char *name )
{
	IM_SETSTR( object->name, name );
	vips_object_changed( object );
}

