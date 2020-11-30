/* A Target subclass with signals you can easily hook up to other output
 * sources.
 * 
 * J.Cupitt, 21/11/19
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

/*
#define VIPS_DEBUG
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
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include "vipsmarshal.h"

G_DEFINE_TYPE( VipsTargetCustom, vips_target_custom, VIPS_TYPE_TARGET );

/* Our signals. 
 */
enum {
	SIG_WRITE,		
	SIG_FINISH,		
	SIG_LAST
};

static guint vips_target_custom_signals[SIG_LAST] = { 0 };

static gint64
vips_target_custom_write_real( VipsTarget *target, 
	const void *data, size_t length )
{
	gint64 bytes_written;

	VIPS_DEBUG_MSG( "vips_target_custom_write_real:\n" );

	/* Return value if no attached handler.
	 */
	bytes_written = 0;

	g_signal_emit( target, vips_target_custom_signals[SIG_WRITE], 0,
		data, (gint64) length, &bytes_written );

	VIPS_DEBUG_MSG( "  %zd\n", bytes_written );

	return( bytes_written );
}

static void
vips_target_custom_finish_real( VipsTarget *target )
{
	VIPS_DEBUG_MSG( "vips_target_custom_seek_real:\n" );

	g_signal_emit( target, vips_target_custom_signals[SIG_FINISH], 0 );
}

static gint64
vips_target_custom_write_signal_real( VipsTargetCustom *target_custom, 
	const void *data, gint64 length )
{
	VIPS_DEBUG_MSG( "vips_target_custom_write_signal_real:\n" );

	return( 0 );
}

static void
vips_target_custom_finish_signal_real( VipsTargetCustom *target_custom ) 
{
	VIPS_DEBUG_MSG( "vips_target_custom_finish_signal_real:\n" );
}

static void
vips_target_custom_class_init( VipsTargetCustomClass *class )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsTargetClass *target_class = VIPS_TARGET_CLASS( class );

	object_class->nickname = "target_custom";
	object_class->description = _( "Custom target" );

	target_class->write = vips_target_custom_write_real;
	target_class->finish = vips_target_custom_finish_real;

	class->write = vips_target_custom_write_signal_real;
	class->finish = vips_target_custom_finish_signal_real;

	/**
	 * VipsTargetCustom::write:
	 * @target_custom: the target being operated on
	 * @data: %pointer, bytes to write
	 * @length: %gint64, number of bytes
	 *
	 * This signal is emitted to write bytes to the target. 
	 *
	 * Returns: the number of bytes written.
	 */
	vips_target_custom_signals[SIG_WRITE] = g_signal_new( "write",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_ACTION,
		G_STRUCT_OFFSET( VipsTargetCustomClass, write ), 
		NULL, NULL,
		vips_INT64__POINTER_INT64,
		G_TYPE_INT64, 2,
		G_TYPE_POINTER, G_TYPE_INT64 );

	/**
	 * VipsTargetCustom::finish:
	 * @target_custom: the target being operated on
	 *
	 * This signal is emitted at the end of write. The target should do
	 * any finishing necessary.
	 */
	vips_target_custom_signals[SIG_FINISH] = g_signal_new( "finish",
		G_TYPE_FROM_CLASS( class ),
		G_SIGNAL_ACTION,
		G_STRUCT_OFFSET( VipsTargetCustomClass, finish ), 
		NULL, NULL,
		g_cclosure_marshal_VOID__VOID,
		G_TYPE_NONE, 0 );

}

static void
vips_target_custom_init( VipsTargetCustom *target_custom )
{
}

/**
 * vips_target_custom_new:
 *
 * Create a #VipsTargetCustom. Attach signals to implement write and finish.
 *
 * Returns: a new #VipsTargetCustom
 */
VipsTargetCustom *
vips_target_custom_new( void )
{
	VipsTargetCustom *target_custom;

	VIPS_DEBUG_MSG( "vips_target_custom_new:\n" );

	target_custom = VIPS_TARGET_CUSTOM( g_object_new( VIPS_TYPE_TARGET_CUSTOM, NULL ) );

	if( vips_object_build( VIPS_OBJECT( target_custom ) ) ) {
		VIPS_UNREF( target_custom );
		return( NULL );
	}

	return( target_custom ); 
}
