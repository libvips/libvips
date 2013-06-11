/* load with libMagick
 *
 * 5/12/11
 * 	- from openslideload.c
 * 17/1/12
 * 	- remove header-only loads
 * 11/6/13
 * 	- add @all_frames option, off by default
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_MAGICK

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "magick.h"

typedef struct _VipsForeignLoadMagick {
	VipsForeignLoad parent_object;

	char *filename; 
	gboolean all_frames;

} VipsForeignLoadMagick;

typedef VipsForeignLoadClass VipsForeignLoadMagickClass;

G_DEFINE_TYPE( VipsForeignLoadMagick, vips_foreign_load_magick, 
	VIPS_TYPE_FOREIGN_LOAD );

static gboolean
ismagick( const char *filename )
{
	VipsImage *t;

	t = vips_image_new();
	if( vips__magick_read_header( filename, t, FALSE ) ) {
		g_object_unref( t );
		return( FALSE );
	}
	g_object_unref( t );

	return( TRUE );
}

static VipsForeignFlags
vips_foreign_load_magick_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_magick_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadMagick *magick = (VipsForeignLoadMagick *) load;

	return( vips_foreign_load_magick_get_flags_filename( 
		magick->filename ) );
}

/*
 * Unfortunately, libMagick does not support header-only reads very well. See
 *
 * http://www.imagemagick.org/discourse-server/viewtopic.php?f=1&t=20017
 *
 * Test especially with BMP, GIF, TGA. So we are forced to read the entire 
 * image in the @header() method.
 */
static int
vips_foreign_load_magick_header( VipsForeignLoad *load )
{
	VipsForeignLoadMagick *magick = (VipsForeignLoadMagick *) load;

	if( vips__magick_read( magick->filename, 
		load->out, magick->all_frames ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_magick_class_init( VipsForeignLoadMagickClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload";
	object_class->description = _( "load file with ImageMagick" );

	/* We need to be well to the back of the queue since the vips's
	 * dedicated loaders are usually preferable.
	 */
	foreign_class->priority = -100;

	load_class->is_a = ismagick;
	load_class->get_flags_filename = 
		vips_foreign_load_magick_get_flags_filename;
	load_class->get_flags = vips_foreign_load_magick_get_flags;
	load_class->header = vips_foreign_load_magick_header;
	load_class->load = NULL;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadMagick, filename ),
		NULL );

	VIPS_ARG_BOOL( class, "all_frames", 3, 
		_( "all_frames" ), 
		_( "Read all frames from an image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick, all_frames ),
		FALSE );
}

static void
vips_foreign_load_magick_init( VipsForeignLoadMagick *magick )
{
}

#endif /*HAVE_MAGICK*/
