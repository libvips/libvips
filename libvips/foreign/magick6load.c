/* load with libMagick
 *
 * 5/12/11
 * 	- from openslideload.c
 * 17/1/12
 * 	- remove header-only loads
 * 11/6/13
 * 	- add @all_frames option, off by default
 * 14/2/16
 * 	- add @page option, 0 by default
 * 25/11/16
 * 	- add @n, deprecate @all_frames (just sets n = -1)
 * 8/9/17
 * 	- don't cache magickload
 * 21/4/21 kleisauke
 * 	- include GObject part from magickload.c
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#ifdef ENABLE_MAGICKLOAD

#ifdef HAVE_MAGICK6

#include "pforeign.h"
#include "magick.h"

typedef struct _VipsForeignLoadMagick {
	VipsForeignLoad parent_object;

	/* Deprecated. Just sets n = -1.
	 */
	gboolean all_frames;

	char *density;			/* Load at this resolution */
	int page;			/* Load this page (frame) */
	int n;				/* Load this many pages */

} VipsForeignLoadMagick;

typedef VipsForeignLoadClass VipsForeignLoadMagickClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadMagick, vips_foreign_load_magick, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_magick_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_magick_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static void
vips_foreign_load_magick_class_init( VipsForeignLoadMagickClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload_base";
	object_class->description = _( "load with ImageMagick" );

	/* Don't cache magickload: it can gobble up memory and disc. 
	 */
	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	/* *magick is fuzzed, but it's such a huge thing it's safer to
	 * disable it.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	/* We need to be well to the back of the queue since vips's
	 * dedicated loaders are usually preferable.
	 */
	foreign_class->priority = -100;

	load_class->get_flags_filename = 
		vips_foreign_load_magick_get_flags_filename;
	load_class->get_flags = vips_foreign_load_magick_get_flags;

	VIPS_ARG_STRING( class, "density", 21,
		_( "Density" ),
		_( "Canvas resolution for rendering vector formats like SVG" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick, density ),
		NULL );

	VIPS_ARG_INT( class, "page", 22,
		_( "Page" ),
		_( "First page to load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick, page ),
		0, 100000, 0 );

	VIPS_ARG_INT( class, "n", 23,
		_( "n" ),
		_( "Number of pages to load, -1 for all" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick, n ),
		-1, 100000, 1 );

	VIPS_ARG_BOOL( class, "all_frames", 20, 
		_( "All frames" ), 
		_( "Read all frames from an image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignLoadMagick, all_frames ),
		FALSE );

}

static void
vips_foreign_load_magick_init( VipsForeignLoadMagick *magick )
{
	magick->n = 1;
}

typedef struct _VipsForeignLoadMagickFile {
	VipsForeignLoadMagick parent_object;

	char *filename; 

} VipsForeignLoadMagickFile;

typedef VipsForeignLoadMagickClass VipsForeignLoadMagickFileClass;

G_DEFINE_TYPE( VipsForeignLoadMagickFile, vips_foreign_load_magick_file, 
	vips_foreign_load_magick_get_type() );

static gboolean
ismagick( const char *filename )
{
	/* Fetch up to the first 100 bytes. Hopefully that'll be enough.
	 */
	unsigned char buf[100];
	int len;

	return( (len = vips__get_bytes( filename, buf, 100 )) > 10 &&
		magick_ismagick( buf, len ) );
}

/* Unfortunately, libMagick does not support header-only reads very well. See
 *
 * http://www.imagemagick.org/discourse-server/viewtopic.php?f=1&t=20017
 *
 * Test especially with BMP, GIF, TGA. So we are forced to read the entire 
 * image in the @header() method.
 */
static int
vips_foreign_load_magick_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadMagick *magick = (VipsForeignLoadMagick *) load;
	VipsForeignLoadMagickFile *magick_file = 
		(VipsForeignLoadMagickFile *) load;

	if( magick->all_frames )
		magick->n = -1;

	if( vips__magick_read( magick_file->filename, 
		load->out, magick->density, 
		magick->page, magick->n ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, magick_file->filename );

	return( 0 );
}

static void
vips_foreign_load_magick_file_class_init( 
	VipsForeignLoadMagickFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload";
	object_class->description = _( "load file with ImageMagick" );

	load_class->is_a = ismagick;
	load_class->header = vips_foreign_load_magick_file_header;
	load_class->load = NULL;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadMagickFile, filename ),
		NULL );

}

static void
vips_foreign_load_magick_file_init( VipsForeignLoadMagickFile *magick_file )
{
}

typedef struct _VipsForeignLoadMagickBuffer {
	VipsForeignLoadMagick parent_object;

	VipsArea *buf;

} VipsForeignLoadMagickBuffer;

typedef VipsForeignLoadMagickClass VipsForeignLoadMagickBufferClass;

G_DEFINE_TYPE( VipsForeignLoadMagickBuffer, vips_foreign_load_magick_buffer, 
	vips_foreign_load_magick_get_type() );

static gboolean
vips_foreign_load_magick_buffer_is_a_buffer( const void *buf, size_t len )
{
	return( len > 10 && magick_ismagick( (const unsigned char *) buf, len ) );
}

/* Unfortunately, libMagick does not support header-only reads very well. See
 *
 * http://www.imagemagick.org/discourse-server/viewtopic.php?f=1&t=20017
 *
 * Test especially with BMP, GIF, TGA. So we are forced to read the entire 
 * image in the @header() method.
 */
static int
vips_foreign_load_magick_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadMagick *magick = (VipsForeignLoadMagick *) load;
	VipsForeignLoadMagickBuffer *magick_buffer = 
		(VipsForeignLoadMagickBuffer *) load;

	if( magick->all_frames )
		magick->n = -1;

	if( vips__magick_read_buffer( 
		magick_buffer->buf->data, magick_buffer->buf->length, 
		load->out, magick->density, magick->page, 
		magick->n ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_magick_buffer_class_init( 
	VipsForeignLoadMagickBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload_buffer";
	object_class->description = _( "load buffer with ImageMagick" );

	load_class->is_a_buffer = vips_foreign_load_magick_buffer_is_a_buffer;
	load_class->header = vips_foreign_load_magick_buffer_header;
	load_class->load = NULL;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadMagickBuffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_magick_buffer_init( VipsForeignLoadMagickBuffer *buffer )
{
}

#endif /*HAVE_MAGICK6*/

#endif /*ENABLE_MAGICKLOAD*/
