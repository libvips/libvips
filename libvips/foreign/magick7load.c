/* load with libMagick7
 *
 * 8/7/16
 * 	- from magickload
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#ifdef HAVE_MAGICK7

typedef struct _VipsForeignLoadMagick7 {
	VipsForeignLoad parent_object;

	gboolean all_frames;		/* Load all frames */
	char *density;			/* Load at this resolution */
	int page;			/* Load this page (frame) */

} VipsForeignLoadMagick7;

typedef VipsForeignLoadClass VipsForeignLoadMagick7Class;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadMagick7, vips_foreign_load_magick7, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_magick7_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_magick7_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static void
vips_foreign_load_magick7_class_init( VipsForeignLoadMagick7Class *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload_base";
	object_class->description = _( "load with ImageMagick7" );

	/* We need to be well to the back of the queue since vips's
	 * dedicated loaders are usually preferable.
	 */
	foreign_class->priority = -100;

	load_class->get_flags_filename = 
		vips_foreign_load_magick7_get_flags_filename;
	load_class->get_flags = vips_foreign_load_magick7_get_flags;

	VIPS_ARG_BOOL( class, "all_frames", 3, 
		_( "all_frames" ), 
		_( "Read all frames from an image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick7, all_frames ),
		FALSE );

	VIPS_ARG_STRING( class, "density", 4,
		_( "Density" ),
		_( "Canvas resolution for rendering vector formats like SVG" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick7, density ),
		NULL );

	VIPS_ARG_INT( class, "page", 5,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick7, page ),
		0, 100000, 0 );
}

static void
vips_foreign_load_magick7_init( VipsForeignLoadMagick7 *magick7 )
{
}

typedef struct _VipsForeignLoadMagick7File {
	VipsForeignLoadMagick7 parent_object;

	char *filename; 

} VipsForeignLoadMagick7File;

typedef VipsForeignLoadMagick7Class VipsForeignLoadMagick7FileClass;

G_DEFINE_TYPE( VipsForeignLoadMagick7File, vips_foreign_load_magick7_file, 
	vips_foreign_load_magick7_get_type() );

static gboolean
ismagick7( const char *filename )
{
	VipsImage *t;
	int result;

	t = vips_image_new();
	vips_error_freeze();
	result = vips__magick7_read_header( filename, t, FALSE, NULL, 0 );
	g_object_unref( t );
	vips_error_thaw();

	return( result == 0 );
}

/* Unfortunately, libMagick7 does not support header-only reads very well. See
 *
 * http://www.imagemagick7.org/discourse-server/viewtopic.php?f=1&t=20017
 *
 * Test especially with BMP, GIF, TGA. So we are forced to read the entire 
 * image in the @header() method.
 */
static int
vips_foreign_load_magick7_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadMagick7 *magick7 = (VipsForeignLoadMagick7 *) load;
	VipsForeignLoadMagick7File *magick7_file = 
		(VipsForeignLoadMagick7File *) load;

	if( vips__magick7_read( magick7_file->filename, 
		load->out, magick7->all_frames, magick7->density, magick7->page ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, magick7_file->filename );

	return( 0 );
}

static void
vips_foreign_load_magick7_file_class_init( 
	VipsForeignLoadMagick7FileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload";
	object_class->description = _( "load file with ImageMagick7" );

	load_class->is_a = ismagick7;
	load_class->header = vips_foreign_load_magick7_file_header;
	load_class->load = NULL;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadMagick7File, filename ),
		NULL );

}

static void
vips_foreign_load_magick7_file_init( VipsForeignLoadMagick7File *magick7_file )
{
}

typedef struct _VipsForeignLoadMagick7Buffer {
	VipsForeignLoadMagick7 parent_object;

	VipsArea *buf;

} VipsForeignLoadMagick7Buffer;

typedef VipsForeignLoadMagick7Class VipsForeignLoadMagick7BufferClass;

G_DEFINE_TYPE( VipsForeignLoadMagick7Buffer, vips_foreign_load_magick7_buffer, 
	vips_foreign_load_magick7_get_type() );

static gboolean
vips_foreign_load_magick7_buffer_is_a_buffer( const void *buf, size_t len )
{
	VipsImage *t;
	int result;

	t = vips_image_new();
	vips_error_freeze();
	result = vips__magick7_read_buffer_header( buf, len, t, FALSE, NULL, 0 );
	g_object_unref( t );
	vips_error_thaw();

	return( result == 0 );
}

/* Unfortunately, libMagick7 does not support header-only reads very well. See
 *
 * http://www.imagemagick7.org/discourse-server/viewtopic.php?f=1&t=20017
 *
 * Test especially with BMP, GIF, TGA. So we are forced to read the entire 
 * image in the @header() method.
 */
static int
vips_foreign_load_magick7_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadMagick7 *magick7 = (VipsForeignLoadMagick7 *) load;
	VipsForeignLoadMagick7Buffer *magick7_buffer = 
		(VipsForeignLoadMagick7Buffer *) load;

	if( vips__magick7_read_buffer( 
		magick7_buffer->buf->data, magick7_buffer->buf->length, 
		load->out, magick7->all_frames, magick7->density, magick7->page ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_magick7_buffer_class_init( 
	VipsForeignLoadMagick7BufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload_buffer";
	object_class->description = _( "load buffer with ImageMagick7" );

	load_class->is_a_buffer = vips_foreign_load_magick7_buffer_is_a_buffer;
	load_class->header = vips_foreign_load_magick7_buffer_header;
	load_class->load = NULL;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadMagick7Buffer, buf ),
		VIPS_TYPE_BLOB );

}

static void
vips_foreign_load_magick7_buffer_init( VipsForeignLoadMagick7Buffer *buffer )
{
}

#endif /*HAVE_MAGICK7*/
