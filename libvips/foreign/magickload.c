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

#ifdef HAVE_MAGICK

#include "pforeign.h"

typedef struct _VipsForeignLoadMagick {
	VipsForeignLoad parent_object;

	gboolean all_frames;		/* Load all frames */
	char *density;			/* Load at this resolution */
	int page;			/* Load this page (frame) */

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
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magickload_base";
	object_class->description = _( "load with ImageMagick" );

	/* We need to be well to the back of the queue since vips's
	 * dedicated loaders are usually preferable.
	 */
	foreign_class->priority = -100;

	load_class->get_flags_filename = 
		vips_foreign_load_magick_get_flags_filename;
	load_class->get_flags = vips_foreign_load_magick_get_flags;

	VIPS_ARG_BOOL( class, "all_frames", 3, 
		_( "all_frames" ), 
		_( "Read all frames from an image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick, all_frames ),
		FALSE );

	VIPS_ARG_STRING( class, "density", 4,
		_( "Density" ),
		_( "Canvas resolution for rendering vector formats like SVG" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick, density ),
		NULL );

	VIPS_ARG_INT( class, "page", 5,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMagick, page ),
		0, 100000, 0 );
}

static void
vips_foreign_load_magick_init( VipsForeignLoadMagick *magick )
{
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
	VipsImage *t;
	int result;

	t = vips_image_new();
	vips_error_freeze();
	result = vips__magick_read_header( filename, t, FALSE, NULL, 0 );
	g_object_unref( t );
	vips_error_thaw();

	return( result == 0 );
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

	if( vips__magick_read( magick_file->filename, 
		load->out, magick->all_frames, magick->density, magick->page ) )
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
	VipsImage *t;
	int result;

	t = vips_image_new();
	vips_error_freeze();
	result = vips__magick_read_buffer_header( buf, len, t, FALSE, NULL, 0 );
	g_object_unref( t );
	vips_error_thaw();

	return( result == 0 );
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

	if( vips__magick_read_buffer( 
		magick_buffer->buf->data, magick_buffer->buf->length, 
		load->out, magick->all_frames, magick->density, magick->page ) )
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

#endif /*HAVE_MAGICK*/

/**
 * vips_magickload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @all_frames: %gboolean, load all frames in sequence
 * * @density: string, canvas resolution for rendering vector formats like SVG
 *
 * Read in an image using libMagick, the ImageMagick library. This library can
 * read more than 80 file formats, including SVG, BMP, EPS, DICOM and many 
 * others.
 * The reader can handle any ImageMagick image, including the float and double
 * formats. It will work with any quantum size, including HDR. Any metadata
 * attached to the libMagick image is copied on to the VIPS image.
 *
 * The reader should also work with most versions of GraphicsMagick. See the
 * "--with-magickpackage" configure option.
 *
 * Normally it will only load the first image in a many-image sequence (such
 * as a GIF). Set @all_frames to true to read the whole image sequence. 
 *
 * @density is "WxH" in DPI, e.g. "600x300" or "600" (default is "72x72"). See
 * the [density 
 * docs](http://www.imagemagick.org/script/command-line-options.php#density) 
 * on the imagemagick website.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magickload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "magickload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_magickload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @all_frames: %gboolean, load all frames in sequence
 * * @density: string, canvas resolution for rendering vector formats like SVG
 *
 * Read an image memory block using libMagick into a VIPS image. Exactly as
 * vips_magickload(), but read from a memory source. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_magickload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_magickload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "magickload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}
