/* load tiff from a file
 *
 * 5/12/11
 * 	- from tiffload.c
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

#ifdef HAVE_TIFF

#include "tiff.h"

typedef struct _VipsForeignLoadTiff {
	VipsForeignLoad parent_object;

	/* Load this page. 
	 */
	int page;

	/* Autorotate using orientation tag.
	 */
	gboolean autorotate;

} VipsForeignLoadTiff;

typedef VipsForeignLoadClass VipsForeignLoadTiffClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadTiff, vips_foreign_load_tiff, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_tiff_class_init( VipsForeignLoadTiffClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	/* Other libraries may be using libtiff, we want to capture tiff
	 * warning and error as soon as we can.
	 *
	 * This class init will be triggered during startup.
	 */
	vips__tiff_init();

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "tiffload_base";
	object_class->description = _( "load tiff" );

	VIPS_ARG_INT( class, "page", 10, 
		_( "Page" ), 
		_( "Load this page from the image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadTiff, page ),
		0, 100000, 0 );

	VIPS_ARG_BOOL( class, "autorotate", 11, 
		_( "Autorotate" ), 
		_( "Rotate image using orientation tag" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadTiff, autorotate ),
		FALSE );
}

static void
vips_foreign_load_tiff_init( VipsForeignLoadTiff *tiff )
{
	tiff->page = 0; 
}

typedef struct _VipsForeignLoadTiffFile {
	VipsForeignLoadTiff parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadTiffFile;

typedef VipsForeignLoadTiffClass VipsForeignLoadTiffFileClass;

G_DEFINE_TYPE( VipsForeignLoadTiffFile, vips_foreign_load_tiff_file, 
	vips_foreign_load_tiff_get_type() );

static VipsForeignFlags
vips_foreign_load_tiff_file_get_flags_filename( const char *filename )
{
	VipsForeignFlags flags;

	flags = 0;
	if( vips__istifftiled( filename ) ) 
		flags |= VIPS_FOREIGN_PARTIAL;
	else
		flags |= VIPS_FOREIGN_SEQUENTIAL;

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_tiff_file_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadTiffFile *file = (VipsForeignLoadTiffFile *) load;

	return( vips_foreign_load_tiff_file_get_flags_filename( 
		file->filename ) );
}

static int
vips_foreign_load_tiff_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadTiff *tiff = (VipsForeignLoadTiff *) load;
	VipsForeignLoadTiffFile *file = (VipsForeignLoadTiffFile *) load;

	if( vips__tiff_read_header( file->filename, load->out, 
		tiff->page, tiff->autorotate ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, file->filename );

	return( 0 );
}

static int
vips_foreign_load_tiff_file_load( VipsForeignLoad *load )
{
	VipsForeignLoadTiff *tiff = (VipsForeignLoadTiff *) load;
	VipsForeignLoadTiffFile *file = (VipsForeignLoadTiffFile *) load;

	if( vips__tiff_read( file->filename, load->real, tiff->page, 
		tiff->autorotate, load->access == VIPS_ACCESS_SEQUENTIAL ) )
		return( -1 );

	return( 0 );
}

const char *vips__foreign_tiff_suffs[] = { ".tif", ".tiff", NULL };

static void
vips_foreign_load_tiff_file_class_init( VipsForeignLoadTiffFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "tiffload";
	object_class->description = _( "load tiff from file" );

	/* We are fast, but must test after openslideload.
	 */
	foreign_class->priority = 50;

	foreign_class->suffs = vips__foreign_tiff_suffs;

	load_class->is_a = vips__istiff;
	load_class->get_flags_filename = 
		vips_foreign_load_tiff_file_get_flags_filename;
	load_class->get_flags = vips_foreign_load_tiff_file_get_flags;
	load_class->header = vips_foreign_load_tiff_file_header;
	load_class->load = vips_foreign_load_tiff_file_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadTiffFile, filename ),
		NULL );
}

static void
vips_foreign_load_tiff_file_init( VipsForeignLoadTiffFile *file )
{
}

typedef struct _VipsForeignLoadTiffBuffer {
	VipsForeignLoadTiff parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadTiffBuffer;

typedef VipsForeignLoadTiffClass VipsForeignLoadTiffBufferClass;

G_DEFINE_TYPE( VipsForeignLoadTiffBuffer, vips_foreign_load_tiff_buffer, 
	vips_foreign_load_tiff_get_type() );

static int
vips_foreign_load_tiff_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadTiff *tiff = (VipsForeignLoadTiff *) load;
	VipsForeignLoadTiffBuffer *buffer = (VipsForeignLoadTiffBuffer *) load;

	if( vips__tiff_read_header_buffer( 
		buffer->buf->data, buffer->buf->length, load->out, 
		tiff->page, tiff->autorotate ) ) 
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_tiff_buffer_load( VipsForeignLoad *load )
{
	VipsForeignLoadTiff *tiff = (VipsForeignLoadTiff *) load;
	VipsForeignLoadTiffBuffer *buffer = (VipsForeignLoadTiffBuffer *) load;

	if( vips__tiff_read_buffer( 
		buffer->buf->data, buffer->buf->length, load->real, 
		tiff->page, tiff->autorotate,
		load->access == VIPS_ACCESS_SEQUENTIAL ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_tiff_buffer_class_init( 
	VipsForeignLoadTiffBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "tiffload_buffer";
	object_class->description = _( "load tiff from buffer" );

	load_class->is_a_buffer = vips__istiff_buffer;
	load_class->header = vips_foreign_load_tiff_buffer_header;
	load_class->load = vips_foreign_load_tiff_buffer_load;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadTiffBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_load_tiff_buffer_init( VipsForeignLoadTiffBuffer *buffer )
{
}

#endif /*HAVE_TIFF*/

/**
 * vips_tiffload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: int, load this page
 * * @autorotate: %gboolean, use orientation tag to rotate the image 
 *   during load
 *
 * Read a TIFF file into a VIPS image. It is a full baseline TIFF 6 reader, 
 * with extensions for tiled images, multipage images, LAB colour space, 
 * pyramidal images and JPEG compression. including CMYK and YCbCr.
 *
 * @page means load this page from the file. By default the first page (page
 * 0) is read.
 *
 * Setting @autorotate to %TRUE will make the loader interpret the 
 * orientation tag and automatically rotate the image appropriately during
 * load. 
 *
 * If @autorotate is %FALSE, the metadata field #VIPS_META_ORIENTATION is set 
 * to the value of the orientation tag. Applications may read and interpret 
 * this field
 * as they wish later in processing. See vips_autorot(). Save
 * operations will use #VIPS_META_ORIENTATION, if present, to set the
 * orientation of output images. 
 *
 * Any ICC profile is read and attached to the VIPS image as
 * #VIPS_META_ICC_NAME. Any XMP metadata is read and attached to the image
 * as #VIPS_META_XMP_NAME. Any IPCT is attached as #VIPS_META_IPCT_NAME. The
 * image description is
 * attached as #VIPS_META_IMAGEDESCRIPTION. Data in the photoshop tag is 
 * attached as #VIPS_META_PHOTOSHOP_NAME.
 *
 * See also: vips_image_new_from_file(), vips_autorot().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_tiffload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "tiffload", ap, filename, out );
	va_end( ap );

	return( result );
}

/**
 * vips_tiffload_buffer:
 * @buf: memory area to load
 * @len: size of memory area
 * @out: image to write
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, load this page
 * * @autorotate: %gboolean, use orientation tag to rotate the image 
 *   during load
 *
 * Read a TIFF-formatted memory block into a VIPS image. Exactly as
 * vips_tiffload(), but read from a memory source. 
 *
 * You must not free the buffer while @out is active. The 
 * #VipsObject::postclose signal on @out is a good place to free. 
 *
 * See also: vips_tiffload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_tiffload_buffer( void *buf, size_t len, VipsImage **out, ... )
{
	va_list ap;
	VipsBlob *blob;
	int result;

	/* We don't take a copy of the data or free it.
	 */
	blob = vips_blob_new( NULL, buf, len );

	va_start( ap, out );
	result = vips_call_split( "tiffload_buffer", ap, blob, out );
	va_end( ap );

	vips_area_unref( VIPS_AREA( blob ) );

	return( result );
}
