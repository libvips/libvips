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

#ifdef HAVE_TIFF

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "tiff.h"

typedef struct _VipsForeignLoadTiff {
	VipsForeignLoad parent_object;

	/* Load this page. 
	 */
	int page;

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

	if( vips__tiff_read_header( file->filename, load->out, tiff->page ) )
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
		load->access == VIPS_ACCESS_SEQUENTIAL ) )
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
		tiff->page ) ) 
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
		tiff->page,
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
