/* load webp images
 *
 * 6/8/13
 * 	- from pngload.c
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
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_LIBWEBP

#include <string.h>

#include <vips/vips.h>

#include "webp.h"

typedef struct _VipsForeignLoadWebp {
	VipsForeignLoad parent_object;

} VipsForeignLoadWebp;

typedef VipsForeignLoadClass VipsForeignLoadWebpClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadWebp, vips_foreign_load_webp, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_webp_get_flags( VipsForeignLoad *load )
{
	return( 0 );
}

static int
vips_foreign_load_webp_build( VipsObject *object )
{
	if( VIPS_OBJECT_CLASS( vips_foreign_load_webp_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_webp_class_init( VipsForeignLoadWebpClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload_base";
	object_class->description = _( "load webp" );
	object_class->build = vips_foreign_load_webp_build;

	load_class->get_flags = vips_foreign_load_webp_get_flags;

}

static void
vips_foreign_load_webp_init( VipsForeignLoadWebp *webp )
{
}

typedef struct _VipsForeignLoadWebpFile {
	VipsForeignLoadWebp parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadWebpFile;

typedef VipsForeignLoadWebpClass VipsForeignLoadWebpFileClass;

G_DEFINE_TYPE( VipsForeignLoadWebpFile, vips_foreign_load_webp_file, 
	vips_foreign_load_webp_get_type() );

static VipsForeignFlags
vips_foreign_load_webp_file_get_flags_filename( const char *filename )
{
	return( 0 );
}

static gboolean
vips_foreign_load_webp_file_is_a( const char *filename )
{
	return( vips__iswebp( filename ) );
}

static int
vips_foreign_load_webp_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadWebpFile *file = (VipsForeignLoadWebpFile *) load;

	if( vips__webp_read_file_header( file->filename, load->out ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, file->filename );

	return( 0 );
}

static int
vips_foreign_load_webp_file_load( VipsForeignLoad *load )
{
	VipsForeignLoadWebpFile *file = (VipsForeignLoadWebpFile *) load;

	if( vips__webp_read_file( file->filename, load->real ) )
		return( -1 );

	return( 0 );
}

const char *vips__webp_suffs[] = { ".webp", NULL };

static void
vips_foreign_load_webp_file_class_init( VipsForeignLoadWebpFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload";
	object_class->description = _( "load webp from file" );

	foreign_class->suffs = vips__webp_suffs;

	load_class->get_flags_filename = 
		vips_foreign_load_webp_file_get_flags_filename;
	load_class->is_a = vips_foreign_load_webp_file_is_a;
	load_class->header = vips_foreign_load_webp_file_header;
	load_class->load = vips_foreign_load_webp_file_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadWebpFile, filename ),
		NULL );
}

static void
vips_foreign_load_webp_file_init( VipsForeignLoadWebpFile *file )
{
}

typedef struct _VipsForeignLoadWebpBuffer {
	VipsForeignLoadWebp parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadWebpBuffer;

typedef VipsForeignLoadWebpClass VipsForeignLoadWebpBufferClass;

G_DEFINE_TYPE( VipsForeignLoadWebpBuffer, vips_foreign_load_webp_buffer, 
	vips_foreign_load_webp_get_type() );

static int
vips_foreign_load_webp_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadWebpBuffer *buffer = (VipsForeignLoadWebpBuffer *) load;

	if( vips__webp_read_buffer_header( buffer->buf->data, 
		buffer->buf->length, load->out ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_webp_buffer_load( VipsForeignLoad *load )
{
	VipsForeignLoadWebpBuffer *buffer = (VipsForeignLoadWebpBuffer *) load;

	if( vips__webp_read_buffer( buffer->buf->data, buffer->buf->length, 
		load->real ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_webp_buffer_class_init( 
	VipsForeignLoadWebpBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpload_buffer";
	object_class->description = _( "load webp from buffer" );

	load_class->is_a_buffer = vips__iswebp_buffer; 
	load_class->header = vips_foreign_load_webp_buffer_header;
	load_class->load = vips_foreign_load_webp_buffer_load;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadWebpBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_load_webp_buffer_init( VipsForeignLoadWebpBuffer *buffer )
{
}

#endif /*HAVE_LIBWEBP*/
