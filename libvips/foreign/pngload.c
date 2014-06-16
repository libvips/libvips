/* load png from a file
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

#ifdef HAVE_PNG

#include "vipspng.h"

typedef struct _VipsForeignLoadPng {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadPng;

typedef VipsForeignLoadClass VipsForeignLoadPngClass;

G_DEFINE_TYPE( VipsForeignLoadPng, vips_foreign_load_png, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_png_get_flags_filename( const char *filename )
{
	VipsForeignFlags flags;

	flags = 0;
	if( vips__png_isinterlaced( filename ) )
		flags |= VIPS_FOREIGN_PARTIAL;
	else
		flags |= VIPS_FOREIGN_SEQUENTIAL;

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_png_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	return( vips_foreign_load_png_get_flags_filename( png->filename ) ); 
}

static int
vips_foreign_load_png_header( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	if( vips__png_header( png->filename, load->out ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, png->filename );

	return( 0 );
}

static int
vips_foreign_load_png_load( VipsForeignLoad *load )
{
	VipsForeignLoadPng *png = (VipsForeignLoadPng *) load;

	if( vips__png_read( png->filename, load->real, 
		load->access == VIPS_ACCESS_SEQUENTIAL ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_png_class_init( VipsForeignLoadPngClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload";
	object_class->description = _( "load png from file" );

	foreign_class->suffs = vips__png_suffs;

	load_class->is_a = vips__png_ispng;
	load_class->get_flags_filename = 
		vips_foreign_load_png_get_flags_filename;
	load_class->get_flags = vips_foreign_load_png_get_flags;
	load_class->header = vips_foreign_load_png_header;
	load_class->load = vips_foreign_load_png_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPng, filename ),
		NULL );
}

static void
vips_foreign_load_png_init( VipsForeignLoadPng *png )
{
}

typedef struct _VipsForeignLoadPngBuffer {
	VipsForeignLoad parent_object;

	/* Load from a buffer.
	 */
	VipsArea *buf;

} VipsForeignLoadPngBuffer;

typedef VipsForeignLoadClass VipsForeignLoadPngBufferClass;

G_DEFINE_TYPE( VipsForeignLoadPngBuffer, vips_foreign_load_png_buffer, 
	VIPS_TYPE_FOREIGN_LOAD );

static int
vips_foreign_load_png_buffer_header( VipsForeignLoad *load )
{
	VipsForeignLoadPngBuffer *png = (VipsForeignLoadPngBuffer *) load;

	if( vips__png_header_buffer( png->buf->data, png->buf->length, 
		load->out ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_png_buffer_load( VipsForeignLoad *load )
{
	VipsForeignLoadPngBuffer *png = (VipsForeignLoadPngBuffer *) load;

	if( vips__png_read_buffer( png->buf->data, png->buf->length, 
		load->real, load->access == VIPS_ACCESS_SEQUENTIAL ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_png_buffer_class_init( VipsForeignLoadPngBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "pngload_buffer";
	object_class->description = _( "load png from buffer" );

	load_class->is_a_buffer = vips__png_ispng_buffer;
	load_class->header = vips_foreign_load_png_buffer_header;
	load_class->load = vips_foreign_load_png_buffer_load;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPngBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_load_png_buffer_init( VipsForeignLoadPngBuffer *png )
{
}

#endif /*HAVE_PNG*/

