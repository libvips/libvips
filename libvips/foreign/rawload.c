/* load raw data from a file
 *
 * 14/12/11
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
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsForeignLoadRaw {
	VipsForeignLoad parent_object;

	char *filename;
	int width;
	int height;
	int bands;
	guint64 offset;
} VipsForeignLoadRaw;

typedef VipsForeignLoadClass VipsForeignLoadRawClass;

G_DEFINE_TYPE( VipsForeignLoadRaw, vips_foreign_load_raw, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_raw_get_flags( VipsForeignLoad *load )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_raw_get_flags_filename( const char *filename )
{
	return( VIPS_FOREIGN_PARTIAL );
}

static int
vips_foreign_load_raw_header( VipsForeignLoad *load )
{
	VipsForeignLoadRaw *raw = (VipsForeignLoadRaw *) load;
	VipsImage *out;
	VipsImage *out2;

	if( !(out2 = vips_image_new_from_file_raw( raw->filename, 
		raw->width, raw->height, raw->bands, raw->offset )) )
		return( -1 );

	/* Remove the @out that's there now. 
	 */
	g_object_get( load, "out", &out, NULL ); 
	g_object_unref( out );
	g_object_unref( out );

	g_object_set( load, "out", out2, NULL ); 

	return( 0 );
}

static void
vips_foreign_load_raw_class_init( VipsForeignLoadRawClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "rawload";
	object_class->description = _( "load raw data from a file" );

	load_class->get_flags = vips_foreign_load_raw_get_flags;
	load_class->get_flags_filename = 
		vips_foreign_load_raw_get_flags_filename;
	load_class->header = vips_foreign_load_raw_header;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadRaw, filename ),
		NULL );

	VIPS_ARG_INT( class, "width", 10, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, width ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "height", 11, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, height ),
		0, 1000000, 0 );

	VIPS_ARG_INT( class, "bands", 12, 
		_( "Bands" ), 
		_( "Number of bands in image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, bands ),
		0, 1000000, 0 );

	VIPS_ARG_UINT64( class, "offset", 13, 
		_( "Size of header" ), 
		_( "Offset in bytes from start of file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, offset ),
		0, 100000000000, 0 );

}

static void
vips_foreign_load_raw_init( VipsForeignLoadRaw *raw )
{
}

/**
 * vips_rawload:
 * @filename: file to load
 * @out: output image
 * @width: width of image in pixels
 * @height: height of image in pixels
 * @bands: number of image bands
 * @offset: offset in bytes from start of file
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation mmaps the file, setting @out so that access to that 
 * image will read from the file.
 *
 * Use functions like vips_copy() to set the pixel type, byte ordering 
 * and so on.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_rawload( const char *filename, VipsImage **out, 
	int width, int height, int bands, ... )
{
	va_list ap;
	int result;

	va_start( ap, bands );
	result = vips_call_split( "rawload", ap, 
		filename, out, width, height, bands );
	va_end( ap );

	return( result );
}


