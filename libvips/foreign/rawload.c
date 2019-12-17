/* load raw data from a file
 *
 * 14/12/11
 * 5/8/19
 * 	- add @format and @interpretation
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

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsForeignLoadRaw {
	VipsForeignLoad parent_object;

	char *filename;
	int width;
	int height;
	int bands;
	guint64 offset;
	VipsBandFormat format;
	VipsInterpretation interpretation;
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
	VipsImage *x;

	if( !(out = vips_image_new_from_file_raw( raw->filename, 
		raw->width, raw->height, 
		vips_format_sizeof_unsafe( raw->format ) * raw->bands,
		raw->offset )) )
		return( -1 );

	if( vips_copy( out, &x,
		"interpretation", raw->interpretation,
		"format", raw->format,
		"bands", raw->bands,
		NULL ) ) {
		g_object_unref( out );
		return( -1 );
	}
	g_object_unref( out );
	out = x;

	/* Remove the @out that's there now. 
	 */
	g_object_get( load, "out", &x, NULL ); 
	g_object_unref( x );
	g_object_unref( x );

	g_object_set( load, "out", out, NULL ); 

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

	VIPS_ARG_INT( class, "width", 20, 
		_( "Width" ), 
		_( "Image width in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, width ),
		0, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( class, "height", 21, 
		_( "Height" ), 
		_( "Image height in pixels" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, height ),
		0, VIPS_MAX_COORD, 0 );

	VIPS_ARG_INT( class, "bands", 22, 
		_( "Bands" ), 
		_( "Number of bands in image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, bands ),
		0, VIPS_MAX_COORD, 0 );

	VIPS_ARG_UINT64( class, "offset", 23, 
		_( "Size of header" ), 
		_( "Offset in bytes from start of file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, offset ),
		0, 100000000000, 0 );

	VIPS_ARG_ENUM( class, "format", 24, 
		_( "Format" ), 
		_( "Pixel format in image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, format ),
		VIPS_TYPE_BAND_FORMAT, VIPS_FORMAT_UCHAR ); 

	VIPS_ARG_ENUM( class, "interpretation", 25, 
		_( "Interpretation" ), 
		_( "Pixel interpretation" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadRaw, interpretation ),
		VIPS_TYPE_INTERPRETATION, VIPS_INTERPRETATION_MULTIBAND ); 

}

static void
vips_foreign_load_raw_init( VipsForeignLoadRaw *raw )
{
	raw->format = VIPS_FORMAT_UCHAR;
	raw->interpretation = VIPS_INTERPRETATION_MULTIBAND;
}

/**
 * vips_rawload:
 * @filename: file to load
 * @out: (out): output image
 * @width: width of image in pixels
 * @height: height of image in pixels
 * @bands: number of image bands
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @offset: %guint64, offset in bytes from start of file
 * * @format: #VipsBandFormat, set image format
 * * @interpretation: #VipsInterpretation, set image interpretation
 *
 * This operation mmaps the file, setting up @out so that access to that 
 * image will read from the file. 
 *
 * By default, it assumes uchar pixels. Use @format to select something else.
 *
 * The image will be tagged as #VIPS_INTERPRETATION_MULTIBAND. Use
 * @interpretation to select something else.
 *
 * Use vips_byteswap() to reverse the byte ordering if necessary. 
 *
 * See also: vips_image_new_from_file(), vips_copy(), vips_byteswap().
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


