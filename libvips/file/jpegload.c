/* save to jpeg
 *
 * 24/11/11
 * 	- wrap a class around the jpeg reader
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
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#ifdef HAVE_EXIF
#ifdef UNTAGGED_EXIF
#include <exif-data.h>
#include <exif-loader.h>
#include <exif-ifd.h>
#include <exif-utils.h>
#else /*!UNTAGGED_EXIF*/
#include <libexif/exif-data.h>
#include <libexif/exif-loader.h>
#include <libexif/exif-ifd.h>
#include <libexif/exif-utils.h>
#endif /*UNTAGGED_EXIF*/
#endif /*HAVE_EXIF*/

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

/* jpeglib includes jconfig.h, which can define HAVE_STDLIB_H ... which we
 * also define. Make sure it's turned off.
 */
#ifdef HAVE_STDLIB_H
#undef HAVE_STDLIB_H
#endif /*HAVE_STDLIB_H*/

#include <jpeglib.h>
#include <jerror.h>

#include "jpeg.h"

typedef struct _VipsFileLoadJpeg {
	VipsFileLoad parent_object;

	/* Shrink by this much during load.
	 */
	int shrink;

	/* Fail on first warning.
	 */
	gboolean fail;

} VipsFileLoadJpeg;

typedef VipsFileLoadClass VipsFileLoadJpegClass;

G_DEFINE_TYPE( VipsFileLoadJpeg, vips_file_load_jpeg, VIPS_TYPE_FILE_LOAD );

static int
vips_file_load_jpeg_build( VipsObject *object )
{
	VipsFileLoadJpeg *jpeg = (VipsFileLoadJpeg *) object;

	if( jpeg->shrink != 1 && 
		jpeg->shrink != 2 && 
		jpeg->shrink != 4 && 
		jpeg->shrink != 8 ) {
		vips_error( "VipsFormatLoadJpeg", 
			_( "bad shrink factor %d" ), jpeg->shrink );
		return( -1 );
	}

	if( VIPS_OBJECT_CLASS( vips_file_load_jpeg_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

/* Read just the image header into ->out.
 */
static int
vips_file_load_jpeg_header( VipsFileLoad *load )
{
	VipsFile *file = VIPS_FILE( load );
	VipsFileLoadJpeg *jpeg = (VipsFileLoadJpeg *) load;

	if( vips__jpeg_read_file( file->filename, load->out, 
		TRUE, jpeg->shrink, jpeg->fail ) )
		return( -1 );

	return( 0 );
}

static int
vips_file_load_jpeg_load( VipsFileLoad *load )
{
	VipsFile *file = VIPS_FILE( load );
	VipsFileLoadJpeg *jpeg = (VipsFileLoadJpeg *) load;

	if( vips__jpeg_read_file( file->filename, load->real, 
		FALSE, jpeg->shrink, jpeg->fail ) )
		return( -1 );

	return( 0 );
}

static void
vips_file_load_jpeg_class_init( VipsFileLoadJpegClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFileClass *file_class = (VipsFileClass *) class;
	VipsFileLoadClass *load_class = (VipsFileLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegload";
	object_class->description = _( "load jpeg from file" );
	object_class->build = vips_file_load_jpeg_build;

	file_class->suffs = vips__jpeg_suffs;

	load_class->is_a = vips__isjpeg;
	load_class->header = vips_file_load_jpeg_header;
	load_class->load = vips_file_load_jpeg_load;

	VIPS_ARG_INT( class, "shrink", 10, 
		_( "Shrink" ), 
		_( "Shrink factor on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFileLoadJpeg, shrink ),
		1, 16, 1 );

	VIPS_ARG_BOOL( class, "fail", 11, 
		_( "Fail" ), 
		_( "Fail on first warning" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsFileLoadJpeg, fail ),
		FALSE );
}

static void
vips_file_load_jpeg_init( VipsFileLoadJpeg *jpeg )
{
	jpeg->shrink = 1;
}

