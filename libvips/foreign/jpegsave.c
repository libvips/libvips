/* save to jpeg
 *
 * 24/11/11
 * 	- wrap a class around the jpeg writer
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

typedef struct _VipsForeignSaveJpeg {
	VipsForeignSave parent_object;

	/* Filename for load.
	 */
	char *filename; 

	/* Quality factor.
	 */
	int Q;

	/* Profile to embed .. "none" means don't attach a profile.
	 */
	char *profile;

} VipsForeignSaveJpeg;

typedef VipsForeignSaveClass VipsForeignSaveJpegClass;

G_DEFINE_TYPE( VipsForeignSaveJpeg, vips_foreign_save_jpeg, VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_jpeg_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveJpeg *jpeg = (VipsForeignSaveJpeg *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_jpeg_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__jpeg_write_file( save->ready, jpeg->filename,
		jpeg->Q, jpeg->profile ) )
		return( -1 );

	return( 0 );
}

#define UC VIPS_FORMAT_UCHAR

/* Type promotion for save ... just always go to uchar.
 */
static int bandfmt_jpeg[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_foreign_save_jpeg_class_init( VipsForeignSaveJpegClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegsave";
	object_class->description = _( "save image to jpeg file" );
	object_class->build = vips_foreign_save_jpeg_build;

	foreign_class->suffs = vips__jpeg_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGB_CMYK;
	save_class->format_table = bandfmt_jpeg;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, filename ),
		NULL );

	VIPS_ARG_INT( class, "Q", 10, 
		_( "Q" ), 
		_( "Q factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, Q ),
		1, 100, 75 );

	VIPS_ARG_STRING( class, "profile", 11, 
		_( "profile" ), 
		_( "ICC profile to embed" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveJpeg, profile ),
		NULL );
}

static void
vips_foreign_save_jpeg_init( VipsForeignSaveJpeg *jpeg )
{
	jpeg->Q = 75;
}
