/* save to jpeg
 *
 * 28/11/03 JC
 *	- better no-overshoot on tile loop
 * 12/11/04
 *	- better demand size choice for eval
 * 30/6/05 JC
 *	- update im_error()/im_warn()
 *	- now loads and saves exif data
 * 30/7/05
 * 	- now loads ICC profiles
 * 	- now saves ICC profiles from the VIPS header
 * 24/8/05
 * 	- jpeg load sets vips xres/yres from exif, if possible
 * 	- jpeg save sets exif xres/yres from vips, if possible
 * 29/8/05
 * 	- cut from old vips_jpeg.c
 * 20/4/06
 * 	- auto convert to sRGB/mono for save
 * 13/10/06
 * 	- add </libexif/ prefix if required
 * 19/1/07
 * 	- oop, libexif confusion
 * 2/11/07
 * 	- use im_wbuffer() API for BG writes
 * 15/2/08
 * 	- write CMYK if Bands == 4 and Type == CMYK
 * 12/5/09
 *	- fix signed/unsigned warning
 * 13/8/09
 * 	- allow "none" for profile, meaning don't embed one
 * 4/2/10
 * 	- gtkdoc
 * 17/7/10
 * 	- use g_assert()
 * 	- allow space for the header in init_destination(), helps writing very
 * 	  small JPEGs (thanks Tim Elliott)
 * 18/7/10
 * 	- collect im_vips2bufjpeg() output in a list of blocks ... we no
 * 	  longer overallocate or underallocate
 * 8/7/11
 * 	- oop CMYK write was not inverting, thanks Ole
 * 12/10/2011
 * 	- write XMP data
 * 18/10/2011
 * 	- update Orientation as well
 * 3/11/11
 * 	- rebuild exif tags from coded metadata values 
 * 24/11/11
 * 	- rework as a class
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
#define VIPS_DEBUG
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
#include <vips/internal.h>
#include <vips/debug.h>
#include <vips/buf.h>

/* jpeglib includes jconfig.h, which can define HAVE_STDLIB_H ... which we
 * also define. Make sure it's turned off.
 */
#ifdef HAVE_STDLIB_H
#undef HAVE_STDLIB_H
#endif /*HAVE_STDLIB_H*/

#include <jpeglib.h>
#include <jerror.h>

#include "jpeg.h"

typedef struct _VipsFileSaveJpeg {
	VipsFileSave parent_object;


} VipsFileSaveJpeg;

typedef VipsFileSaveClass VipsFileSaveJpegClass;

G_DEFINE_TYPE( VipsFileSaveJpeg, vips_file_save_jpeg, VIPS_TYPE_FILE_SAVE );

static int
vips_file_load_save_build( VipsObject *object )
{
	VipsFileSaveJpeg *jpeg = (VipsFileSaveJpeg *) object;

	if( VIPS_OBJECT_CLASS( vips_file_save_jpeg_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_file_save_jpeg_class_init( VipsFileLoadJpegClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFileSaveClass *save_class = (VipsFileSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "jpegsave";
	object_class->description = _( "save jpeg from file" );
	object_class->build = vips_file_save_jpeg_build;

}

static void
vips_file_save_jpeg_init( VipsFileSaveJpeg *jpeg )
{
}

