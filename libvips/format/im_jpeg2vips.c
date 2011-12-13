/* Convert 1 or 3-band 8-bit VIPS images to/from JPEG.
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
 * 13/10/06
 * 	- add </libexif/ prefix if required
 * 11/2/08
 * 	- spot CMYK jpegs and set Type
 * 	- spot Adobe CMYK JPEG and invert ink density
 * 15/2/08
 * 	- added "shrink" parameter
 * 16/6/09
 *	- added "fail" option ... fail on any warnings
 * 12/10/09
 * 	- also set scale_num on shrink (thanks Guido)
 * 4/2/10
 * 	- gtkdoc
 * 4/12/10
 * 	- attach the jpeg thumbnail and multiscan fields (thanks Mike)
 * 21/2/10
 * 	- only accept the first APP1 block which starts "Exif..." as exif
 * 	  data, some jpegs seem to have several APP1s, argh
 * 20/4/2011
 * 	- added im_bufjpeg2vips()
 * 12/10/2011
 * 	- read XMP data
 * 3/11/11
 * 	- attach exif tags as coded values 
 * 30/11/11
 * 	- now just a stub
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

#include <stdlib.h>

#include <vips/vips.h>

int
im_jpeg2vips( const char *name, IMAGE *out )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *p, *q;
	int shrink;
	gboolean fail_on_warn;
	VipsImage *t;

	/* By default, we ignore any warnings. We want to get as much of
	 * the user's data as we can.
	 */
	fail_on_warn = FALSE;

	/* Parse the filename.
	 */
	im_filename_split( name, filename, mode );
	p = &mode[0];
	shrink = 1;
	if( (q = im_getnextoption( &p )) ) {
		shrink = atoi( q );

		if( shrink != 1 && shrink != 2 && 
			shrink != 4 && shrink != 8 ) {
			im_error( "im_jpeg2vips", 
				_( "bad shrink factor %d" ), shrink );
			return( -1 );
		}
	}
	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "fail", q ) ) 
			fail_on_warn = TRUE;
	}

	if( vips_jpegload( filename, &t, 
		"shrink", shrink,
		"fail", fail_on_warn,
		NULL ) )
		return( -1 );

	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
im_bufjpeg2vips( void *buf, size_t len, IMAGE *out, gboolean header_only )
{
	VipsImage *t;

	/* header_only is now automatic ... this call will only decompress on 
	 * pixel access.
	 */

	if( vips_jpegload_buffer( buf, len, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
isjpeg( const char *name )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

	return( vips_foreign_is_a( "jpegload", filename ) );
}

static const char *jpeg_suffs[] = { ".jpg", ".jpeg", ".jpe", NULL };

/* jpeg format adds no new members.
 */
typedef VipsFormat VipsFormatJpeg;
typedef VipsFormatClass VipsFormatJpegClass;

static void
vips_format_jpeg_class_init( VipsFormatJpegClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "jpeg";
	object_class->description = _( "JPEG" );

	format_class->is_a = isjpeg;
	format_class->header = im_jpeg2vips;
	format_class->save = im_vips2jpeg;
	format_class->suffs = jpeg_suffs;
}

static void
vips_format_jpeg_init( VipsFormatJpeg *object )
{
}

G_DEFINE_TYPE( VipsFormatJpeg, vips_format_jpeg, VIPS_TYPE_FORMAT );
