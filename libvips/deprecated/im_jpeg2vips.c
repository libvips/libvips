/* Convert 1 or 3-band 8-bit VIPS images to/from JPEG.
 *
 * 30/11/11
 * 	- now just a stub
 * 10/7/12
 * 	- use jpeg funcs directly rather than going though vips_jpegload()
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

#include <stdlib.h>
#include <setjmp.h>

#include <vips/vips.h>

#ifdef HAVE_JPEG
#include <jpeglib.h>
#include <jerror.h>
#include "../foreign/jpeg.h"
#endif /*HAVE_JPEG*/

static int
jpeg2vips( const char *name, IMAGE *out, gboolean header_only )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *p, *q;
	int shrink;
	int seq;
	gboolean fail_on_warn;

	/* By default, we ignore any warnings. We want to get as much of
	 * the user's data as we can.
	 */
	fail_on_warn = FALSE;

	/* Parse the filename.
	 */
	im_filename_split( name, filename, mode );
	p = &mode[0];
	shrink = 1;
	seq = 0;
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
	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "seq", q ) )
			seq = 1;
	}

	/* Don't use vips_jpegload() ... we call the jpeg func directly in
	 * order to avoid the foreign.c mechanisms for load-via-disc and stuff
	 * like that.
	 */

	/* We need to be compatible with the pre-sequential mode 
	 * im_jpeg2vips(). This returned a "t" if given a "p" image, since it
	 * used writeline.
	 *
	 * If we're writing the image to a "p", switch it to a "t".
	 */

	if( !header_only &&
		!seq &&
		out->dtype == VIPS_IMAGE_PARTIAL ) {
		if( vips__image_wio_output( out ) ) 
			return( -1 );
	}

#ifdef HAVE_JPEG
	if( vips__jpeg_read_file( filename, out, 
		header_only, shrink, fail_on_warn, TRUE ) )
		return( -1 );
#else
	vips_error( "im_jpeg2vips", 
		"%s", _( "no JPEG support in your libvips" ) ); 

	return( -1 );
#endif /*HAVE_JPEG*/

	return( 0 );
}

int
im_jpeg2vips( const char *name, IMAGE *out )
{
	return( jpeg2vips( name, out, FALSE ) ); 
}

/* By having a separate header func, we get lazy.c to open via disc/mem.
 */
static int
im_jpeg2vips_header( const char *name, IMAGE *out )
{
	return( jpeg2vips( name, out, TRUE ) ); 
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
	format_class->header = im_jpeg2vips_header;
	format_class->load = im_jpeg2vips;
	format_class->save = im_vips2jpeg;
	format_class->suffs = jpeg_suffs;
}

static void
vips_format_jpeg_init( VipsFormatJpeg *object )
{
}

G_DEFINE_TYPE( VipsFormatJpeg, vips_format_jpeg, VIPS_TYPE_FORMAT );
