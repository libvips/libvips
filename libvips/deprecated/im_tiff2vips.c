/* vips7 compat stub for tiff loading ... see foreign/tiff2vips for the
 * replacement
 *
 * 6/12/11
 * 	- just a stub
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
#include <vips/internal.h>
#include <vips/thread.h>

#include "../foreign/pforeign.h"

static int
tiff2vips( const char *name, IMAGE *out, gboolean header_only )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *p, *q;
	int page;
	int seq;

	im_filename_split( name, filename, mode );

	page = 0;
	seq = 0;
	p = &mode[0];
	if( (q = im_getnextoption( &p )) ) {
		page = atoi( q );
	}
	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "seq", q ) )
			seq = 1;
	}

	/* We need to be compatible with the pre-sequential mode 
	 * im_tiff2vips(). This returned a "t" if given a "p" image, since it
	 * used writeline.
	 *
	 * If we're writing the image to a "p", switch it to a "t". And only
	 * for non-tiled (strip) images which we write with writeline.
	 *
	 * Don't do this for header read, since we don't want to force a
	 * malloc if all we are doing is looking at fields.
	 */

#ifdef HAVE_TIFF
	if( !header_only &&
		!seq &&
		!vips__istifftiled( filename ) &&
		out->dtype == VIPS_IMAGE_PARTIAL ) {
		if( vips__image_wio_output( out ) ) 
			return( -1 );
	}

	if( header_only ) {
		if( vips__tiff_read_header( filename, out, page, 1, FALSE ) )
			return( -1 );
	}
	else {
		if( vips__tiff_read( filename, out, page, 1, FALSE, TRUE ) )
			return( -1 );
	}
#else
	vips_error( "im_tiff2vips", 
		"%s", _( "no TIFF support in your libvips" ) ); 

	return( -1 );
#endif /*HAVE_TIFF*/

	return( 0 );
}

int
im_tiff2vips( const char *name, IMAGE *out )
{
	return( tiff2vips( name, out, FALSE ) ); 
}

/* By having a separate header func, we get lazy.c to open via disc/mem.
 */
static int
im_tiff2vips_header( const char *name, IMAGE *out )
{
	return( tiff2vips( name, out, TRUE ) ); 
}

static VipsFormatFlags
tiff_flags( const char *name )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

	return( (VipsFormatFlags)
		vips_foreign_flags( "tiffload", filename ) );
}

static int
istiff( const char *name )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

	return( vips_foreign_is_a( "tiffload", filename ) );
}

static const char *tiff_suffs[] = { ".tif", ".tiff", NULL };

typedef VipsFormat VipsFormatTiff;
typedef VipsFormatClass VipsFormatTiffClass;

static void
vips_format_tiff_class_init( VipsFormatTiffClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "tiff";
	object_class->description = _( "TIFF" );

	format_class->is_a = istiff;
	format_class->header = im_tiff2vips_header;
	format_class->load = im_tiff2vips;
	format_class->save = im_vips2tiff;
	format_class->get_flags = tiff_flags;
	format_class->suffs = tiff_suffs;
}

static void
vips_format_tiff_init( VipsFormatTiff *object )
{
}

G_DEFINE_TYPE( VipsFormatTiff, vips_format_tiff, VIPS_TYPE_FORMAT );
