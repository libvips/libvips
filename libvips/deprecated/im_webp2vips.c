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
#include <glib/gi18n-lib.h>

#include <stdio.h>

#include <vips/vips.h>
#include <vips/vips7compat.h>
#include <vips/internal.h>

#include "../foreign/pforeign.h"

static int
webp2vips( const char *name, IMAGE *out, gboolean header_only )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

#ifdef HAVE_LIBWEBP
{
	VipsSource *source;
	int result;

	if( !(source = vips_source_new_from_file( filename )) ) 
		return( -1 );
	if( header_only ) 
		result = vips__webp_read_header_source( source, out, 0, 1, 1 );
	else 
		result = vips__webp_read_source( source, out, 0, 1, 1 );
	VIPS_UNREF( source );

	if( result )
		return( result );
}
#else
	vips_error( "im_webp2vips", 
		"%s", _( "no webp support in your libvips" ) ); 

	return( -1 );
#endif /*HAVE_LIBWEBP*/

	return( 0 );
}

static gboolean
vips__iswebp( const char *filename )
{
	gboolean result;

#ifdef HAVE_LIBWEBP
	VipsSource *source;

	if( !(source = vips_source_new_from_file( filename )) )
		return( FALSE );
	result = vips__iswebp_source( source );
	VIPS_UNREF( source );
#else /*!HAVE_LIBWEBP*/
	result = -1;
#endif /*HAVE_LIBWEBP*/

	return( result );
}

int
im_webp2vips( const char *name, IMAGE *out )
{
	return( webp2vips( name, out, FALSE ) ); 
}

#ifdef HAVE_LIBWEBP

static int
im_webp2vips_header( const char *name, IMAGE *out )
{
	return( webp2vips( name, out, TRUE ) ); 
}

static const char *webp_suffs[] = { ".webp", NULL };

typedef VipsFormat VipsFormatWebp;
typedef VipsFormatClass VipsFormatWebpClass;

static void
vips_format_webp_class_init( VipsFormatWebpClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "webp";
	object_class->description = _( "webp" );

	format_class->is_a = vips__iswebp;
	format_class->header = im_webp2vips_header;
	format_class->load = im_webp2vips;
	format_class->save = im_vips2webp;
	format_class->suffs = webp_suffs;
}

static void
vips_format_webp_init( VipsFormatWebp *object )
{
}

G_DEFINE_TYPE( VipsFormatWebp, vips_format_webp, VIPS_TYPE_FORMAT );

#endif /*HAVE_LIBWEBP*/

