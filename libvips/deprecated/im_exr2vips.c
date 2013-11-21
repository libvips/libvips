/* Convert OpenEXR to VIPS
 *
 * 17/12/11
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
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/internal.h>

#include "../foreign/openexr2vips.h"

int
im_exr2vips( const char *filename, IMAGE *out )
{
#ifdef HAVE_OPENEXR
	return( vips__openexr_read( filename, out ) ); 
#else
	vips_error( "im_exr2vips", 
		"%s", _( "no OpenEXR support in your libvips" ) ); 

	return( -1 );
#endif /*HAVE_OPENEXR*/
}

static const char *exr_suffs[] = { ".exr", NULL };

static VipsFormatFlags
exr_flags( const char *name )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

	return( (VipsFormatFlags) 
		vips_foreign_flags( "openexrload", filename ) );
}

static int
isexr( const char *name )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

	return( vips_foreign_is_a( "openexrload", filename ) );
}

/* exr format adds no new members.
 */
typedef VipsFormat VipsFormatExr;
typedef VipsFormatClass VipsFormatExrClass;

static void
vips_format_exr_class_init( VipsFormatExrClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "exr";
	object_class->description = _( "OpenEXR" );

	format_class->is_a = isexr;
	format_class->load = im_exr2vips;
	format_class->get_flags = exr_flags;
	format_class->suffs = exr_suffs;
}

static void
vips_format_exr_init( VipsFormatExr *object )
{
}

G_DEFINE_TYPE( VipsFormatExr, vips_format_exr, VIPS_TYPE_FORMAT );

