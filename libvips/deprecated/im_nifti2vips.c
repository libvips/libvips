/* load nifti images
 *
 * 10/9/18
 *	- from im_openslide2vips
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
#include <vips/vips7compat.h>
#include <vips/thread.h>
#include <vips/internal.h>

static int
im_nifti2vips( const char *name, IMAGE *out )
{
	VipsImage *t;

	if( vips_niftiload( name, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static const char *nifti_suffs[] = { 
	".nii", ".nii.gz", 
	".hdr", ".hdr.gz", 
	".img", ".img.gz", 
	".nia", ".nia.gz", 
	NULL 
};

static VipsFormatFlags
nifti_flags( const char *name )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

	return( (VipsFormatFlags) 
		vips_foreign_flags( "niftiload", filename ) );
}

static int
isnifti( const char *name )
{
	char filename[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( name, filename, mode );

	return( vips_foreign_is_a( "niftiload", filename ) );
}

/* nifti format adds no new members.
 */
typedef VipsFormat VipsFormatNifti;
typedef VipsFormatClass VipsFormatNiftiClass;

static void
vips_format_nifti_class_init( VipsFormatNiftiClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "im_nifti";
	object_class->description = _( "NIfTI" );

	format_class->priority = 100;
	format_class->is_a = isnifti;
	format_class->load = im_nifti2vips;
	format_class->get_flags = nifti_flags;
	format_class->suffs = nifti_suffs;
}

static void
vips_format_nifti_init( VipsFormatNifti *object )
{
}

G_DEFINE_TYPE( VipsFormatNifti, vips_format_nifti, VIPS_TYPE_FORMAT );

