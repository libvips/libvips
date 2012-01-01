/* load tiff from a file
 *
 * 5/12/11
 * 	- from tiffload.c
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_TIFF

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "tiff.h"

typedef struct _VipsForeignLoadTiff {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

	/* Load this page. 
	 */
	int page;

} VipsForeignLoadTiff;

typedef VipsForeignLoadClass VipsForeignLoadTiffClass;

G_DEFINE_TYPE( VipsForeignLoadTiff, vips_foreign_load_tiff, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_tiff_get_flags_filename( const char *filename )
{
	VipsForeignFlags flags;

	flags = 0;
	if( vips__istifftiled( filename ) ) 
		flags |= VIPS_FOREIGN_PARTIAL;

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_tiff_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadTiff *tiff = (VipsForeignLoadTiff *) load;

	return( vips_foreign_load_tiff_get_flags_filename( tiff->filename ) );
}

static int
vips_foreign_load_tiff_header( VipsForeignLoad *load )
{
	VipsForeignLoadTiff *tiff = (VipsForeignLoadTiff *) load;

	if( vips__tiff_read_header( tiff->filename, load->out, tiff->page ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_tiff_load( VipsForeignLoad *load )
{
	VipsForeignLoadTiff *tiff = (VipsForeignLoadTiff *) load;

	if( vips__tiff_read( tiff->filename, load->real, tiff->page ) )
		return( -1 );

	return( 0 );
}

const char *vips__foreign_tiff_suffs[] = { ".tif", ".tiff", NULL };

static void
vips_foreign_load_tiff_class_init( VipsForeignLoadTiffClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "tiffload";
	object_class->description = _( "load tiff from file" );

	foreign_class->suffs = vips__foreign_tiff_suffs;

	load_class->is_a = vips__istiff;
	load_class->get_flags_filename = 
		vips_foreign_load_tiff_get_flags_filename;
	load_class->get_flags = vips_foreign_load_tiff_get_flags;
	load_class->header = vips_foreign_load_tiff_header;
	load_class->load = vips_foreign_load_tiff_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadTiff, filename ),
		NULL );

	VIPS_ARG_INT( class, "page", 10, 
		_( "Page" ), 
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadTiff, page ),
		0, 100000, 0 );
}

static void
vips_foreign_load_tiff_init( VipsForeignLoadTiff *tiff )
{
}

#endif /*HAVE_TIFF*/
