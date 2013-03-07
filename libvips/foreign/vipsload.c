/* load vips from a file
 *
 * 24/11/11
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

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsForeignLoadVips {
	VipsForeignLoad parent_object;

	char *filename;

} VipsForeignLoadVips;

typedef VipsForeignLoadClass VipsForeignLoadVipsClass;

G_DEFINE_TYPE( VipsForeignLoadVips, vips_foreign_load_vips, 
	VIPS_TYPE_FOREIGN_LOAD );

static gboolean
vips_foreign_load_vips_is_a( const char *filename )
{
	return( vips__file_magic( filename ) );
}

static VipsForeignFlags
vips_foreign_load_vips_get_flags_filename( const char *filename )
{
	VipsForeignFlags flags;

	flags = VIPS_FOREIGN_PARTIAL;

	if( vips__file_magic( filename ) == VIPS_MAGIC_SPARC ) 
		flags |= VIPS_FOREIGN_BIGENDIAN;

	return( flags );
}

static VipsForeignFlags
vips_foreign_load_vips_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadVips *vips = (VipsForeignLoadVips *) load;

	return( vips_foreign_load_vips_get_flags_filename( vips->filename ) );
}

static int
vips_foreign_load_vips_header( VipsForeignLoad *load )
{
	VipsForeignLoadVips *vips = (VipsForeignLoadVips *) load;
	VipsImage *out;
	VipsImage *out2;

	if( !(out2 = vips_image_new_from_file( vips->filename )) )
		return( -1 );

	/* Remove the @out that's there now. 
	 */
	g_object_get( load, "out", &out, NULL ); 
	g_object_unref( out );
	g_object_unref( out );

	g_object_set( load, "out", out2, NULL ); 

	return( 0 );
}

static const char *vips_suffs[] = { ".v", NULL };

static void
vips_foreign_load_vips_class_init( VipsForeignLoadVipsClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "vipsload";
	object_class->description = _( "load vips from file" );

	foreign_class->suffs = vips_suffs;

	load_class->is_a = vips_foreign_load_vips_is_a;
	load_class->get_flags = vips_foreign_load_vips_get_flags;
	load_class->get_flags_filename = 
		vips_foreign_load_vips_get_flags_filename;
	load_class->header = vips_foreign_load_vips_header;
	load_class->load = NULL;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadVips, filename ),
		NULL );
}

static void
vips_foreign_load_vips_init( VipsForeignLoadVips *vips )
{
}
