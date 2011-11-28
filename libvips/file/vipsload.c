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

#include <stdio.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef VipsFileLoad VipsFileLoadVips;
typedef VipsFileLoadClass VipsFileLoadVipsClass;

G_DEFINE_TYPE( VipsFileLoadVips, vips_file_load_vips, VIPS_TYPE_FILE_LOAD );

static gboolean
vips_file_load_vips_is_a( const char *filename )
{
	return( vips__file_magic( filename ) );
}

static int
vips_file_load_vips_get_flags( VipsFileLoad *load )
{
	VipsFile *file = VIPS_FILE( load );

	load->flags = VIPS_FILE_PARTIAL;

	if( vips__file_magic( file->filename ) == VIPS_MAGIC_INTEL ) {
		printf( "vips_file_load_vips_get_flags: "
			"%s is intel, setting bigendian\n",
			file->filename );
		load->flags |= VIPS_FILE_BIGENDIAN;
	}

	return( 0 );
}

static int
vips_file_load_vips_header( VipsFileLoad *load )
{
	VipsFile *file = VIPS_FILE( load );
	VipsImage *out;
	VipsImage *out2;

	if( !(out2 = vips_image_new_from_file( file->filename )) )
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
vips_file_load_vips_class_init( VipsFileLoadVipsClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFileClass *file_class = (VipsFileClass *) class;
	VipsFileLoadClass *load_class = (VipsFileLoadClass *) class;

	object_class->nickname = "vipsload";
	object_class->description = _( "load vips from file" );

	file_class->suffs = vips_suffs;

	load_class->is_a = vips_file_load_vips_is_a;
	load_class->get_flags = vips_file_load_vips_get_flags;
	load_class->header = vips_file_load_vips_header;
	load_class->load = NULL;
}

static void
vips_file_load_vips_init( VipsFileLoadVips *vips )
{
}

