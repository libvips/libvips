/* load ppm from a file
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
#include <vips/buf.h>
#include <vips/internal.h>

#include "ppm.h"

typedef struct _VipsForeignLoadPpm {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadPpm;

typedef VipsForeignLoadClass VipsForeignLoadPpmClass;

G_DEFINE_TYPE( VipsForeignLoadPpm, vips_foreign_load_ppm, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_ppm_get_flags_filename( const char *filename )
{
	return( vips__ppm_flags( filename ) );
}

static VipsForeignFlags
vips_foreign_load_ppm_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) load;

	return( vips_foreign_load_ppm_get_flags_filename( ppm->filename ) );
}

static int
vips_foreign_load_ppm_header( VipsForeignLoad *load )
{
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) load;

	if( vips__ppm_header( ppm->filename, load->out ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_ppm_load( VipsForeignLoad *load )
{
	VipsForeignLoadPpm *ppm = (VipsForeignLoadPpm *) load;

	if( vips__ppm_load( ppm->filename, load->real ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_ppm_class_init( VipsForeignLoadPpmClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "ppmload";
	object_class->description = _( "load ppm from file" );

	foreign_class->suffs = vips__ppm_suffs;

	load_class->is_a = vips__ppm_isppm;
	load_class->get_flags_filename = 
		vips_foreign_load_ppm_get_flags_filename;
	load_class->get_flags = vips_foreign_load_ppm_get_flags;
	load_class->header = vips_foreign_load_ppm_header;
	load_class->load = vips_foreign_load_ppm_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadPpm, filename ),
		NULL );
}

static void
vips_foreign_load_ppm_init( VipsForeignLoadPpm *ppm )
{
}

/**
 * vips_ppmload:
 * @filename: file to load
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a PPM/PBM/PGM/PFM file into a VIPS image. 
 *
 * It can read 1, 8, 16 and 32 bit images, colour or monochrome,
 * stored in binary or in ASCII. One bit images become 8 bit VIPS images, 
 * with 0 and 255 for 0 and 1.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_ppmload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "ppmload", ap, filename, out ); 
	va_end( ap );

	return( result );
}

