/* load fits from a file
 *
 * 5/12/11
 * 	- from openslideload.c
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

#ifdef HAVE_CFITSIO

#include "fits.h"

typedef struct _VipsForeignLoadFits {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadFits;

typedef VipsForeignLoadClass VipsForeignLoadFitsClass;

G_DEFINE_TYPE( VipsForeignLoadFits, vips_foreign_load_fits, 
	VIPS_TYPE_FOREIGN_LOAD );

static int
vips_foreign_load_fits_header( VipsForeignLoad *load )
{
	VipsForeignLoadFits *fits = (VipsForeignLoadFits *) load;

	if( vips__fits_read_header( fits->filename, load->out ) ) 
		return( -1 );

	VIPS_SETSTR( load->out->filename, fits->filename );

	return( 0 );
}

static int
vips_foreign_load_fits_load( VipsForeignLoad *load )
{
	VipsForeignLoadFits *fits = (VipsForeignLoadFits *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( fits ), 2 );

	t[0] = vips_image_new();
	if( vips__fits_read( fits->filename, t[0] ) || 
		vips_flip( t[0], &t[1], VIPS_DIRECTION_VERTICAL, NULL ) ||
		vips_image_write( t[1], load->real ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_fits_class_init( VipsForeignLoadFitsClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "fitsload";
	object_class->description = _( "load a FITS image" );

	/* is_a() is not that quick ... lower the priority.
	 */
	foreign_class->priority = -50;

	foreign_class->suffs = vips__fits_suffs;

	load_class->is_a = vips__fits_isfits;
	load_class->header = vips_foreign_load_fits_header;
	load_class->load = vips_foreign_load_fits_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadFits, filename ),
		NULL );
}

static void
vips_foreign_load_fits_init( VipsForeignLoadFits *fits )
{
}

#endif /*HAVE_CFITSIO*/

/**
 * vips_fitsload:
 * @filename: file to load
 * @out: decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a FITS image file into a VIPS image. 
 *
 * This operation can read images with up to three dimensions. Any higher
 * dimensions must be empty. 
 *
 * It can read 8, 16 and 32-bit integer images, signed and unsigned, float and 
 * double. 
 *
 * FITS metadata is attached with the "fits-" prefix.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_fitsload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "fitsload", ap, filename, out );
	va_end( ap );

	return( result );
}
