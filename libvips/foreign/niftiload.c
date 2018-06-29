/* load nifti from a file
 *
 * 29/6/18
 * 	- from niftiload.c
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
#include <vips/debug.h>
#include <vips/internal.h>

#ifdef HAVE_NIFTI

#include <nifti1_io.h>

#include "pforeign.h"

typedef struct _VipsForeignLoadNifti {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadNifti;

typedef VipsForeignLoadClass VipsForeignLoadNiftiClass;

G_DEFINE_TYPE( VipsForeignLoadNifti, vips_foreign_load_nifti, 
	VIPS_TYPE_FOREIGN_LOAD );

static int
vips_foreign_load_nifti_is_a( const char *filename )
{
	nifti_image *nim;

	gboolean result;

	VIPS_DEBUG_MSG( "nifti_is_a: testing \"%s\"\n", filename );

	result = FALSE;
	if( (nim = nifti_image_read( filename, FALSE )) ) {
		nifti_image_free( nim );
		result = TRUE;
	}

	return( result );
}

static int
vips_foreign_load_nifti_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadNifti *nifti = (VipsForeignLoadNifti *) load;

	nifti_image *nim;

	/* FALSE means don't read data, just the header. Use
	 * nifti_image_load() later to pull the data in.
	 */
	if( !(nim = nifti_image_read( nifti->filename, FALSE )) ) { 
		vips_error( class->nickname, 
			"%s", _( "unable to read NIFTI file" ) );
		return( 0 );
	}

	/* Set load->out.
	 */

	nifti_image_free( nim );

	VIPS_SETSTR( load->out->filename, nifti->filename );

	return( 0 );
}

const char *vips__nifti_suffs[] = { ".nii", ".nii.gz", NULL };

static void
vips_foreign_load_nifti_class_init( VipsForeignLoadNiftiClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "niftiload";
	object_class->description = _( "load a FITS image" );

	/* is_a() is not that quick ... lower the priority.
	 */
	foreign_class->priority = -50;

	foreign_class->suffs = vips__nifti_suffs;

	load_class->is_a = vips_foreign_load_nifti_is_a;
	load_class->header = vips_foreign_load_nifti_header;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadNifti, filename ),
		NULL );
}

static void
vips_foreign_load_nifti_init( VipsForeignLoadNifti *nifti )
{
}

#endif /*HAVE_CFITSIO*/

/**
 * vips_niftiload:
 * @filename: file to load
 * @out: (out): decompressed image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a NIFTI image file into a VIPS image. 
 *
 * NIFTI metadata is attached with the "nifti-" prefix.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_niftiload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "niftiload", ap, filename, out );
	va_end( ap );

	return( result );
}
