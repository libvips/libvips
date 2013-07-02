/* load matrix from a file
 *
 * 5/12/11
 * 	- from csvload.c
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

#include "csv.h"

typedef struct _VipsForeignLoadMatrix {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadMatrix;

typedef VipsForeignLoadClass VipsForeignLoadMatrixClass;

G_DEFINE_TYPE( VipsForeignLoadMatrix, vips_foreign_load_matrix, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_matrix_get_flags_filename( const char *filename )
{
	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_matrix_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadMatrix *matrix = (VipsForeignLoadMatrix *) load;

	return( vips_foreign_load_matrix_get_flags_filename( matrix->filename ) );
}

static int
vips_foreign_load_matrix_header( VipsForeignLoad *load )
{
	VipsForeignLoadMatrix *matrix = (VipsForeignLoadMatrix *) load;

	int width;
	int height;
	double scale;
	double offset;

	if( vips__array_read_header( matrix->filename,
		&width, &height, &scale, &offset ) )
		return( -1 );

	vips_image_init_fields( load->out,
		width, height, 1, 
		VIPS_FORMAT_DOUBLE, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );
	vips_image_set_double( load->out, "scale", scale ); 
	vips_image_set_double( load->out, "offset", offset ); 

	return( 0 );
}

static int
vips_foreign_load_matrix_load( VipsForeignLoad *load )
{
	VipsForeignLoadMatrix *matrix = (VipsForeignLoadMatrix *) load;

	VipsImage *out; 

	if( !(out = vips__array_read( matrix->filename )) )
		return( -1 );
	if( vips_image_write( out, load->real ) ) {
		g_object_unref( out );
		return( -1 );
	}
	g_object_unref( out );

	return( 0 );
}

static void
vips_foreign_load_matrix_class_init( VipsForeignLoadMatrixClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "matrixload";
	object_class->description = _( "load matrix from file" );

	foreign_class->suffs = vips__foreign_matrix_suffs;

	load_class->get_flags_filename = 
		vips_foreign_load_matrix_get_flags_filename;
	load_class->get_flags = vips_foreign_load_matrix_get_flags;
	load_class->header = vips_foreign_load_matrix_header;
	load_class->load = vips_foreign_load_matrix_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadMatrix, filename ),
		NULL );
}

static void
vips_foreign_load_matrix_init( VipsForeignLoadMatrix *matrix )
{
}

/**
 * vips_matrixload:
 * @filename: file to load
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Reads a matrix from a file.
 *
 * Matrix files have a simple format that's supposed to be easy to create with
 * a text editor or a spreadsheet. 
 *
 * The first line has four numbers for width, height, scale and
 * offset (scale and offset may be omitted, in which case they default to 1.0
 * and 0.0). Scale must be non-zero. Width and height must be positive
 * integers. The numbers are separated by any mixture of spaces, commas, 
 * tabs and quotation marks ("). The scale and offset fields may be 
 * floating-point, and must use '.'
 * as a decimal separator.
 *
 * Subsequent lines each hold one line of matrix data, with numbers again
 * separated by any mixture of spaces, commas, 
 * tabs and quotation marks ("). The numbers may be floating-point, and must
 * use '.'
 * as a decimal separator.
 *
 * Extra characters at the ends of lines or at the end of the file are
 * ignored.
 *
 * See also: vips_csvload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_matrixload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "matrixload", ap, filename, out ); 
	va_end( ap );

	return( result );
}

