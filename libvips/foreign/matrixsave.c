/* save to matrix
 *
 * 2/7/13
 * 	- wrap a class around the matrix writer
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
#define DEBUG_VERBOSE
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

#include "csv.h"

typedef struct _VipsForeignSaveMatrix {
	VipsForeignSave parent_object;

	/* Filename for save.
	 */
	char *filename; 

} VipsForeignSaveMatrix;

typedef VipsForeignSaveClass VipsForeignSaveMatrixClass;

G_DEFINE_TYPE( VipsForeignSaveMatrix, vips_foreign_save_matrix, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_matrix_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveMatrix *matrix = (VipsForeignSaveMatrix *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_matrix_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__matrix_write( save->ready, matrix->filename ) )
		return( -1 );

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static int bandfmt_matrix[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   D,  D,  D,  D,  D,  D, D, D, D, D
};

static void
vips_foreign_save_matrix_class_init( VipsForeignSaveMatrixClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "matrixsave";
	object_class->description = _( "save image to matrix file" );
	object_class->build = vips_foreign_save_matrix_build;

	foreign_class->suffs = vips__foreign_matrix_suffs;

	save_class->saveable = VIPS_SAVEABLE_MONO;
	save_class->format_table = bandfmt_matrix;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveMatrix, filename ),
		NULL );
}

static void
vips_foreign_save_matrix_init( VipsForeignSaveMatrix *matrix )
{
}

/**
 * vips_matrixsave:
 * @in: image to save 
 * @filename: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write @in to @filename in matrix format. See vips_matrixload() for a
 * description of the format.
 *
 * See also: vips_matrixload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_matrixsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "matrixsave", ap, in, filename );
	va_end( ap );

	return( result );
}

typedef struct _VipsForeignPrintMatrix {
	VipsForeignSave parent_object;

} VipsForeignPrintMatrix;

typedef VipsForeignSaveClass VipsForeignPrintMatrixClass;

G_DEFINE_TYPE( VipsForeignPrintMatrix, vips_foreign_print_matrix, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_print_matrix_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_print_matrix_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__matrix_write_file( save->ready, stdout ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_print_matrix_class_init( VipsForeignPrintMatrixClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	object_class->nickname = "matrixprint";
	object_class->description = _( "print matrix" );
	object_class->build = vips_foreign_print_matrix_build;

	foreign_class->suffs = vips__foreign_matrix_suffs;

	save_class->saveable = VIPS_SAVEABLE_MONO;
	save_class->format_table = bandfmt_matrix;
}

static void
vips_foreign_print_matrix_init( VipsForeignPrintMatrix *matrix )
{
}

/**
 * vips_matrixprint:
 * @in: image to print 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Print @in to %stdout in matrix format. See vips_matrixload() for a
 * description of the format.
 *
 * See also: vips_matrixload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_matrixprint( VipsImage *in, ... )
{
	va_list ap;
	int result;

	va_start( ap, in );
	result = vips_call_split( "matrixprint", ap, in );
	va_end( ap );

	return( result );
}
