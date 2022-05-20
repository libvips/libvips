/* save to matrix
 *
 * 2/12/11
 * 	- wrap a class around the matrix writer
 * 21/2/20
 * 	- rewrite for the VipsTarget API
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "pforeign.h"

typedef struct _VipsForeignSaveMatrix {
	VipsForeignSave parent_object;

	VipsTarget *target;

	const char *separator;
} VipsForeignSaveMatrix;

typedef VipsForeignSaveClass VipsForeignSaveMatrixClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveMatrix, vips_foreign_save_matrix, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_matrix_dispose( GObject *gobject )
{
	VipsForeignSaveMatrix *matrix = (VipsForeignSaveMatrix *) gobject;

	VIPS_UNREF( matrix->target );

	G_OBJECT_CLASS( vips_foreign_save_matrix_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_save_matrix_block( VipsRegion *region, VipsRect *area, void *a )
{
	VipsForeignSaveMatrix *matrix = (VipsForeignSaveMatrix *) a;

	int x, y;

	for( y = 0; y < area->height; y++ ) {
		double *p = (double *) 
			VIPS_REGION_ADDR( region, 0, area->top + y );

		char buf[G_ASCII_DTOSTR_BUF_SIZE]; 

		for( x = 0; x < area->width; x++ ) {
			if( x > 0 ) 
				vips_target_writes( matrix->target, " " );

			g_ascii_dtostr( buf, G_ASCII_DTOSTR_BUF_SIZE, p[x] );
			vips_target_writes( matrix->target, buf ); 
		} 

		if( vips_target_writes( matrix->target, "\n" ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_foreign_save_matrix_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveMatrix *matrix = (VipsForeignSaveMatrix *) object;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	double scale;
	double offset;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_matrix_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_check_mono( class->nickname, save->ready ) ||
		vips_check_uncoded( class->nickname, save->ready ) )
		return( -1 );

	vips_target_writef( matrix->target, "%d %d", 
		save->ready->Xsize, save->ready->Ysize );
	scale = vips_image_get_scale( save->ready );
	offset = vips_image_get_offset( save->ready );
	if( scale != 1.0 || offset != 0.0 )
		vips_target_writef( matrix->target, " %g %g", scale, offset );
	if( vips_target_writes( matrix->target, "\n" ) )
		return( -1 );

	if( vips_sink_disc( save->ready,
		vips_foreign_save_matrix_block, matrix ) )
		return( -1 );

	if( vips_target_end( matrix->target ) )
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

static const char *vips_foreign_save_matrix_suffs[] = {
	".mat",
	NULL
};

static void
vips_foreign_save_matrix_class_init( VipsForeignSaveMatrixClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_matrix_dispose;

	object_class->nickname = "matrixsave_base";
	object_class->description = _( "save image to matrix" );
	object_class->build = vips_foreign_save_matrix_build;

	foreign_class->suffs = vips_foreign_save_matrix_suffs;

	save_class->saveable = VIPS_SAVEABLE_MONO;
	save_class->format_table = bandfmt_matrix;

}

static void
vips_foreign_save_matrix_init( VipsForeignSaveMatrix *matrix )
{
}

typedef struct _VipsForeignSaveMatrixFile {
	VipsForeignSaveMatrix parent_object;

	char *filename; 
} VipsForeignSaveMatrixFile;

typedef VipsForeignSaveMatrixClass VipsForeignSaveMatrixFileClass;

G_DEFINE_TYPE( VipsForeignSaveMatrixFile, vips_foreign_save_matrix_file, 
	vips_foreign_save_matrix_get_type() );

static int
vips_foreign_save_matrix_file_build( VipsObject *object )
{
	VipsForeignSaveMatrix *matrix = (VipsForeignSaveMatrix *) object;
	VipsForeignSaveMatrixFile *file = (VipsForeignSaveMatrixFile *) object;

	if( file->filename &&
		!(matrix->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	return( VIPS_OBJECT_CLASS( 
		vips_foreign_save_matrix_file_parent_class )->build( object ) );
}

static void
vips_foreign_save_matrix_file_class_init( 
	VipsForeignSaveMatrixFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "matrixsave";
	object_class->build = vips_foreign_save_matrix_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveMatrixFile, filename ),
		NULL );

}

static void
vips_foreign_save_matrix_file_init( VipsForeignSaveMatrixFile *file )
{
}

typedef struct _VipsForeignSaveMatrixTarget {
	VipsForeignSaveMatrix parent_object;

	VipsTarget *target;
} VipsForeignSaveMatrixTarget;

typedef VipsForeignSaveMatrixClass VipsForeignSaveMatrixTargetClass;

G_DEFINE_TYPE( VipsForeignSaveMatrixTarget, vips_foreign_save_matrix_target, 
	vips_foreign_save_matrix_get_type() );

static int
vips_foreign_save_matrix_target_build( VipsObject *object )
{
	VipsForeignSaveMatrix *matrix = (VipsForeignSaveMatrix *) object;
	VipsForeignSaveMatrixTarget *target = 
		(VipsForeignSaveMatrixTarget *) object;

	if( target->target ) {
		matrix->target = target->target; 
		g_object_ref( matrix->target );
	}

	return( VIPS_OBJECT_CLASS( 
		vips_foreign_save_matrix_target_parent_class )->
			build( object ) );
}

static void
vips_foreign_save_matrix_target_class_init( 
	VipsForeignSaveMatrixTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "matrixsave_target";
	object_class->build = vips_foreign_save_matrix_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveMatrixTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_matrix_target_init( VipsForeignSaveMatrixTarget *target )
{
}

typedef struct _VipsForeignPrintMatrix {
	VipsForeignSaveMatrix parent_object;

} VipsForeignPrintMatrix;

typedef VipsForeignSaveClass VipsForeignPrintMatrixClass;

G_DEFINE_TYPE( VipsForeignPrintMatrix, vips_foreign_print_matrix, 
	vips_foreign_save_matrix_get_type() );

static int
vips_foreign_print_matrix_build( VipsObject *object )
{
	VipsForeignSaveMatrix *matrix = (VipsForeignSaveMatrix *) object;

	if( !(matrix->target = vips_target_new_to_descriptor( 0 )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_print_matrix_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_print_matrix_class_init( VipsForeignPrintMatrixClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "matrixprint";
	object_class->description = _( "print matrix" );
	object_class->build = vips_foreign_print_matrix_build;
}

static void
vips_foreign_print_matrix_init( VipsForeignPrintMatrix *matrix )
{
}

/**
 * vips_matrixsave: (method)
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

/**
 * vips_matrixsave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * As vips_matrixsave(), but save to a target.
 *
 * See also: vips_matrixsave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_matrixsave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "matrixsave_target", ap, in, target );
	va_end( ap );

	return( result );
}

/**
 * vips_matrixprint: (method)
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
