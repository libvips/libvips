/* save to csv
 *
 * 2/12/11
 * 	- wrap a class around the csv writer
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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "pforeign.h"

typedef struct _VipsForeignSaveCsv {
	VipsForeignSave parent_object;

	VipsTarget *target;

	const char *separator;
} VipsForeignSaveCsv;

typedef VipsForeignSaveClass VipsForeignSaveCsvClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveCsv, vips_foreign_save_csv, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_csv_dispose( GObject *gobject )
{
	VipsForeignSaveCsv *csv = (VipsForeignSaveCsv *) gobject;

	if( csv->target ) 
		vips_target_finish( csv->target );
	VIPS_UNREF( csv->target );

	G_OBJECT_CLASS( vips_foreign_save_csv_parent_class )->
		dispose( gobject );
}

#define PRINT_INT( TYPE ) { \
	TYPE *pt = (TYPE *) p; \
	\
	for( x = 0; x < image->Xsize; x++ ) { \
		if( x > 0 ) \
			vips_target_writes( csv->target, csv->separator ); \
		vips_target_writef( csv->target, "%d", pt[x] ); \
	} \
}

#define PRINT_FLOAT( TYPE ) { \
	TYPE *pt = (TYPE *) p; \
	char buf[G_ASCII_DTOSTR_BUF_SIZE]; \
	\
	for( x = 0; x < image->Xsize; x++ ) { \
		if( x > 0 ) \
			vips_target_writes( csv->target, csv->separator ); \
		g_ascii_dtostr( buf, G_ASCII_DTOSTR_BUF_SIZE, pt[x] ); \
		vips_target_writes( csv->target, buf ); \
	} \
}

#define PRINT_COMPLEX( TYPE ) { \
	TYPE *pt = (TYPE *) p; \
	char buf[G_ASCII_DTOSTR_BUF_SIZE]; \
	\
	for( x = 0; x < image->Xsize; x++ ) { \
		if( x > 0 ) \
			vips_target_writes( csv->target, csv->separator ); \
		VIPS_TARGET_PUTC( csv->target, '(' ); \
		g_ascii_dtostr( buf, G_ASCII_DTOSTR_BUF_SIZE, pt[0] ); \
		vips_target_writes( csv->target, buf ); \
		VIPS_TARGET_PUTC( csv->target, ',' ); \
		g_ascii_dtostr( buf, G_ASCII_DTOSTR_BUF_SIZE, pt[1] ); \
		vips_target_writes( csv->target, buf ); \
		VIPS_TARGET_PUTC( csv->target, ')' ); \
		pt += 2; \
	} \
}

static int
vips_foreign_save_csv_block( VipsRegion *region, VipsRect *area, void *a )
{
	VipsForeignSaveCsv *csv = (VipsForeignSaveCsv *) a;
	VipsImage *image = region->im;

	int x, y;

	for( y = 0; y < area->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( region, 0, area->top + y );

		switch( image->BandFmt ) {
		case VIPS_FORMAT_UCHAR:		
			PRINT_INT( unsigned char ); break; 
		case VIPS_FORMAT_CHAR:		
			PRINT_INT( char ); break; 
		case VIPS_FORMAT_USHORT:		
			PRINT_INT( unsigned short ); break; 
		case VIPS_FORMAT_SHORT:		
			PRINT_INT( short ); break; 
		case VIPS_FORMAT_UINT:		
			PRINT_INT( unsigned int ); break; 
		case VIPS_FORMAT_INT:		
			PRINT_INT( int ); break; 
		case VIPS_FORMAT_FLOAT:		
			PRINT_FLOAT( float ); break; 
		case VIPS_FORMAT_DOUBLE:		
			PRINT_FLOAT( double ); break; 
		case VIPS_FORMAT_COMPLEX:	
			PRINT_COMPLEX( float ); break; 
		case VIPS_FORMAT_DPCOMPLEX:	
			PRINT_COMPLEX( double ); break; 

		default: 
			g_assert_not_reached();
		}

		if( vips_target_writes( csv->target, "\n" ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_foreign_save_csv_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveCsv *csv = (VipsForeignSaveCsv *) object;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_csv_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_check_mono( class->nickname, save->ready ) ||
		vips_check_uncoded( class->nickname, save->ready ) )
		return( -1 );

	if( vips_sink_disc( save->ready, vips_foreign_save_csv_block, csv ) )
		return( -1 );

	vips_target_finish( csv->target );

	return( 0 );
}

static const char *vips_foreign_save_csv_suffs[] = {
	".csv",
	NULL
};

static void
vips_foreign_save_csv_class_init( VipsForeignSaveCsvClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_csv_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "csvsave_base";
	object_class->description = _( "save image to csv" );
	object_class->build = vips_foreign_save_csv_build;

	foreign_class->suffs = vips_foreign_save_csv_suffs;

	save_class->saveable = VIPS_SAVEABLE_MONO;

	VIPS_ARG_STRING( class, "separator", 13, 
		_( "Separator" ), 
		_( "Separator characters" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCsv, separator ),
		"\t" ); 
}

static void
vips_foreign_save_csv_init( VipsForeignSaveCsv *csv )
{
	csv->separator = g_strdup( "\t" );
}

typedef struct _VipsForeignSaveCsvFile {
	VipsForeignSaveCsv parent_object;

	char *filename; 
} VipsForeignSaveCsvFile;

typedef VipsForeignSaveCsvClass VipsForeignSaveCsvFileClass;

G_DEFINE_TYPE( VipsForeignSaveCsvFile, vips_foreign_save_csv_file, 
	vips_foreign_save_csv_get_type() );

static int
vips_foreign_save_csv_file_build( VipsObject *object )
{
	VipsForeignSaveCsv *csv = (VipsForeignSaveCsv *) object;
	VipsForeignSaveCsvFile *file = (VipsForeignSaveCsvFile *) object;

	if( file->filename &&
		!(csv->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	return( VIPS_OBJECT_CLASS( vips_foreign_save_csv_file_parent_class )->
		build( object ) );
}

static void
vips_foreign_save_csv_file_class_init( VipsForeignSaveCsvFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "csvsave";
	object_class->build = vips_foreign_save_csv_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveCsvFile, filename ),
		NULL );

}

static void
vips_foreign_save_csv_file_init( VipsForeignSaveCsvFile *file )
{
}

typedef struct _VipsForeignSaveCsvTarget {
	VipsForeignSaveCsv parent_object;

	VipsTarget *target;
} VipsForeignSaveCsvTarget;

typedef VipsForeignSaveCsvClass VipsForeignSaveCsvTargetClass;

G_DEFINE_TYPE( VipsForeignSaveCsvTarget, vips_foreign_save_csv_target, 
	vips_foreign_save_csv_get_type() );

static int
vips_foreign_save_csv_target_build( VipsObject *object )
{
	VipsForeignSaveCsv *csv = (VipsForeignSaveCsv *) object;
	VipsForeignSaveCsvTarget *target = (VipsForeignSaveCsvTarget *) object;

	if( target->target ) {
		csv->target = target->target; 
		g_object_ref( csv->target );
	}

	return( VIPS_OBJECT_CLASS( vips_foreign_save_csv_target_parent_class )->
		build( object ) );
}

static void
vips_foreign_save_csv_target_class_init( VipsForeignSaveCsvTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "csvsave_target";
	object_class->build = vips_foreign_save_csv_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveCsvTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_csv_target_init( VipsForeignSaveCsvTarget *target )
{
}

/**
 * vips_csvsave: (method)
 * @in: image to save 
 * @filename: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @separator: separator string
 *
 * Writes the pixels in @in to the @filename as CSV (comma-separated values).
 * The image is written
 * one line of text per scanline. Complex numbers are written as 
 * "(real,imaginary)" and will need extra parsing I guess. Only the first band
 * is written. 
 *
 * @separator gives the string to use to separate numbers in the output. 
 * The default is "\\t" (tab).
 *
 * See also: vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_csvsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "csvsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_csvsave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @separator: separator string
 *
 * As vips_csvsave(), but save to a target.
 *
 * See also: vips_csvsave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_csvsave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "csvsave_target", ap, in, target );
	va_end( ap );

	return( result );
}
