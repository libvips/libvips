/* save to csv
 *
 * 2/12/11
 * 	- wrap a class around the csv writer
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

typedef struct _VipsForeignSaveCsv {
	VipsForeignSave parent_object;

	/* Filename for save.
	 */
	char *filename; 

	const char *separator;
} VipsForeignSaveCsv;

typedef VipsForeignSaveClass VipsForeignSaveCsvClass;

G_DEFINE_TYPE( VipsForeignSaveCsv, vips_foreign_save_csv, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_csv_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveCsv *csv = (VipsForeignSaveCsv *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_csv_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__csv_write( save->ready, csv->filename, csv->separator ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_csv_class_init( VipsForeignSaveCsvClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "csvsave";
	object_class->description = _( "save image to csv file" );
	object_class->build = vips_foreign_save_csv_build;

	foreign_class->suffs = vips__foreign_csv_suffs;

	save_class->saveable = VIPS_SAVEABLE_MONO;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveCsv, filename ),
		NULL );

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

/**
 * vips_csvsave:
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
