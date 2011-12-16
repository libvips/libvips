/* load csv from a file
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
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "csv.h"

typedef struct _VipsForeignLoadCsv {
	VipsForeignLoad parent_object;

	/* Filename for load.
	 */
	char *filename; 

	int skip;
	int lines;
	const char *whitespace;
	const char *separator;

} VipsForeignLoadCsv;

typedef VipsForeignLoadClass VipsForeignLoadCsvClass;

G_DEFINE_TYPE( VipsForeignLoadCsv, vips_foreign_load_csv, 
	VIPS_TYPE_FOREIGN_LOAD );

static VipsForeignFlags
vips_foreign_load_csv_get_flags_filename( const char *filename )
{
	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_csv_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) load;

	return( vips_foreign_load_csv_get_flags_filename( csv->filename ) );
}

static int
vips_foreign_load_csv_header( VipsForeignLoad *load )
{
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) load;

	if( vips__csv_read_header( csv->filename, load->out, 
		csv->skip, csv->lines, csv->whitespace, csv->separator ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_csv_load( VipsForeignLoad *load )
{
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) load;

	if( vips__csv_read( csv->filename, load->real, 
		csv->skip, csv->lines, csv->whitespace, csv->separator ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_csv_class_init( VipsForeignLoadCsvClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "csvload";
	object_class->description = _( "load csv from file" );

	foreign_class->suffs = vips__foreign_csv_suffs;

	load_class->get_flags_filename = 
		vips_foreign_load_csv_get_flags_filename;
	load_class->get_flags = vips_foreign_load_csv_get_flags;
	load_class->header = vips_foreign_load_csv_header;
	load_class->load = vips_foreign_load_csv_load;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadCsv, filename ),
		NULL );

	VIPS_ARG_INT( class, "skip", 10, 
		_( "Skip" ), 
		_( "Skip this many lines at the start of the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadCsv, skip ),
		0, 10000000, 0 );

	VIPS_ARG_INT( class, "lines", 11, 
		_( "Lines" ), 
		_( "Read this many lines from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadCsv, lines ),
		-1, 10000000, 0 );

	VIPS_ARG_STRING( class, "whitespace", 12, 
		_( "Whitespace" ), 
		_( "Set of whitespace characters" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadCsv, whitespace ),
		" " ); 

	VIPS_ARG_STRING( class, "separator", 13, 
		_( "Separator" ), 
		_( "Set of separator characters" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadCsv, separator ),
		";,\t" ); 
}

static void
vips_foreign_load_csv_init( VipsForeignLoadCsv *csv )
{
	csv->lines = -1;
	csv->whitespace = g_strdup( " " );
	csv->separator = g_strdup( ";,\t" );
}

/**
 * vips_csvload:
 * @filename: file to load
 * @out: output image
 * @skip: skip this many lines at start of file
 * @lines: read this many lines from file
 * @whitespace: set of whitespace characters
 * @separator: set of separator characters
 * @...: %NULL-terminated list of optional named arguments
 *
 * Load a CSV (comma-separated values) file. The output image is always 1 
 * band (monochrome), #VIPS_FORMAT_DOUBLE. 
 *
 * Items in lines can be either floating point numbers in the C locale, or 
 * strings enclosed in double-quotes ("), or empty.
 * You can use a backslash (\) within the quotes to escape special characters,
 * such as quote marks.
 *
 * The reader is deliberately rather fussy: it will fail if there are any 
 * short lines, or if the file is too short. It will ignore lines that are 
 * too long.
 *
 * @skip sets the number of lines to skip at the start of the file. 
 * Default zero.
 *
 * @lines sets the number of lines to read from the file. Default -1, 
 * meaning read all lines to end of file.
 *
 * @whitespace sets the skippable whitespace characters. 
 * Default <emphasis>space</emphasis>.
 * Whitespace characters are always run together.
 *
 * @separator sets the characters that separate fields. 
 * Default ;,<emphasis>tab</emphasis>. Separators are never run together.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_csvload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "csvload", ap, filename, out ); 
	va_end( ap );

	return( result );
}


