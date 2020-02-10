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

#include "pforeign.h"

/* The largest item we can read. It only needs to be big enough for a double.
 */
#define MAX_ITEM_SIZE (256)

typedef struct _VipsForeignLoadCsv {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsSource *source;

	/* Buffered source.
	 */
	VipsSbuf *sbuf;

	/* Load options.
	 */
	int skip;
	int lines;
	const char *whitespace;
	const char *separator;

	/* Current position in file for error messages.
	 */
	int lineno;
	int colno;

	/* Our whitespace and separator strings turned into LUTs.
	 */
	char whitemap[256];
	char sepmap[256];

	/* Fetch items into this buffer. It just needs to be large enough for
	 * a double.
	 */
	char item[MAX_ITEM_SIZE];

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

/* Skip to the start of the next block of non-whitespace.
 *
 * FIXME ... we should have something to stop \n appearing in whitespace
 */
static int 
vips_foreign_load_csv_skip_white( VipsForeignLoadCsv *csv )
{
        int ch;

	do {
		ch = VIPS_SBUF_GETC( csv->sbuf );
	} while( ch != EOF && 
		ch != '\n' && 
		csv->whitemap[ch] );

	VIPS_SBUF_UNGETC( csv->sbuf );

	return( ch );
}

/* We have just seen " (open quotes). Skip to just after the matching close 
 * quotes. 
 *
 * If there is no matching close quotes before the end of the line, don't
 * skip to the  next line.
 */
static int 
vips_foreign_load_csv_skip_quoted( VipsForeignLoadCsv *csv )
{
        int ch;

	do {
		ch = VIPS_SBUF_GETC( csv->sbuf );

		/* Ignore \" in strings.
		 */
		if( ch == '\\' ) 
			ch = VIPS_SBUF_GETC( csv->sbuf );
		else if( ch == '"' )
			break;
	} while( ch != EOF && 
		ch != '\n' );

	if( ch == '\n' )
		VIPS_SBUF_UNGETC( csv->sbuf );

	return( ch );
}

/* Fetch the next item, as a string. The string is valid until the next call
 * to fetch item.
 */
static const char *
vips_foreign_load_csv_fetch_item( VipsForeignLoadCsv *csv )
{
	int write_point;
	int space_remaining;
	int ch;

	write_point = 0;
	space_remaining = MAX_ITEM_SIZE;

	while( (ch = VIPS_SBUF_GETC( csv->sbuf )) != -1 &&
		ch != '\n' &&
		!csv->whitemap[ch] &&
		!csv->sepmap[ch] &&
		space_remaining > 0 ) {
		csv->item[write_point] = ch;
		write_point += 1;
		space_remaining -= 1;
	}
	csv->item[write_point] = '\0';

	/* If we hit EOF immediately, return EOF.
	 */
	if( ch == -1 && 
		write_point == 0 )
		return( NULL );

	/* If we filled the item buffer without seeing the end of the item, 
	 * keep going.
	 */
	if( space_remaining == 0 &&
		ch != '\n' &&
		!csv->whitemap[ch] &&
		!csv->sepmap[ch] ) {
		while( (ch = VIPS_SBUF_GETC( sbuf )) != -1 &&
			ch != '\n' && 
			!csv->whitemap[ch] &&
			!csv->sepmap[ch] ) 
			;
	}

	return( csv->item );
}

/* Read a single item. The syntax is:
 *
 * element : 
 * 	whitespace* item whitespace* [EOF|EOL|separator]
 *
 * item : 
 * 	double |
 * 	"anything" |
 * 	empty
 *
 * the anything in quotes can contain " escaped with \, and can contain
 * separator and whitespace characters.
 *
 * Return the char that caused failure on fail (EOF or \n).
 */
static int
vips_foreign_load_csv_read_double( VipsForeignLoadCsv *csv, double *out )
{
	int ch;

	/* The fscanf() may change this ... but all other cases need a zero.
	 */
	*out = 0;

	ch = vips_foreign_load_csv_skip_white( csv );
	if( ch == EOF || 
		ch == '\n' ) 
		return( ch );

	if( ch == '"' ) {
		(void) VIPS_SBUF_GETC( csv->sbuf );
		(void) vips_foreign_load_csv_skip_quoted( fp );
	}
	else if( !csv->sepmap[ch] ) {

		\\
			
			g_ascii_strtod( 
		fscanf( fp, "%lf", out ) != 1 ) {
		/* Only a warning, since (for example) exported spreadsheets
		 * will often have text or date fields.
		 */
		g_warning( _( "error parsing number, line %d, column %d" ),
			lineno, colno );
		if( fail )
			return( EOF ); 

		/* Step over the bad data to the next separator.
		 */
		(void) skip_to_sep( fp, sepmap );
	}

	/* Don't need to check result, we have read a field successfully.
	 */
	ch = skip_white( fp, whitemap );

	/* If it's a separator, we have to step over it. 
	 */
	if( ch != EOF && 
		sepmap[ch] ) 
		(void) vips__fgetc( fp );

	return( 0 );
}

static int
vips_foreign_load_csv_header( VipsForeignLoad *load )
{
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) load;

	if( vips__csv_read_header( csv->filename, load->out, 
		csv->skip, csv->lines, csv->whitespace, csv->separator,
		load->fail ) )
		return( -1 );

	VIPS_SETSTR( load->out->filename, csv->filename );

	return( 0 );
}

static int
vips_foreign_load_csv_load( VipsForeignLoad *load )
{
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) load;

	if( vips__csv_read( csv->filename, load->real, 
		csv->skip, csv->lines, csv->whitespace, csv->separator,
		load->fail ) )
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

	VIPS_ARG_INT( class, "skip", 20, 
		_( "Skip" ), 
		_( "Skip this many lines at the start of the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadCsv, skip ),
		0, 10000000, 0 );

	VIPS_ARG_INT( class, "lines", 21, 
		_( "Lines" ), 
		_( "Read this many lines from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadCsv, lines ),
		-1, 10000000, 0 );

	VIPS_ARG_STRING( class, "whitespace", 22, 
		_( "Whitespace" ), 
		_( "Set of whitespace characters" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadCsv, whitespace ),
		" " ); 

	VIPS_ARG_STRING( class, "separator", 23, 
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
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @skip: skip this many lines at start of file
 * * @lines: read this many lines from file
 * * @whitespace: set of whitespace characters
 * * @separator: set of separator characters
 * * @fail: %gboolean, fail on errors
 *
 * Load a CSV (comma-separated values) file. The output image is always 1 
 * band (monochrome), #VIPS_FORMAT_DOUBLE. Use vips_bandfold() to turn
 * RGBRGBRGB mono images into colour iamges. 
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
 * Setting @fail to %TRUE makes the reader fail on any errors. 
 *
 * See also: vips_image_new_from_file(), vips_bandfold().
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


