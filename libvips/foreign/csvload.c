/* load csv from a file
 *
 * 5/12/11
 * 	- from csvload.c
 * 21/2/20
 * 	- rewrite for new source API
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
#include <errno.h>

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

	/* A line of pixels.
	 */
	double *linebuf;

} VipsForeignLoadCsv;

typedef VipsForeignLoadClass VipsForeignLoadCsvClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadCsv, vips_foreign_load_csv, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_csv_dispose( GObject *gobject )
{
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) gobject;

	VIPS_UNREF( csv->source );
	VIPS_UNREF( csv->sbuf );
	VIPS_FREE( csv->linebuf );

	G_OBJECT_CLASS( vips_foreign_load_csv_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_csv_build( VipsObject *object )
{
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) object;

	int i;
	const char *p;

	if( !(csv->sbuf = vips_sbuf_new_from_source( csv->source )) )
		return( -1 );

	/* Make our char maps. 
	 */
	for( i = 0; i < 256; i++ ) {
		csv->whitemap[i] = 0;
		csv->sepmap[i] = 0;
	}
	for( p = csv->whitespace; *p; p++ )
		csv->whitemap[(int) *p] = 1;
	for( p = csv->separator; *p; p++ )
		csv->sepmap[(int) *p] = 1;

	/* \n must not be in the maps or we'll get very confused.
	 */
	csv->sepmap[(int) '\n'] = 0;
	csv->whitemap[(int) '\n'] = 0;

	if( VIPS_OBJECT_CLASS( vips_foreign_load_csv_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_csv_get_flags( VipsForeignLoad *load )
{
	return( 0 );
}

/* Skip to the start of the next block of non-whitespace.
 *
 * Result: !white, \n, EOF
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
 * skip to the next line.
 *
 * Result: ", \n, EOF
 */
static int 
vips_foreign_load_csv_skip_quoted( VipsForeignLoadCsv *csv )
{
        int ch;

	do {
		ch = VIPS_SBUF_GETC( csv->sbuf );

		/* Ignore \" (actually \anything) in strings.
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

/* Fetch the next item (not whitespace, separator or \n), as a string. The 
 * returned string is valid until the next call to fetch item. NULL for EOF.
 */
static const char *
vips_foreign_load_csv_fetch_item( VipsForeignLoadCsv *csv )
{
	int write_point;
	int space_remaining;
	int ch;

	/* -1 so there's space for the \0 terminator.
	 */
	space_remaining = MAX_ITEM_SIZE - 1;
	write_point = 0;

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
	 * read up to the item end.
	 */
	while( ch != -1 &&
		ch != '\n' &&
		!csv->whitemap[ch] &&
		!csv->sepmap[ch] ) 
		ch = VIPS_SBUF_GETC( csv->sbuf );

	/* We've (probably) read the end of item character. Push it bakc.
	 */
	if( ch == '\n' ||
		csv->whitemap[ch] ||
		csv->sepmap[ch] ) 
		VIPS_SBUF_UNGETC( csv->sbuf );

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
 * Result: sep, \n, EOF
 */
static int
vips_foreign_load_csv_read_double( VipsForeignLoadCsv *csv, double *out )
{
	int ch;

	/* The strtod() may change this ... but all other cases need a zero.
	 */
	*out = 0;

	ch = vips_foreign_load_csv_skip_white( csv );
	if( ch == EOF || 
		ch == '\n' ) 
		return( ch );

	if( ch == '"' ) {
		(void) VIPS_SBUF_GETC( csv->sbuf );
		ch = vips_foreign_load_csv_skip_quoted( csv );
	}
	else if( !csv->sepmap[ch] ) {
		const char *item;

		item = vips_foreign_load_csv_fetch_item( csv );
		if( !item )
			return( EOF );

		if( vips_strtod( item, out ) ) 
			/* Only a warning, since (for example) exported 
			 * spreadsheets will often have text or date fields.
			 */
			g_warning( _( "bad number, line %d, column %d" ),
				csv->lineno, csv->colno );
	}

	ch = vips_foreign_load_csv_skip_white( csv );
	if( ch == EOF || 
		ch == '\n' ) 
		return( ch );

	/* If it's a separator, we have to step over it. 
	 */
	if( csv->sepmap[ch] ) 
		(void) VIPS_SBUF_GETC( csv->sbuf ); 

	return( ch );
}

static int
vips_foreign_load_csv_header( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) load;

	int i;
	double value;
	int ch;
	int width;
	int height;

	/* Rewind.
	 */
	vips_sbuf_unbuffer( csv->sbuf );
	if( vips_source_rewind( csv->source ) )
		return( -1 );

	/* Skip the first few lines.
	 */
	for( i = 0; i < csv->skip; i++ )
		if( !vips_sbuf_get_line( csv->sbuf ) ) {
			vips_error( class->nickname,
				"%s", _( "unexpected end of file" ) );
			return( -1 );
		}

	/* Parse the first line to get the number of columns.
	 */
	csv->lineno = csv->skip + 1;
	csv->colno = 0;
	do {
		csv->colno += 1;
		ch = vips_foreign_load_csv_read_double( csv, &value );
	} while( ch != '\n' &&
		ch != EOF );
	width = csv->colno;

	if( !(csv->linebuf = VIPS_ARRAY( NULL, width, double )) )
		return( -1 );

	/* If @lines is -1, we must scan the whole file to get the height.
	 */
	if( csv->lines == -1 ) 
		for( height = 0; vips_sbuf_get_line( csv->sbuf ); height++ )
			;
	else 
		height = csv->lines;

	vips_image_pipelinev( load->out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );
	vips_image_init_fields( load->out,
		width, height, 1, 
		VIPS_FORMAT_DOUBLE, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );

	VIPS_SETSTR( load->out->filename, 
		vips_connection_filename( VIPS_CONNECTION( csv->source ) ) );

	return( 0 );
}

static int
vips_foreign_load_csv_load( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) load;

	int i;
	int x, y;
	int ch;

	/* Rewind.
	 */
	vips_sbuf_unbuffer( csv->sbuf );
	if( vips_source_rewind( csv->source ) )
		return( -1 );

	/* Skip the first few lines.
	 */
	for( i = 0; i < csv->skip; i++ )
		if( !vips_sbuf_get_line( csv->sbuf ) ) {
			vips_error( class->nickname,
				"%s", _( "unexpected end of file" ) );
			return( -1 );
		}

	vips_image_pipelinev( load->real, VIPS_DEMAND_STYLE_THINSTRIP, NULL );
	vips_image_init_fields( load->real,
		load->out->Xsize, load->out->Ysize, 1, 
		VIPS_FORMAT_DOUBLE, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );

	csv->lineno = csv->skip + 1;
	for( y = 0; y < load->real->Ysize; y++ ) {
		csv->colno = 0;

		/* Not needed, but stops a used-before-set compiler warning.
		 */
		ch = EOF;

		for( x = 0; x < load->real->Xsize; x++ ) {
			double value;

			csv->colno += 1;
			ch = vips_foreign_load_csv_read_double( csv, &value );
			if( ch == EOF ) {
				vips_error( class->nickname,
					"%s", _( "unexpected end of file" ) );
				return( -1 );
			}
			if( ch == '\n' &&
				x != load->real->Xsize - 1 ) {
				vips_error( class->nickname,
					_( "line %d has only %d columns" ),
					csv->lineno, csv->colno );
				if( load->fail )
					return( -1 );
			}

			csv->linebuf[x] = value;
		}

		/* Step over the line separator.
		 */
		if( ch == '\n' ) {
			(void) VIPS_SBUF_GETC( csv->sbuf ); 
			csv->lineno += 1;
		}

		if( vips_image_write_line( load->real, y, 
			(VipsPel *) csv->linebuf ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_foreign_load_csv_class_init( VipsForeignLoadCsvClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_csv_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "csvload_base";
	object_class->description = _( "load csv" );
	object_class->build = vips_foreign_load_csv_build;

	load_class->get_flags = vips_foreign_load_csv_get_flags;
	load_class->header = vips_foreign_load_csv_header;
	load_class->load = vips_foreign_load_csv_load;

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

typedef struct _VipsForeignLoadCsvFile {
	VipsForeignLoadCsv parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadCsvFile;

typedef VipsForeignLoadCsvClass VipsForeignLoadCsvFileClass;

G_DEFINE_TYPE( VipsForeignLoadCsvFile, vips_foreign_load_csv_file,
	vips_foreign_load_csv_get_type() );

static VipsForeignFlags
vips_foreign_load_csv_file_get_flags_filename( const char *filename )
{
	return( 0 );
}

static int
vips_foreign_load_csv_file_build( VipsObject *object )
{
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) object;
	VipsForeignLoadCsvFile *file = (VipsForeignLoadCsvFile *) object;

	if( file->filename ) 
		if( !(csv->source = 
			vips_source_new_from_file( file->filename )) )
			return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_csv_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static const char *vips_foreign_load_csv_suffs[] = {
	".csv",
	NULL
};

static void
vips_foreign_load_csv_file_class_init( VipsForeignLoadCsvFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "csvload";
	object_class->build = vips_foreign_load_csv_file_build;

	foreign_class->suffs = vips_foreign_load_csv_suffs;

	load_class->get_flags_filename = 
		vips_foreign_load_csv_file_get_flags_filename;

	VIPS_ARG_STRING( class, "filename", 1,
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadCsvFile, filename ),
		NULL );

}

static void
vips_foreign_load_csv_file_init( VipsForeignLoadCsvFile *file )
{
}

typedef struct _VipsForeignLoadCsvSource {
	VipsForeignLoadCsv parent_object;

	VipsSource *source;

} VipsForeignLoadCsvSource;

typedef VipsForeignLoadCsvClass VipsForeignLoadCsvSourceClass;

G_DEFINE_TYPE( VipsForeignLoadCsvSource, vips_foreign_load_csv_source,
	vips_foreign_load_csv_get_type() );

static int
vips_foreign_load_csv_source_build( VipsObject *object )
{
	VipsForeignLoadCsv *csv = (VipsForeignLoadCsv *) object;
	VipsForeignLoadCsvSource *source = (VipsForeignLoadCsvSource *) object;

	if( source->source ) {
		csv->source = source->source;
		g_object_ref( csv->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_csv_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static gboolean
vips_foreign_load_csv_source_is_a_source( VipsSource *source )
{
	/* Detecting CSV files automatically is tricky. Define this method to
	 * prevent a warning, but users will need to run the csv loader
	 * explicitly.
	 */
	return( FALSE );
}

static void
vips_foreign_load_csv_source_class_init( VipsForeignLoadCsvFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "csvload_source";
	object_class->build = vips_foreign_load_csv_source_build;

	load_class->is_a_source = vips_foreign_load_csv_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadCsvSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_csv_source_init( VipsForeignLoadCsvSource *source )
{
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

/**
 * vips_csvload_source:
 * @source: source to load
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
 * Exactly as vips_csvload(), but read from a source. 
 *
 * See also: vips_csvload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_csvload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "csvload_source", ap, source, out ); 
	va_end( ap );

	return( result );
}




