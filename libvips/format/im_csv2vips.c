/* Read a csv file.
 * 
 * 19/12/05 JC
 *	- hacked from ppm reader
 * 11/9/06
 * 	- now distingushes whitespace and separators, so we can have blank 
 * 	  fields
 * 20/9/06
 * 	- oop, unquoted trailing columns could get missed
 * 17/5/07
 * 	- added im_csv2vips_header()
 * 4/2/10
 * 	- gtkdoc
 * 1/3/10
 * 	- allow lines that end with EOF rather than \n
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <ctype.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Skip to the start of the next line (ie. read until we see a '\n'), return
 * zero if we are at EOF. 
 *
 * Files can end with EOF or with \nEOF. Tricky!
 */
static int 
skip_line( FILE *fp )
{
        int ch;

	/* Are we at a delayed EOF? See below.
	 */
	if( (ch = fgetc( fp )) == EOF )
		return( 0 );
	ungetc( ch, fp );

	/* If we hit EOF and no \n, wait until the next call to report EOF.
	 */
        while( (ch = fgetc( fp )) != '\n' && ch != EOF )
		;

	return( -1 );
}

static int 
skip_white( FILE *fp, const char whitemap[256] )
{
        int ch;

	do {
		ch = fgetc( fp );
	} while (ch != EOF && ch != '\n' && whitemap[ch] );

	ungetc( ch, fp );

	return( ch );
}

static int 
skip_to_sep( FILE *fp, const char sepmap[256] )
{
        int ch;

	do {
		ch = fgetc( fp );
	} while (ch != EOF && ch != '\n' && !sepmap[ch] );

	ungetc( ch, fp );

	return( ch );
}

/* Read a single item. Syntax is:
 *
 * item : whitespace* double? whitespace* [EOF|EOL|separator]
 *
 * Return the char that caused failure on fail (EOF or \n).
 */
static int
read_double( FILE *fp, const char whitemap[256], const char sepmap[256],
	int lineno, int colno, double *out )
{
	int ch;

	/* The fscanf() may change this ... but all other cases need a zero.
	 */
	*out = 0;

	ch = skip_white( fp, whitemap );
	if( ch == EOF || ch == '\n' ) 
		return( ch );

	if( !sepmap[ch] && fscanf( fp, "%lf", out ) != 1 ) {
		/* Only a warning, since (for example) exported spreadsheets
		 * will often have text or date fields.
		 */
		im_warn( "im_csv2vips", 
			_( "error parsing number, line %d, column %d" ),
			lineno, colno );

		/* Step over the bad data to the next separator.
		 */
		ch = skip_to_sep( fp, sepmap );
	}

	/* Don't need to check result, we have read a field successfully.
	 */
	ch = skip_white( fp, whitemap );

	/* If it's a separator, we have to step over it. 
	 */
	if( ch != EOF && sepmap[ch] ) 
		(void) fgetc( fp );

	return( 0 );
}

static int
read_csv( FILE *fp, IMAGE *out, 
	int start_skip, 
	const char *whitespace, const char *separator, 
	int lines )
{
	int i;
	char whitemap[256];
	char sepmap[256];
	const char *p;
	fpos_t pos;
	int columns;
	int ch;
	double d;
	double *buf;
	int y;

	/* Make our char maps. 
	 */
	for( i = 0; i < 256; i++ ) {
		whitemap[i] = 0;
		sepmap[i] = 0;
	}
	for( p = whitespace; *p; p++ )
		whitemap[(int) *p] = 1;
	for( p = separator; *p; p++ )
		sepmap[(int) *p] = 1;

	/* Skip first few lines.
	 */
	for( i = 0; i < start_skip; i++ )
		if( !skip_line( fp ) ) {
			im_error( "im_csv2vips", 
				"%s", _( "end of file while skipping start" ) );
			return( -1 );
		}

	/* Parse the first line to get number of columns. Only bother checking
	 * fgetpos() the first time we use it: assume it's working after this.
	 */
	if( fgetpos( fp, &pos ) ) {
		im_error_system( errno, "im_csv2vips", 
			"%s", _( "unable to seek" ) );
		return( -1 );
	}
	for( columns = 0; 
		(ch = read_double( fp, whitemap, sepmap, 
			start_skip + 1, columns + 1, &d )) == 0; 
		columns++ )
		;
	fsetpos( fp, &pos );

	if( columns == 0 ) {
		im_error( "im_csv2vips", "%s", _( "empty line" ) );
		return( -1 );
	}
	if( ch == -2 ) 
		/* Failed to parse a number.
		 */
		return( -1 );

	/* If lines is -1, we have to parse the whole file to get the
	 * number of lines out.
	 */
	if( lines == -1 ) {
		fgetpos( fp, &pos );
		for( lines = 0; skip_line( fp ); lines++ )
			;
		fsetpos( fp, &pos );

		printf( "detected %d lines after skip\n", lines );
	}

	im_initdesc( out, columns, lines, 1, 
		IM_BBITS_DOUBLE, IM_BANDFMT_DOUBLE, 
		IM_CODING_NONE, IM_TYPE_B_W, 1.0, 1.0, 0, 0 );

	if( im_outcheck( out ) || im_setupout( out ) ||
		!(buf = IM_ARRAY( out, IM_IMAGE_N_ELEMENTS( out ), double )) )
		return( -1 );

	for( y = 0; y < lines; y++ ) {
		int x;

		for( x = 0; x < columns; x++ ) {
			ch = read_double( fp, whitemap, sepmap,
				y + start_skip + 1, x + 1, &d );
			if( ch == EOF ) {
				im_error( "im_csv2vips", 
					"%s", _( "unexpected end of file" ) );
				return( -1 );
			}
			else if( ch == '\n' ) {
				im_error( "im_csv2vips", 
					"%s", _( "unexpected end of line" ) );
				return( -1 );
			}
			else if( ch )
				/* Parse error.
				 */
				return( -1 );

			buf[x] = d;
		}

		if( im_writeline( y, out, (PEL *) buf ) )
			return( -1 );

		/* Skip over the '\n' to the next line.
		 */
		skip_line( fp );
	}

	return( 0 );
}

/**
 * im_csv2vips:
 * @filename: file to load
 * @out: image to write to
 *
 * Load a CSV (comma-separated values) file. The output image is always 1 
 * band (monochrome), %IM_BANDFMT_DOUBLE. 
 * The reader is deliberately rather fussy: it will fail if there are any 
 * short lines, or if the file is too short. It will ignore lines that are 
 * too long.
 *
 * Read options can be embedded in the filename. The options can be given 
 * in any order and are:
 *
 * <itemizedlist>
 *   <listitem>
 *     <para>
 * <emphasis>skip:lines-to-skip</emphasis> The number of lines to skip at 
 * the start of the file. Default zero.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>line:lines-to-read</emphasis> 
 * The number of lines to read from the file. Default -1, meaning read to end of
 * file.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>whi:whitespace-characters</emphasis> 
 * The skippable whitespace characters. Default <emphasis>space</emphasis> and 
 * double quotes (").
 * Whitespace characters are always run together.
 *     </para>
 *   </listitem>
 *   <listitem>
 *     <para>
 * <emphasis>sep:separator-characters</emphasis> 
 * The characters that separate fields. Default ;,<emphasis>tab</emphasis>. 
 * Separators are never run together.
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * For example:
 *
 * |[
 * im_csv2vips( "fred.csv:skip:58,sep:\,,line:3", out );
 * ]|
 *
 * Will read three lines starting at line 59, with comma as the only
 * allowed separator. Note that the ',' has to be escaped with a backslash.
 *
 * See also: #VipsFormat, im_vips2csv(), im_read_dmask(), im_ppm2vips().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_csv2vips( const char *filename, IMAGE *out )
{
	/* Read options.
	 */
	int start_skip = 0;
	char *whitespace = " \"";
	char *separator = ";,\t";
	int lines = -1;

	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *p, *q, *r;
	FILE *fp;

	/* Parse mode string.
	 */
	im_filename_split( filename, name, mode );
	p = &mode[0];
	while( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "ski", q ) && (r = im_getsuboption( q )) )
			start_skip = atoi( r );
		else if( im_isprefix( "whi", q ) && (r = im_getsuboption( q )) )
			whitespace = r;
		else if( im_isprefix( "sep", q ) && (r = im_getsuboption( q )) )
			separator = r;
		else if( im_isprefix( "lin", q ) && (r = im_getsuboption( q )) )
			lines = atoi( r );
	}

	if( !(fp = fopen( name, "r" )) ) {
		im_error( "im_csv2vips", 
			_( "unable to open \"%s\"" ), name );
		return( -1 );
	}

	if( read_csv( fp, out, start_skip, whitespace, separator, lines ) ) {
		fclose( fp );
		return( -1 );
	}
	fclose( fp );

	return( 0 );
}

/* We can't just read the header of a CSV. Instead, we read to a temp image,
 * then copy just the header to the output.
 */
static int
csv2vips_header( const char *filename, IMAGE *out )
{
	IMAGE *t;

	if( !(t = im_open( "im_csv2vips_header", "p" )) )
		return( -1 );
	if( im_csv2vips( filename, t ) ||
		im_cp_desc( out, t ) ) {
		im_close( t );
		return( -1 );
	}
	im_close( t );

	return( 0 );
}

static const char *csv_suffs[] = { ".csv", NULL };

/* csv format adds no new members.
 */
typedef VipsFormat VipsFormatCsv;
typedef VipsFormatClass VipsFormatCsvClass;

static void
vips_format_csv_class_init( VipsFormatCsvClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "csv";
	object_class->description = _( "CSV" );

	format_class->header = csv2vips_header;
	format_class->load = im_csv2vips;
	format_class->save = im_vips2csv;
	format_class->suffs = csv_suffs;
}

static void
vips_format_csv_init( VipsFormatCsv *object )
{
}

G_DEFINE_TYPE( VipsFormatCsv, vips_format_csv, VIPS_TYPE_FORMAT );
