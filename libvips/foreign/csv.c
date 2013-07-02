/* Read/write csv files.
 * 
 * 19/12/05 JC
 *	- hacked from ppm reader
 * 9/6/06
 *	- hacked from im_debugim
 * 11/9/06
 * 	- now distingushes whitespace and separators, so we can have blank 
 * 	  fields
 * 20/9/06
 * 	- oop, unquoted trailing columns could get missed
 * 23/10/06
 * 	- allow separator to be specified (default "\t", <tab>)
 * 17/11/06
 * 	- oops, was broken
 * 17/5/07
 * 	- added im_csv2vips_header()
 * 4/2/10
 * 	- gtkdoc
 * 1/3/10
 * 	- allow lines that end with EOF 
 * 23/9/11
 * 	- allow quoted strings, including escaped quotes
 * 16/12/11
 * 	- rework as a set of fns ready for wrapping as a class
 * 23/2/12
 * 	- report positions for EOF/EOL errors
 * 2/7/13
 * 	- add array read/write
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "csv.h"

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
        while( (ch = fgetc( fp )) != '\n' && 
		ch != EOF )
		;

	return( -1 );
}

static int 
skip_white( FILE *fp, const char whitemap[256] )
{
        int ch;

	do {
		ch = fgetc( fp );
	} while( ch != EOF && 
		ch != '\n' && 
		whitemap[ch] );

	ungetc( ch, fp );

	return( ch );
}

static int 
skip_to_quote( FILE *fp )
{
        int ch;

	do {
		ch = fgetc( fp );

		/* Ignore \" in strings.
		 */
		if( ch == '\\' ) 
			ch = fgetc( fp );
		else if( ch == '"' )
			break;
	} while( ch != EOF && 
		ch != '\n' );

	ungetc( ch, fp );

	return( ch );
}

static int 
skip_to_sep( FILE *fp, const char sepmap[256] )
{
        int ch;

	do {
		ch = fgetc( fp );
	} while( ch != EOF && 
		ch != '\n' && 
		!sepmap[ch] );

	ungetc( ch, fp );

	return( ch );
}

/* Read a single item. Syntax is:
 *
 * element : 
 * 	whitespace* item whitespace* [EOF|EOL|separator]
 *
 * item : 
 * 	double |
 * 	"anything" |
 * 	empty
 *
 * the anything in quotes can contain " escaped with \
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
	if( ch == EOF || 
		ch == '\n' ) 
		return( ch );

	if( ch == '"' ) {
		(void) fgetc( fp );
		(void) skip_to_quote( fp );
		ch = fgetc( fp );
	}
	else if( !sepmap[ch] && 
		fscanf( fp, "%lf", out ) != 1 ) {
		/* Only a warning, since (for example) exported spreadsheets
		 * will often have text or date fields.
		 */
		vips_warn( "csv2vips", 
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
	if( ch != EOF && 
		sepmap[ch] ) 
		(void) fgetc( fp );

	return( 0 );
}

static int
read_csv( FILE *fp, VipsImage *out, 
	int skip, 
	int lines,
	const char *whitespace, const char *separator,
	gboolean read_image )
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
	for( i = 0; i < skip; i++ )
		if( !skip_line( fp ) ) {
			vips_error( "csv2vips", 
				"%s", _( "end of file while skipping start" ) );
			return( -1 );
		}

	/* Parse the first line to get number of columns. Only bother checking
	 * fgetpos() the first time we use it: assume it's working after this.
	 */
	if( fgetpos( fp, &pos ) ) {
		vips_error_system( errno, "csv2vips", 
			"%s", _( "unable to seek" ) );
		return( -1 );
	}
	for( columns = 0; 
		(ch = read_double( fp, whitemap, sepmap, 
			skip + 1, columns + 1, &d )) == 0; 
		columns++ )
		;
	fsetpos( fp, &pos );

	if( columns == 0 ) {
		vips_error( "csv2vips", "%s", _( "empty line" ) );
		return( -1 );
	}

	/* If lines is -1, we have to scan the whole file to get the
	 * number of lines out.
	 */
	if( lines == -1 ) {
		fgetpos( fp, &pos );
		for( lines = 0; skip_line( fp ); lines++ )
			;
		fsetpos( fp, &pos );
	}

	vips_image_init_fields( out,
		columns, lines, 1, 
		VIPS_FORMAT_DOUBLE, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );
	vips_demand_hint( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	/* Just reading the header? We are done.
	 */
	if( !read_image )
		return( 0 );

	if( !(buf = VIPS_ARRAY( out, 
		VIPS_IMAGE_N_ELEMENTS( out ), double )) )
		return( -1 );

	for( y = 0; y < lines; y++ ) {
		int x;

		for( x = 0; x < columns; x++ ) {
			int lineno = y + skip + 1;
			int colno = x + 1;

			ch = read_double( fp, whitemap, sepmap,
				lineno, colno, &d );
			if( ch == EOF ) {
				vips_error( "csv2vips", 
					_( "unexpected EOF, line %d col %d" ), 
					lineno, colno );
				return( -1 );
			}
			else if( ch == '\n' ) {
				vips_error( "csv2vips", 
					_( "unexpected EOL, line %d col %d" ), 
					lineno, colno );
				return( -1 );
			}
			else if( ch )
				/* Parse error.
				 */
				return( -1 );

			buf[x] = d;
		}

		if( vips_image_write_line( out, y, (VipsPel *) buf ) )
			return( -1 );

		/* Skip over the '\n' to the next line.
		 */
		skip_line( fp );
	}

	return( 0 );
}

int
vips__csv_read( const char *filename, VipsImage *out,
	int skip, int lines, const char *whitespace, const char *separator )
{
	FILE *fp;

	if( !(fp = vips__file_open_read( filename, NULL, TRUE )) ) 
		return( -1 );
	if( read_csv( fp, out, skip, lines, whitespace, separator, TRUE ) ) {
		fclose( fp );
		return( -1 );
	}
	fclose( fp );

	return( 0 );
}

int
vips__csv_read_header( const char *filename, VipsImage *out,
	int skip, int lines, const char *whitespace, const char *separator )
{
	FILE *fp;

	if( !(fp = vips__file_open_read( filename, NULL, TRUE )) ) 
		return( -1 );
	if( read_csv( fp, out, skip, lines, whitespace, separator, FALSE ) ) {
		fclose( fp );
		return( -1 );
	}
	fclose( fp );

	return( 0 );
}

const char *vips__foreign_csv_suffs[] = { ".csv", NULL };

#define PRINT_INT( TYPE ) fprintf( fp, "%d", *((TYPE*)p) );
#define PRINT_FLOAT( TYPE ) fprintf( fp, "%g", *((TYPE*)p) );
#define PRINT_COMPLEX( TYPE ) fprintf( fp, "(%g, %g)", \
	((TYPE*)p)[0], ((TYPE*)p)[1] );

static int
vips2csv( VipsImage *in, FILE *fp, const char *sep )
{
	int w = VIPS_IMAGE_N_ELEMENTS( in );
	int es = VIPS_IMAGE_SIZEOF_ELEMENT( in );

	int x, y; 
	VipsPel *p;

	p = in->data; 
	for( y = 0; y < in->Ysize; y++ ) { 
		for( x = 0; x < w; x++ ) { 
			if( x > 0 )
				fprintf( fp, "%s", sep );

			switch( in->BandFmt ) {
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
				g_assert( 0 );
			}

			 p += es; 
		} 

		fprintf( fp, "\n" ); 
	} 

	return( 0 );
}

int
vips__csv_write( VipsImage *in, const char *filename, const char *separator )
{
	FILE *fp;

	if( vips_check_mono( "vips2csv", in ) ||
		vips_check_uncoded( "vips2csv", in ) ||
		vips_image_wio_input( in ) )
		return( -1 );

	if( !(fp = vips__file_open_write( filename, TRUE )) ) 
		return( -1 );
	if( vips2csv( in, fp, separator ) ) {
		fclose( fp );
		return( -1 );
	}
	fclose( fp );

	return( 0 );
}

/* Read to non-whitespace, or buffer overflow.
 */
static int
fetch_nonwhite( FILE *fp, const char whitemap[256], char *buf, int max )
{
	int ch;
	int i;

	for( i = 0; i < max - 1; i++ ) {
		ch = fgetc( fp );

		if( ch == EOF || ch == '\n' || whitemap[ch] )
			break;

		buf[i] = ch;
	}

	buf[i] = '\0';

	/* We mustn't skip the terminator.
	 */
	ungetc( ch, fp );

	return( ch ); 
}

/* Read a single double in ascii (not locale) encoding.
 *
 * Return the char that caused failure on fail (EOF or \n).
 */
static int
read_ascii_double( FILE *fp, const char whitemap[256], double *out )
{
	int ch;
	char buf[256];

	ch = skip_white( fp, whitemap );

	if( ch == EOF || 
		ch == '\n' ) 
		return( ch );

	fetch_nonwhite( fp, whitemap, buf, 256 );

	*out = g_ascii_strtod( buf, NULL );

	return( 0 );
}

/* Read the header. Two numbers for width and height, and two optional
 * numbers for scale and offset. 
 */
static int
vips__array_header( char *whitemap, FILE *fp,
	int *width, int *height, double *scale, double *offset )   
{
	double header[4];
	double d;
	int i;
	int ch;

	for( i = 0; i < 4 && 
		(ch = read_ascii_double( fp, whitemap, &header[i] )) == 0; 
		i++ )
		;

	if( i < 2 ) {
		vips_error( "mask2vips", "%s", _( "no width / height" ) );
		return( -1 );
	}
	if( floor( header[0] ) != header[0] ||
		floor( header[1] ) != header[1] ) {
		vips_error( "mask2vips", "%s", _( "width / height not int" ) );
		return( -1 );
	}
	if( i == 3 ) { 
		vips_error( "mask2vips", "%s", _( "bad scale / offset" ) );
		return( -1 );
	}
	if( (ch = read_ascii_double( fp, whitemap, &d )) != '\n' ) {
		vips_error( "mask2vips", "%s", _( "extra chars in header" ) );
		return( -1 );
	}
	if( i > 2 && 
		header[2] == 0.0 ) {
		vips_error( "mask2vips", "%s", _( "zero scale" ) );
		return( -1 );
	}

	*width = header[0];
	*height = header[0];
	*scale = i > 2 ?  header[2] : 1.0;
	*offset = i > 2 ?  header[3] : 0.0;

	skip_line( fp );

	return( 0 );
}

#define WHITESPACE " \"\t\n;,"

/* Get the header from an array file. 
 *
 * Also read the first line and make sure there are the right number of
 * entries. 
 */
int
vips__array_read_header( const char *filename,
	int *width, int *height, double *scale, double *offset )
{
	char whitemap[256];
	int i;
	char *p;
	FILE *fp;
	int ch;
	double d;

	for( i = 0; i < 256; i++ ) 
		whitemap[i] = 0;
	for( p = WHITESPACE; *p; p++ )
		whitemap[(int) *p] = 1;

	if( !(fp = vips__file_open_read( filename, NULL, TRUE )) ) 
		return( -1 );
	if( vips__array_header( whitemap, fp,
		width, height, scale, offset ) ) {  
		fclose( fp );
		return( -1 );
	}

	for( i = 0; i < *width; i++ ) {
		ch = read_ascii_double( fp, whitemap, &d );

		if( ch ) {
			fclose( fp );
			vips_error( "mask2vips", "%s", _( "line too short" ) );
			return( -1 );
		}
	}

	/* Deliberately don't check for line too long.
	 */

	fclose( fp );

	return( 0 );
}

static int
vips__array_body( char *whitemap, VipsImage *out, FILE *fp )
{
	int x, y;

	for( y = 0; y < out->Ysize; y++ ) {
		for( x = 0; x < out->Xsize; x++ ) {
			int ch;
			double d;

			ch = read_ascii_double( fp, whitemap, &d );
			if( ch == EOF ||
				ch == '\n' ) {
				vips_error( "mask2vips", 
					_( "line %d too short" ), y + 1 );
				return( -1 );
			}
			*((double *) VIPS_IMAGE_ADDR( out, x, y )) = d; 

			/* Deliberately don't check for line too long.
			 */
		}

		skip_line( fp );
	}

	return( 0 );
}

VipsImage * 
vips__array_read( const char *filename )
{
	char whitemap[256];
	int i;
	char *p;
	FILE *fp;
	int width;
	int height;
	double scale;
	double offset;
	VipsImage *out; 

	for( i = 0; i < 256; i++ ) 
		whitemap[i] = 0;
	for( p = WHITESPACE; *p; p++ )
		whitemap[(int) *p] = 1;

	if( !(fp = vips__file_open_read( filename, NULL, TRUE )) ) 
		return( NULL );
	if( vips__array_header( whitemap, fp,
		&width, &height, &scale, &offset ) ) {  
		fclose( fp );
		return( NULL );
	}

	if( !(out = vips_image_new_matrix( width, height )) )
		return( NULL );
	vips_image_set_double( out, "scale", scale ); 
	vips_image_set_double( out, "offset", offset ); 

	if( vips__array_body( whitemap, out, fp ) ) {
		g_object_unref( out );
		fclose( fp );
		return( NULL );
	}
	fclose( fp );

	return( out ); 
}

int
vips__array_write( VipsImage *in, const char *filename )
{
	VipsImage *mask;
	FILE *fp;
	int x, y; 

	if( vips_check_matrix( "vips2mask", in, &mask ) )
		return( -1 );

	if( !(fp = vips__file_open_write( filename, TRUE )) ) {
		g_object_unref( mask ); 
		return( -1 );
	}
	fprintf( fp, "%d %d ", mask->Xsize, mask->Ysize ); 
	if( vips_image_get_typeof( mask, "scale" ) && 
		vips_image_get_typeof( mask, "offset" ) ) 
		fprintf( fp, "%g %g ", 
			vips_image_get_scale( mask ),
			vips_image_get_offset( mask ) );
	fprintf( fp, "\n" ); 

	for( y = 0; y < mask->Ysize; y++ ) { 
		for( x = 0; x < mask->Xsize; x++ ) 
			fprintf( fp, "%g ", 
				*((double *) VIPS_IMAGE_ADDR( mask, x, y )) ); 

		fprintf( fp, "\n" ); 
	}

	g_object_unref( mask ); 
	fclose( fp ); 

	return( 0 );
}

const char *vips__foreign_matrix_suffs[] = { ".mat", NULL };

