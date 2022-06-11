/* load matrix from a file
 *
 * 5/12/11
 * 	- from csvload.c
 * 22/2/20
 * 	- rewrite for source API
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>

#include "pforeign.h"

typedef struct _VipsForeignLoadMatrix {
	VipsForeignLoad parent_object;

	/* Set by subclasses.
	 */
	VipsSource *source;

	/* Buffered source.
	 */
	VipsSbuf *sbuf;

	/* A line of pixels.
	 */
	double *linebuf;

} VipsForeignLoadMatrix;

typedef VipsForeignLoadClass VipsForeignLoadMatrixClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadMatrix, vips_foreign_load_matrix, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_matrix_dispose( GObject *gobject )
{
	VipsForeignLoadMatrix *matrix = (VipsForeignLoadMatrix *) gobject;

	VIPS_UNREF( matrix->source );
	VIPS_UNREF( matrix->sbuf );
	VIPS_FREE( matrix->linebuf );

	G_OBJECT_CLASS( vips_foreign_load_matrix_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_load_matrix_build( VipsObject *object )
{
	VipsForeignLoadMatrix *matrix = (VipsForeignLoadMatrix *) object;

	if( !(matrix->sbuf = vips_sbuf_new_from_source( matrix->source )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_matrix_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_matrix_get_flags( VipsForeignLoad *load )
{
	return( 0 );
}

/* Parse a header line. Two numbers for width and height, and two optional
 * numbers for scale and offset. 
 *
 * We can have scale and no offset, in which case we assume offset = 0.
 */
static int
parse_matrix_header( char *line,
	int *width, int *height, double *scale, double *offset )   
{
	double header[4];
	char *p, *q;
	int i;

	for( i = 0, p = line; 
		(q = vips_break_token( p, " \t" )) &&
			i < 4; 
		i++, p = q )
		if( vips_strtod( p, &header[i] ) ) {
			vips_error( "matload", 
				_( "bad number \"%s\"" ), p );
			return( -1 );
		}

	if( i < 4 )
		header[3] = 0.0;
	if( i < 3 )
		header[2] = 1.0;
	if( i < 2 ) {
		vips_error( "matload", "%s", _( "no width / height" ) );
		return( -1 );
	}

	if( VIPS_FLOOR( header[0] ) != header[0] ||
		VIPS_FLOOR( header[1] ) != header[1] ) {
		vips_error( "mask2vips", "%s", _( "width / height not int" ) );
		return( -1 );
	}

	/* Width / height can be 65536 for a 16-bit LUT, for example.
	 */
	*width = header[0];
	*height = header[1];
	if( *width <= 0 || 
		*width > 100000 ||
		*height <= 0 || 
		*height > 100000 ) { 
		vips_error( "mask2vips", 
			"%s", _( "width / height out of range" ) );
		return( -1 );
	}
	if( header[2] == 0.0 ) {
		vips_error( "mask2vips", "%s", _( "zero scale" ) );
		return( -1 );
	}

	*scale = header[2];
	*offset = header[3];

	return( 0 );
}

static int
vips_foreign_load_matrix_header( VipsForeignLoad *load )
{
	VipsForeignLoadMatrix *matrix = (VipsForeignLoadMatrix *) load;

	char *line;
	int width;
	int height;
	double scale;
	double offset;
	int result;

	/* Rewind.
	 */
	vips_sbuf_unbuffer( matrix->sbuf );
	if( vips_source_rewind( matrix->source ) )
		return( -1 );

	line = vips_sbuf_get_line_copy( matrix->sbuf );
	result = parse_matrix_header( line, &width, &height, &scale, &offset );
	g_free( line );
	if( result )
		return( -1 );

	if( vips_image_pipelinev( load->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, NULL ) )
		return( -1 );
	vips_image_init_fields( load->out,
		width, height, 1, 
		VIPS_FORMAT_DOUBLE, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );

	vips_image_set_double( load->out, "scale", scale ); 
	vips_image_set_double( load->out, "offset", offset ); 

	VIPS_SETSTR( load->out->filename, 
		vips_connection_filename( VIPS_CONNECTION( matrix->source ) ) );

	if( !(matrix->linebuf = VIPS_ARRAY( NULL, width, double )) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_matrix_load( VipsForeignLoad *load )
{
	VipsForeignLoadMatrix *matrix = (VipsForeignLoadMatrix *) load;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );

	int x, y;

	if( vips_image_pipelinev( load->real, 
		VIPS_DEMAND_STYLE_THINSTRIP, NULL ) )
		return( -1 );
	vips_image_init_fields( load->real,
		load->out->Xsize, load->out->Ysize, 1, 
		VIPS_FORMAT_DOUBLE, 
		VIPS_CODING_NONE, VIPS_INTERPRETATION_B_W, 1.0, 1.0 );

	for( y = 0; y < load->real->Ysize; y++ ) {
		char *line;
		char *p, *q;

		line = vips_sbuf_get_line_copy( matrix->sbuf );

		for( x = 0, p = line; 
			(q = vips_break_token( p, " \t" )) &&
				x < load->out->Xsize;
			x++, p = q )
			if( vips_strtod( p, &matrix->linebuf[x] ) ) {
				vips_error( class->nickname, 
					_( "bad number \"%s\"" ), p );
				g_free( line );
				return( -1 );
			}

		g_free( line );

		if( x != load->out->Xsize ) {
			vips_error( class->nickname, 
				_( "line %d too short" ), y );
			return( -1 );
		}

		if( vips_image_write_line( load->real, y, 
			(VipsPel *) matrix->linebuf ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_foreign_load_matrix_class_init( VipsForeignLoadMatrixClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_matrix_dispose;

	object_class->nickname = "matrixload_base";
	object_class->description = _( "load matrix" );
	object_class->build = vips_foreign_load_matrix_build;

	load_class->get_flags = vips_foreign_load_matrix_get_flags;
	load_class->header = vips_foreign_load_matrix_header;
	load_class->load = vips_foreign_load_matrix_load;

}

static void
vips_foreign_load_matrix_init( VipsForeignLoadMatrix *matrix )
{
}

typedef struct _VipsForeignLoadMatrixFile {
	VipsForeignLoadMatrix parent_object;

	/* Filename for load.
	 */
	char *filename;

} VipsForeignLoadMatrixFile;

typedef VipsForeignLoadMatrixClass VipsForeignLoadMatrixFileClass;

G_DEFINE_TYPE( VipsForeignLoadMatrixFile, vips_foreign_load_matrix_file,
	vips_foreign_load_matrix_get_type() );

static VipsForeignFlags
vips_foreign_load_matrix_file_get_flags_filename( const char *filename )
{
	return( 0 );
}

static int
vips_foreign_load_matrix_file_build( VipsObject *object )
{
	VipsForeignLoadMatrix *matrix = (VipsForeignLoadMatrix *) object;
	VipsForeignLoadMatrixFile *file = (VipsForeignLoadMatrixFile *) object;

	if( file->filename ) 
		if( !(matrix->source = 
			vips_source_new_from_file( file->filename )) )
			return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_matrix_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static const char *vips_foreign_load_matrix_suffs[] = {
	".mat",
	NULL
};

static gboolean
vips_foreign_load_matrix_file_is_a( const char *filename )
{
	unsigned char line[80];
	guint64 bytes;
	int width;
	int height;
	double scale;
	double offset;
	int result;

	if( (bytes = vips__get_bytes( filename, line, 79 )) <= 0 )
		return( FALSE );
	line[bytes] = '\0';

	vips_error_freeze();
	result = parse_matrix_header( (char *) line, 
		&width, &height, &scale, &offset ); 
	vips_error_thaw();

	return( result == 0 ); 
}

static void
vips_foreign_load_matrix_file_class_init( 
	VipsForeignLoadMatrixFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "matrixload";
	object_class->build = vips_foreign_load_matrix_file_build;

	foreign_class->suffs = vips_foreign_load_matrix_suffs;

	load_class->is_a = vips_foreign_load_matrix_file_is_a;
	load_class->get_flags_filename = 
		vips_foreign_load_matrix_file_get_flags_filename;

	VIPS_ARG_STRING( class, "filename", 1,
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadMatrixFile, filename ),
		NULL );

}

static void
vips_foreign_load_matrix_file_init( VipsForeignLoadMatrixFile *file )
{
}

typedef struct _VipsForeignLoadMatrixSource {
	VipsForeignLoadMatrix parent_object;

	VipsSource *source;

} VipsForeignLoadMatrixSource;

typedef VipsForeignLoadMatrixClass VipsForeignLoadMatrixSourceClass;

G_DEFINE_TYPE( VipsForeignLoadMatrixSource, vips_foreign_load_matrix_source,
	vips_foreign_load_matrix_get_type() );

static int
vips_foreign_load_matrix_source_build( VipsObject *object )
{
	VipsForeignLoadMatrix *matrix = (VipsForeignLoadMatrix *) object;
	VipsForeignLoadMatrixSource *source = 
		(VipsForeignLoadMatrixSource *) object;

	if( source->source ) {
		matrix->source = source->source;
		g_object_ref( matrix->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_matrix_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_matrix_source_is_a_source( VipsSource *source )
{
	unsigned char *data;
	gint64 bytes_read;
	char line[80];
	int width;
	int height;
	double scale;
	double offset;
	int result;

	if( (bytes_read = vips_source_sniff_at_most( source, 
		&data, 79 )) <= 0 )
		return( FALSE );
	vips_strncpy( line, (const char *) data, 80 );

	vips_error_freeze();
	result = parse_matrix_header( line, 
		&width, &height, &scale, &offset ); 
	vips_error_thaw();

	return( result == 0 ); 
}

static void
vips_foreign_load_matrix_source_class_init( 
	VipsForeignLoadMatrixFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "matrixload_source";
	object_class->build = vips_foreign_load_matrix_source_build;

	operation_class->flags |= VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_matrix_source_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadMatrixSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_matrix_source_init( VipsForeignLoadMatrixSource *source )
{
}

/**
 * vips_matrixload:
 * @filename: file to load
 * @out: (out): output image
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
 * Subsequent lines each hold one row of matrix data, with numbers again
 * separated by any mixture of spaces, commas, 
 * tabs and quotation marks ("). The numbers may be floating-point, and must
 * use '.'
 * as a decimal separator.
 *
 * Extra characters at the ends of lines or at the end of the file are
 * ignored.
 *
 * See also: vips_matrixload().
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

/**
 * vips_matrixload_source:
 * @source: source to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_matrixload(), but read from a source. 
 *
 * See also: vips_matrixload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_matrixload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "matrixload_source", ap, source, out ); 
	va_end( ap );

	return( result );
}

