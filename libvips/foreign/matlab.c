/* Read matlab save files with libmatio
 *
 * 4/8/09
 *	- transpose on load, assemble planes into bands (thanks Mikhail)
 * 20/12/11
 * 	- reworked as some fns ready for new-style classes
 * 21/8/14
 * 	- swap width/height
 * 	- set interpretation to rgb16 etc. 
 * 16/2/16
 * 	- more specific is_a test 
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

	Remaining issues:

+ it will not do complex images

+ it will not handle sparse matricies

+ it loads the first variable in the file with between 1 and 3 dimensions, 
  is this sensible behaviour?

+ load only, no save

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_MATIO

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include <matio.h>

#include "matlab.h"

/* What we track during a Mat-file read.
 */
typedef struct {
	char *filename;
	VipsImage *out;

	mat_t *mat;
	matvar_t *var;
} Read;

static void
read_destroy( Read *read )
{
	VIPS_FREE( read->filename );
	VIPS_FREEF( Mat_VarFree, read->var );
	VIPS_FREEF( Mat_Close, read->mat );

	vips_free( read );
}

static Read *
read_new( const char *filename, VipsImage *out )
{
	Read *read;

	if( !(read = VIPS_NEW( NULL, Read )) )
		return( NULL );

	read->filename = vips_strdup( NULL, filename );
	read->out = out;
	read->mat = NULL;
	read->var = NULL;

	if( !(read->mat = Mat_Open( filename, MAT_ACC_RDONLY )) ) {
		vips_error( "mat2vips", 
			_( "unable to open \"%s\"" ), filename );
		read_destroy( read );
		return( NULL );
	}

	for(;;) {
		if( !(read->var = Mat_VarReadNextInfo( read->mat )) ) {
			vips_error( "mat2vips", 
				_( "no matrix variables in \"%s\"" ), 
				filename );
			read_destroy( read );
			return( NULL );
		}

#ifdef DEBUG
		printf( "mat2vips: seen:\n" );
		printf( "var->name == %s\n", read->var->name );
		printf( "var->class_type == %d\n", read->var->class_type );
		printf( "var->rank == %d\n", read->var->rank );
#endif /*DEBUG*/

		/* Vector to colour image is OK for us.
		 */
		if( read->var->rank >= 1 && read->var->rank <= 3 )
			break;

		VIPS_FREEF( Mat_VarFree, read->var );
	}

	return( read );
}

/* Matlab classes -> VIPS band formats.
 */
static int mat2vips_formats[][2] = {
	{ MAT_C_UINT8, VIPS_FORMAT_UCHAR },
	{ MAT_C_INT8, VIPS_FORMAT_CHAR },
	{ MAT_C_UINT16, VIPS_FORMAT_USHORT },
	{ MAT_C_INT16, VIPS_FORMAT_SHORT },
	{ MAT_C_UINT32, VIPS_FORMAT_UINT },
	{ MAT_C_INT32, VIPS_FORMAT_INT },
	{ MAT_C_SINGLE, VIPS_FORMAT_FLOAT },
	{ MAT_C_DOUBLE, VIPS_FORMAT_DOUBLE }
};

/* Pick an interpretation.
 */
static VipsInterpretation 
mat2vips_pick_interpretation( int bands, VipsBandFormat format )
{
	if( bands == 3 &&
		vips_band_format_is8bit( format ) )
		return( VIPS_INTERPRETATION_sRGB );
	if( bands == 3 &&
		(format == VIPS_FORMAT_USHORT || 
		 format == VIPS_FORMAT_SHORT) )
		return( VIPS_INTERPRETATION_RGB16 );
	if( bands == 1 &&
		(format == VIPS_FORMAT_USHORT || 
		 format == VIPS_FORMAT_SHORT) )
		return( VIPS_INTERPRETATION_GREY16 );
	if( bands > 1 )
		return( VIPS_INTERPRETATION_MULTIBAND ); 

	return( VIPS_INTERPRETATION_MULTIBAND );
}

static int
mat2vips_get_header( matvar_t *var, VipsImage *im )
{
	int width, height, bands;
	VipsBandFormat format;
	VipsInterpretation interpretation; 
	int i;

	width = 1;
	bands = 1;
	switch( var->rank ) {
	case 3:
		bands = var->dims[2];

	case 2:
		width = var->dims[1];

	case 1:
		height = var->dims[0];
		break;

	default:
		vips_error( "mat2vips", 
			_( "unsupported rank %d\n" ), var->rank );
		return( -1 );
	}

	for( i = 0; i < VIPS_NUMBER( mat2vips_formats ); i++ )
		if( mat2vips_formats[i][0] == var->class_type )
			break;
	if( i == VIPS_NUMBER( mat2vips_formats ) ) {
		vips_error( "mat2vips", _( "unsupported class type %d\n" ),
			var->class_type );
		return( -1 );
	}
	format = mat2vips_formats[i][1];
	interpretation = mat2vips_pick_interpretation( bands, format );

	vips_image_init_fields( im,
		 width, height, bands,
		 format,
		 VIPS_CODING_NONE, interpretation, 1.0, 1.0 );

	return( 0 );
}

int
vips__mat_header( const char *filename, VipsImage *out )
{
	Read *read;

#ifdef DEBUG
	printf( "mat2vips_header: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out )) ) 
		return( -1 );
	if( mat2vips_get_header( read->var, read->out ) ) {
		read_destroy( read );
		return( -1 );
	}
	read_destroy( read );

	return( 0 );
}

static int
mat2vips_get_data( mat_t *mat, matvar_t *var, VipsImage *im )
{
	int y;
	VipsPel *buffer;
	const int es = VIPS_IMAGE_SIZEOF_ELEMENT( im );

	/* Matlab images are plane-separate, so we have to assemble bands in
	 * image-size chunks.
	 */
	const guint64 is = es * VIPS_IMAGE_N_PELS( im );

	if( Mat_VarReadDataAll( mat, var ) ) {
		vips_error( "mat2vips", "%s", 
			_( "Mat_VarReadDataAll failed" ) );
		return( -1 );
	}

	/* Matlab images are in columns, so we have to transpose into
	 * scanlines with this buffer.
	 */
	if( !(buffer = VIPS_ARRAY( im, 
		VIPS_IMAGE_SIZEOF_LINE( im ), VipsPel )) )
		return( -1 );

	for( y = 0; y < im->Ysize; y++ ) {
		const VipsPel *p = var->data + y * es;
		int x;
		VipsPel *q;

		q = buffer;
		for( x = 0; x < im->Xsize; x++ ) {
			int b;

			for( b = 0; b < im->Bands; b++ ) {
				const VipsPel *p2 = p + b * is;
				int z;

				for( z = 0; z < es; z++ )
					q[z] = p2[z];

				q += es;
			}

			p += es * im->Ysize;
		}

		if( vips_image_write_line( im, y, buffer ) )
			return( -1 );
	}

	return( 0 );
}

int
vips__mat_load( const char *filename, VipsImage *out )
{
	Read *read;

#ifdef DEBUG
	printf( "mat2vips: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out )) ) 
		return( -1 );
	if( mat2vips_get_header( read->var, read->out ) ||
		mat2vips_get_data( read->mat, read->var, read->out ) ) {
		read_destroy( read );
		return( -1 );
	}
	read_destroy( read );

	return( 0 );
}

int
vips__mat_ismat( const char *filename )
{
	unsigned char buf[15];

	if( vips__get_bytes( filename, buf, 10 ) &&
		vips_isprefix( "MATLAB 5.0", (char *) buf ) )
		return( 1 );

	return( 0 );
}

const char *vips__mat_suffs[] = { ".mat", NULL };

#endif /*HAVE_MATIO*/
