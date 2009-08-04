/* Read matlab save files with libmatio
 *
 * 4/8/09
 *	- transpose on load, assemble planes into bands (thanks Mikhail)
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
#include <assert.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include <matio.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* What we track during a Mat-file read.
 */
typedef struct {
	char *filename;
	IMAGE *out;

	mat_t *mat;
	matvar_t *var;
} Read;

static void
read_destroy( Read *read )
{
	IM_FREE( read->filename );
	IM_FREEF( Mat_VarFree, read->var );
	IM_FREEF( Mat_Close, read->mat );

	im_free( read );
}

static Read *
read_new( const char *filename, IMAGE *out )
{
	Read *read;

	if( !(read = IM_NEW( NULL, Read )) )
		return( NULL );

	read->filename = im_strdup( NULL, filename );
	read->out = out;
	read->mat = NULL;
	read->var = NULL;

	if( !(read->mat = Mat_Open( filename, MAT_ACC_RDONLY )) ) {
		im_error( "mat2vips", 
			_( "unable to open \"%s\"" ), filename );
		read_destroy( read );
		return( NULL );
	}

	for(;;) {
		if( !(read->var = Mat_VarReadNextInfo( read->mat )) ) {
			im_error( "mat2vips", 
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

		IM_FREEF( Mat_VarFree, read->var );
	}

	return( read );
}

/* Matlab classes -> VIPS band formats.
 */
static int mat2vips_formats[][2] = {
	{ MAT_C_UINT8, IM_BANDFMT_UCHAR },
	{ MAT_C_INT8, IM_BANDFMT_CHAR },
	{ MAT_C_UINT16, IM_BANDFMT_USHORT },
	{ MAT_C_INT16, IM_BANDFMT_SHORT },
	{ MAT_C_UINT32, IM_BANDFMT_UINT },
	{ MAT_C_INT32, IM_BANDFMT_INT },
	{ MAT_C_SINGLE, IM_BANDFMT_FLOAT },
	{ MAT_C_DOUBLE, IM_BANDFMT_DOUBLE }
};

static int
mat2vips_get_header( matvar_t *var, IMAGE *im )
{
	int width, height, bands, format, type;
	int i;

	width = 1;
	height = 1;
	bands = 1;
	switch( var->rank ) {
	case 3:
		bands = var->dims[2];

	case 2:
		height = var->dims[1];

	case 1:
		width = var->dims[0];
		break;

	default:
		im_error( "mat2vips", _( "unsupported bands %d\n" ),
			var->rank );
		return( -1 );
	}

	if( bands > 1 )
		type = IM_TYPE_MULTIBAND;
	else
		type = IM_TYPE_B_W;

	for( i = 0; i < IM_NUMBER( mat2vips_formats ); i++ )
		if( mat2vips_formats[i][0] == var->class_type )
			break;
	if( i == IM_NUMBER( mat2vips_formats ) ) {
		im_error( "mat2vips", _( "unsupported class type %d\n" ),
			var->class_type );
		return( -1 );
	}
	format = mat2vips_formats[i][1];

	im_initdesc( im,
		 width, height, bands,
		 im_bits_of_fmt( format ), format,
		 IM_CODING_NONE, type, 1.0, 1.0, 0, 0 );

	return( 0 );
}

static int
mat2vips_header( const char *filename, IMAGE *out )
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
mat2vips_get_data( mat_t *mat, matvar_t *var, IMAGE *im )
{
	int y;
	PEL *buffer;
	const int es = IM_IMAGE_SIZEOF_ELEMENT( im );

	/* Matlab images are plane-separate, so we have to assemble bands in
	 * image-size chunks.
	 */
	const int is = es * im->Xsize * im->Ysize;

	if( Mat_VarReadDataAll( mat, var ) ) {
		im_error( "mat2vips", "%s", _( "Mat_VarReadDataAll failed" ) );
		return( -1 );
	}
	if( im_outcheck( im ) ||
		im_setupout( im ) )
		return( -1 );

	/* Matlab images are in columns, so we have to transpose into
	 * scanlines with this buffer.
	 */
	if( !(buffer = IM_ARRAY( im, IM_IMAGE_SIZEOF_LINE( im ), PEL )) )
		return( -1 );

	for( y = 0; y < im->Ysize; y++ ) {
		const PEL *p = var->data + y * es;
		int x;
		PEL *q;

		q = buffer;
		for( x = 0; x < im->Xsize; x++ ) {
			int b;

			for( b = 0; b < im->Bands; b++ ) {
				const PEL *p2 = p + b * is;
				int z;

				for( z = 0; z < es; z++ )
					q[z] = p2[z];

				q += es;
			}

			p += es * im->Ysize;
		}

		if( im_writeline( y, im, buffer ) )
			return( -1 );
	}

	return( 0 );
}

static int
mat2vips( const char *filename, IMAGE *out )
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

static int
ismat( const char *filename )
{
	mat_t *mat;

	if( !(mat = Mat_Open( filename, MAT_ACC_RDONLY )) )
		return( 0 );
	Mat_Close( mat );

	return( 1 );
}

static const char *mat_suffs[] = { ".mat", NULL };

/* mat format adds no new members.
 */
typedef VipsFormat VipsFormatMat;
typedef VipsFormatClass VipsFormatMatClass;

static void
vips_format_mat_class_init( VipsFormatMatClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "mat";
	object_class->description = _( "Matlab" );

	format_class->is_a = ismat;
	format_class->header = mat2vips_header;
	format_class->load = mat2vips;
	format_class->save = NULL;
	format_class->suffs = mat_suffs;
}

static void
vips_format_mat_init( VipsFormatMat *object )
{
}

G_DEFINE_TYPE( VipsFormatMat, vips_format_mat, VIPS_TYPE_FORMAT );

#endif /*HAVE_MATIO*/
