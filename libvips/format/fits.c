/* Read FITS files with cfitsio
 *
 * 26/10/10
 *	- from matlab.c
 * 27/10/10
 * 	- oops, forgot to init status in close
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

#ifdef HAVE_CFITSIO

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include <fitsio.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* What we track during a cfitsio-file read.
 */
typedef struct {
	char *filename;
	IMAGE *out;

	fitsfile *fptr;
	int datatype;
} Read;

static void
read_error( int status )
{
	char buf[80];

	fits_get_errstatus( status, buf );
	im_error( "fits", "%s", buf );
}

static void
read_destroy( Read *read )
{
	IM_FREE( read->filename );
	if( read->fptr ) {
		int status;

		status = 0;

		if( fits_close_file( read->fptr, &status ) ) 
			read_error( status );

		read->fptr = NULL;
	}

	im_free( read );
}

static Read *
read_new( const char *filename, IMAGE *out )
{
	Read *read;
	int status;

	if( !(read = IM_NEW( NULL, Read )) )
		return( NULL );

	read->filename = im_strdup( NULL, filename );
	read->out = out;
	read->fptr = NULL;

	status = 0;

	if( fits_open_file( &read->fptr, filename, READONLY, &status ) ) {
		im_error( "fits", _( "unable to open \"%s\"" ), filename );
		read_error( status );
		read_destroy( read );
		return( NULL );
	}

	return( read );
}

/* fits image types -> VIPS band formats. VIPS doesn't have 64-bit int, so no
 * entry for LONGLONG_IMG (64).
 */
static int fits2vips_formats[][3] = {
	{ BYTE_IMG, IM_BANDFMT_UCHAR, TBYTE },
	{ SHORT_IMG,  IM_BANDFMT_USHORT, TUSHORT },
	{ LONG_IMG,  IM_BANDFMT_UINT, TUINT },
	{ FLOAT_IMG,  IM_BANDFMT_FLOAT, TFLOAT },
	{ DOUBLE_IMG, IM_BANDFMT_DOUBLE, TDOUBLE }
};

static int
fits2vips_get_header( Read *read )
{
	int status;
	int bitpix;
	int naxis;
	long long int naxes[10];

	int width, height, bands, format, type;
	int keysexist;
	int morekeys;
	int i;

	status = 0;

	if( fits_get_img_paramll( read->fptr, 
		10, &bitpix, &naxis, naxes, &status ) ) {
		read_error( status );
		return( -1 );
	}

	printf( "naxis = %d\n", naxis );
	for( i = 0; i < naxis; i++ )
		printf( "%d) %lld\n", i, naxes[i] );

	width = 1;
	height = 1;
	bands = 1;
	switch( naxis ) {
	case 3:
		bands = naxes[2];

	case 2:
		height = naxes[1];

	case 1:
		width = naxes[0];
		break;

	default:
		im_error( "fits", "bad number of axis %d", naxis );
		return( -1 );
	}

	if( bands == 1 )
		type = IM_TYPE_B_W;
	else if( bands == 3 )
		type = IM_TYPE_RGB;
	else
		type = IM_TYPE_MULTIBAND;

	/* Get image format. We want the 'raw' format of the image, our caller
	 * can convert using the meta info if they want.
	 */
	for( i = 0; i < IM_NUMBER( fits2vips_formats ); i++ )
		if( fits2vips_formats[i][0] == bitpix )
			break;
	if( i == IM_NUMBER( fits2vips_formats ) ) {
		im_error( "im_fits2vips", _( "unsupported bitpix %d\n" ),
			bitpix );
		return( -1 );
	}
	format = fits2vips_formats[i][1];
	read->datatype = fits2vips_formats[i][2];

	im_initdesc( read->out,
		 width, height, bands,
		 im_bits_of_fmt( format ), format,
		 IM_CODING_NONE, type, 1.0, 1.0, 0, 0 );

	/* Read all keys into meta.
	 */
	if( fits_get_hdrspace( read->fptr, &keysexist, &morekeys, &status ) ) {
		read_error( status );
		return( -1 );
	}

	for( i = 0; i < keysexist; i++ ) {
		char key[81];
		char value[81];
		char comment[81];
		char vipsname[100];

		if( fits_read_keyn( read->fptr, i + 1, 
			key, value, comment, &status ) ) {
			read_error( status );
			return( -1 );
		}

#ifdef DEBUG
		printf( "fits: seen:\n" );
		printf( " key == %s\n", key );
		printf( " value == %s\n", value );
		printf( " comment == %s\n", comment );
#endif /*DEBUG*/

		im_snprintf( vipsname, 100, "fits-%s", key );
		if( im_meta_set_string( read->out, vipsname, value ) ) 
			return( -1 );
		im_snprintf( vipsname, 100, "fits-%s-comment", key );
		if( im_meta_set_string( read->out, vipsname, comment ) ) 
			return( -1 );
	}

	return( 0 );
}

static int
fits2vips_header( const char *filename, IMAGE *out )
{
	Read *read;

#ifdef DEBUG
	printf( "fits2vips_header: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out )) ) 
		return( -1 );
	if( fits2vips_get_header( read ) ) {
		read_destroy( read );
		return( -1 );
	}
	read_destroy( read );

	return( 0 );
}

static int
fits2vips_get_data( Read *read )
{
	IMAGE *im = read->out;
	const int es = IM_IMAGE_SIZEOF_ELEMENT( im );

	PEL *line_buffer;
	PEL *band_buffer;
	PEL *p, *q;
	int x, y, b, z;
	int status;

	status = 0;

	if( !(line_buffer = IM_ARRAY( im, IM_IMAGE_SIZEOF_LINE( im ), PEL )) ||
		!(band_buffer = IM_ARRAY( im, es * im->Xsize, PEL )) ||
		im_outcheck( im ) ||
		im_setupout( im ) )
		return( -1 );

	for( y = 0; y < im->Ysize; y++ ) {
		long int fpixel[3];

		/* Start of scanline. We have to read top-to-bottom.
		 */
		fpixel[0] = 1;
		fpixel[1] = im->Ysize - y;
		fpixel[2] = 1;

		for( b = 0; b < im->Bands; b++ ) {
			fpixel[2] = b + 1;

			/* Read one band of one scanline, then scatter-write
			 * into the line buffer.
			 */
			if( fits_read_pix( read->fptr, 
				read->datatype, fpixel, im->Xsize,
				NULL, band_buffer, NULL, &status ) ) {
				read_error( status );
				return( -1 );
			}

			p = band_buffer;
			q = line_buffer + b * es;
			for( x = 0; x < im->Xsize; x++ ) {
				for( z = 0; z < es; z++ )
					q[z] = p[z];

				p += es;
				q += im->Bands * es;
			}
		}

		if( im_writeline( y, im, line_buffer ) )
			return( -1 );
	}

	return( 0 );
}

/**
 * im_fits2vips:
 * @filename: file to load
 * @out: image to write to
 *
 * Read a FITS image file into a VIPS image. 
 *
 *
 * See also: #VipsFormat.
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_fits2vips( const char *filename, IMAGE *out )
{
	Read *read;

#ifdef DEBUG
	printf( "im_fits2vips: reading \"%s\"\n", filename );
#endif /*DEBUG*/

	if( !(read = read_new( filename, out )) ) 
		return( -1 );
	if( fits2vips_get_header( read ) ||
		fits2vips_get_data( read ) ) {
		read_destroy( read );
		return( -1 );
	}

	read_destroy( read );

	return( 0 );
}

static int
isfits( const char *filename )
{
	fitsfile *fptr;
	int status;

#ifdef DEBUG
	printf( "isfits: testing \"%s\"\n", filename );
#endif /*DEBUG*/

	status = 0;

	if( fits_open_image( &fptr, filename, READONLY, &status ) ) {
#ifdef DEBUG
		printf( "isfits: error reading \"%s\"\n", filename );
		read_error( status );
#endif /*DEBUG*/

		return( 0 );
	}
	fits_close_file( fptr, &status );

	return( 1 );
}

static const char *fits_suffs[] = { ".fits", NULL };

/* fits format adds no new members.
 */
typedef VipsFormat VipsFormatFits;
typedef VipsFormatClass VipsFormatFitsClass;

static void
vips_format_fits_class_init( VipsFormatFitsClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "fits";
	object_class->description = _( "FITS" );

	format_class->is_a = isfits;
	format_class->header = fits2vips_header;
	format_class->load = im_fits2vips;
	format_class->save = NULL;
	format_class->suffs = fits_suffs;
}

static void
vips_format_fits_init( VipsFormatFits *object )
{
}

G_DEFINE_TYPE( VipsFormatFits, vips_format_fits, VIPS_TYPE_FORMAT );

#endif /*HAVE_CFITSIO*/
