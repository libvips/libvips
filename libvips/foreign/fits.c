/* Read FITS files with cfitsio
 *
 * 26/10/10
 *	- from matlab.c
 * 27/10/10
 * 	- oops, forgot to init status in close
 * 30/11/10
 * 	- set RGB16/GREY16 if appropriate
 * 	- allow up to 10 dimensions as long as they are empty
 * 27/1/11
 * 	- lazy read
 * 31/1/11
 * 	- read in planes and combine with im_bandjoin()
 * 	- read whole tiles with fits_read_subset() when we can
 * 17/3/11
 * 	- renames, updates etc. ready for adding fits write
 * 	- fits write!
 * 21/3/11
 * 	- read/write metadata as whole records to avoid changing things
 * 	- cast input to a supported format
 * 	- bandsplit for write 
 * 13/12/11
 * 	- redo as a set of fns ready for wrapping in a new-style class
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_CFITSIO

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#include <fitsio.h>

#include "fits.h"

/*

   	TODO

	- ask Doug for a test colour image

		found WFPC2u5780205r_c0fx.fits on the fits samples page, 
		but it's tiny

	- test performance

	- vips__fits_read() makes rather ugly bandjoins, fix

 */

/* vips only supports 3 dimensions, but we allow up to MAX_DIMENSIONS as long
 * as the higher dimensions are all empty. If you change this value, change
 * fits2vips_get_header() as well.
 */
#define MAX_DIMENSIONS (10)

/* What we track during a cfitsio-file read or write.
 */
typedef struct {
	char *filename;
	VipsImage *image;

	fitsfile *fptr;
	int datatype;
	int naxis;
	long long int naxes[MAX_DIMENSIONS];

	GMutex *lock;		/* Lock fits_*() calls with this */

	/* Set this to -1 to read all bands, or a +ve int to read a specific
	 * band.
	 */
	int band_select;	

	/* We split bands up for write into this buffer.
	 */
	VipsPel *buffer;
} VipsFits;

const char *vips__fits_suffs[] = { ".fits", NULL };

static void
vips_fits_error( int status )
{
	char buf[80];

	fits_get_errstatus( status, buf );
	vips_error( "fits", "%s", buf );
}

/* Shut down. Can be called many times.
 */
static void
vips_fits_close( VipsFits *fits )
{
	VIPS_FREE( fits->filename );
	VIPS_FREEF( vips_g_mutex_free, fits->lock );

	if( fits->fptr ) {
		int status;

		status = 0;

		if( fits_close_file( fits->fptr, &status ) ) 
			vips_fits_error( status );

		fits->fptr = NULL;
	}

	VIPS_FREE( fits->buffer );
}

static void
vips_fits_close_cb( VipsImage *image, VipsFits *fits )
{
	vips_fits_close( fits );
}

static VipsFits *
vips_fits_new_read( const char *filename, VipsImage *out, int band_select )
{
	VipsFits *fits;
	int status;

	if( !(fits = VIPS_NEW( out, VipsFits )) )
		return( NULL );

	fits->filename = vips_strdup( NULL, filename );
	fits->image = out;
	fits->fptr = NULL;
	fits->lock = NULL;
	fits->band_select = band_select;
	fits->buffer = NULL;
	g_signal_connect( out, "close", 
		G_CALLBACK( vips_fits_close_cb ), fits );

	status = 0;
	if( fits_open_file( &fits->fptr, filename, READONLY, &status ) ) {
		vips_error( "fits", _( "unable to open \"%s\"" ), filename );
		vips_fits_error( status );
		return( NULL );
	}

	fits->lock = vips_g_mutex_new();

	return( fits );
}

/* fits image types -> VIPS band formats. VIPS doesn't have 64-bit int, so no
 * entry for LONGLONG_IMG (64).
 */
static int fits2vips_formats[][3] = {
	{ BYTE_IMG, VIPS_FORMAT_UCHAR, TBYTE },
	{ SHORT_IMG,  VIPS_FORMAT_USHORT, TUSHORT },
	{ LONG_IMG,  VIPS_FORMAT_UINT, TUINT },
	{ FLOAT_IMG,  VIPS_FORMAT_FLOAT, TFLOAT },
	{ DOUBLE_IMG, VIPS_FORMAT_DOUBLE, TDOUBLE }
};

static int
vips_fits_get_header( VipsFits *fits, VipsImage *out )
{
	int status;
	int bitpix;

	int width, height, bands, format, type;
	int keysexist;
	int i;

	status = 0;

	if( fits_get_img_paramll( fits->fptr, 
		10, &bitpix, &fits->naxis, fits->naxes, &status ) ) {
		vips_fits_error( status );
		return( -1 );
	}

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "naxis = %d\n", fits->naxis );
	for( i = 0; i < fits->naxis; i++ )
		VIPS_DEBUG_MSG( "%d) %lld\n", i, fits->naxes[i] );
#endif /*VIPS_DEBUG*/

	width = 1;
	height = 1;
	bands = 1;
	switch( fits->naxis ) {
	/* If you add more dimensions here, adjust data read below. See also
	 * the definition of MAX_DIMENSIONS above.
	 */
	case 10:
	case 9:
	case 8:
	case 7:
	case 6:
	case 5:
	case 4:
		for( i = fits->naxis; i > 3; i-- )
			if( fits->naxes[i - 1] != 1 ) {
				vips_error( "fits", 
					"%s", _( "dimensions above 3 "
					"must be size 1" ) );
				return( -1 );
			}

	case 3:
		bands = fits->naxes[2];

	case 2:
		height = fits->naxes[1];

	case 1:
		width = fits->naxes[0];
		break;

	default:
		vips_error( "fits", _( "bad number of axis %d" ), fits->naxis );
		return( -1 );
	}

	/* Are we in one-band mode?
	 */
	if( fits->band_select != -1 )
		bands = 1;

	/* Get image format. We want the 'raw' format of the image, our caller
	 * can convert using the meta info if they want.
	 */
	for( i = 0; i < VIPS_NUMBER( fits2vips_formats ); i++ )
		if( fits2vips_formats[i][0] == bitpix )
			break;
	if( i == VIPS_NUMBER( fits2vips_formats ) ) {
		vips_error( "fits", _( "unsupported bitpix %d\n" ),
			bitpix );
		return( -1 );
	}
	format = fits2vips_formats[i][1];
	fits->datatype = fits2vips_formats[i][2];

	if( bands == 1 ) {
		if( format == VIPS_FORMAT_USHORT )
			type = VIPS_INTERPRETATION_GREY16;
		else
			type = VIPS_INTERPRETATION_B_W;
	}
	else if( bands == 3 ) {
		if( format == VIPS_FORMAT_USHORT )
			type = VIPS_INTERPRETATION_RGB16;
		else
			type = VIPS_INTERPRETATION_RGB;
	}
	else
		type = VIPS_INTERPRETATION_MULTIBAND;

	vips_image_init_fields( out,
		 width, height, bands,
		 format,
		 VIPS_CODING_NONE, type, 1.0, 1.0 );
	vips_demand_hint( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );

	/* Read all keys into meta.
	 */
	if( fits_get_hdrspace( fits->fptr, &keysexist, NULL, &status ) ) {
		vips_fits_error( status );
		return( -1 );
	}

	for( i = 0; i < keysexist; i++ ) {
		char record[81];
		char vipsname[100];

		if( fits_read_record( fits->fptr, i + 1, record, &status ) ) {
			vips_fits_error( status );
			return( -1 );
		}

		VIPS_DEBUG_MSG( "fits2vips: setting meta on vips image:\n" );
		VIPS_DEBUG_MSG( " record == \"%s\"\n", record );

		/* FITS lets keys repeat. For example, HISTORY appears many
		 * times, each time with a fresh line of history attached. We
		 * have to include the key index in the vips name we assign.
		 */

		vips_snprintf( vipsname, 100, "fits-%d", i );
		vips_image_set_string( out, vipsname, record );
	}

	return( 0 );
}

int
vips__fits_read_header( const char *filename, VipsImage *out )
{
	VipsFits *fits;

	VIPS_DEBUG_MSG( "fits2vips_header: reading \"%s\"\n", filename );

	if( !(fits = vips_fits_new_read( filename, out, -1 )) || 
		vips_fits_get_header( fits, out ) ) 
		return( -1 );

	return( 0 );
}

static int
fits2vips_generate( VipsRegion *out, 
	void *seq, void *a, void *b, gboolean *stop )
{
	VipsFits *fits = (VipsFits *) a;
	Rect *r = &out->valid;

	VipsPel *q;
	int z;
	int status;

	long fpixel[MAX_DIMENSIONS];
	long lpixel[MAX_DIMENSIONS];
	long inc[MAX_DIMENSIONS];

	status = 0;

	VIPS_DEBUG_MSG( "fits2vips_generate: "
		"generating left = %d, top = %d, width = %d, height = %d\n", 
		r->left, r->top, r->width, r->height );

	/* Special case: the region we are writing to is exactly the width we
	 * need, ie. we can read a rectangular area into it.
	 */
	if( VIPS_REGION_LSKIP( out ) == VIPS_REGION_SIZEOF_LINE( out ) ) {
		VIPS_DEBUG_MSG( "fits2vips_generate: block read\n" );

		for( z = 0; z < MAX_DIMENSIONS; z++ )
			fpixel[z] = 1;
		fpixel[0] = r->left + 1;
		fpixel[1] = r->top + 1;
		fpixel[2] = fits->band_select + 1;

		for( z = 0; z < MAX_DIMENSIONS; z++ )
			lpixel[z] = 1;
		lpixel[0] = VIPS_RECT_RIGHT( r );
		lpixel[1] = VIPS_RECT_BOTTOM( r );
		lpixel[2] = fits->band_select + 1;

		for( z = 0; z < MAX_DIMENSIONS; z++ )
			inc[z] = 1;

		q = VIPS_REGION_ADDR( out, r->left, r->top );

		/* Break on ffgsv() for this call.
		 */
		g_mutex_lock( fits->lock );
		if( fits_read_subset( fits->fptr, fits->datatype, 
			fpixel, lpixel, inc, 
			NULL, q, NULL, &status ) ) {
			vips_fits_error( status );
			g_mutex_unlock( fits->lock );
			return( -1 );
		}
		g_mutex_unlock( fits->lock );
	}
	else {
		int y;

		for( y = r->top; y < VIPS_RECT_BOTTOM( r ); y ++ ) {
			for( z = 0; z < MAX_DIMENSIONS; z++ )
				fpixel[z] = 1;
			fpixel[0] = r->left + 1;
			fpixel[1] = y + 1;
			fpixel[2] = fits->band_select + 1;

			for( z = 0; z < MAX_DIMENSIONS; z++ )
				lpixel[z] = 1;
			lpixel[0] = VIPS_RECT_RIGHT( r );
			lpixel[1] = y + 1;
			lpixel[2] = fits->band_select + 1;

			for( z = 0; z < MAX_DIMENSIONS; z++ )
				inc[z] = 1;

			q = VIPS_REGION_ADDR( out, r->left, y );

			/* Break on ffgsv() for this call.
			 */
			g_mutex_lock( fits->lock );
			if( fits_read_subset( fits->fptr, fits->datatype, 
				fpixel, lpixel, inc, 
				NULL, q, NULL, &status ) ) {
				vips_fits_error( status );
				g_mutex_unlock( fits->lock );
				return( -1 );
			}
			g_mutex_unlock( fits->lock );
		}
	}

	return( 0 );
}

static int
fits2vips( const char *filename, VipsImage *out, int band_select )
{
	VipsFits *fits;

	/* The -1 mode is just for reading the header.
	 */
	g_assert( band_select >= 0 );

	if( !(fits = vips_fits_new_read( filename, out, band_select )) )
		return( -1 );
	if( vips_fits_get_header( fits, out ) ||
		vips_image_generate( out, 
			NULL, fits2vips_generate, NULL, fits, NULL ) ) {
		vips_fits_close( fits );
		return( -1 );
	}

	/* Don't vips_fits_close(), we need it to stick around for the
	 * generate.
	 */

	return( 0 );
}

int
vips__fits_read( const char *filename, VipsImage *out )
{
	VipsImage *t;
	int n_bands;

	VIPS_DEBUG_MSG( "fits2vips: reading \"%s\"\n", filename );

	/* fits is naturally a band-separated format. For single-band images
	 * we can just read out. For many bands we read each band out
	 * separately then join them.
	 */

	t = vips_image_new();
	if( vips__fits_read_header( filename, t ) ) {
		g_object_unref( t );
		return( -1 );
	}
	n_bands = t->Bands;
	g_object_unref( t );

	if( n_bands == 1 ) {
		if( fits2vips( filename, out, 0 ) )
			return( -1 );
	}
	else {
		VipsImage **x;
		int i;

		t = vips_image_new();
		x = (VipsImage **) vips_object_local_array( VIPS_OBJECT( t ), 
			n_bands + 1 );

		for( i = 0; i < n_bands; i++ ) {
			x[i] = vips_image_new();
			if( fits2vips( filename, x[i], i ) ) {
				g_object_unref( t );
				return( -1 );
			}
		}

		if( vips_bandjoin( x, &x[n_bands], n_bands, NULL ) ||
			vips_image_write( x[n_bands], out ) ) {
			g_object_unref( t );
			return( -1 );
		}

		g_object_unref( t );
	}

	return( 0 );
}

int
vips__fits_isfits( const char *filename )
{
	fitsfile *fptr;
	int status;

	VIPS_DEBUG_MSG( "isfits: testing \"%s\"\n", filename );

	status = 0;

	if( fits_open_image( &fptr, filename, READONLY, &status ) ) {
		VIPS_DEBUG_MSG( "isfits: error reading \"%s\"\n", filename );
#ifdef VIPS_DEBUG
		vips_fits_error( status );
#endif /*VIPS_DEBUG*/

		return( 0 );
	}
	fits_close_file( fptr, &status );

	return( 1 );
}

static VipsFits *
vips_fits_new_write( VipsImage *in, const char *filename )
{
	VipsFits *fits;
	int status;

	status = 0;

	if( !(fits = VIPS_NEW( in, VipsFits )) )
		return( NULL );
	fits->filename = vips_strdup( VIPS_OBJECT( in ), filename );
	fits->image = in;
	fits->fptr = NULL;
	fits->lock = NULL;
	fits->band_select = -1;
	fits->buffer = NULL;
	g_signal_connect( in, "close", 
		G_CALLBACK( vips_fits_close_cb ), fits );

	if( !(fits->filename = vips_strdup( NULL, filename )) )
		return( NULL );

	/* We need to be able to hold one scanline of one band.
	 */
	if( !(fits->buffer = VIPS_ARRAY( NULL, 
		VIPS_IMAGE_SIZEOF_ELEMENT( in ) * in->Xsize, VipsPel )) )
		return( NULL );

	/* fits_create_file() will fail if there's a file of thet name, unless
	 * we put a "!" in front ofthe filename. This breaks conventions with
	 * the rest of vips, so just unlink explicitly.
	 */
	g_unlink( filename );

	if( fits_create_file( &fits->fptr, filename, &status ) ) {
		vips_error( "fits", 
			_( "unable to write to \"%s\"" ), filename );
		vips_fits_error( status );
		return( NULL );
	}

	fits->lock = vips_g_mutex_new();

	return( fits );
}

static void *
vips_fits_write_meta( VipsImage *image, 
	const char *field, GValue *value, void *a )
{
	VipsFits *fits = (VipsFits *) a;

	int status;
	const char *value_str;

	status = 0;

	/* We want fields which start "fits-".
	 */
	if( !vips_isprefix( "fits-", field ) )
		return( NULL );

	/* The value should be a refstring, since we wrote it in fits2vips 
	 * above ^^.
	 */
	value_str = vips_value_get_ref_string( value, NULL );

	VIPS_DEBUG_MSG( "vips_fits_write_meta: setting meta on fits image:\n" );
	VIPS_DEBUG_MSG( " value == \"%s\"\n", value_str );

	if( fits_write_record( fits->fptr, value_str, &status ) ) {
		vips_fits_error( status );
		return( a );
	}

	return( NULL );
}

static int
vips_fits_set_header( VipsFits *fits, VipsImage *in )
{
	int status;
	int bitpix;
	int i;

	status = 0;

	fits->naxis = 3;
	fits->naxes[0] = in->Xsize;
	fits->naxes[1] = in->Ysize;
	fits->naxes[2] = in->Bands;

	for( i = 0; i < VIPS_NUMBER( fits2vips_formats ); i++ )
		if( fits2vips_formats[i][1] == in->BandFmt )
			break;
	if( i == VIPS_NUMBER( fits2vips_formats ) ) {
		vips_error( "fits", 
			_( "unsupported BandFmt %d\n" ), in->BandFmt );
		return( -1 );
	}
	bitpix = fits2vips_formats[i][0];
	fits->datatype = fits2vips_formats[i][2];

#ifdef VIPS_DEBUG
	VIPS_DEBUG_MSG( "naxis = %d\n", fits->naxis );
	for( i = 0; i < fits->naxis; i++ )
		VIPS_DEBUG_MSG( "%d) %lld\n", i, fits->naxes[i] );
	VIPS_DEBUG_MSG( "bitpix = %d\n", bitpix );
#endif /*VIPS_DEBUG*/

	if( fits_create_imgll( fits->fptr, bitpix, fits->naxis, 
		fits->naxes, &status ) ) {
		vips_fits_error( status );
		return( -1 );
	}

	if( vips_image_map( in,
		(VipsImageMapFn) vips_fits_write_meta, fits ) )
		return( -1 );

	return( 0 );
}

static int
vips_fits_write( VipsRegion *region, VipsRect *area, void *a )
{
	VipsFits *fits = (VipsFits *) a;
	VipsImage *image = fits->image;
	int es = VIPS_IMAGE_SIZEOF_ELEMENT( image );
	int ps = VIPS_IMAGE_SIZEOF_PEL( image );

	int status;
	int y, b, x, k;

	status = 0;

	VIPS_DEBUG_MSG( "vips_fits_write: "
		"writing left = %d, top = %d, width = %d, height = %d\n", 
		area->left, area->top, area->width, area->height );

	/* We need to write a band at a time. We can't bandsplit in vips,
	 * since vips_sink_disc() can't loop over many images at once, sadly.
	 */

	for( y = 0; y < area->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( region, 
			area->left, area->top + y );

		for( b = 0; b < image->Bands; b++ ) {
			VipsPel *p1, *q;
			long fpixel[3];

			p1 = p + b * es;
			q = fits->buffer;

			for( x = 0; x < area->width; x++ ) {
				for( k = 0; k < es; k++ ) 
					q[k] = p1[k];
				
				q += es;
				p1 += ps;
			}

			fpixel[0] = area->left + 1;
			fpixel[1] = area->top + y + 1;
			fpixel[2] = b + 1;

			/* No need to lock, write functions are single-threaded.
			 */

			if( fits_write_pix( fits->fptr, fits->datatype, 
				fpixel, area->width, fits->buffer, 
				&status ) ) {
				vips_fits_error( status );
				return( -1 );
			}
		}
	}

	return( 0 );
}

int
vips__fits_write( VipsImage *in, const char *filename )
{
	VipsFits *fits;

	VIPS_DEBUG_MSG( "vips2fits: writing \"%s\"\n", filename );

	if( !(fits = vips_fits_new_write( in, filename )) )
		return( -1 );

	if( vips_fits_set_header( fits, fits->image ) ||
		vips_sink_disc( fits->image, vips_fits_write, fits ) ) {
		vips_fits_close( fits );
		return( -1 );
	}
	vips_fits_close( fits );

	return( 0 );
}

#endif /*HAVE_CFITSIO*/
