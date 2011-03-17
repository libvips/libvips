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
#define VIPS_DEBUG
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
#include <vips/debug.h>

#include <fitsio.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/*

   	TODO

	- ask Doug for a test colour image

		found WFPC2u5780205r_c0fx.fits on the fits samples page, 
		but it's tiny

	- test performance

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
} VipsFits;

static void
vips_fits_error( int status )
{
	char buf[80];

	fits_get_errstatus( status, buf );
	im_error( "fits", "%s", buf );
}

static void
vips_fits_destroy( VipsFits *fits )
{
	VIPS_FREE( fits->filename );
	VIPS_FREEF( g_mutex_free, fits->lock );

	if( fits->fptr ) {
		int status;

		status = 0;

		if( fits_close_file( fits->fptr, &status ) ) 
			vips_fits_error( status );

		fits->fptr = NULL;
	}

	im_free( fits );
}

static VipsFits *
vips_fits_new_read( const char *filename, VipsImage *out, int band_select )
{
	VipsFits *fits;
	int status;

	if( !(fits = VIPS_NEW( NULL, VipsFits )) )
		return( NULL );

	fits->filename = im_strdup( NULL, filename );
	fits->image = out;
	fits->fptr = NULL;
	fits->lock = NULL;
	fits->band_select = band_select;
	g_signal_connect( out, "close", 
		G_CALLBACK( vips_fits_destroy ), fits );

	status = 0;
	if( fits_open_file( &fits->fptr, filename, READONLY, &status ) ) {
		im_error( "fits", _( "unable to open \"%s\"" ), filename );
		vips_fits_error( status );
		return( NULL );
	}

	fits->lock = g_mutex_new();

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
	int morekeys;
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
				im_error( "fits", "%s", _( "dimensions above 3 "
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
		im_error( "fits", _( "bad number of axis %d" ), fits->naxis );
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
		im_error( "fits", _( "unsupported bitpix %d\n" ),
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

	im_initdesc( out,
		 width, height, bands,
		 im_bits_of_fmt( format ), format,
		 VIPS_CODING_NONE, type, 1.0, 1.0, 0, 0 );

	/* Read all keys into meta.
	 */
	if( fits_get_hdrspace( fits->fptr, &keysexist, &morekeys, &status ) ) {
		vips_fits_error( status );
		return( -1 );
	}

	for( i = 0; i < keysexist; i++ ) {
		char key[81];
		char value[81];
		char comment[81];
		char vipsname[100];

		if( fits_read_keyn( fits->fptr, i + 1, 
			key, value, comment, &status ) ) {
			vips_fits_error( status );
			return( -1 );
		}

		VIPS_DEBUG_MSG( "fits: seen:\n" );
		VIPS_DEBUG_MSG( " key == %s\n", key );
		VIPS_DEBUG_MSG( " value == %s\n", value );
		VIPS_DEBUG_MSG( " comment == %s\n", comment );

		im_snprintf( vipsname, 100, "fits-%s", key );
		if( im_meta_set_string( out, vipsname, value ) ) 
			return( -1 );
		im_snprintf( vipsname, 100, "fits-%s-comment", key );
		if( im_meta_set_string( out, vipsname, comment ) ) 
			return( -1 );
	}

	return( 0 );
}

static int
fits2vips_header( const char *filename, VipsImage *out )
{
	VipsFits *fits;

	VIPS_DEBUG_MSG( "fits2vips_header: reading \"%s\"\n", filename );

	if( !(fits = vips_fits_new_read( filename, out, -1 )) || 
		vips_fits_get_header( fits, out ) ) 
		return( -1 );

	return( 0 );
}

static int
fits2vips_generate( VipsRegion *out, void *seq, void *a, void *b )
{
	VipsFits *fits = (VipsFits *) a;
	Rect *r = &out->valid;

	PEL *q;
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

		q = (PEL *) VIPS_REGION_ADDR( out, r->left, r->top );

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

			q = (PEL *) VIPS_REGION_ADDR( out, r->left, y );

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

	if( !(fits = vips_fits_new_read( filename, out, band_select )) ||
		vips_fits_get_header( fits, out ) ||
		im_demand_hint( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL ) ||
		im_generate( out, NULL, fits2vips_generate, NULL, fits, NULL ) )
		return( -1 );

	return( 0 );
}

/**
 * im_fits2vips:
 * @filename: file to load
 * @out: image to write to
 *
 * Read a FITS image file into a VIPS image. 
 *
 * See also: #VipsFormat.
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_fits2vips( const char *filename, VipsImage *out )
{
	VipsImage *t;
	int n_bands;

	VIPS_DEBUG_MSG( "im_fits2vips: reading \"%s\"\n", filename );

	/* fits is naturally a band-separated format. For single-band images,
	 * we can just read out. For many bands, we read each band out
	 * separately then join them.
	 */

	if( !(t = vips_image_new( "p" )) ||
		vips_object_local( out, t ) ||
		fits2vips_header( filename, t ) )
		return( -1 );
	n_bands = t->Bands;

	if( n_bands == 1 ) {
		if( !(t = vips_image_new( "p" )) ||
			vips_object_local( out, t ) ||
			fits2vips( filename, t, 0 ) )
			return( -1 );
	}
	else {
		VipsImage *acc;
		int i;

		acc = NULL;
		for( i = 0; i < n_bands; i++ ) {
			if( !(t = vips_image_new( "p" )) ||
				vips_object_local( out, t ) ||
				fits2vips( filename, t, i ) )
				return( -1 );

			if( !acc )
				acc = t;
			else {
				VipsImage *t2;

				if( !(t2 = vips_image_new( "p" )) ||
					vips_object_local( out, t2 ) ||
					im_bandjoin( acc, t, t2 ) )
					return( -1 );
				acc = t2;
			}
		}

		t = acc;
	}

	/* fits has inverted y.
	 */
	if( im_flipver( t, out ) )
		return( -1 );

	return( 0 );
}

static int
isfits( const char *filename )
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

	if( !(fits = VIPS_NEW( NULL, VipsFits )) )
		return( NULL );

	fits->filename = im_strdup( NULL, filename );
	fits->image = in;
	fits->fptr = NULL;
	fits->lock = NULL;
	fits->band_select = -1;
	g_signal_connect( in, "close", 
		G_CALLBACK( vips_fits_destroy ), fits );

	status = 0;
	if( fits_create_file( &fits->fptr, filename, &status ) ) {
		im_error( "fits", _( "unable to write to \"%s\"" ), filename );
		vips_fits_error( status );
		return( NULL );
	}

	fits->lock = g_mutex_new();

	return( fits );
}

static int
vips_fits_set_header( VipsFits *fits, VipsImage *in )
{
	int status;
	int bitpix;
	long int naxes[MAX_DIMENSIONS];

	/*
	int width, height, bands, format, type;
	int keysexist;
	int morekeys;
	 */

	int i;

	status = 0;

	fits->naxis = 3;
	fits->naxes[2] = naxes[2] = in->Bands;
	fits->naxes[1] = naxes[1] = in->Ysize;
	fits->naxes[0] = naxes[0] = in->Xsize;

	for( i = 0; i < VIPS_NUMBER( fits2vips_formats ); i++ )
		if( fits2vips_formats[i][1] == in->BandFmt )
			break;
	if( i == VIPS_NUMBER( fits2vips_formats ) ) {
		im_error( "fits", _( "unsupported BandFmt %d\n" ),
			in->BandFmt );
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

	if( fits_create_img( fits->fptr, bitpix, fits->naxis, 
		naxes, &status ) ) {
		vips_fits_error( status );
		return( -1 );
	}

	/* Read all keys into meta.
	if( fits_get_hdrspace( fits->fptr, &keysexist, &morekeys, &status ) ) {
		vips_fits_error( status );
		return( -1 );
	}

	for( i = 0; i < keysexist; i++ ) {
		char key[81];
		char value[81];
		char comment[81];
		char vipsname[100];

		if( fits_read_keyn( fits->fptr, i + 1, 
			key, value, comment, &status ) ) {
			vips_fits_error( status );
			return( -1 );
		}

		VIPS_DEBUG_MSG( "fits: seen:\n" );
		VIPS_DEBUG_MSG( " key == %s\n", key );
		VIPS_DEBUG_MSG( " value == %s\n", value );
		VIPS_DEBUG_MSG( " comment == %s\n", comment );

		im_snprintf( vipsname, 100, "fits-%s", key );
		if( im_meta_set_string( out, vipsname, value ) ) 
			return( -1 );
		im_snprintf( vipsname, 100, "fits-%s-comment", key );
		if( im_meta_set_string( out, vipsname, comment ) ) 
			return( -1 );
	}
	 */

	return( 0 );
}

static int
vips_fits_write( VipsFits *fits, VipsImage *in )
{
	return( 0 );
}

/**
 * im_vips2fits:
 * @in: image to write 
 * @filename: file to write to
 *
 * Write @in to @filename in FITS format.
 *
 * See also: #VipsFormat.
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_vips2fits( VipsImage *in, const char *filename )
{
	VipsFits *fits;

	VIPS_DEBUG_MSG( "im_vips2fits: writing \"%s\"\n", filename );

	if( !(fits = vips_fits_new_write( in, filename )) ||
		vips_fits_set_header( fits, in ) ||
		vips_fits_write( fits, in ) )
		return( -1 );

	return( 0 );
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
	format_class->save = im_vips2fits;
	format_class->suffs = fits_suffs;
}

static void
vips_format_fits_init( VipsFormatFits *object )
{
}

G_DEFINE_TYPE( VipsFormatFits, vips_format_fits, VIPS_TYPE_FORMAT );

#endif /*HAVE_CFITSIO*/
