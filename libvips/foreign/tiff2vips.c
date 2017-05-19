/* TIFF parts: Copyright (c) 1988, 1990 by Sam Leffler.
 * All rights reserved.
 *
 * This file is provided for unrestricted use provided that this
 * legend is included on all tape media and as a part of the
 * software program in whole or part.  Users may copy, modify or
 * distribute this file at will.
 * -----------------------------
 * Modifications for VIPS:  Kirk Martinez 1994
 * 22/11/94 JC
 *	- more general
 *	- memory leaks fixed
 * 20/3/95 JC
 *	- TIFF error handler added
 *	- read errors detected correctly
 *
 * Modified to handle LAB in tiff format.
 * It convert LAB-tiff format to VIPS_INTERPRETATION_LABQ in vips format.
 *  Copyright July-1995 Ahmed Abbood.
 *
 *
 * 19/9/95 JC
 *	- now calls TIFFClose ... stupid
 * 25/1/96 JC
 *	- typo on MINISBLACK ...
 * 7/4/97 JC
 *	- completely redone for TIFF 6
 *	- now full baseline TIFF 6 reader, and does CIELAB as well
 * 11/4/97 JC
 *	- added partial read for tiled images
 * 23/4/97 JC
 *	- extra subsample parameter
 *	- im_istiffpyramid() added
 * 5/12/97 JC
 *	- if loading YCbCr, convert to VIPS_CODING_LABQ
 * 1/5/98 JC
 *	- now reads 16-bit greyscale and RGB
 * 26/10/98 JC
 *	- now used "rb" mode on systems that need binary open
 * 12/11/98 JC
 *	- no sub-sampling if sub == 1
 * 26/2/99 JC
 *	- ooops, else missing for subsample stuff above
 * 2/10/99 JC
 *	- tiled 16-bit greyscale read was broken
 *	- added mutex for TIFFReadTile() calls
 * 11/5/00 JC
 *	- removed TIFFmalloc/TIFFfree usage
 * 23/4/01 JC
 *	- HAVE_TIFF turns on TIFF goodness
 * 24/5/01 JC
 *	- im_tiff2vips_header() added
 * 11/7/01 JC
 *	- subsample now in input filename
 *	- ... and it's a page number (from 0) instead
 * 21/8/02 JC
 *	- now reads CMYK
 *	- hmm, dpi -> ppm conversion was wrong!
 * 10/9/02 JC
 *	- oops, handle TIFF errors better
 * 2/12/02 JC
 *	- reads 8-bit RGBA
 * 12/12/02 JC
 *	- reads 16-bit LAB
 * 13/2/03 JC
 *	- pixels/cm res read was wrong
 * 17/11/03 Andrey Kiselev
 *	- read 32-bit float greyscale and rgb
 * 5/4/04
 *	- better handling of edge tiles (thanks Ruven)
 * 16/4/04
 *	- cleanup
 *	- added broken tile read mode
 * 18/5/04 Andrey Kiselev
 *	- better no resolution diagnostic
 * 26/5/04
 *	- reads 16 bit RGBA
 * 28/7/04
 *	- arrg, 16bit RGB was broken, thanks haida
 * 26/11/04
 *	- add a TIFF warning handler, stops occasional libMagick exceptions
 * 9/3/05
 *	- load 32-bit float LAB
 * 8/4/05
 *	- onebit read no longer reads one byte too many on multiple of 8 wide
 *	  images
 * 22/6/05
 *	- 16 bit LAB read was broken
 * 9/9/05
 * 	- read any ICCPROFILE tag
 * 8/5/06
 * 	- set RGB16 and GREY16 Type
 * 21/5/06
 * 	- use external im_tile_cache() operation for great code shrinkage
 * 	- less RAM usage too, esp. with >1 CPU
 * 	- should be slightly faster
 * 	- removed 'broken' read option
 * 18/7/07 Andrey Kiselev
 * 	- remove "b" option on TIFFOpen()
 * 9/4/08
 * 	- set VIPS_META_RESOLUTION_UNIT
 * 17/4/08
 * 	- allow CMYKA (thanks Doron)
 * 17/7/08
 * 	- convert YCbCr to RGB on read (thanks Ole)
 * 15/8/08
 * 	- reorganise for image format system
 * 20/12/08
 * 	- dont read with mmap: no performance advantage with libtiff, chews up 
 * 	  VM wastefully
 * 13/1/09
 * 	- read strip-wise, not scanline-wise ... works with more compression /
 * 	  subsampling schemes (esp. subsampled YCbCr), and it's a bit quicker
 * 4/2/10
 * 	- gtkdoc
 * 12/12/10
 * 	- oops, we can just memcpy() now heh
 * 	- avoid unpacking via buffers if we can: either read a tile directly
 * 	  into the output region, or writeline directly from the tiff buffer
 * 4/4/11
 * 	- argh int/uint mixup for rows_per_strip, thanks Bubba
 * 21/4/11
 * 	- palette read can do 1,2,4,8 bits per sample
 * 	- palette read can do mono images
 * 5/12/11
 * 	- make into a simple function call ready to be wrapped as a new-style
 * 	  VipsForeign class
 * 18/2/12
 * 	- switch to sequential read
 * 	- remove the lock ... tilecache does this for us
 * 3/6/12
 * 	- always offer THINSTRIP ... later stages can ask for something more
 * 	  relaxed if they wish
 * 7/6/12
 * 	- clip rows_per_strip down to image height to avoid overflows for huge
 * 	  values (thanks Nicolas)
 * 	- better error msg for not PLANARCONFIG_CONTIG images
 * 16/9/13
 * 	- support alpha for 8, 16 and 32-bit greyscale images, thanks Robert
 * 17/9/13
 * 	- support separate planes for strip read
 * 	- big cleanup
 * 	- support for many more formats, eg. 32-bit int etc. 
 * 11/4/14
 * 	- support 16 bits per sample palette images
 * 	- palette images can have an alpha
 * 22/4/14
 * 	- add read from buffer
 * 30/4/14
 * 	- 1/2/4 bit palette images can have alpha
 * 27/10/14 Lovell
 * 	- better istiff detector spots bigtiff
 * 3/12/14
 * 	- read any XMP metadata
 * 19/1/15
 * 	- try to handle 8-bit colormaps
 * 26/2/15
 * 	- close the read down early for a header read ... this saves an
 * 	  fd during file read, handy for large numbers of input images 
 * 29/9/15
 * 	- load IPCT metadata
 * 	- load photoshop metadata
 * 21/12/15
 * 	- load TIFFTAG_IMAGEDESCRIPTION
 * 11/4/16
 * 	- non-int RGB images are tagged as scRGB ... matches photoshop
 * 	  convention
 * 26/5/16
 * 	- add autorotate support
 * 17/11/16
 * 	- add multi-page read 
 * 17/1/17
 * 	- invalidate operation on read error
 * 27/1/17
 * 	- if rows_per_strip is large, read with scanline API instead
 * 19/5/17
 * 	- page > 0 could break edge tiles or strips
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

#ifdef HAVE_TIFF

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/thread.h>

#include "pforeign.h"
#include "tiff.h"

/* What we read from the tiff dir to set our read strategy. For multipage
 * read, we need to read and compare lots of these, so it needs to be broken
 * out as a separate thing.
 */
typedef struct _RtiffHeader {
	uint32 width;
	uint32 height;
	int samples_per_pixel;
	int bits_per_sample;
	int photometric_interpretation;
	int sample_format;
	gboolean separate; 
	int orientation; 

	/* Result of TIFFIsTiled().
	 */
	gboolean tiled;

	/* Fields for tiled images.
	 */
	uint32 tile_width;
	uint32 tile_height;		

	/* Fields for strip images.
	 *
	 * If read_scanlinewise is TRUE, the strips are too large to read in a
	 * single lump and we need to use the scanline API.
	 */
	uint32 rows_per_strip;
	tsize_t strip_size;
	int number_of_strips;
	gboolean read_scanlinewise;
} RtiffHeader;

/* Scanline-type process function.
 */
struct _Rtiff;
typedef void (*scanline_process_fn)( struct _Rtiff *, 
	VipsPel *q, VipsPel *p, int n, void *client );

/* Stuff we track during a read.
 */
typedef struct _Rtiff {
	/* Parameters.
	 */
	char *filename;
	VipsImage *out;
	int page;
	int n;
	gboolean autorotate;

	/* The TIFF we read.
	 */
	TIFF *tiff;

	/* The current page we have set.
	 */
	int current_page;

	/* Process for this image type.
	 */
	scanline_process_fn sfn;
	void *client;

	/* Set this is the processfn is just doing a memcpy.
	 */
	gboolean memcpy;

	/* Geometry as read from the TIFF header. This is read for the first
	 * page, and equal for all other pages. 
	 */
	RtiffHeader header; 

	/* Hold a single strip or tile, possibly just an image plane.
	 */
	tdata_t plane_buf;

	/* Hold a plane-assembled strip or tile ... a set of samples_per_pixel 
	 * strips or tiles interleaved. 
	 */
	tdata_t contig_buf;
} Rtiff;

/* Test for field exists.
 */
static int
tfexists( TIFF *tif, ttag_t tag )
{
	uint32 a, b;

	if( TIFFGetField( tif, tag, &a, &b ) ) 
		return( 1 );
	else 
		return( 0 );
}

/* Get a uint32 field. 
 */
static int
tfget32( TIFF *tif, ttag_t tag, uint32 *out )
{
	uint32 fld;

	if( !TIFFGetFieldDefaulted( tif, tag, &fld ) ) {
		vips_error( "tiff2vips", 
			_( "required field %d missing" ), tag );
		return( 0 );
	}

	*out = fld;

	return( 1 );
}

/* Get a uint16 field.
 */
static int
tfget16( TIFF *tif, ttag_t tag, int *out )
{
	uint16 fld;

	if( !TIFFGetFieldDefaulted( tif, tag, &fld ) ) {
		vips_error( "tiff2vips", 
			_( "required field %d missing" ), tag );
		return( 0 );
	}

	*out = fld;

	return( 1 );
}

static int
get_resolution( TIFF *tiff, VipsImage *out )
{
	float x, y;
	int ru;

	if( TIFFGetFieldDefaulted( tiff, TIFFTAG_XRESOLUTION, &x ) &&
		TIFFGetFieldDefaulted( tiff, TIFFTAG_YRESOLUTION, &y ) &&
		tfget16( tiff, TIFFTAG_RESOLUTIONUNIT, &ru ) ) {
		switch( ru ) {
		case RESUNIT_NONE:
			break;

		case RESUNIT_INCH:
			/* In pixels-per-inch ... convert to mm.
			 */
			x /= 10.0 * 2.54;
			y /= 10.0 * 2.54;
			vips_image_set_string( out, 
				VIPS_META_RESOLUTION_UNIT, "in" );
			break;

		case RESUNIT_CENTIMETER:
			/* In pixels-per-centimetre ... convert to mm.
			 */
			x /= 10.0;
			y /= 10.0;
			vips_image_set_string( out, 
				VIPS_META_RESOLUTION_UNIT, "cm" );
			break;

		default:
			vips_error( "tiff2vips", 
				"%s", _( "unknown resolution unit" ) );
			return( -1 );
		}
	}
	else {
		g_warning( _( "no resolution information for "
			"TIFF image \"%s\" -- defaulting to 1 pixel per mm" ), 
			TIFFFileName( tiff ) );
		x = 1.0;
		y = 1.0;
	}

	out->Xres = x;
	out->Yres = y;

	return( 0 );
}

static int
get_sample_format( TIFF *tiff )
{
	int sample_format;
	uint16 v;

	sample_format = SAMPLEFORMAT_INT;

	if( TIFFGetFieldDefaulted( tiff, TIFFTAG_SAMPLEFORMAT, &v ) ) {
		/* Some images have this set to void, bizarre.
		 */
		if( v == SAMPLEFORMAT_VOID )
			v = SAMPLEFORMAT_UINT;

		sample_format = v;
	}

	return( sample_format ); 
}

static int
get_orientation( TIFF *tiff )
{
	int orientation;
	uint16 v;

	orientation = ORIENTATION_TOPLEFT;

	if( TIFFGetFieldDefaulted( tiff, TIFFTAG_ORIENTATION, &v ) ) 
		/* Can have mad values. 
		 */
		orientation = VIPS_CLIP( 1, v, 8 );

	return( orientation );
}

static int
rtiff_strip_read( Rtiff *rtiff, int strip, tdata_t buf )
{
	tsize_t length;

#ifdef DEBUG
	printf( "rtiff_strip_read: reading strip %d\n", strip ); 
#endif /*DEBUG*/

	if( rtiff->header.read_scanlinewise )  
		length = TIFFReadScanline( rtiff->tiff, 
			buf, strip, (tsize_t) -1 );
	else 
		length = TIFFReadEncodedStrip( rtiff->tiff, 
			strip, buf, (tsize_t) -1 );

	if( length == -1 ) {
		vips_foreign_load_invalidate( rtiff->out );
		vips_error( "tiff2vips", "%s", _( "read error" ) );
		return( -1 );
	}

	return( 0 );
}

static int
rtiff_set_page( Rtiff *rtiff, int page )
{
	if( rtiff->current_page != page ) {
#ifdef DEBUG
		printf( "rtiff_set_page: selecting page %d\n", page ); 
#endif /*DEBUG*/

		if( !TIFFSetDirectory( rtiff->tiff, page ) ) {
			vips_error( "tiff2vips", 
				_( "TIFF does not contain page %d" ), page );
			return( -1 );
		}

		rtiff->current_page = page;
	}

	return( 0 );
}

static int
rtiff_n_pages( Rtiff *rtiff )
{
	int n;

	(void) TIFFSetDirectory( rtiff->tiff, 0 );

	for( n = 1; TIFFReadDirectory( rtiff->tiff ); n++ )
		;

	(void) TIFFSetDirectory( rtiff->tiff, rtiff->current_page );

#ifdef DEBUG
	printf( "rtiff_n_pages: found %d pages\n", n ); 
#endif /*DEBUG*/

	return( n );
}

static int
rtiff_check_samples( Rtiff *rtiff, int samples_per_pixel )
{
	if( rtiff->header.samples_per_pixel != samples_per_pixel ) { 
		vips_error( "tiff2vips", 
			_( "not %d bands" ), samples_per_pixel ); 
		return( -1 );
	}

	return( 0 );
}

/* Check n and n+1 so we can have an alpha.
 */
static int
rtiff_check_min_samples( Rtiff *rtiff, int samples_per_pixel )
{
	if( rtiff->header.samples_per_pixel < samples_per_pixel ) { 
		vips_error( "tiff2vips", 
			_( "not at least %d samples per pixel" ), 
			samples_per_pixel ); 
		return( -1 );
	}

	return( 0 );
}

static int
rtiff_check_interpretation( Rtiff *rtiff, int photometric_interpretation )
{
	if( rtiff->header.photometric_interpretation != 
		photometric_interpretation ) { 
		vips_error( "tiff2vips", 
			_( "not photometric interpretation %d" ), 
			photometric_interpretation ); 
		return( -1 );
	}

	return( 0 );
}

static int
rtiff_check_bits( Rtiff *rtiff, int bits_per_sample )
{
	if( rtiff->header.bits_per_sample != bits_per_sample ) { 
		vips_error( "tiff2vips", 
			_( "not %d bits per sample" ), bits_per_sample );
		return( -1 );
	}

	return( 0 );
}

static int
rtiff_check_bits_palette( Rtiff *rtiff )
{
	if( rtiff->header.bits_per_sample != 16 && 
		rtiff->header.bits_per_sample != 8 && 
		rtiff->header.bits_per_sample != 4 && 
		rtiff->header.bits_per_sample != 2 && 
		rtiff->header.bits_per_sample != 1 ) {
		vips_error( "tiff2vips", 
			_( "%d bits per sample palette image not supported" ),
			rtiff->header.bits_per_sample );
		return( -1 );
	}

	return( 0 );
}

static VipsBandFormat
rtiff_guess_format( Rtiff *rtiff )
{
	int bits_per_sample = rtiff->header.bits_per_sample;
	int sample_format = rtiff->header.sample_format;

	switch( bits_per_sample ) {
	case 1:
	case 2:
	case 4:
	case 8:
		if( sample_format == SAMPLEFORMAT_INT )
			return( VIPS_FORMAT_CHAR );
		if( sample_format == SAMPLEFORMAT_UINT )
			return( VIPS_FORMAT_UCHAR );
		break;

	case 16:
		if( sample_format == SAMPLEFORMAT_INT )
			return( VIPS_FORMAT_SHORT );
		if( sample_format == SAMPLEFORMAT_UINT )
			return( VIPS_FORMAT_USHORT );
		break;

	case 32:
		if( sample_format == SAMPLEFORMAT_INT )
			return( VIPS_FORMAT_INT );
		if( sample_format == SAMPLEFORMAT_UINT )
			return( VIPS_FORMAT_UINT );
		if( sample_format == SAMPLEFORMAT_IEEEFP )
			return( VIPS_FORMAT_FLOAT );
		break;

	case 64:
		if( sample_format == SAMPLEFORMAT_IEEEFP )
			return( VIPS_FORMAT_DOUBLE );
		if( sample_format == SAMPLEFORMAT_COMPLEXIEEEFP )
			return( VIPS_FORMAT_COMPLEX );
		break;

	case 128:
		if( sample_format == SAMPLEFORMAT_COMPLEXIEEEFP )
			return( VIPS_FORMAT_DPCOMPLEX );
		break;

	default:
		break;
	}

	vips_error( "tiff2vips", "%s", _( "unsupported tiff image type\n" ) ); 

	return( VIPS_FORMAT_NOTSET ); 
}

/* Per-scanline process function for VIPS_CODING_LABQ.
 */
static void
rtiff_labpack_line( Rtiff *rtiff, VipsPel *q, VipsPel *p, int n, void *dummy )
{
	int samples_per_pixel = rtiff->header.samples_per_pixel;

	int x;

	for( x = 0; x < n; x++ ) {
		q[0] = p[0];
		q[1] = p[1];
		q[2] = p[2];
		q[3] = 0;

		q += 4;
		p += samples_per_pixel;
	}
}

/* Read an 8-bit LAB image.
 */
static int
rtiff_parse_labpack( Rtiff *rtiff, VipsImage *out )
{
	if( rtiff_check_min_samples( rtiff, 3 ) ||
		rtiff_check_bits( rtiff, 8 ) ||
		rtiff_check_interpretation( rtiff, PHOTOMETRIC_CIELAB ) )
		return( -1 );

	out->Bands = 4; 
	out->BandFmt = VIPS_FORMAT_UCHAR; 
	out->Coding = VIPS_CODING_LABQ; 
	out->Type = VIPS_INTERPRETATION_LAB; 

	rtiff->sfn = rtiff_labpack_line;

	return( 0 );
}

/* Per-scanline process function for LABS.
 */
static void
rtiff_labs_line( Rtiff *rtiff, VipsPel *q, VipsPel *p, int n, void *dummy )
{
	int samples_per_pixel = rtiff->header.samples_per_pixel;

	unsigned short *p1;
	short *q1;
	int x;
	int i; 

	p1 = (unsigned short *) p;
	q1 = (short *) q;
	for( x = 0; x < n; x++ ) {
		/* We use a signed int16 for L.
		 */
		q1[0] = p1[0] >> 1;

		for( i = 1; i < samples_per_pixel; i++ ) 
			q1[i] = p1[i];

		q1 += samples_per_pixel;
		p1 += samples_per_pixel;
	}
}

/* Read a 16-bit LAB image.
 */
static int
rtiff_parse_labs( Rtiff *rtiff, VipsImage *out )
{
	if( rtiff_check_min_samples( rtiff, 3 ) ||
		rtiff_check_bits( rtiff, 16 ) ||
		rtiff_check_interpretation( rtiff, PHOTOMETRIC_CIELAB ) )
		return( -1 );

	out->Bands = rtiff->header.samples_per_pixel; 
	out->BandFmt = VIPS_FORMAT_SHORT; 
	out->Coding = VIPS_CODING_NONE; 
	out->Type = VIPS_INTERPRETATION_LABS; 

	rtiff->sfn = rtiff_labs_line;

	return( 0 );
}

/* Per-scanline process function for 1 bit images.
 */
static void
rtiff_onebit_line( Rtiff *rtiff, VipsPel *q, VipsPel *p, int n, void *flg )
{
	int photometric_interpretation = 
		rtiff->header.photometric_interpretation;

	int x, i, z;
	VipsPel bits;

	int black = photometric_interpretation == PHOTOMETRIC_MINISBLACK ?
		0 : 255;
	int white = black ^ 0xff;

	/* (sigh) how many times have I written this?
	 */
	x = 0; 
	for( i = 0; i < (n >> 3); i++ ) {
		bits = (VipsPel) p[i];

		for( z = 0; z < 8; z++ ) {
			q[x] = (bits & 128) ? white : black;
			bits <<= 1;
			x += 1;
		}
	}

	/* Do last byte in line.
	 */
	if( n & 7 ) {
		bits = p[i];
		for( z = 0; z < (n & 7); z++ ) {
			q[x + z] = (bits & 128) ? white : black;
			bits <<= 1;
		}
	}
}

/* Read a 1-bit TIFF image. 
 */
static int
rtiff_parse_onebit( Rtiff *rtiff, VipsImage *out )
{
	if( rtiff_check_samples( rtiff, 1 ) ||
		rtiff_check_bits( rtiff, 1 ) )
		return( -1 );

	out->Bands = 1; 
	out->BandFmt = VIPS_FORMAT_UCHAR; 
	out->Coding = VIPS_CODING_NONE; 
	out->Type = VIPS_INTERPRETATION_B_W; 

	rtiff->sfn = rtiff_onebit_line;

	return( 0 );
}

/* Swap the sense of the first channel, if necessary. 
 */
#define GREY_LOOP( TYPE, MAX ) { \
	TYPE *p1; \
	TYPE *q1; \
	\
	p1 = (TYPE *) p; \
	q1 = (TYPE *) q; \
	for( x = 0; x < n; x++ ) { \
		if( invert ) \
			q1[0] = MAX - p1[0]; \
		else \
			q1[0] = p1[0]; \
		\
		for( i = 1; i < samples_per_pixel; i++ ) \
			q1[i] = p1[i]; \
		\
		q1 += samples_per_pixel; \
		p1 += samples_per_pixel; \
	} \
}

/* Per-scanline process function for greyscale images.
 */
static void
rtiff_greyscale_line( Rtiff *rtiff, VipsPel *q, VipsPel *p, int n, void *client )
{
	int samples_per_pixel = rtiff->header.samples_per_pixel;
	int photometric_interpretation = 
		rtiff->header.photometric_interpretation;
	gboolean invert = photometric_interpretation == PHOTOMETRIC_MINISWHITE;
	VipsBandFormat format = rtiff_guess_format( rtiff ); 

	int x, i;

	switch( format ) {
	case VIPS_FORMAT_UCHAR:
	case VIPS_FORMAT_CHAR:
		GREY_LOOP( guchar, UCHAR_MAX ); 
		break;

	case VIPS_FORMAT_SHORT:
		GREY_LOOP( gshort, SHRT_MAX ); 
		break;

	case VIPS_FORMAT_USHORT:
		GREY_LOOP( gushort, USHRT_MAX ); 
		break;

	case VIPS_FORMAT_INT:
		GREY_LOOP( gint, INT_MAX ); 
		break;

	case VIPS_FORMAT_UINT:
		GREY_LOOP( guint, UINT_MAX ); 
		break;

	case VIPS_FORMAT_FLOAT:
		GREY_LOOP( float, 1.0 ); 
		break;

	case VIPS_FORMAT_DOUBLE:
		GREY_LOOP( double, 1.0 ); 
		break;

	default:
		g_assert_not_reached();
	}
}

/* Read a grey-scale TIFF image. We have to invert the first band if
 * PHOTOMETRIC_MINISBLACK is set. 
 */
static int
rtiff_parse_greyscale( Rtiff *rtiff, VipsImage *out )
{
	if( rtiff_check_min_samples( rtiff, 1 ) )
		return( -1 );

	out->Bands = rtiff->header.samples_per_pixel; 
	out->BandFmt = rtiff_guess_format( rtiff );
	if( out->BandFmt == VIPS_FORMAT_NOTSET )
		return( -1 ); 
	out->Coding = VIPS_CODING_NONE; 

	if( rtiff->header.bits_per_sample == 16 )
		out->Type = VIPS_INTERPRETATION_GREY16; 
	else
		out->Type = VIPS_INTERPRETATION_B_W; 

	/* rtiff_greyscale_line() doesn't do complex.
	 */
	if( vips_check_noncomplex( "tiff2vips", out ) )
		return( -1 ); 

	rtiff->sfn = rtiff_greyscale_line;

	return( 0 );
}

typedef struct {
	/* LUTs mapping image indexes to RGB.
	 */
	VipsPel *red8;
	VipsPel *green8;
	VipsPel *blue8;

	guint16 *red16;
	guint16 *green16;
	guint16 *blue16;

	/* All maps equal, so we write mono.
	 */
	gboolean mono;
} PaletteRead;

/* 1/2/4 bit samples with an 8-bit palette.
 */
static void
rtiff_palette_line_bit( Rtiff *rtiff, 
	VipsPel *q, VipsPel *p, int n, void *client )
{
	PaletteRead *read = (PaletteRead *) client;
	int samples_per_pixel = rtiff->header.samples_per_pixel;
	int bits_per_sample = rtiff->header.bits_per_sample;

	int bit;
	VipsPel data;
	int x;

	bit = 0;
	data = 0;
	for( x = 0; x < n * samples_per_pixel; x++ ) {
		int i;

		if( bit <= 0 ) {
			data = *p++;
			bit = 8;
		}

		i = data >> (8 - bits_per_sample);
		data <<= bits_per_sample;
		bit -= bits_per_sample;

		/* The first band goes through the LUT, subsequent bands are
		 * left-justified and copied.
		 */
		if( x % samples_per_pixel == 0 ) { 
			if( read->mono ) 
				*q++ = read->red8[i];
			else {
				q[0] = read->red8[i];
				q[1] = read->green8[i];
				q[2] = read->blue8[i];
				q += 3;
			}
		}
		else 
			*q++ = i << (8 - bits_per_sample);
	}
}

/* 8-bit samples with an 8-bit palette.
 */
static void
rtiff_palette_line8( Rtiff *rtiff, VipsPel *q, VipsPel *p, int n, 
	void *client )
{
	PaletteRead *read = (PaletteRead *) client;
	int samples_per_pixel = rtiff->header.samples_per_pixel;

	int x;
	int s;

	for( x = 0; x < n; x++ ) {
		int i = p[0];

		if( read->mono ) 
			q[0] = read->red8[i];
		else {
			q[0] = read->red8[i];
			q[1] = read->green8[i];
			q[2] = read->blue8[i];
			q += 2;
		}

		for( s = 1; s < samples_per_pixel; s++ )
			q[s] = p[s]; 

		q += samples_per_pixel; 
		p += samples_per_pixel; 
	}
}

/* 16-bit samples with 16-bit data in the palette. 
 */
static void
rtiff_palette_line16( Rtiff *rtiff, VipsPel *q, VipsPel *p, int n, 
	void *client )
{
	PaletteRead *read = (PaletteRead *) client;
	int samples_per_pixel = rtiff->header.samples_per_pixel;

	guint16 *p16, *q16;
	int x;
	int s;

	q16 = (guint16 *) q;
	p16 = (guint16 *) p;

	for( x = 0; x < n; x++ ) {
		int i = p16[0];

		if( read->mono ) 
			q16[0] = read->red16[i];
		else {
			q16[0] = read->red16[i];
			q16[1] = read->green16[i];
			q16[2] = read->blue16[i];
			q16 += 2;
		}

		for( s = 1; s < samples_per_pixel; s++ )
			q16[s] = p16[s]; 

		q16 += samples_per_pixel; 
		p16 += samples_per_pixel; 
	}
}

/* Read a palette-ised TIFF image. 
 */
static int
rtiff_parse_palette( Rtiff *rtiff, VipsImage *out )
{
	int samples_per_pixel = rtiff->header.samples_per_pixel;
	int bits_per_sample = rtiff->header.bits_per_sample;

	int len;
	PaletteRead *read;
	int i;

	if( rtiff_check_bits_palette( rtiff ) ||
		rtiff_check_min_samples( rtiff, 1 ) )
		return( -1 ); 
	len = 1 << bits_per_sample;

	if( !(read = VIPS_NEW( out, PaletteRead )) ||
		!(read->red8 = VIPS_ARRAY( out, len, VipsPel )) ||
		!(read->green8 = VIPS_ARRAY( out, len, VipsPel )) ||
		!(read->blue8 = VIPS_ARRAY( out, len, VipsPel )) )
		return( -1 );

	/* Get maps, convert to 8-bit data.
	 */
	if( !TIFFGetField( rtiff->tiff, 
		TIFFTAG_COLORMAP, 
		&read->red16, &read->green16, &read->blue16 ) ) {
		vips_error( "tiff2vips", "%s", _( "bad colormap" ) );
		return( -1 );
	}

	/* Old-style colourmaps were 8-bit. If all the top bytes are zero,
	 * assume we have one of these.
	 *
	 * See: https://github.com/jcupitt/libvips/issues/220
	 */
	for( i = 0; i < len; i++ ) 
		if( (read->red16[i] >> 8) | 
			(read->green16[i] >> 8) | 
			(read->blue16[i] >> 8) )
			break;
	if( i < len ) 
		for( i = 0; i < len; i++ ) {
			read->red8[i] = read->red16[i] >> 8;
			read->green8[i] = read->green16[i] >> 8;
			read->blue8[i] = read->blue16[i] >> 8;
		}
	else {
		g_warning( "%s", _( "assuming 8-bit palette" ) );

		for( i = 0; i < len; i++ ) {
			read->red8[i] = read->red16[i] & 0xff;
			read->green8[i] = read->green16[i] & 0xff;
			read->blue8[i] = read->blue16[i] & 0xff;
		}
	}

	/* Are all the maps equal? We have a mono image.
	 */
	read->mono = TRUE;
	for( i = 0; i < len; i++ ) 
		if( read->red16[i] != read->green16[i] ||
			read->green16[i] != read->blue16[i] ) {
			read->mono = FALSE;
			break;
		}

	/* There's a TIFF extension, INDEXED, that is the preferred way to
	 * encode mono palette images, but few applications support it. So we
	 * just search the colormap.
	 */

	if( bits_per_sample <= 8 )
		out->BandFmt = VIPS_FORMAT_UCHAR; 
	else
		out->BandFmt = VIPS_FORMAT_USHORT; 
	out->Coding = VIPS_CODING_NONE; 

	if( read->mono ) {
		out->Bands = samples_per_pixel; 
		if( bits_per_sample <= 8 )
			out->Type = VIPS_INTERPRETATION_B_W; 
		else
			out->Type = VIPS_INTERPRETATION_GREY16; 
	}
	else {
		out->Bands = samples_per_pixel + 2; 
		if( bits_per_sample <= 8 )
			out->Type = VIPS_INTERPRETATION_sRGB; 
		else
			out->Type = VIPS_INTERPRETATION_RGB16; 
	}

	rtiff->client = read;
	if( bits_per_sample < 8 )
		rtiff->sfn = rtiff_palette_line_bit;
	else if( bits_per_sample == 8 )
		rtiff->sfn = rtiff_palette_line8;
	else if( bits_per_sample == 16 )
		rtiff->sfn = rtiff_palette_line16;
	else
		g_assert_not_reached(); 

	return( 0 );
}

/* Per-scanline process function when we just need to copy.
 */
static void
rtiff_memcpy_line( Rtiff *rtiff, VipsPel *q, VipsPel *p, int n, void *client )
{
	VipsImage *im = (VipsImage *) client;
	size_t len = n * VIPS_IMAGE_SIZEOF_PEL( im );

	memcpy( q, p, len ); 
}

/* Read a regular multiband image where we can just copy pixels from the tiff
 * buffer.
 */
static int
rtiff_parse_copy( Rtiff *rtiff, VipsImage *out )
{
	int samples_per_pixel = rtiff->header.samples_per_pixel;
	int photometric_interpretation = 
		rtiff->header.photometric_interpretation;

	out->Bands = samples_per_pixel; 
	out->BandFmt = rtiff_guess_format( rtiff );
	if( out->BandFmt == VIPS_FORMAT_NOTSET )
		return( -1 ); 
	out->Coding = VIPS_CODING_NONE; 

	if( samples_per_pixel >= 3 &&
		(photometric_interpretation == PHOTOMETRIC_RGB ||
		 photometric_interpretation == PHOTOMETRIC_YCBCR) ) {
		if( out->BandFmt == VIPS_FORMAT_USHORT )
			out->Type = VIPS_INTERPRETATION_RGB16; 
		else if( !vips_band_format_isint( out->BandFmt ) )
			/* Most float images use 0 - 1 for black - white.
			 * Photoshop uses 0 - 1 and no gamma. 
			 */
			out->Type = VIPS_INTERPRETATION_scRGB; 
		else
			out->Type = VIPS_INTERPRETATION_sRGB; 
	}

	if( samples_per_pixel >= 3 &&
		photometric_interpretation == PHOTOMETRIC_CIELAB )
		out->Type = VIPS_INTERPRETATION_LAB; 

	if( samples_per_pixel >= 4 &&
		photometric_interpretation == PHOTOMETRIC_SEPARATED )
		out->Type = VIPS_INTERPRETATION_CMYK; 

	rtiff->sfn = rtiff_memcpy_line;
	rtiff->client = out;
	rtiff->memcpy = TRUE;

	return( 0 );
}

typedef int (*reader_fn)( Rtiff *rtiff, VipsImage *out );

/* We have a range of output paths. Look at the tiff header and try to
 * route the input image to the best output path.
 */
static reader_fn
rtiff_pick_reader( Rtiff *rtiff )
{
	int bits_per_sample = rtiff->header.bits_per_sample;
	int photometric_interpretation = 
		rtiff->header.photometric_interpretation;

	if( photometric_interpretation == PHOTOMETRIC_CIELAB ) {
		if( bits_per_sample == 8 )
			return( rtiff_parse_labpack );
		if( bits_per_sample == 16 )
			return( rtiff_parse_labs );
	}

	if( photometric_interpretation == PHOTOMETRIC_MINISWHITE ||
		photometric_interpretation == PHOTOMETRIC_MINISBLACK ) {
		if( bits_per_sample == 1 )
			return( rtiff_parse_onebit ); 
		else
			return( rtiff_parse_greyscale ); 
	}

	if( photometric_interpretation == PHOTOMETRIC_PALETTE ) 
		return( rtiff_parse_palette ); 

	if( photometric_interpretation == PHOTOMETRIC_YCBCR ) { 
		/* Sometimes JPEG in TIFF images are tagged as YCBCR. Ask
		 * libtiff to convert to RGB for us.
		 */
		TIFFSetField( rtiff->tiff, 
			TIFFTAG_JPEGCOLORMODE, JPEGCOLORMODE_RGB );
	}

	return( rtiff_parse_copy );
}

/* Set the header on @out from our rtiff. rtiff_header_read() has already been
 * called. 
 */
static int
rtiff_set_header( Rtiff *rtiff, VipsImage *out )
{
	uint32 data_length;
	void *data;

	out->Xsize = rtiff->header.width;
	out->Ysize = rtiff->header.height * rtiff->n;

	if( rtiff->n > 1 ) 
		vips_image_set_int( out, 
			VIPS_META_PAGE_HEIGHT, rtiff->header.height );

	/* Even though we could end up serving tiled data, always hint
	 * THINSTRIP, since we're quite happy doing that too, and it could need
	 * a lot less memory.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

#ifdef DEBUG
	printf( "rtiff_set_header: header.samples_per_pixel = %d\n", 
		rtiff->header.samples_per_pixel );
	printf( "rtiff_set_header: header.bits_per_sample = %d\n", 
		rtiff->header.bits_per_sample );
	printf( "rtiff_set_header: header.sample_format = %d\n", 
		rtiff->header.sample_format );
	printf( "rtiff_set_header: header.orientation = %d\n", 
		rtiff->header.orientation );
#endif /*DEBUG*/

	/* We have a range of output paths. Look at the tiff header and try to
	 * route the input image to the best output path.
	 */
	if( rtiff_pick_reader( rtiff )( rtiff, out ) ) 
		return( -1 ); 

	/* Read any ICC profile.
	 */
	if( TIFFGetField( rtiff->tiff, 
		TIFFTAG_ICCPROFILE, &data_length, &data ) &&
		data &&
		data_length ) {
		void *data_copy;

		if( !(data_copy = vips_malloc( NULL, data_length )) ) 
			return( -1 );
		memcpy( data_copy, data, data_length );
		vips_image_set_blob( out, VIPS_META_ICC_NAME, 
			(VipsCallbackFn) vips_free, data_copy, data_length );
	}

	/* Read any XMP metadata.
	 */
	if( TIFFGetField( rtiff->tiff, 
		TIFFTAG_XMLPACKET, &data_length, &data ) &&
		data &&
		data_length ) {
		void *data_copy;

		if( !(data_copy = vips_malloc( NULL, data_length )) ) 
			return( -1 );
		memcpy( data_copy, data, data_length );
		vips_image_set_blob( out, VIPS_META_XMP_NAME, 
			(VipsCallbackFn) vips_free, data_copy, data_length );
	}

	/* Read any IPCT metadata.
	 */
	if( TIFFGetField( rtiff->tiff, 
		TIFFTAG_RICHTIFFIPTC, &data_length, &data ) &&
		data &&
		data_length ) {
		void *data_copy;

		/* For no very good reason, libtiff stores IPCT as an array of
		 * long, not byte.
		 */
		data_length *= 4;

		if( !(data_copy = vips_malloc( NULL, data_length )) ) 
			return( -1 );
		memcpy( data_copy, data, data_length );
		vips_image_set_blob( out, VIPS_META_IPCT_NAME, 
			(VipsCallbackFn) vips_free, data_copy, data_length );
	}

	/* Read any photoshop metadata.
	 */
	if( TIFFGetField( rtiff->tiff, 
		TIFFTAG_PHOTOSHOP, &data_length, &data ) &&
		data &&
		data_length ) {
		void *data_copy;

		if( !(data_copy = vips_malloc( NULL, data_length )) ) 
			return( -1 );
		memcpy( data_copy, data, data_length );
		vips_image_set_blob( out, VIPS_META_PHOTOSHOP_NAME, 
			(VipsCallbackFn) vips_free, data_copy, data_length );
	}

	/* IMAGEDESCRIPTION often has useful metadata.
	 */
	if( TIFFGetField( rtiff->tiff, TIFFTAG_IMAGEDESCRIPTION, &data ) ) {
		/* libtiff makes sure that data is null-terminated and contains
		 * no embedded null characters.
		 */
		vips_image_set_string( out, 
			VIPS_META_IMAGEDESCRIPTION, (char *) data ); 
	}

	if( get_resolution( rtiff->tiff, out ) )
		return( -1 );

	/* Set the "orientation" tag. This is picked up later by autorot, if
	 * requested.
	 */
	vips_image_set_int( out, 
		VIPS_META_ORIENTATION, rtiff->header.orientation );

	/* Tell downstream if we are reading sequentially.
	 */
	if( !rtiff->header.tiled ) 
		vips_image_set_area( out, VIPS_META_SEQUENTIAL, NULL, NULL ); 

	return( 0 );
}

/* The size of the buffer written by TIFFReadTile(). We can't use 
 * TIFFTileSize() since that ignores the setting of TIFFTAG_JPEGCOLORMODE. If
 * this pseudo tag has been set and the tile is encoded with YCbCr, the tile
 * is returned with chrominance upsampled. 
 *
 * This seems not to happen for old-style jpeg-compressed tiles. 
 */
static size_t
rtiff_tile_size( Rtiff *rtiff )
{
	return( TIFFTileRowSize( rtiff->tiff ) * rtiff->header.tile_height );
}

/* Allocate a tile buffer. Have one of these for each thread so we can unpack
 * to vips in parallel.
 */
static void *
rtiff_seq_start( VipsImage *out, void *a, void *b )
{
	Rtiff *rtiff = (Rtiff *) a;
	tsize_t size;
	tdata_t *buf;

	size = rtiff_tile_size( rtiff );
	if( !(buf = vips_malloc( NULL, size )) )
		return( NULL );

	return( (void *) buf );
}

static int
rtiff_read_tile( Rtiff *rtiff, tdata_t *buf, int x, int y )
{
	if( TIFFReadTile( rtiff->tiff, buf, x, y, 0, 0 ) < 0 ) { 
		vips_foreign_load_invalidate( rtiff->out );
		return( -1 ); 
	}

	return( 0 ); 
}

/* Paint a tile from the file. This is a
 * special-case for when a region is exactly a tiff tile, and pixels need no
 * conversion. In this case, libtiff can read tiles directly to our output
 * region.
 */
static int
rtiff_fill_region_aligned( VipsRegion *out, void *seq, void *a, void *b )
{
	Rtiff *rtiff = (Rtiff *) a;
	VipsRect *r = &out->valid;

	g_assert( (r->left % rtiff->header.tile_width) == 0 );
	g_assert( (r->top % rtiff->header.tile_height) == 0 );
	g_assert( r->width == rtiff->header.tile_width );
	g_assert( r->height == rtiff->header.tile_height );
	g_assert( VIPS_REGION_LSKIP( out ) == VIPS_REGION_SIZEOF_LINE( out ) );

#ifdef DEBUG
	printf( "rtiff_fill_region_aligned: left = %d, top = %d\n", 
		r->left, r->top ); 
#endif /*DEBUG*/

	VIPS_GATE_START( "rtiff_fill_region_aligned: work" ); 

	/* Read that tile directly into the vips tile.
	 */
	if( rtiff_read_tile( rtiff,
		(tdata_t *) VIPS_REGION_ADDR( out, r->left, r->top ), 
		r->left, r->top ) ) {
		VIPS_GATE_STOP( "rtiff_fill_region_aligned: work" ); 
		return( -1 );
	}

	VIPS_GATE_STOP( "rtiff_fill_region_aligned: work" ); 

	return( 0 );
}

/* Loop over the output region painting in tiles from the file.
 */
static int
rtiff_fill_region( VipsRegion *out, void *seq, void *a, void *b, gboolean *stop )
{
	tdata_t *buf = (tdata_t *) seq;
	Rtiff *rtiff = (Rtiff *) a;
	int tile_width = rtiff->header.tile_width;
	int tile_height = rtiff->header.tile_height;
	VipsRect *r = &out->valid;

	/* Sizeof a line of bytes in the TIFF tile.
	 */
	int tls = rtiff_tile_size( rtiff ) / tile_height;

	/* Sizeof a pel in the TIFF file. This won't work for formats which
	 * are <1 byte per pel, like onebit :-( Fortunately, it's only used
	 * to calculate addresses within a tile and, because we are wrapped in
	 * vips_tilecache(), we will never have to calculate positions not 
	 * within a tile.
	 */
	int tps = tls / tile_width;

	int x, y, z;

	/* Special case: we are filling a single tile exactly sized to match
	 * the tiff tile and we have no repacking to do for this format.
	 */
	if( rtiff->memcpy &&
		r->left % tile_width == 0 &&
		r->top % tile_height == 0 &&
		r->width == tile_width &&
		r->height == tile_height &&
		VIPS_REGION_LSKIP( out ) == VIPS_REGION_SIZEOF_LINE( out ) )
		return( rtiff_fill_region_aligned( out, seq, a, b ) );

	VIPS_GATE_START( "rtiff_fill_region: work" ); 

	y = 0;
	while( y < r->height ) {
		VipsRect tile, page, hit;

		/* Not necessary, but it stops static analyzers complaining
		 * about a used-before-set.
		 */
		tile.height = 0;

		x = 0;
		while( x < r->width ) { 
			/* page_no is within this toilet roll image, not tiff
			 * file page number ... add the number of the start
			 * page to get that.
			 */
			int page_no = (r->top + y) / rtiff->header.height;
			int page_y = (r->top + y) % rtiff->header.height;

			/* Coordinate of the tile on this page that xy falls in.
			 */
			int xs = ((r->left + x) / tile_width) * tile_width;
			int ys = (page_y / tile_height) * tile_height;

			if( rtiff_set_page( rtiff, rtiff->page + page_no ) ||
				rtiff_read_tile( rtiff, buf, xs, ys ) ) { 
				VIPS_GATE_STOP( "rtiff_fill_region: work" ); 
				return( -1 );
			}

			/* Position of tile on the page. 
			 */
			tile.left = xs;
			tile.top = ys;
			tile.width = tile_width;
			tile.height = tile_height;

			/* It'll be clipped by this page.
			 */
			page.left = 0;
			page.top = 0;
			page.width = rtiff->header.width;
			page.height = rtiff->header.height;
			vips_rect_intersectrect( &tile, &page, &tile );

			/* To image coordinates.
			 */
			tile.top += page_no * rtiff->header.height;

			/* And clip again by this region.
			 */
			vips_rect_intersectrect( &tile, r, &hit );

			/* Unpack to VIPS format. 
			 * Just unpack the section of the tile we need.
			 */
			for( z = 0; z < hit.height; z++ ) {
				VipsPel *p = (VipsPel *) buf +
					(hit.left - tile.left) * tps +
					(hit.top - tile.top + z) * tls;
				VipsPel *q = VIPS_REGION_ADDR( out, 
					hit.left, hit.top + z );

				rtiff->sfn( rtiff,
					q, p, hit.width, rtiff->client );
			}

			x += tile.width;
		}

		y += tile.height;
	}

	VIPS_GATE_STOP( "rtiff_fill_region: work" ); 

	return( 0 );
}

static int
rtiff_seq_stop( void *seq, void *a, void *b )
{
	vips_free( seq );

	return( 0 );
}

/* Auto-rotate handling. 
 */
static int
rtiff_autorotate( Rtiff *rtiff, VipsImage *in, VipsImage **out )
{
	VipsAngle angle = vips_autorot_get_angle( in );

	if( rtiff->autorotate &&
		angle != VIPS_ANGLE_D0 ) { 
		/* Need to copy to memory or disc, we have to stay seq.
		 */
		const guint64 image_size = VIPS_IMAGE_SIZEOF_IMAGE( in );
		const guint64 disc_threshold = vips_get_disc_threshold();

		VipsImage *x;

		if( image_size > disc_threshold ) 
			x = vips_image_new_temp_file( "%s.v" );
		else
			x = vips_image_new_memory();

		if( vips_image_write( in, x ) ||
			vips_rot( x, out, angle, NULL ) ) {
			g_object_unref( x );
			return( -1 );
		}
		g_object_unref( x );

		/* We must remove the tag to prevent accidental
		 * double rotations.
		 */
		vips_autorot_remove_angle( *out ); 
	}
	else {
		*out = in;
		g_object_ref( in ); 
	}

	return( 0 );
}

/* Tile-type TIFF reader core - pass in a per-tile transform. Generate into
 * the im and do it all partially.
 */
static int
rtiff_read_tilewise( Rtiff *rtiff, VipsImage *out )
{
	int tile_width = rtiff->header.tile_width;
	int tile_height = rtiff->header.tile_height;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

#ifdef DEBUG
	printf( "tiff2vips: rtiff_read_tilewise\n" );
#endif /*DEBUG*/

	/* I don't have a sample images for tiled + separate, ban it for now.
	 */
	if( rtiff->header.separate ) {
		vips_error( "tiff2vips", 
			"%s", _( "tiled separate planes not supported" ) ); 
		return( -1 );
	}

	/* Read to this image, then cache to out, see below.
	 */
	t[0] = vips_image_new(); 

	if( rtiff_set_header( rtiff, t[0] ) )
		return( -1 );

	/* Double check: in memcpy mode, the vips tilesize should exactly
	 * match the tifftile size.
	 */
	if( rtiff->memcpy ) {
		size_t vips_tile_size;

		vips_tile_size = VIPS_IMAGE_SIZEOF_PEL( t[0] ) * 
			tile_width * tile_height; 

		if( rtiff_tile_size( rtiff ) != vips_tile_size ) { 
			vips_error( "tiff2vips", 
				"%s", _( "unsupported tiff image type" ) );
			return( -1 );
		}
	}

	/* Even though this is a tiled reader, we hint thinstrip since with
	 * the cache we are quite happy serving that if anything downstream 
	 * would like it.
	 */
        vips_image_pipelinev( t[0], VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	if( vips_image_generate( t[0], 
		rtiff_seq_start, rtiff_fill_region, rtiff_seq_stop, 
		rtiff, NULL ) )
		return( -1 );

	/* Copy to out, adding a cache. Enough tiles for two complete rows.
	 */
	if( vips_tilecache( t[0], &t[1],
		"tile_width", tile_width,
		"tile_height", tile_height,
		"max_tiles", 2 * (1 + t[0]->Xsize / tile_width),
		NULL ) ) 
		return( -1 );
	if( rtiff_autorotate( rtiff, t[1], &t[2] ) )
		return( -1 );
	if( vips_image_write( t[2], out ) ) 
		return( -1 );

	return( 0 );
}

/* Read a strip. If the image is in separate planes, read each plane and
 * interleave to the output.
 *
 * strip is the number of this strip in this page. 
 */
static int
rtiff_strip_read_interleaved( Rtiff *rtiff, tstrip_t strip, tdata_t buf )
{
	int samples_per_pixel = rtiff->header.samples_per_pixel;
	int rows_per_strip = rtiff->header.rows_per_strip;
	int bits_per_sample = rtiff->header.bits_per_sample;
	int strip_y = strip * rows_per_strip;

	if( rtiff->header.separate ) {
		int page_width = rtiff->header.width;
		int page_height = rtiff->header.height;
		int strips_per_plane = 1 + (page_height - 1) / rows_per_strip;
		int strip_height = VIPS_MIN( rows_per_strip, 
			page_height - strip_y ); 
		int pels_per_strip = page_width * strip_height;
		int bytes_per_sample = bits_per_sample >> 3; 

		int i, j, k;

		for( i = 0; i < samples_per_pixel; i++ ) { 
			VipsPel *p;
			VipsPel *q;

			if( rtiff_strip_read( rtiff,
				strips_per_plane * i + strip, 
				rtiff->plane_buf ) )
				return( -1 );

			p = (VipsPel *) rtiff->plane_buf;
			q = i * bytes_per_sample + (VipsPel *) buf;
			for( j = 0; j < pels_per_strip; j++ ) {
				for( k = 0; k < bytes_per_sample; k++ ) 
					q[k] = p[k];

				p += bytes_per_sample;
				q += bytes_per_sample * samples_per_pixel;
			}
		}
	}
	else { 
		if( rtiff_strip_read( rtiff, strip, buf ) )
			return( -1 );
	}

	return( 0 ); 
}

static int
rtiff_stripwise_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	Rtiff *rtiff = (Rtiff *) a;
	int rows_per_strip = rtiff->header.rows_per_strip;
	int page_height = rtiff->header.height;
	tsize_t scanline_size = TIFFScanlineSize( rtiff->tiff );
        VipsRect *r = &or->valid;

	int y;

#ifdef DEBUG
	printf( "tiff2vips: read_stripwise_generate: top = %d, height = %d\n",
		r->top, r->height );
#endif /*DEBUG*/

	/* We're inside a tilecache where tiles are the full image width, so
	 * this should always be true.
	 */
	g_assert( r->left == 0 );
	g_assert( r->width == or->im->Xsize );
	g_assert( VIPS_RECT_BOTTOM( r ) <= or->im->Ysize );

	/* If we're reading more than one page, tiles won't fall on strip
	 * boundaries.
	 */

	/* Tiles should always be a strip in height, unless it's the final
	 * strip in the image.
	 */
	g_assert( r->height == 
		VIPS_MIN( rows_per_strip, or->im->Ysize - r->top ) ); 

	VIPS_GATE_START( "rtiff_stripwise_generate: work" ); 

	y = 0;
	while( y < r->height ) { 
		/* page_no is within this toilet roll image, not tiff
		 * file page number ... add the number of the start
		 * page to get that.
		 */
		int page_no = (r->top + y) / page_height;
		int y_page = (r->top + y) % page_height;

		/* Strip number.
		 */
		tstrip_t strip_no = y_page / rows_per_strip;

		VipsRect image, page, strip, hit;

		/* Our four (including the output region) rects, all in 
		 * output image coordinates.
		 */
		image.left = 0;
		image.top = 0;
		image.width = rtiff->out->Xsize;
		image.height = rtiff->out->Ysize;

		page.left = 0;
		page.top = page_height * ((r->top + y) / page_height);
		page.width = rtiff->out->Xsize;
		page.height = page_height;

		strip.left = 0;
		strip.top = page.top + strip_no * rows_per_strip;
		strip.width = rtiff->out->Xsize;
		strip.height = rows_per_strip;

		/* Clip strip against page and image ... the final strip will 
		 * be smaller.
		 */
		vips_rect_intersectrect( &strip, &image, &strip );
		vips_rect_intersectrect( &strip, &page, &strip );

		/* Now the bit that overlaps with the region we are filling.
		 */
		vips_rect_intersectrect( &strip, r, &hit );

		g_assert( hit.height > 0 ); 

		if( rtiff_set_page( rtiff, rtiff->page + page_no ) ) {
			VIPS_GATE_STOP( "rtiff_stripwise_generate: work" ); 
			return( -1 );
		}

		/* Read directly into the image if we can. Otherwise, we must 
		 * read to a temp buffer then unpack into the image.
		 *
		 * We need to read via a buffer if we need to reformat pixels,
		 * or if this strip is not aligned on a tile boundary.
		 */
		if( rtiff->memcpy &&
			hit.top == strip.top &&
			hit.height == strip.height ) {
			if( rtiff_strip_read_interleaved( rtiff, strip_no, 
				VIPS_REGION_ADDR( or, 0, r->top + y ) ) ) {
				VIPS_GATE_STOP( 
					"rtiff_stripwise_generate: work" ); 
				return( -1 ); 
			}
		}
		else {
			VipsPel *p;
			VipsPel *q;
			int z;

			/* Read and interleave the entire strip.
			 */
			if( rtiff_strip_read_interleaved( rtiff, strip_no, 
				rtiff->contig_buf ) ) {
				VIPS_GATE_STOP( 
					"rtiff_stripwise_generate: work" ); 
				return( -1 ); 
			}

			/* Do any repacking to generate pixels in vips layout.
			 */
			p = rtiff->contig_buf + 
				(hit.top - strip.top) * scanline_size;
			q = VIPS_REGION_ADDR( or, 0, r->top + y );
			for( z = 0; z < hit.height; z++ ) { 
				rtiff->sfn( rtiff, 
					q, p, or->im->Xsize, rtiff->client );

				p += scanline_size;
				q += VIPS_REGION_LSKIP( or ); 
			}
		}

		y += hit.height;
	}

	VIPS_GATE_STOP( "rtiff_stripwise_generate: work" ); 

	return( 0 );
}

/* Stripwise reading.
 *
 * We could potentially read strips in any order, but this would give
 * catastrophic performance for operations like 90 degress rotate on a 
 * large image. Only offer sequential read.
 */
static int
rtiff_read_stripwise( Rtiff *rtiff, VipsImage *out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

#ifdef DEBUG
	printf( "tiff2vips: rtiff_read_stripwise\n" );
#endif /*DEBUG*/

	t[0] = vips_image_new();
	if( rtiff_set_header( rtiff, t[0] ) )
		return( -1 );

        vips_image_pipelinev( t[0], VIPS_DEMAND_STYLE_THINSTRIP, NULL );

#ifdef DEBUG
	printf( "rtiff_read_stripwise: header.rows_per_strip = %u\n", 
		rtiff->header.rows_per_strip );
	printf( "rtiff_read_stripwise: header.strip_size = %zd\n", 
		rtiff->header.strip_size );
	printf( "rtiff_read_stripwise: header.number_of_strips = %d\n", 
		rtiff->header.number_of_strips );
#endif /*DEBUG*/

	/* Double check: in memcpy mode, the vips linesize should exactly
	 * match the tiff line size.
	 */
	if( rtiff->memcpy ) {
		size_t vips_line_size;

		/* Lines are smaller in plane-separated mode.
		 */
		if( rtiff->header.separate )
			vips_line_size = VIPS_IMAGE_SIZEOF_ELEMENT( t[0] ) * 
				t[0]->Xsize; 
		else
			vips_line_size = VIPS_IMAGE_SIZEOF_LINE( t[0] );

		if( vips_line_size != TIFFScanlineSize( rtiff->tiff ) ) { 
			vips_error( "tiff2vips", 
				"%s", _( "unsupported tiff image type" ) );
			return( -1 );
		}
	}

	/* If we have separate image planes, we must read to a plane buffer,
	 * then interleave to the output.
	 *
	 * We don't need a separate buffer per thread since the _generate()
	 * function runs inside the cache lock. 
	 */
	if( rtiff->header.separate ) {
		if( !(rtiff->plane_buf = vips_malloc( VIPS_OBJECT( out ), 
			rtiff->header.strip_size )) ) 
			return( -1 );
	}

	/* If we need to manipulate pixels, we must read to an interleaved
	 * plane buffer before repacking to the output.
	 *
	 * If we are doing a multi-page read, we need a strip buffer, since
	 * strips may not be aligned on tile boundaries.
	 *
	 * We don't need a separate buffer per thread since the _generate()
	 * function runs inside the cache lock. 
	 */
	if( !rtiff->memcpy ||
		rtiff->n > 1 ) { 
		tsize_t size;

		size = rtiff->header.strip_size;
		if( rtiff->header.separate )
			size *= rtiff->header.samples_per_pixel;

		if( !(rtiff->contig_buf = 
			vips_malloc( VIPS_OBJECT( out ), size )) ) 
			return( -1 );

	}

	if( 
		vips_image_generate( t[0], 
			NULL, rtiff_stripwise_generate, NULL, 
			rtiff, NULL ) ||
		vips_sequential( t[0], &t[1], 
			"tile_height", rtiff->header.rows_per_strip,
			NULL ) ||
		rtiff_autorotate( rtiff, t[1], &t[2] ) ||
		vips_image_write( t[2], out ) )
		return( -1 );

	return( 0 );
}

/* Can be called many times.
 */
static void
rtiff_free( Rtiff *rtiff )
{
	VIPS_FREEF( TIFFClose, rtiff->tiff );
}

static void
rtiff_close( VipsObject *object, Rtiff *rtiff )
{
	rtiff_free( rtiff ); 
}

static Rtiff *
rtiff_new( VipsImage *out, int page, int n, gboolean autorotate )
{
	Rtiff *rtiff;

	if( !(rtiff = VIPS_NEW( out, Rtiff )) )
		return( NULL );

	rtiff->filename = NULL;
	rtiff->out = out;
	rtiff->page = page;
	rtiff->n = n;
	rtiff->autorotate = autorotate;
	rtiff->tiff = NULL;
	rtiff->current_page = -1;
	rtiff->sfn = NULL;
	rtiff->client = NULL;
	rtiff->memcpy = FALSE;
	rtiff->plane_buf = NULL;
	rtiff->contig_buf = NULL;

	g_signal_connect( out, "close", 
		G_CALLBACK( rtiff_close ), rtiff ); 

	if( rtiff->page < 0 || rtiff->page > 1000000 ) {
		vips_error( "tiff2vips", _( "bad page number %d" ),
			rtiff->page );
		return( NULL );
	}

	/* We allow n == -1, meaning all pages. It gets swapped for a real n
	 * value when we open the TIFF.
	 */
	if( rtiff->n != -1 &&
		(rtiff->n < 1 || rtiff->n > 1000000) ) {
		vips_error( "tiff2vips", _( "bad number of pages %d" ),
			rtiff->n );
		return( NULL );
	}

	return( rtiff );
}

/* Load from a tiff dir into one of our tiff header structs.
 */
static int
rtiff_header_read( Rtiff *rtiff, RtiffHeader *header )
{
	if( !tfget32( rtiff->tiff, TIFFTAG_IMAGEWIDTH, &header->width ) ||
		!tfget32( rtiff->tiff, TIFFTAG_IMAGELENGTH, &header->height ) ||
		!tfget16( rtiff->tiff, 
			TIFFTAG_SAMPLESPERPIXEL, &header->samples_per_pixel ) ||
		!tfget16( rtiff->tiff, 
			TIFFTAG_BITSPERSAMPLE, &header->bits_per_sample ) ||
		!tfget16( rtiff->tiff, 
			TIFFTAG_PHOTOMETRIC, 
			&header->photometric_interpretation ) )
		return( -1 );

	/* Arbitrary sanity-checking limits.
	 */
	if( header->width <= 0 || 
		header->width > VIPS_MAX_COORD || 
		header->height <= 0 || 
		header->height > VIPS_MAX_COORD ) {
		vips_error( "tiff2vips", 
			"%s", _( "width/height out of range" ) );
		return( -1 );
	}

	if( header->samples_per_pixel <= 0 || 
		header->samples_per_pixel > 10000 || 
		header->bits_per_sample <= 0 || 
		header->bits_per_sample > 32 ) {
		vips_error( "tiff2vips", 
			"%s", _( "samples out of range" ) );
		return( -1 );
	}

	header->sample_format = get_sample_format( rtiff->tiff );
	header->orientation = get_orientation( rtiff->tiff );

	header->separate = FALSE; 
	if( tfexists( rtiff->tiff, TIFFTAG_PLANARCONFIG ) ) {
		int v; 

		if( !tfget16( rtiff->tiff, TIFFTAG_PLANARCONFIG, &v ) )
			return( -1 );
		if( v == PLANARCONFIG_SEPARATE )
			header->separate = TRUE; 
	}

	/* Tiles and strip images have slightly different fields.
	 */
	header->tiled = TIFFIsTiled( rtiff->tiff );

	if( header->tiled ) {
		if( !tfget32( rtiff->tiff, 
			TIFFTAG_TILEWIDTH, &header->tile_width ) ||
			!tfget32( rtiff->tiff, 
				TIFFTAG_TILELENGTH, &header->tile_height ) )
			return( -1 );
	}
	else {
		if( !tfget32( rtiff->tiff, 
			TIFFTAG_ROWSPERSTRIP, &header->rows_per_strip ) )
			return( -1 );
		header->strip_size = TIFFStripSize( rtiff->tiff );
		header->number_of_strips = TIFFNumberOfStrips( rtiff->tiff );
		header->read_scanlinewise = FALSE;

		/* rows_per_strip can be 2 ** 32 - 1, meaning the whole image. 
		 * Clip this down to height to avoid confusing vips. 
		 *
		 * And it musn't be zero.
		 */
		header->rows_per_strip = 
			VIPS_CLIP( 1, header->rows_per_strip, header->height );

		/* libtiff has two strip-wise readers. TIFFReadEncodedStrip()
		 * decompresses an entire strip to memory. It's fast, but it
		 * will need a lot of ram if the strip is large.
		 * TIFFReadScanline() reads a single scanline. It's slower, but
		 * will save a lot of memory if strips are large.
		 *
		 * If this image has a strip size of over 128 lines, fall back
		 * to TIFFReadScanline(), otherwise use TIFFReadEncodedStrip().
		 */
		if( header->rows_per_strip > 128 ) {
			header->rows_per_strip = 1;
			header->strip_size = TIFFScanlineSize( rtiff->tiff );
			header->number_of_strips = header->height;
			header->read_scanlinewise = TRUE;
		}
	}

	return( 0 );
}

static int
rtiff_header_equal( RtiffHeader *h1, RtiffHeader *h2 )
{
	if( h1->width != h2->width ||
		h1->height != h2->height ||
		h1->samples_per_pixel != h2->samples_per_pixel ||
		h1->bits_per_sample != h2->bits_per_sample ||
		h1->photometric_interpretation != 
			h2->photometric_interpretation ||
		h1->sample_format != h2->sample_format ||
		h1->separate != h2->separate ||
		h1->tiled != h2->tiled ||
		h1->orientation != h2->orientation )
		return( 0 );

	if( h1->tiled ) {
		if( h1->tile_width != h2->tile_width ||
			h1->tile_height != h2->tile_height )
			return( 0 );
	}
	else {
		if( h1->rows_per_strip != h2->rows_per_strip ||
			h1->strip_size != h2->strip_size ||
			h1->number_of_strips != h2->number_of_strips )
			return( 0 );
	}

	return( 1 );
}

static int
rtiff_header_read_all( Rtiff *rtiff )
{
#ifdef DEBUG
	printf( "tiff2vips: reading header for page %d ...\n", rtiff->page );
#endif /*DEBUG*/

	if( rtiff_set_page( rtiff, rtiff->page ) ||
		rtiff_header_read( rtiff, &rtiff->header ) )
		return( -1 ); 

	/* -1 means "to the end".
	 */
	if( rtiff->n == -1 )
		rtiff->n = rtiff_n_pages( rtiff ) - rtiff->page;

	/* If we're to read many pages, verify that they are all identical. 
	 */
	if( rtiff->n > 1 ) {
		int i;

		for( i = 1; i < rtiff->n; i++ ) {
			RtiffHeader header;

#ifdef DEBUG
			printf( "tiff2vips: verifying header for page %d ...\n",
				rtiff->page + i );
#endif /*DEBUG*/

			if( rtiff_set_page( rtiff, rtiff->page + i ) ||
				rtiff_header_read( rtiff, &header ) )
				return( -1 );

			if( !rtiff_header_equal( &rtiff->header, &header ) ) {
				vips_error( "tiff2vips",
					_( "page %d differs from page %d" ),
					rtiff->page + i, rtiff->page );
				return( -1 );
			}
		}
	}

	return( 0 );
}

static Rtiff *
rtiff_new_filename( const char *filename, VipsImage *out, 
	int page, int n, gboolean autorotate )
{
	Rtiff *rtiff;

	if( !(rtiff = rtiff_new( out, page, n, autorotate )) ||
		!(rtiff->tiff = vips__tiff_openin( filename )) || 
		rtiff_header_read_all( rtiff ) )
		return( NULL );

	rtiff->filename = vips_strdup( VIPS_OBJECT( out ), filename );

	return( rtiff );
}

static Rtiff *
rtiff_new_buffer( const void *buf, size_t len, VipsImage *out, 
	int page, int n, gboolean autorotate )
{
	Rtiff *rtiff;

	if( !(rtiff = rtiff_new( out, page, n, autorotate )) ||
		!(rtiff->tiff = vips__tiff_openin_buffer( out, buf, len )) ||
		rtiff_header_read_all( rtiff ) )
		return( NULL );

	return( rtiff );
}

/* 

	FIXME ... Unused for now, perhaps if we add another format flag.

static int
istiffpyramid( const char *name )
{
	TIFF *tif;

	vips__tiff_init();

	if( (tif = get_directory( name, 2 )) ) {
		// We can see page 2 ... assume it is.
		TIFFClose( tif );
		return( 1 );
	}

	return( 0 );
}
 */

int
vips__tiff_read( const char *filename, VipsImage *out, 
	int page, int n, gboolean autorotate )
{
	Rtiff *rtiff;

#ifdef DEBUG
	printf( "tiff2vips: libtiff version is \"%s\"\n", TIFFGetVersion() );
	printf( "tiff2vips: libtiff starting for %s\n", filename );
#endif /*DEBUG*/

	vips__tiff_init();

	if( !(rtiff = rtiff_new_filename( filename, out, page, n, autorotate )) )
		return( -1 );

	if( rtiff->header.tiled ) {
		if( rtiff_read_tilewise( rtiff, out ) )
			return( -1 );
	}
	else {
		if( rtiff_read_stripwise( rtiff, out ) )
			return( -1 );
	}

	return( 0 );
}

/* On a header-only read, we can just swap width/height if orientaion is 6 or
 * 8. 
 */
static void
vips__tiff_read_header_orientation( Rtiff *rtiff, VipsImage *out )
{
	int orientation;

	if( rtiff->autorotate &&
		vips_image_get_typeof( out, VIPS_META_ORIENTATION ) &&
		!vips_image_get_int( out, 
			VIPS_META_ORIENTATION, &orientation ) ) {
		if( orientation == 3 || 
			orientation == 6 )
			VIPS_SWAP( int, out->Xsize, out->Ysize );

		/* We must remove VIPS_META_ORIENTATION to prevent accidental
		 * double rotations.
		 */
		vips_image_remove( out, VIPS_META_ORIENTATION );
	}
}

int
vips__tiff_read_header( const char *filename, VipsImage *out, 
	int page, int n, gboolean autorotate )
{
	Rtiff *rtiff;

	vips__tiff_init();

	if( !(rtiff = rtiff_new_filename( filename, out, page, n, autorotate )) )
		return( -1 );

	if( rtiff_set_header( rtiff, out ) )
		return( -1 );

	vips__tiff_read_header_orientation( rtiff, out ); 

	/* Just a header read: we can free the tiff read early and save an fd.
	 */
	rtiff_free( rtiff );

	return( 0 );
}

gboolean
vips__istifftiled( const char *filename )
{
	TIFF *tif;
	gboolean tiled;

	vips__tiff_init();

	if( !(tif = vips__tiff_openin( filename )) ) {
		vips_error_clear();
		return( FALSE );
	}
	tiled = TIFFIsTiled( tif );
	TIFFClose( tif );

	return( tiled );
}

gboolean
vips__istiff_buffer( const void *buf, size_t len )
{
	char *str = (char *) buf; 

	if( len >= 4 &&
		((str[0] == 'M' && str[1] == 'M' &&
			str[2] == '\0' && (str[3] == '*' || str[3] == '+')) ||
		(str[0] == 'I' && str[1] == 'I' &&
			(str[2] == '*' || str[2] == '+') && str[3] == '\0')) )
		return( TRUE );

	return( FALSE );
}

gboolean
vips__istiff( const char *filename )
{
	unsigned char buf[4];

	if( vips__get_bytes( filename, buf, 4 ) &&
		vips__istiff_buffer( buf, 4 ) )
		return( TRUE );

	return( FALSE );
}

int
vips__tiff_read_header_buffer( const void *buf, size_t len, VipsImage *out, 
	int page, int n, gboolean autorotate )
{
	Rtiff *rtiff;

	vips__tiff_init();

	if( !(rtiff = rtiff_new_buffer( buf, len, out, page, n, autorotate )) )
		return( -1 );

	if( rtiff_set_header( rtiff, out ) )
		return( -1 );

	vips__tiff_read_header_orientation( rtiff, out ); 

	return( 0 );
}

int
vips__tiff_read_buffer( const void *buf, size_t len, 
	VipsImage *out, int page, int n, gboolean autorotate )
{
	Rtiff *rtiff;

#ifdef DEBUG
	printf( "tiff2vips: libtiff version is \"%s\"\n", TIFFGetVersion() );
	printf( "tiff2vips: libtiff starting for buffer %p\n", buf );
#endif /*DEBUG*/

	vips__tiff_init();

	if( !(rtiff = rtiff_new_buffer( buf, len, out, page, n, autorotate )) )
		return( -1 );

	if( rtiff->header.tiled ) {
		if( rtiff_read_tilewise( rtiff, out ) )
			return( -1 );
	}
	else {
		if( rtiff_read_stripwise( rtiff, out ) )
			return( -1 );
	}

	return( 0 );
}

gboolean
vips__istifftiled_buffer( const void *buf, size_t len )
{
	VipsImage *im;
	TIFF *tif;
	gboolean tiled;

	vips__tiff_init();

	im = vips_image_new();

	if( !(tif = vips__tiff_openin_buffer( im, buf, len )) ) {
		g_object_unref( im );
		vips_error_clear();
		return( FALSE );
	}

	tiled = TIFFIsTiled( tif );

	TIFFClose( tif );
	g_object_unref( im );

	return( tiled );
}

#endif /*HAVE_TIFF*/
