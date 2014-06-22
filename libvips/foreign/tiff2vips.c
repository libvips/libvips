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

#include <tiffio.h>

#include "tiff.h"

/* Scanline-type process function.
 */
struct _ReadTiff;
typedef void (*scanline_process_fn)( struct _ReadTiff *, 
	VipsPel *q, VipsPel *p, int n, void *client );

/* Stuff we track during a read.
 */
typedef struct _ReadTiff {
	/* Parameters.
	 */
	char *filename;
	void *buf;
	size_t len;
	VipsImage *out;
	int page;
	gboolean readbehind; 

	/* The TIFF we read.
	 */
	TIFF *tiff;

	/* Process for this image type.
	 */
	scanline_process_fn sfn;
	void *client;

	/* Set this is the processfn is just doing a memcpy.
	 */
	gboolean memcpy;

	/* The current 'file pointer' for memory buffers.
	 */
	size_t pos;

	/* Geometry.
	 */
	uint32 twidth, theight;		/* Tile size */
	uint32 rows_per_strip;
	tsize_t scanline_size;
	tsize_t strip_size;
	int number_of_strips;
	int samples_per_pixel;
	int bits_per_sample;
	int photometric_interpretation;
	int sample_format;

	/* Turn on separate plane reading.
	 */
	gboolean separate; 

	/* Hold a single strip or tile, possibly just an image plane.
	 */
	tdata_t plane_buf;

	/* Hold a plane-assembled strip or tile ... a set of samples_per_pixel 
	 * strips or tiles interleaved. 
	 */
	tdata_t contig_buf;
} ReadTiff;

/* Handle TIFF errors here. Shared with vips2tiff.c. These can be called from
 * more than one thread, but vips_error and vips_warn have mutexes in, so that's
 * OK.
 */
static void 
vips__thandler_error( const char *module, const char *fmt, va_list ap )
{
	vips_verror( module, fmt, ap );
}

static void 
vips__thandler_warning( const char *module, const char *fmt, va_list ap )
{
	char buf[256];

	vips_vsnprintf( buf, 256, fmt, ap );
	vips_warn( module, "%s", buf );
}

/* Call this during startup. Other libraries may be using libtiff and we want
 * to capture any messages they send as well.
 */
void
vips__tiff_init( void )
{
	TIFFSetErrorHandler( vips__thandler_error );
	TIFFSetWarningHandler( vips__thandler_warning );
}

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
check_samples( ReadTiff *rtiff, int samples_per_pixel )
{
	if( rtiff->samples_per_pixel != samples_per_pixel ) { 
		vips_error( "tiff2vips", 
			_( "not %d bands" ), samples_per_pixel ); 
		return( -1 );
	}

	return( 0 );
}

/* Check n and n+1 so we can have an alpha.
 */
static int
check_min_samples( ReadTiff *rtiff, int samples_per_pixel )
{
	if( rtiff->samples_per_pixel < samples_per_pixel ) { 
		vips_error( "tiff2vips", 
			_( "not at least %d samples per pixel" ), 
			samples_per_pixel ); 
		return( -1 );
	}

	return( 0 );
}

static int
check_interpretation( ReadTiff *rtiff, int photometric_interpretation )
{
	if( rtiff->photometric_interpretation != photometric_interpretation ) { 
		vips_error( "tiff2vips", 
			_( "not photometric interpretation %d" ), 
			photometric_interpretation ); 
		return( -1 );
	}

	return( 0 );
}

static int
check_bits( ReadTiff *rtiff, int bits_per_sample )
{
	if( rtiff->bits_per_sample != bits_per_sample ) { 
		vips_error( "tiff2vips", 
			_( "not %d bits per sample" ), bits_per_sample );
		return( -1 );
	}

	return( 0 );
}

static int
check_bits_palette( ReadTiff *rtiff )
{
	if( rtiff->bits_per_sample != 16 && 
		rtiff->bits_per_sample != 8 && 
		rtiff->bits_per_sample != 4 && 
		rtiff->bits_per_sample != 2 && 
		rtiff->bits_per_sample != 1 ) {
		vips_error( "tiff2vips", 
			_( "%d bits per sample palette image not supported" ),
			rtiff->bits_per_sample );
		return( -1 );
	}

	return( 0 );
}

static VipsBandFormat
guess_format( ReadTiff *rtiff )
{
	switch( rtiff->bits_per_sample ) {
	case 1:
	case 2:
	case 4:
	case 8:
		if( rtiff->sample_format == SAMPLEFORMAT_INT )
			return( VIPS_FORMAT_CHAR );
		if( rtiff->sample_format == SAMPLEFORMAT_UINT )
			return( VIPS_FORMAT_UCHAR );
		break;

	case 16:
		if( rtiff->sample_format == SAMPLEFORMAT_INT )
			return( VIPS_FORMAT_SHORT );
		if( rtiff->sample_format == SAMPLEFORMAT_UINT )
			return( VIPS_FORMAT_USHORT );
		break;

	case 32:
		if( rtiff->sample_format == SAMPLEFORMAT_INT )
			return( VIPS_FORMAT_INT );
		if( rtiff->sample_format == SAMPLEFORMAT_UINT )
			return( VIPS_FORMAT_UINT );
		if( rtiff->sample_format == SAMPLEFORMAT_IEEEFP )
			return( VIPS_FORMAT_FLOAT );
		break;

	case 64:
		if( rtiff->sample_format == SAMPLEFORMAT_IEEEFP )
			return( VIPS_FORMAT_DOUBLE );
		if( rtiff->sample_format == SAMPLEFORMAT_COMPLEXIEEEFP )
			return( VIPS_FORMAT_COMPLEX );
		break;

	case 128:
		if( rtiff->sample_format == SAMPLEFORMAT_COMPLEXIEEEFP )
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
labpack_line( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, void *dummy )
{
	int x;

	for( x = 0; x < n; x++ ) {
		q[0] = p[0];
		q[1] = p[1];
		q[2] = p[2];
		q[3] = 0;

		q += 4;
		p += rtiff->samples_per_pixel;
	}
}

/* Read an 8-bit LAB image.
 */
static int
parse_labpack( ReadTiff *rtiff, VipsImage *out )
{
	if( check_min_samples( rtiff, 3 ) ||
		check_bits( rtiff, 8 ) ||
		check_interpretation( rtiff, PHOTOMETRIC_CIELAB ) )
		return( -1 );

	out->Bands = 4; 
	out->BandFmt = VIPS_FORMAT_UCHAR; 
	out->Coding = VIPS_CODING_LABQ; 
	out->Type = VIPS_INTERPRETATION_LAB; 

	rtiff->sfn = labpack_line;

	return( 0 );
}

/* Per-scanline process function for LABS.
 */
static void
labs_line( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, void *dummy )
{
	int x;
	unsigned short *p1 = (unsigned short *) p;
	short *q1 = (short *) q;
	int i; 

	for( x = 0; x < n; x++ ) {
		/* We use a signed int16 for L.
		 */
		q1[0] = p1[0] >> 1;

		for( i = 1; i < rtiff->samples_per_pixel; i++ ) 
			q1[i] = p1[i];

		q1 += rtiff->samples_per_pixel;
		p1 += rtiff->samples_per_pixel;
	}
}

/* Read a 16-bit LAB image.
 */
static int
parse_labs( ReadTiff *rtiff, VipsImage *out )
{
	if( check_min_samples( rtiff, 3 ) ||
		check_bits( rtiff, 16 ) ||
		check_interpretation( rtiff, PHOTOMETRIC_CIELAB ) )
		return( -1 );

	out->Bands = rtiff->samples_per_pixel; 
	out->BandFmt = VIPS_FORMAT_SHORT; 
	out->Coding = VIPS_CODING_NONE; 
	out->Type = VIPS_INTERPRETATION_LABS; 

	rtiff->sfn = labs_line;

	return( 0 );
}

/* Per-scanline process function for 1 bit images.
 */
static void
onebit_line( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, void *flg )
{
	int x, i, z;
	VipsPel bits;

	int black = 
		rtiff->photometric_interpretation == PHOTOMETRIC_MINISBLACK ?
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
parse_onebit( ReadTiff *rtiff, VipsImage *out )
{
	if( check_samples( rtiff, 1 ) ||
		check_bits( rtiff, 1 ) )
		return( -1 );

	out->Bands = 1; 
	out->BandFmt = VIPS_FORMAT_UCHAR; 
	out->Coding = VIPS_CODING_NONE; 
	out->Type = VIPS_INTERPRETATION_B_W; 

	rtiff->sfn = onebit_line;

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
		for( i = 1; i < rtiff->samples_per_pixel; i++ ) \
			q1[i] = p1[i]; \
		\
		q1 += rtiff->samples_per_pixel; \
		p1 += rtiff->samples_per_pixel; \
	} \
}

/* Per-scanline process function for greyscale images.
 */
static void
greyscale_line( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, void *client )
{
	gboolean invert = 
		rtiff->photometric_interpretation == PHOTOMETRIC_MINISWHITE;
	VipsBandFormat format = guess_format( rtiff ); 

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
		g_assert( 0 );
	}
}

/* Read a grey-scale TIFF image. We have to invert the first band if
 * PHOTOMETRIC_MINISBLACK is set. 
 */
static int
parse_greyscale( ReadTiff *rtiff, VipsImage *out )
{
	if( check_min_samples( rtiff, 1 ) )
		return( -1 );

	out->Bands = rtiff->samples_per_pixel; 
	if( (out->BandFmt = guess_format( rtiff )) == VIPS_FORMAT_NOTSET )
		return( -1 ); 
	out->Coding = VIPS_CODING_NONE; 

	if( rtiff->bits_per_sample == 16 )
		out->Type = VIPS_INTERPRETATION_GREY16; 
	else
		out->Type = VIPS_INTERPRETATION_B_W; 

	/* greyscale_line() doesn't do complex.
	 */
	if( vips_check_noncomplex( "tiff2vips", out ) )
		return( -1 ); 

	rtiff->sfn = greyscale_line;

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
palette_line_bit( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, void *client )
{
	PaletteRead *read = (PaletteRead *) client;
	int samples = rtiff->samples_per_pixel;

	int bit;
	VipsPel data;
	int x;

	bit = 0;
	data = 0;
	for( x = 0; x < n * samples; x++ ) {
		int i;

		if( bit <= 0 ) {
			data = *p++;
			bit = 8;
		}

		i = data >> (8 - rtiff->bits_per_sample);
		data <<= rtiff->bits_per_sample;
		bit -= rtiff->bits_per_sample;

		/* The first band goes through the LUT, subsequent bands are
		 * left-justified and copied.
		 */
		if( x % samples == 0 ) { 
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
			*q++ = i << (8 - rtiff->bits_per_sample);
	}
}

/* 8-bit samples with an 8-bit palette.
 */
static void
palette_line8( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, 
	void *client )
{
	PaletteRead *read = (PaletteRead *) client;
	int samples = rtiff->samples_per_pixel;

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

		for( s = 1; s < samples; s++ )
			q[s] = p[s]; 

		q += samples; 
		p += samples; 
	}
}

/* 16-bit samples with 16-bit data in the palette. 
 */
static void
palette_line16( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, 
	void *client )
{
	PaletteRead *read = (PaletteRead *) client;
	int samples = rtiff->samples_per_pixel;

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

		for( s = 1; s < samples; s++ )
			q16[s] = p16[s]; 

		q16 += samples; 
		p16 += samples; 
	}
}

/* Read a palette-ised TIFF image. 
 */
static int
parse_palette( ReadTiff *rtiff, VipsImage *out )
{
	int len;
	PaletteRead *read;
	int i;

	if( check_bits_palette( rtiff ) ||
		check_min_samples( rtiff, 1 ) )
		return( -1 ); 
	len = 1 << rtiff->bits_per_sample;

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
	for( i = 0; i < len; i++ ) {
		read->red8[i] = read->red16[i] >> 8;
		read->green8[i] = read->green16[i] >> 8;
		read->blue8[i] = read->blue16[i] >> 8;
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

	if( rtiff->bits_per_sample <= 8 )
		out->BandFmt = VIPS_FORMAT_UCHAR; 
	else
		out->BandFmt = VIPS_FORMAT_USHORT; 
	out->Coding = VIPS_CODING_NONE; 

	if( read->mono ) {
		out->Bands = rtiff->samples_per_pixel; 
		if( rtiff->bits_per_sample <= 8 )
			out->Type = VIPS_INTERPRETATION_B_W; 
		else
			out->Type = VIPS_INTERPRETATION_GREY16; 
	}
	else {
		out->Bands = rtiff->samples_per_pixel + 2; 
		if( rtiff->bits_per_sample <= 8 )
			out->Type = VIPS_INTERPRETATION_sRGB; 
		else
			out->Type = VIPS_INTERPRETATION_RGB16; 
	}

	rtiff->client = read;
	if( rtiff->bits_per_sample < 8 )
		rtiff->sfn = palette_line_bit;
	else if( rtiff->bits_per_sample == 8 )
		rtiff->sfn = palette_line8;
	else if( rtiff->bits_per_sample == 16 )
		rtiff->sfn = palette_line16;
	else
		g_assert( 0 ); 

	return( 0 );
}

/* Per-scanline process function when we just need to copy.
 */
static void
memcpy_line( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, void *client )
{
	VipsImage *im = (VipsImage *) client;
	size_t len = n * VIPS_IMAGE_SIZEOF_PEL( im );

	memcpy( q, p, len ); 
}

/* Read a regular multiband image where we can just copy pixels from the tiff
 * buffer.
 */
static int
parse_copy( ReadTiff *rtiff, VipsImage *out )
{
	out->Bands = rtiff->samples_per_pixel; 
	if( (out->BandFmt = guess_format( rtiff )) == VIPS_FORMAT_NOTSET )
		return( -1 ); 
	out->Coding = VIPS_CODING_NONE; 

	if( rtiff->samples_per_pixel >= 3 &&
		(rtiff->photometric_interpretation == PHOTOMETRIC_RGB ||
		 rtiff->photometric_interpretation == PHOTOMETRIC_YCBCR) ) {
		if( rtiff->bits_per_sample == 16 )
			out->Type = VIPS_INTERPRETATION_RGB16; 
		else
			out->Type = VIPS_INTERPRETATION_sRGB; 
	}

	if( rtiff->samples_per_pixel >= 3 &&
		rtiff->photometric_interpretation == PHOTOMETRIC_CIELAB )
		out->Type = VIPS_INTERPRETATION_LAB; 

	if( rtiff->samples_per_pixel >= 4 &&
		rtiff->photometric_interpretation == PHOTOMETRIC_SEPARATED )
		out->Type = VIPS_INTERPRETATION_CMYK; 

	rtiff->sfn = memcpy_line;
	rtiff->client = out;
	rtiff->memcpy = TRUE;

	return( 0 );
}

/* Read resolution from a TIFF image.
 */
static int
parse_resolution( TIFF *tiff, VipsImage *out )
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
		vips_warn( "tiff2vips", _( "no resolution information for "
			"TIFF image \"%s\" -- defaulting to 1 pixel per mm" ), 
			TIFFFileName( tiff ) );
		x = 1.0;
		y = 1.0;
	}

	out->Xres = x;
	out->Yres = y;

	return( 0 );
}

typedef int (*reader_fn)( ReadTiff *rtiff, VipsImage *out );

/* We have a range of output paths. Look at the tiff header and try to
 * route the input image to the best output path.
 */
static reader_fn
pick_reader( ReadTiff *rtiff )
{
	if( rtiff->photometric_interpretation == PHOTOMETRIC_CIELAB ) {
		if( rtiff->bits_per_sample == 8 )
			return( parse_labpack );
		if( rtiff->bits_per_sample == 16 )
			return( parse_labs );
	}

	if( rtiff->photometric_interpretation == PHOTOMETRIC_MINISWHITE ||
		rtiff->photometric_interpretation == PHOTOMETRIC_MINISBLACK ) {
		if( rtiff->bits_per_sample == 1 )
			return( parse_onebit ); 
		else
			return( parse_greyscale ); 
	}

	if( rtiff->photometric_interpretation == PHOTOMETRIC_PALETTE ) 
		return( parse_palette ); 

	if( rtiff->photometric_interpretation == PHOTOMETRIC_YCBCR ) { 
		/* Sometimes JPEG in TIFF images are tagged as YCBCR. Ask
		 * libtiff to convert to RGB for us.
		 */
		TIFFSetField( rtiff->tiff, 
			TIFFTAG_JPEGCOLORMODE, JPEGCOLORMODE_RGB );
	}

	return( parse_copy );
}

/* Look at PhotometricInterpretation and BitsPerPixel and try to figure out 
 * which of the image classes this is.
 */
static int
parse_header( ReadTiff *rtiff, VipsImage *out )
{
	uint32 data_length;
	uint32 width, height;
	void *data;

	if( tfexists( rtiff->tiff, TIFFTAG_PLANARCONFIG ) ) {
		int v; 

		tfget16( rtiff->tiff, TIFFTAG_PLANARCONFIG, &v );
		if( v == PLANARCONFIG_SEPARATE )
			rtiff->separate = TRUE; 
	}

	/* We always need dimensions.
	 */
	if( !tfget32( rtiff->tiff, TIFFTAG_IMAGEWIDTH, &width ) ||
		!tfget32( rtiff->tiff, TIFFTAG_IMAGELENGTH, &height ) ||
		parse_resolution( rtiff->tiff, out ) ||
		!tfget16( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 
		&rtiff->samples_per_pixel ) ||
		!tfget16( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 
			&rtiff->bits_per_sample ) ||
		!tfget16( rtiff->tiff, TIFFTAG_PHOTOMETRIC, 
			&rtiff->photometric_interpretation ) )
		return( -1 );

	/* Some optional fields. 
	 */
{
	uint16 v;

	TIFFGetFieldDefaulted( rtiff->tiff, TIFFTAG_SAMPLEFORMAT, &v );

	/* Some images have this set to void, bizarre.
	 */
	if( v == SAMPLEFORMAT_VOID )
		v = SAMPLEFORMAT_UINT;

	rtiff->sample_format = v;
}

	/* Arbitrary sanity-checking limits.
	 */

	if( width <= 0 || 
		width > 10000000 || 
		height <= 0 || 
		height > 10000000 ) {
		vips_error( "tiff2vips", 
			"%s", _( "width/height out of range" ) );
		return( -1 );
	}

	if( rtiff->samples_per_pixel <= 0 || 
		rtiff->samples_per_pixel > 10000 || 
		rtiff->bits_per_sample <= 0 || 
		rtiff->bits_per_sample > 32 ) {
		vips_error( "tiff2vips", 
			"%s", _( "samples out of range" ) );
		return( -1 );
	}

	out->Xsize = width;
	out->Ysize = height;

#ifdef DEBUG
	printf( "parse_header: samples_per_pixel = %d\n", 
		rtiff->samples_per_pixel );
	printf( "parse_header: bits_per_sample = %d\n", 
		rtiff->bits_per_sample );
	printf( "parse_header: sample_format = %d\n", 
		rtiff->sample_format );
#endif /*DEBUG*/

	/* We have a range of output paths. Look at the tiff header and try to
	 * route the input image to the best output path.
	 */
	if( pick_reader( rtiff )( rtiff, out ) ) 
		return( -1 ); 

	/* Read any ICC profile.
	 */
	if( TIFFGetField( rtiff->tiff, 
		TIFFTAG_ICCPROFILE, &data_length, &data ) ) {
		void *data_copy;

		if( !(data_copy = vips_malloc( NULL, data_length )) ) 
			return( -1 );
		memcpy( data_copy, data, data_length );
		vips_image_set_blob( out, VIPS_META_ICC_NAME, 
			(VipsCallbackFn) vips_free, data_copy, data_length );
	}

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
tiff_tile_size( ReadTiff *rtiff )
{
	return( TIFFTileRowSize( rtiff->tiff ) * rtiff->theight );
}

/* Allocate a tile buffer. Have one of these for each thread so we can unpack
 * to vips in parallel.
 */
static void *
tiff_seq_start( VipsImage *out, void *a, void *b )
{
	ReadTiff *rtiff = (ReadTiff *) a;
	tsize_t size;
	tdata_t *buf;

	size = tiff_tile_size( rtiff );
	if( !(buf = vips_malloc( NULL, size )) )
		return( NULL );

	return( (void *) buf );
}

/* Paint a tile from the file. This is a
 * special-case for a region is exactly a tiff tile, and pixels need no
 * conversion. In this case, libtiff can read tiles directly to our output
 * region.
 */
static int
tiff_fill_region_aligned( VipsRegion *out, void *seq, void *a, void *b )
{
	ReadTiff *rtiff = (ReadTiff *) a;
	VipsRect *r = &out->valid;

	g_assert( (r->left % rtiff->twidth) == 0 );
	g_assert( (r->top % rtiff->theight) == 0 );
	g_assert( r->width == rtiff->twidth );
	g_assert( r->height == rtiff->theight );
	g_assert( VIPS_REGION_LSKIP( out ) == VIPS_REGION_SIZEOF_LINE( out ) );

#ifdef DEBUG
	printf( "tiff_fill_region_aligned: left = %d, top = %d\n", 
		r->left, r->top ); 
#endif /*DEBUG*/

	VIPS_GATE_START( "tiff_fill_region_aligned: work" ); 

	/* Read that tile directly into the vips tile.
	 */
	if( TIFFReadTile( rtiff->tiff, 
		VIPS_REGION_ADDR( out, r->left, r->top ), 
		r->left, r->top, 0, 0 ) < 0 ) {
		VIPS_GATE_STOP( "tiff_fill_region_aligned: work" ); 
		return( -1 );
	}

	VIPS_GATE_STOP( "tiff_fill_region_aligned: work" ); 

	return( 0 );
}

/* Loop over the output region painting in tiles from the file.
 */
static int
tiff_fill_region( VipsRegion *out, void *seq, void *a, void *b, gboolean *stop )
{
	tdata_t *buf = (tdata_t *) seq;
	ReadTiff *rtiff = (ReadTiff *) a;
	VipsRect *r = &out->valid;

	/* Find top left of tiles we need.
	 */
	int xs = (r->left / rtiff->twidth) * rtiff->twidth;
	int ys = (r->top / rtiff->theight) * rtiff->theight;

	/* Sizeof a line of bytes in the TIFF tile.
	 */
	int tls = tiff_tile_size( rtiff ) / rtiff->theight;

	/* Sizeof a pel in the TIFF file. This won't work for formats which
	 * are <1 byte per pel, like onebit :-( Fortunately, it's only used
	 * to calculate addresses within a tile and, because we are wrapped in
	 * vips_tilecache(), we will never have to calculate positions not 
	 * within a tile.
	 */
	int tps = tls / rtiff->twidth;

	int x, y, z;

	/* Special case: we are filling a single tile exactly sized to match
	 * the tiff tile and we have no repacking to do for this format.
	 */
	if( rtiff->memcpy &&
		r->left % rtiff->twidth == 0 &&
		r->top % rtiff->theight == 0 &&
		r->width == rtiff->twidth &&
		r->height == rtiff->theight &&
		VIPS_REGION_LSKIP( out ) == VIPS_REGION_SIZEOF_LINE( out ) )
		return( tiff_fill_region_aligned( out, seq, a, b ) );

	VIPS_GATE_START( "tiff_fill_region: work" ); 

	for( y = ys; y < VIPS_RECT_BOTTOM( r ); y += rtiff->theight )
		for( x = xs; x < VIPS_RECT_RIGHT( r ); x += rtiff->twidth ) {
			VipsRect tile;
			VipsRect hit;

			/* Read that tile.
			 */
			if( TIFFReadTile( rtiff->tiff, buf, x, y, 0, 0 ) < 0 ) {
				VIPS_GATE_STOP( "tiff_fill_region: work" ); 
				return( -1 );
			}

			/* The tile we read.
			 */
			tile.left = x;
			tile.top = y;
			tile.width = rtiff->twidth;
			tile.height = rtiff->theight;

			/* The section that hits the region we are building.
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
		}

	VIPS_GATE_STOP( "tiff_fill_region: work" ); 

	return( 0 );
}

static int
tiff_seq_stop( void *seq, void *a, void *b )
{
	vips_free( seq );

	return( 0 );
}

/* Tile-type TIFF reader core - pass in a per-tile transform. Generate into
 * the im and do it all partially.
 */
static int
read_tilewise( ReadTiff *rtiff, VipsImage *out )
{
	VipsImage *raw;
	VipsImage *t;

#ifdef DEBUG
	printf( "tiff2vips: read_tilewise\n" );
#endif /*DEBUG*/

	/* I don't have a sample images for tiled + separate, ban it for now.
	 */
	if( rtiff->separate ) {
		vips_error( "tiff2vips", 
			"%s", _( "tiled separate planes not supported" ) ); 
		return( -1 );
	}

	/* Get tiling geometry.
	 */
	if( !tfget32( rtiff->tiff, TIFFTAG_TILEWIDTH, &rtiff->twidth ) ||
		!tfget32( rtiff->tiff, TIFFTAG_TILELENGTH, &rtiff->theight ) )
		return( -1 );

	/* Read to this image, then cache to out, see below.
	 */
	raw = vips_image_new(); 
	vips_object_local( out, raw );

	/* Parse the TIFF header and set up raw.
	 */
	if( parse_header( rtiff, raw ) )
		return( -1 );

	/* Double check: in memcpy mode, the vips tilesize should exactly
	 * match the tifftile size.
	 */
	if( rtiff->memcpy ) {
		size_t vips_tile_size;

		vips_tile_size = VIPS_IMAGE_SIZEOF_PEL( raw ) * 
			rtiff->twidth * rtiff->theight; 

		if( tiff_tile_size( rtiff ) != vips_tile_size ) { 
			vips_error( "tiff2vips", 
				"%s", _( "unsupported tiff image type" ) );
			return( -1 );
		}
	}

	/* Even though this is a tiled reader, we hint thinstrip since with
	 * the cache we are quite happy serving that if anything downstream 
	 * would like it.
	 */
        vips_image_pipelinev( raw, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	if( vips_image_generate( raw, 
		tiff_seq_start, tiff_fill_region, tiff_seq_stop, 
		rtiff, NULL ) )
		return( -1 );

	/* Copy to out, adding a cache. Enough tiles for two complete rows.
	 */
	if( vips_tilecache( raw, &t,
		"tile_width", rtiff->twidth,
		"tile_height", rtiff->theight,
		"max_tiles", 2 * (1 + raw->Xsize / rtiff->twidth),
		NULL ) ) 
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
tiff2vips_strip_read( TIFF *tiff, int strip, tdata_t buf )
{
	tsize_t length;

	length = TIFFReadEncodedStrip( tiff, strip, buf, (tsize_t) -1 );
	if( length == -1 ) {
		vips_error( "tiff2vips", "%s", _( "read error" ) );
		return( -1 );
	}

	return( 0 );
}

/* Read a strip. If the image is in separate planes, read each plane and
 * interleave to the output.
 */
static int
tiff2vips_strip_read_interleaved( ReadTiff *rtiff, int y, tdata_t buf )
{
	tstrip_t strip = y / rtiff->rows_per_strip;

	if( rtiff->separate ) {
		int strips_per_plane = 1 + (rtiff->out->Ysize - 1) / 
			rtiff->rows_per_strip;
		int strip_height = VIPS_MIN( rtiff->rows_per_strip,
			rtiff->out->Ysize - y ); 
		int pels_per_strip = rtiff->out->Xsize * strip_height;
		int bytes_per_sample = rtiff->bits_per_sample >> 3; 

		int i, j, k;

		for( i = 0; i < rtiff->samples_per_pixel; i++ ) { 
			VipsPel *p;
			VipsPel *q;

			if( tiff2vips_strip_read( rtiff->tiff,
				strips_per_plane * i + strip, 
				rtiff->plane_buf ) )
				return( -1 );

			p = (VipsPel *) rtiff->plane_buf;
			q = i * bytes_per_sample + (VipsPel *) buf;
			for( j = 0; j < pels_per_strip; j++ ) {
				for( k = 0; k < bytes_per_sample; k++ ) 
					q[k] = p[k];

				p += bytes_per_sample;
				q += bytes_per_sample * 
					rtiff->samples_per_pixel;
			}
		}
	}
	else { 
		if( tiff2vips_strip_read( rtiff->tiff, 
			y / rtiff->rows_per_strip, buf ) )
			return( -1 );
	}

	return( 0 ); 
}

static int
tiff2vips_stripwise_generate( VipsRegion *or, 
	void *seq, void *a, void *b, gboolean *stop )
{
	ReadTiff *rtiff = (ReadTiff *) a;
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

	/* Tiles should always be on a strip boundary.
	 */
	g_assert( r->top % rtiff->rows_per_strip == 0 );

	/* Tiles should always be a strip in height, unless it's the final
	 * strip.
	 */
	g_assert( r->height == 
		VIPS_MIN( rtiff->rows_per_strip, or->im->Ysize - r->top ) ); 

	VIPS_GATE_START( "tiff2vips_stripwise_generate: work" ); 

	for( y = 0; y < r->height; y += rtiff->rows_per_strip ) {
		tdata_t dst;

		/* Read directly into the image if we can. Otherwise, we must 
		 * read to a temp buffer then unpack into the image.
		 */
		if( rtiff->memcpy ) 
			dst = VIPS_REGION_ADDR( or, 0, r->top + y );
		else
			dst = rtiff->contig_buf;

		if( tiff2vips_strip_read_interleaved( rtiff, 
			r->top + y, dst ) ) {
			VIPS_GATE_STOP( "tiff2vips_stripwise_generate: work" ); 
			return( -1 ); 
		}

		/* If necessary, unpack to destination.
		 */
		if( !rtiff->memcpy ) {
			int height = VIPS_MIN( VIPS_MIN( rtiff->rows_per_strip,
				or->im->Ysize - (r->top + y) ), r->height );

			VipsPel *p;
			VipsPel *q;
			int z;

			p = rtiff->contig_buf;
			q = VIPS_REGION_ADDR( or, 0, r->top + y );
			for( z = 0; z < height; z++ ) { 
				rtiff->sfn( rtiff, 
					q, p, or->im->Xsize, rtiff->client );

				p += rtiff->scanline_size;
				q += VIPS_REGION_LSKIP( or ); 
			}
		}
	}

	VIPS_GATE_STOP( "tiff2vips_stripwise_generate: work" ); 

	return( 0 );
}

/* Stripwise reading.
 *
 * We could potentially read strips in any order, but this would give
 * catastrophic performance for operations like 90 degress rotate on a 
 * large image. Only offer sequential read.
 */
static int
read_stripwise( ReadTiff *rtiff, VipsImage *out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 3 );

#ifdef DEBUG
	printf( "tiff2vips: read_stripwise\n" );
#endif /*DEBUG*/

	t[0] = vips_image_new();

	if( parse_header( rtiff, t[0] ) )
		return( -1 );

        vips_image_pipelinev( t[0], VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	if( !tfget32( rtiff->tiff, 
		TIFFTAG_ROWSPERSTRIP, &rtiff->rows_per_strip ) )
		return( -1 );
	rtiff->scanline_size = TIFFScanlineSize( rtiff->tiff );
	rtiff->strip_size = TIFFStripSize( rtiff->tiff );
	rtiff->number_of_strips = TIFFNumberOfStrips( rtiff->tiff );

	/* rows_per_strip can be 2 ** 32 - 1, meaning the whole image. Clip 
	 * this down to ysize to avoid confusing vips. 
	 *
	 * And it musn't be zero.
	 */
	rtiff->rows_per_strip = 
		VIPS_CLIP( 1, rtiff->rows_per_strip, t[0]->Ysize );

#ifdef DEBUG
	printf( "read_stripwise: rows_per_strip = %u\n", 
		rtiff->rows_per_strip );
	printf( "read_stripwise: scanline_size = %zd\n", 
		rtiff->scanline_size );
	printf( "read_stripwise: strip_size = %zd\n", 
		rtiff->strip_size );
	printf( "read_stripwise: number_of_strips = %d\n", 
		rtiff->number_of_strips );
#endif /*DEBUG*/

	/* Double check: in memcpy mode, the vips linesize should exactly
	 * match the tiff line size.
	 */
	if( rtiff->memcpy ) {
		size_t vips_line_size;

		/* Lines are smaller in plane-separated mode.
		 */
		if( rtiff->separate )
			vips_line_size = VIPS_IMAGE_SIZEOF_ELEMENT( t[0] ) * 
				t[0]->Xsize; 
		else
			vips_line_size = VIPS_IMAGE_SIZEOF_LINE( t[0] );

		if( rtiff->scanline_size != vips_line_size ) { 
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
	if( rtiff->separate ) {
		if( !(rtiff->plane_buf = 
			vips_malloc( VIPS_OBJECT( out ), rtiff->strip_size )) ) 
			return( -1 );
	}

	/* If we need to manipulate pixels, we must read to an interleaved
	 * plane buffer before repacking to the output.
	 *
	 * We don't need a separate buffer per thread since the _generate()
	 * function runs inside the cache lock. 
	 */
	if( !rtiff->memcpy ) { 
		tsize_t size;

		size = rtiff->strip_size;
		if( rtiff->separate )
			size *= rtiff->samples_per_pixel;

		if( !(rtiff->contig_buf = 
			vips_malloc( VIPS_OBJECT( out ), size )) ) 
			return( -1 );
	}

	if( 
		vips_image_generate( t[0], 
			NULL, tiff2vips_stripwise_generate, NULL, 
			rtiff, NULL ) ||
		vips_sequential( t[0], &t[1], 
			"tile_height", rtiff->rows_per_strip,
			"access", rtiff->readbehind ? 
				VIPS_ACCESS_SEQUENTIAL : 
				VIPS_ACCESS_SEQUENTIAL_UNBUFFERED,
			NULL ) ||
		vips_image_write( t[1], out ) )
		return( -1 );

	return( 0 );
}

static void
readtiff_destroy( VipsObject *object, ReadTiff *rtiff )
{
	VIPS_FREEF( TIFFClose, rtiff->tiff );
}

static ReadTiff *
readtiff_new( VipsImage *out, int page, gboolean readbehind )
{
	ReadTiff *rtiff;

	if( !(rtiff = VIPS_NEW( out, ReadTiff )) )
		return( NULL );

	rtiff->filename = NULL;
	rtiff->buf = NULL;
	rtiff->len = 0;
	rtiff->out = out;
	rtiff->page = page;
	rtiff->readbehind = readbehind;
	rtiff->tiff = NULL;
	rtiff->sfn = NULL;
	rtiff->client = NULL;
	rtiff->memcpy = FALSE;
	rtiff->pos = 0;
	rtiff->twidth = 0;
	rtiff->theight = 0;
	rtiff->separate = FALSE;
	rtiff->plane_buf = NULL;
	rtiff->contig_buf = NULL;

	g_signal_connect( out, "close", 
		G_CALLBACK( readtiff_destroy ), rtiff ); 

	if( rtiff->page < 0 || rtiff->page > 1000 ) {
		vips_error( "tiff2vips", _( "bad page number %d" ),
			rtiff->page );
		return( NULL );
	}

	return( rtiff );
}

static ReadTiff *
readtiff_new_filename( const char *filename, VipsImage *out, int page, 
	gboolean readbehind )
{
	ReadTiff *rtiff;
	int i;

	if( !(rtiff = readtiff_new( out, page, readbehind )) )
		return( NULL );

	rtiff->filename = vips_strdup( VIPS_OBJECT( out ), filename );

	/* No mmap --- no performance advantage with libtiff, and it burns up
	 * our VM if the tiff file is large.
	 */
	if( !(rtiff->tiff = TIFFOpen( filename, "rm" )) ) {
		vips_error( "tiff2vips", _( "unable to open \"%s\" for input" ),
			filename );
		return( NULL );
	}

	for( i = 0; i < page; i++ ) 
		if( !TIFFReadDirectory( rtiff->tiff ) ) {
			vips_error( "tiff2vips", 
				_( "TIFF does not contain page %d" ), 
				rtiff->page );
			return( NULL );
		}

	return( rtiff );
}

static tsize_t 
my_tiff_read( thandle_t st, tdata_t buffer, tsize_t size )
{
	ReadTiff *rtiff = (ReadTiff *) st;

	size_t available = rtiff->len - rtiff->pos;
	size_t copy = VIPS_MIN( size, available );

	memcpy( buffer, rtiff->buf + rtiff->pos, copy );
	rtiff->pos += copy;

	return( copy ); 
}

static tsize_t 
my_tiff_write( thandle_t st, tdata_t buffer, tsize_t size )
{
	g_assert( 0 ); 

	return( 0 ); 
}

static int 
my_tiff_close( thandle_t st )
{
	return 0;
}

static toff_t 
my_tiff_seek( thandle_t st, toff_t pos, int whence )
{
	ReadTiff *rtiff = (ReadTiff *) st;

	if( whence == SEEK_SET )
		rtiff->pos = pos;
	else if( whence == SEEK_CUR )
		rtiff->pos += pos;
	else if( whence == SEEK_END )
		rtiff->pos = rtiff->len + pos;
	else
		g_assert( 0 ); 

	return( rtiff->pos ); 
}

static toff_t 
my_tiff_size( thandle_t st )
{
	ReadTiff *rtiff = (ReadTiff *) st;

	return( rtiff->len ); 
}

static int 
my_tiff_map( thandle_t st, tdata_t *start, toff_t *len )
{
	g_assert( 0 ); 

	return 0;
}

static void 
my_tiff_unmap( thandle_t st, tdata_t start, toff_t len )
{
	g_assert( 0 ); 

	return;
}

static ReadTiff *
readtiff_new_buffer( void *buf, size_t len, VipsImage *out, int page, 
	gboolean readbehind )
{
	ReadTiff *rtiff;
	int i;

	if( !(rtiff = readtiff_new( out, page, readbehind )) )
		return( NULL );

	rtiff->buf = buf;
	rtiff->len = len;

	if( !(rtiff->tiff = TIFFClientOpen( "memory buffer", "rm",
		(thandle_t) rtiff,
		my_tiff_read, my_tiff_write, my_tiff_seek, my_tiff_close, 
		my_tiff_size, my_tiff_map, my_tiff_unmap )) ) { 
		vips_error( "tiff2vips", "%s", 
			_( "unable to open memory buffer for input" ) );
		return( NULL );
	}

	for( i = 0; i < page; i++ ) 
		if( !TIFFReadDirectory( rtiff->tiff ) ) {
			vips_error( "tiff2vips", 
				_( "TIFF does not contain page %d" ), 
				rtiff->page );
			return( NULL );
		}

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
vips__tiff_read( const char *filename, VipsImage *out, int page, 
	gboolean readbehind )
{
	ReadTiff *rtiff;

#ifdef DEBUG
	printf( "tiff2vips: libtiff version is \"%s\"\n", TIFFGetVersion() );
	printf( "tiff2vips: libtiff starting for %s\n", filename );
#endif /*DEBUG*/

	vips__tiff_init();

	if( !(rtiff = readtiff_new_filename( filename, 
		out, page, readbehind )) )
		return( -1 );

	if( TIFFIsTiled( rtiff->tiff ) ) {
		if( read_tilewise( rtiff, out ) )
			return( -1 );
	}
	else {
		if( read_stripwise( rtiff, out ) )
			return( -1 );
	}

	return( 0 );
}

int
vips__tiff_read_header( const char *filename, VipsImage *out, int page )
{
	ReadTiff *rtiff;

	vips__tiff_init();

	if( !(rtiff = readtiff_new_filename( filename, out, page, FALSE )) )
		return( -1 );

	if( parse_header( rtiff, out ) )
		return( -1 );

	return( 0 );
}

gboolean
vips__istifftiled( const char *filename )
{
	TIFF *tif;
	gboolean tiled;

	vips__tiff_init();

	if( !(tif = TIFFOpen( filename, "rm" )) ) {
		vips_error_clear();
		return( FALSE );
	}
	tiled = TIFFIsTiled( tif );
	TIFFClose( tif );

	return( tiled );
}

gboolean
vips__istiff_buffer( const unsigned char *buf, size_t len )
{
	if( len >= 2 &&
		((buf[0] == 'M' && buf[1] == 'M') ||
		 (buf[0] == 'I' && buf[1] == 'I')) ) 
		return( TRUE );

	return( FALSE );
}

gboolean
vips__istiff( const char *filename )
{
	unsigned char buf[2];

	if( vips__get_bytes( filename, buf, 2 ) &&
		vips__istiff_buffer( buf, 2 ) )
		return( TRUE );

	return( FALSE );
}

int
vips__tiff_read_header_buffer( void *buf, size_t len, VipsImage *out, int page )
{
	ReadTiff *rtiff;

	vips__tiff_init();

	if( !(rtiff = readtiff_new_buffer( buf, len, out, page, FALSE )) )
		return( -1 );

	if( parse_header( rtiff, out ) )
		return( -1 );

	return( 0 );
}

int
vips__tiff_read_buffer( void *buf, size_t len, VipsImage *out, 
	int page, gboolean readbehind )
{
	ReadTiff *rtiff;

#ifdef DEBUG
	printf( "tiff2vips: libtiff version is \"%s\"\n", TIFFGetVersion() );
	printf( "tiff2vips: libtiff starting for %s\n", filename );
#endif /*DEBUG*/

	vips__tiff_init();

	if( !(rtiff = readtiff_new_buffer( buf, len, out, page, readbehind )) )
		return( -1 );

	if( TIFFIsTiled( rtiff->tiff ) ) {
		if( read_tilewise( rtiff, out ) )
			return( -1 );
	}
	else {
		if( read_stripwise( rtiff, out ) )
			return( -1 );
	}

	return( 0 );
}

#endif /*HAVE_TIFF*/
