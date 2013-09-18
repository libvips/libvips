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
	VipsImage *out;

	/* From filename.
	 */
	int page;

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

/* Test a uint16 field. Field must be defined and equal to the value.
 */
static int
tfequals( TIFF *tif, ttag_t tag, uint16 val )
{
	int v; 

	if( !tfget16( tif, tag, &v ) )
		return( 0 );
	if( v != val ) {
		vips_error( "tiff2vips", 
			_( "required field %d = %d, not %d" ), tag, v, val );
		return( 0 );
	}

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
check_samples_alpha( ReadTiff *rtiff, int samples_per_pixel )
{
	if( rtiff->samples_per_pixel != samples_per_pixel && 
		rtiff->samples_per_pixel != samples_per_pixel + 1 ) {
		vips_error( "tiff2vips", 
			_( "not %d or %d bands" ), 
			samples_per_pixel, samples_per_pixel + 1 );
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
	if( rtiff->bits_per_sample != 8 && 
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

static int
check_float(  ReadTiff *rtiff )
{
	int format; 

	if( !tfget16( rtiff->tiff, TIFFTAG_SAMPLEFORMAT, &format ) ) 
		return( -1 );
	if( format != SAMPLEFORMAT_IEEEFP ) {
		vips_error( "tiff2vips", 
			"%s", _( "not a floating-point image" ) );
		return( -1 );
	}

	return( 0 );
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
	if( check_samples_alpha( rtiff, 3 ) ||
		check_bits( rtiff, 8 ) )
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

	for( x = 0; x < n; x++ ) {
		q1[0] = p1[0] >> 1;
		q1[1] = p1[1];
		q1[2] = p1[2];

		q1 += 3;
		p1 += rtiff->samples_per_pixel;
	}
}

/* Read a 16-bit LAB image.
 */
static int
parse_labs( ReadTiff *rtiff, VipsImage *out )
{
	if( check_samples_alpha( rtiff, 3 ) ||
		check_bits( rtiff, 16 ) )
		return( -1 );

	out->Bands = 3; 
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
	int white = black ^ -1;

	/* (sigh) how many times have I written this?
	 */
	for( x = 0, i = 0; i < (n >> 3); i++ ) {
		bits = (VipsPel) p[i];

		for( z = 0; z < 8; z++, x++ ) {
			q[x] = (bits & 128) ? white : black;
			bits <<= 1;
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

/* Read a 1-bit TIFF image. Pass in pixel values to use for black and white.
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

/* Per-scanline process function for 8-bit greyscale images.
 */
static void
greyscale8_line( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, void *client )
{
	int mask = 
		rtiff->photometric_interpretation == PHOTOMETRIC_MINISBLACK ? 
		0 : -1;

	int x;

	/* Read bytes, swapping sense if necessary.
	 */
	for( x = 0; x < n; x++ ) {
		q[0] = p[0] ^ mask;

		/* Process alpha, if any. Don't swap this.
		 */
		if( rtiff->samples_per_pixel == 2 )
			q[1] = p[1];

		q += rtiff->samples_per_pixel;
		p += rtiff->samples_per_pixel; 
	}
}

/* Read a 8-bit grey-scale TIFF image. 
 */
static int
parse_greyscale8( ReadTiff *rtiff, VipsImage *out )
{
	if( check_samples_alpha( rtiff, 1 ) ||
		check_bits( rtiff, 8 ) )
		return( -1 );

	out->Bands = rtiff->samples_per_pixel; 
	out->BandFmt = VIPS_FORMAT_UCHAR; 
	out->Coding = VIPS_CODING_NONE; 
	out->Type = VIPS_INTERPRETATION_B_W; 

	rtiff->sfn = greyscale8_line;

	return( 0 );
}

/* Per-scanline process function for 16-bit greyscale images.
 */
static void
greyscale16_line( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, void *client )
{
	int mask = 
		rtiff->photometric_interpretation == PHOTOMETRIC_MINISBLACK ? 
		0 : -1;

	unsigned short *p1;
	unsigned short *q1;
	int x;

	/* Read bytes, swapping sense if necessary.
	 */
	p1 = (unsigned short *) p;
	q1 = (unsigned short *) q;
	for( x = 0; x < n; x++ ) {
		q1[0] = p1[0] ^ mask;

		/* Process alpha, if any. Don't swap this.
		 */
		if( rtiff->samples_per_pixel == 2 )
			q1[1] = p1[1];

		q1 += rtiff->samples_per_pixel;
		p1 += rtiff->samples_per_pixel; 
	}
}

/* Read a 16-bit grey-scale TIFF image. 
 */
static int
parse_greyscale16( ReadTiff *rtiff, VipsImage *out )
{
	if( check_samples_alpha( rtiff, 1 ) ||
		check_bits( rtiff, 16 ) )
		return( -1 );

	out->Bands = rtiff->samples_per_pixel; 
	out->BandFmt = VIPS_FORMAT_USHORT; 
	out->Coding = VIPS_CODING_NONE; 
	out->Type = VIPS_INTERPRETATION_GREY16; 

	rtiff->sfn = greyscale16_line;

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

/* Read a 32-bit floating point greyscale TIFF image. What do we do about
 * MINISWHITE/MINISBLACK (pm)? Not sure ... just ignore it.
 */
static int
parse_greyscale32f( ReadTiff *rtiff, VipsImage *out )
{
	if( check_samples_alpha( rtiff, 1 ) ||
		check_bits( rtiff, 32 ) )
		return( -1 );

	out->Bands = rtiff->samples_per_pixel; 
	out->BandFmt = VIPS_FORMAT_FLOAT;
	out->Coding = VIPS_CODING_NONE; 
	out->Type = VIPS_INTERPRETATION_B_W; 

	rtiff->sfn = memcpy_line;
	rtiff->client = out;
	rtiff->memcpy = TRUE;

	return( 0 );
}

typedef struct {
	/* LUTs mapping image indexes to RGB.
	 */
	VipsPel *red;
	VipsPel *green;
	VipsPel *blue;

	/* All maps equal, so we write mono.
	 */
	gboolean mono;
} PaletteRead;

/* Per-scanline process function for palette images.
 */
static void
palette_line( ReadTiff *rtiff, VipsPel *q, VipsPel *p, int n, void *client )
{
	PaletteRead *read = (PaletteRead *) client;

	int bit;
	VipsPel data;
	int x;

	bit = 0;
	data = 0;
	for( x = 0; x < n; x++ ) {
		int i;

		if( bit <= 0 ) {
			data = *p++;
			bit = 8;
		}

		i = data >> (8 - rtiff->bits_per_sample);
		data <<= rtiff->bits_per_sample;
		bit -= rtiff->bits_per_sample;

		if( read->mono ) {
			q[0] = read->red[i];
			q += 1;
		}
		else {
			q[0] = read->red[i];
			q[1] = read->green[i];
			q[2] = read->blue[i];
			q += 3;
		}
	}
}

/* Read a palette-ised TIFF image. 1/2/4/8 bits only.
 */
static int
parse_palette( ReadTiff *rtiff, VipsImage *out )
{
	PaletteRead *read;
	uint16 *tred, *tgreen, *tblue;
	int i;

	if( check_bits_palette( rtiff ) ||
		check_samples( rtiff, 1 ) )
		return( -1 ); 

	if( !(read = VIPS_NEW( out, PaletteRead )) ||
		!(read->red = VIPS_ARRAY( out, 256, VipsPel )) ||
		!(read->green = VIPS_ARRAY( out, 256, VipsPel )) ||
		!(read->blue = VIPS_ARRAY( out, 256, VipsPel )) )
		return( -1 );

	/* Get maps, convert to 8-bit data.
	 */
	if( !TIFFGetField( rtiff->tiff, 
		TIFFTAG_COLORMAP, &tred, &tgreen, &tblue ) ) {
		vips_error( "tiff2vips", "%s", _( "bad colormap" ) );
		return( -1 );
	}
	for( i = 0; i < (1 << rtiff->bits_per_sample); i++ ) {
		read->red[i] = tred[i] >> 8;
		read->green[i] = tgreen[i] >> 8;
		read->blue[i] = tblue[i] >> 8;
	}

	/* Are all the maps equal? We have a mono image.
	 */
	read->mono = TRUE;
	for( i = 0; i < (1 << rtiff->bits_per_sample); i++ ) 
		if( read->red[i] != read->green[i] ||
			read->green[i] != read->blue[i] ) {
			read->mono = FALSE;
			break;
		}

	/* There's a TIFF extension, INDEXED, that is the preferred way to
	 * encode mono palette images, but few applications support it. So we
	 * just search the colormap.
	 */

	out->BandFmt = VIPS_FORMAT_UCHAR; 
	out->Coding = VIPS_CODING_NONE; 

	if( read->mono ) {
		out->Bands = 1; 
		out->Type = VIPS_INTERPRETATION_B_W; 
	}
	else {
		out->Bands = 3; 
		out->Type = VIPS_INTERPRETATION_sRGB; 
	}

	rtiff->client = read;
	rtiff->sfn = palette_line;

	return( 0 );
}

/* Read an 8-bit RGB/RGBA image.
 */
static int
parse_rgb8( ReadTiff *rtiff, VipsImage *out )
{
	if( check_samples_alpha( rtiff, 3 ) ||
		check_bits( rtiff, 8 ) )
		return( -1 );

	out->Bands = rtiff->samples_per_pixel; 
	out->BandFmt = VIPS_FORMAT_UCHAR; 
	out->Coding = VIPS_CODING_NONE; 
	out->Type = VIPS_INTERPRETATION_sRGB; 

	rtiff->sfn = memcpy_line;
	rtiff->client = out;
	rtiff->memcpy = TRUE;

	return( 0 );
}

/* Read a 16-bit RGB/RGBA image.
 */
static int
parse_rgb16( ReadTiff *rtiff, VipsImage *out )
{
	if( check_samples_alpha( rtiff, 3 ) ||
		check_bits( rtiff, 16 ) )
		return( -1 );

	out->Bands = rtiff->samples_per_pixel; 
	out->BandFmt = VIPS_FORMAT_USHORT; 
	out->Coding = VIPS_CODING_NONE; 
	out->Type = VIPS_INTERPRETATION_RGB16; 

	rtiff->sfn = memcpy_line;
	rtiff->client = out;
	rtiff->memcpy = TRUE;

	return( 0 );
}

/* Read a 32-bit float image. RGB or LAB, with or without alpha.
 */
static int
parse_32f( ReadTiff *rtiff, VipsImage *out )
{
	if( check_samples_alpha( rtiff, 3 ) ||
		check_bits( rtiff, 32 ) ||
		check_float( rtiff ) )
		return( -1 );

	out->Bands = rtiff->samples_per_pixel; 
	out->BandFmt = VIPS_FORMAT_FLOAT; 
	out->Coding = VIPS_CODING_NONE; 

	switch( rtiff->photometric_interpretation ) {
	case PHOTOMETRIC_CIELAB:
		out->Type = VIPS_INTERPRETATION_LAB; 
		break;

	case PHOTOMETRIC_RGB:
		out->Type = VIPS_INTERPRETATION_sRGB; 
		break;

	default:
		g_assert( 0 );
	}

	rtiff->sfn = memcpy_line;
	rtiff->client = out;
	rtiff->memcpy = TRUE;

	return( 0 );
}

/* Read a CMYK image.
 */
static int
parse_cmyk( ReadTiff *rtiff, VipsImage *out )
{
	if( check_samples_alpha( rtiff, 4 ) ||
		check_bits( rtiff, 8 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_INKSET, INKSET_CMYK ) )
		return( -1 );

	out->Bands = rtiff->samples_per_pixel; 
	out->BandFmt = VIPS_FORMAT_UCHAR; 
	out->Coding = VIPS_CODING_NONE; 
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

/* Look at PhotometricInterpretation and BitsPerPixel and try to figure out 
 * which of the image classes this is.
 */
static int
parse_header( ReadTiff *rtiff, VipsImage *out )
{
	int format;
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

	/* Arbitrary sanity-checking limits.
	 */

	if( width <= 0 || 
		width > 1000000 || 
		height <= 0 || 
		height > 1000000 ) {
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
#endif /*DEBUG*/

	switch( rtiff->photometric_interpretation ) {
	case PHOTOMETRIC_CIELAB:
		switch( rtiff->bits_per_sample ) {
		case 8:
			if( parse_labpack( rtiff, out ) )
				return( -1 );
			break;

		case 16:
			if( parse_labs( rtiff, out ) )
				return( -1 );
			break;

		case 32:
			if( parse_32f( rtiff, out ) )
				return( -1 );
			break;

		default:
			vips_error( "tiff2vips", 
				_( "unsupported depth %d for LAB image" ), 
				rtiff->bits_per_sample );
			return( -1 );
		}

		break;

	case PHOTOMETRIC_MINISWHITE:
	case PHOTOMETRIC_MINISBLACK:
		switch( rtiff->bits_per_sample ) {
		case 1:
			if( parse_onebit( rtiff, out ) )
				return( -1 );

			break;

		case 8:
			if( parse_greyscale8( rtiff, out ) )
				return( -1 );

			break;

		case 16:
			if( parse_greyscale16( rtiff, out ) )
				return( -1 );

			break;

		case 32:
			if( !tfget16( rtiff->tiff, 
				TIFFTAG_SAMPLEFORMAT, &format ) ) 
				return( -1 );

			if( format == SAMPLEFORMAT_IEEEFP ) {
				if( parse_greyscale32f( rtiff, out ) )
					return( -1 );
			}
			else {
				vips_error( "tiff2vips", 
					_( "unsupported sample format "
					"%d for greyscale image" ),
					format );
				return( -1 );
			}

			break;

		default:
			vips_error( "tiff2vips", 
				_( "unsupported depth %d for greyscale image" ),
				rtiff->bits_per_sample );
			return( -1 );
		}

		break;

	case PHOTOMETRIC_PALETTE:
		/* Full colour pallette.
		 */
		if( parse_palette( rtiff, out ) )
			return( -1 );

		break;

	case PHOTOMETRIC_YCBCR:
		/* Sometimes JPEG in TIFF images are tagged as YCBCR. Ask
		 * libtiff to convert to RGB for us.
		 */
		TIFFSetField( rtiff->tiff, 
			TIFFTAG_JPEGCOLORMODE, JPEGCOLORMODE_RGB );
		if( parse_rgb8( rtiff, out ) )
			return( -1 );
		break;

	case PHOTOMETRIC_RGB:
		switch( rtiff->bits_per_sample ) {
		case 8:
			if( parse_rgb8( rtiff, out ) )
				return( -1 );
			break;

		case 16:
			if( parse_rgb16( rtiff, out ) )
				return( -1 );
			break;

		case 32:
			if( parse_32f( rtiff, out ) )
				return( -1 );
			break;

		default:
			vips_error( "tiff2vips", 
				_( "unsupported depth %d for RGB image" ), 
				rtiff->bits_per_sample );
			return( -1 );
		}

		break;

	case PHOTOMETRIC_SEPARATED:
		if( parse_cmyk( rtiff, out ) )
			return( -1 );

		break;

	default:
		vips_error( "tiff2vips", 
			_( "unknown photometric interpretation %d" ), 
			rtiff->photometric_interpretation );
		return( -1 );
	}

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

/* Allocate a tile buffer. Have one of these for each thread so we can unpack
 * to vips in parallel.
 */
static void *
tiff_seq_start( VipsImage *out, void *a, void *b )
{
	ReadTiff *rtiff = (ReadTiff *) a;
	tsize_t size;
	tdata_t *buf;

	size = TIFFTileSize( rtiff->tiff );
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

	/* Read that tile directly into the vips tile.
	 */
	if( TIFFReadTile( rtiff->tiff, 
		VIPS_REGION_ADDR( out, r->left, r->top ), 
		r->left, r->top, 0, 0 ) < 0 ) 
		return( -1 );

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
	int tls = TIFFTileSize( rtiff->tiff ) / rtiff->theight;

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

	for( y = ys; y < VIPS_RECT_BOTTOM( r ); y += rtiff->theight )
		for( x = xs; x < VIPS_RECT_RIGHT( r ); x += rtiff->twidth ) {
			VipsRect tile;
			VipsRect hit;

			/* Read that tile.
			 */
			if( TIFFReadTile( rtiff->tiff, buf, x, y, 0, 0 ) < 0 ) 
				return( -1 );

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

	/* Even though this is a tiled reader, we hint thinstrip since with
	 * the cache we are quite happy serving that if anything downstream 
	 * would like it.
	 */
        vips_demand_hint( raw, VIPS_DEMAND_STYLE_THINSTRIP, NULL );

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

	for( y = 0; y < r->height; y += rtiff->rows_per_strip ) {
		tdata_t dst;

		/* Read directly into the image if we can. Otherwise, we must 
		 * read to a temp buffer then unpack into the image.
		 */
		if( rtiff->memcpy ) 
			dst = VIPS_REGION_ADDR( or, 0, r->top + y );
		else
			dst = rtiff->contig_buf;

		if( tiff2vips_strip_read_interleaved( rtiff, r->top + y, dst ) )
			return( -1 ); 

		/* If necessary, unpack to destination.
		 */
		if( !rtiff->memcpy ) {
			int height = VIPS_MIN( VIPS_MIN( rtiff->rows_per_strip,
				or->im->Ysize - (r->top + y) ), r->height );
			int bytes_per_line = (rtiff->bits_per_sample >> 3) * 
				rtiff->samples_per_pixel *
				or->im->Xsize; 

			int z;

			for( z = 0; z < height; z++ ) { 
				VipsPel *p = rtiff->contig_buf + 
					z * bytes_per_line;
				VipsPel *q = VIPS_REGION_ADDR( or, 
					0, r->top + y + z );

				rtiff->sfn( rtiff, 
					q, p, or->im->Xsize, rtiff->client );
			}
		}
	}

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

        vips_demand_hint( t[0], VIPS_DEMAND_STYLE_THINSTRIP, NULL );

	if( !tfget32( rtiff->tiff, 
		TIFFTAG_ROWSPERSTRIP, &rtiff->rows_per_strip ) )
		return( -1 );
	rtiff->scanline_size = TIFFScanlineSize( rtiff->tiff );
	rtiff->strip_size = TIFFStripSize( rtiff->tiff );
	rtiff->number_of_strips = TIFFNumberOfStrips( rtiff->tiff );

	/* rows_per_strip can be 2**32-1, meaning the whole image. Clip this
	 * down to ysize to avoid confusing vips. 
	 */
	rtiff->rows_per_strip = VIPS_MIN( rtiff->rows_per_strip, t[0]->Ysize );

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
readtiff_new( const char *filename, VipsImage *out, int page )
{
	ReadTiff *rtiff;

	if( !(rtiff = VIPS_NEW( out, ReadTiff )) )
		return( NULL );

	rtiff->filename = vips_strdup( VIPS_OBJECT( out ), filename );
	rtiff->out = out;
	rtiff->page = page;
	rtiff->tiff = NULL;
	rtiff->sfn = NULL;
	rtiff->client = NULL;
	rtiff->memcpy = FALSE;
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

/* Pull out the nth directory from a TIFF file.
 */
static TIFF *
get_directory( const char *filename, int page )
{
	TIFF *tif;
	int i;

	/* No mmap --- no performance advantage with libtiff, and it burns up
	 * our VM if the tiff file is large.
	 */
	if( !(tif = TIFFOpen( filename, "rm" )) ) {
		vips_error( "tiff2vips", 
			_( "unable to open \"%s\" for input" ),
			filename );
		return( NULL );
	}

	for( i = 0; i < page; i++ ) 
		if( !TIFFReadDirectory( tif ) ) {
			/* Run out of directories.
			 */
			TIFFClose( tif );
			return( NULL );
		}

	return( tif );
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
vips__tiff_read( const char *filename, VipsImage *out, int page )
{
	ReadTiff *rtiff;

#ifdef DEBUG
	printf( "tiff2vips: libtiff version is \"%s\"\n", TIFFGetVersion() );
	printf( "tiff2vips: libtiff starting for %s\n", filename );
#endif /*DEBUG*/

	vips__tiff_init();

	if( !(rtiff = readtiff_new( filename, out, page )) )
		return( -1 );

	if( !(rtiff->tiff = get_directory( rtiff->filename, rtiff->page )) ) {
		vips_error( "tiff2vips", _( "TIFF file does not "
			"contain page %d" ), rtiff->page );
		return( -1 );
	}

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

	if( !(rtiff = readtiff_new( filename, out, page )) )
		return( -1 );

	if( !(rtiff->tiff = get_directory( rtiff->filename, rtiff->page )) ) {
		vips_error( "tiff2vips", 
			_( "TIFF file does not contain page %d" ), 
			rtiff->page );
		return( -1 );
	}

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
vips__istiff( const char *filename )
{
	unsigned char buf[2];

	if( vips__get_bytes( filename, buf, 2 ) )
		if( (buf[0] == 'M' && buf[1] == 'M') ||
			(buf[0] == 'I' && buf[1] == 'I') ) 
			return( TRUE );

	return( FALSE );
}

#endif /*HAVE_TIFF*/
