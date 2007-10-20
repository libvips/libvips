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
 * It convert LAB-tiff format to IM_TYPE_LABQ in vips format.
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
 *	- if loading YCbCr, convert to IM_CODING_LABQ
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
 *	- added mutex for TIFF*() calls
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

/* Turn on debugging output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifndef HAVE_TIFF

#include <vips/vips.h>

int
im_tiff2vips( const char *tiffile, IMAGE *im )
{
	im_error( "im_tiff2vips", _( "TIFF support disabled" ) );
	return( -1 );
}

int
im_istiffpyramid( const char *name )
{
	return( 0 );
}

int
im_tiff2vips_header( const char *tiffile, IMAGE *im )
{
	im_error( "im_tiff2vips", _( "TIFF support disabled" ) );
	return( -1 );
}

#else /*HAVE_TIFF*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <vips/vips.h>
#include <vips/thread.h>

#include <tiffio.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Scanline-type process function.
 */
typedef void (*scanline_process_fn)( PEL *q, PEL *p, int n, void *user );

/* Stuff we track during a read.
 */
typedef struct {
	/* Parameters.
	 */
	char *filename;
	IMAGE *out;

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

	/* Geometry.
	 */
	int twidth, theight;		/* Tile size */

	/* Only need one of these, since we mutex around TIFF*().
	 */
	GMutex *tlock;			/* Lock for TIFF*() calls */
} ReadTiff;

/* Reading a YCbCr image ... parameters we use for conversion.
 */
typedef struct {
	/* Input and output.
	 */
	TIFF *tif;			/* From here */
	IMAGE *im;			/* To here */

	/* RGB <-> YCbCr conversion.
	 */
	float LumaRed, LumaGreen, LumaBlue;

	/* RGB -> LAB conversion.
	 */
	void *table;
} YCbCrParams;

/* Handle TIFF errors here. 
 */
static void 
thandler_error( char *module, char *fmt, va_list ap )
{
	im_verror( module, fmt, ap );
}

static void 
thandler_warning( char *module, char *fmt, va_list ap )
{
	char buf[256];

	im_vsnprintf( buf, 256, fmt, ap );
	im_warn( module, "%s", buf );
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

/* Test a uint16 field. Field must be defined and equal to the value.
 */
static int
tfequals( TIFF *tif, ttag_t tag, uint16 val )
{
	uint16 fld;

	if( !TIFFGetFieldDefaulted( tif, tag, &fld ) ) {
		im_error( "im_tiff2vips", 
			_( "required field %d missing" ), tag );
		return( 0 );
	}
	if( fld != val ) {
		im_error( "im_tiff2vips", _( "required field %d=%d, not %d" ),
			tag, fld, val );
		return( 0 );
	}

	/* All ok.
	 */
	return( 1 );
}

/* Get a uint32 field.
 */
static int
tfget32( TIFF *tif, ttag_t tag, int *out )
{
	uint32 fld;

	if( !TIFFGetFieldDefaulted( tif, tag, &fld ) ) {
		im_error( "im_tiff2vips", 
			_( "required field %d missing" ), tag );
		return( 0 );
	}

	/* All ok.
	 */
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
		im_error( "im_tiff2vips", 
			_( "required field %d missing" ), tag );
		return( 0 );
	}

	/* All ok.
	 */
	*out = fld;
	return( 1 );
}

/* Per-scanline process function for IM_CODING_LABQ.
 */
static void
labpack_line( PEL *q, PEL *p, int n, void *dummy )
{
	int x;

	for( x = 0; x < n; x++ ) {
		q[0] = p[0];
		q[1] = p[1];
		q[2] = p[2];
		q[3] = 0;

		q += 4;
		p += 3;
	}
}

/* Read an 8-bit LAB image.
 */
static int
parse_labpack( ReadTiff *rtiff, IMAGE *out )
{
	if( !tfequals( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 3 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 8 ) )
		return( -1 );

	out->Bands = 4; 
	out->Bbits = 8; 
	out->BandFmt = IM_BANDFMT_UCHAR; 
	out->Coding = IM_CODING_LABQ; 
	out->Type = IM_TYPE_LAB; 

	rtiff->sfn = labpack_line;
	rtiff->client = NULL;

	return( 0 );
}

/* Per-scanline process function for IM_CODING_LABQ.
 */
static void
labs_line( PEL *q, PEL *p, int n, void *dummy )
{
	int x;
	unsigned short *p1 = (unsigned short *) p;
	short *q1 = (short *) q;

	for( x = 0; x < n; x++ ) {
		q1[0] = p1[0] >> 1;
		q1[1] = p1[1];
		q1[2] = p1[2];

		q1 += 3;
		p1 += 3;
	}
}

/* Read a 16-bit LAB image.
 */
static int
parse_labs( ReadTiff *rtiff, IMAGE *out )
{
	if( !tfequals( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 3 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 16 ) )
		return( -1 );

	out->Bands = 3; 
	out->Bbits = 16; 
	out->BandFmt = IM_BANDFMT_SHORT; 
	out->Coding = IM_CODING_NONE; 
	out->Type = IM_TYPE_LABS; 

	rtiff->sfn = labs_line;
	rtiff->client = NULL;

	return( 0 );
}

/* Per-scanline process function for IM_CODING_LABQ.
 */
static void
ycbcr_line( PEL *q, PEL *p, int n, void *dummy )
{
	int x;

	for( x = 0; x < n; x++ ) {
		q[0] = p[0];
		q[1] = p[1];
		q[2] = p[2];
		q[3] = 0;

		q += 4;
		p += 3;
	}
}

/* Read a YCbCr image.
 */
static int
parse_ycbcr( ReadTiff *rtiff, IMAGE *out )
{
	if( !tfequals( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 3 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 8 ) )
		return( -1 );

	out->Bands = 4; 
	out->Bbits = 8; 
	out->BandFmt = IM_BANDFMT_UCHAR; 
	out->Coding = IM_CODING_LABQ; 
	out->Type = IM_TYPE_LAB; 

	rtiff->sfn = ycbcr_line;
	rtiff->client = NULL;

	return( 0 );
}

/* Per-scanline process function for 1 bit images.
 */
static void
onebit_line( PEL *q, PEL *p, int n, void *flg )
{
	/* Extract PHOTOMETRIC_INTERPRETATION.
	 */
	int pm = *((int *) flg);
	int x, i, z;
	PEL bits;

	int black = (pm == PHOTOMETRIC_MINISBLACK) ? 0 : 255;
	int white = black ^ -1;

	/* (sigh) how many times have I written this?
	 */
	for( x = 0, i = 0; i < (n >> 3); i++ ) {
		bits = (PEL) p[i];

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
parse_onebit( ReadTiff *rtiff, int pm, IMAGE *out )
{
	int *ppm;

	if( !tfequals( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 1 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 1 ) )
		return( -1 );

	out->Bands = 1; 
	out->Bbits = 8; 
	out->BandFmt = IM_BANDFMT_UCHAR; 
	out->Coding = IM_CODING_NONE; 
	out->Type = IM_TYPE_B_W; 

	/* Note pm for later.
	 */
	if( !(ppm = IM_ARRAY( out, 1, int )) )
		return( -1 );
	*ppm = pm;

	rtiff->sfn = onebit_line;
	rtiff->client = ppm;

	return( 0 );
}

/* Per-scanline process function for 8-bit greyscale images.
 */
static void
greyscale8_line( PEL *q, PEL *p, int n, void *flg )
{
	/* Extract swap mask.
	 */
	PEL mask = *((PEL *) flg);
	int x;

	/* Read bytes, swapping sense if necessary.
	 */
	for( x = 0; x < n; x++ ) 
		q[x] = p[x] ^ mask;
}

/* Read a 8-bit grey-scale TIFF image. 
 */
static int
parse_greyscale8( ReadTiff *rtiff, int pm, IMAGE *out )
{
	PEL *mask;

	if( !tfequals( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 1 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 8 ) )
		return( -1 );

	/* Eor each pel with this later.
	 */
	if( !(mask = IM_ARRAY( out, 1, PEL )) )
		return( -1 );
	*mask = (pm == PHOTOMETRIC_MINISBLACK) ? 0 : 255;

	out->Bands = 1; 
	out->Bbits = 8; 
	out->BandFmt = IM_BANDFMT_UCHAR; 
	out->Coding = IM_CODING_NONE; 
	out->Type = IM_TYPE_B_W; 

	rtiff->sfn = greyscale8_line;
	rtiff->client = mask;

	return( 0 );
}

/* Per-scanline process function for 16-bit greyscale images.
 */
static void
greyscale16_line( PEL *q, PEL *p, int n, void *flg )
{
	/* Extract swap mask.
	 */
	unsigned short mask = *((unsigned short *) flg);
	unsigned short *p1 = (unsigned short *) p;
	unsigned short *q1 = (unsigned short *) q;
	int x;

	/* Read bytes, swapping sense if necessary.
	 */
	for( x = 0; x < n; x++ ) 
		q1[x] = p1[x] ^ mask;
}

/* Read a 16-bit grey-scale TIFF image. 
 */
static int
parse_greyscale16( ReadTiff *rtiff, int pm, IMAGE *out )
{
	unsigned short *mask;

	if( !tfequals( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 1 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 16 ) )
		return( -1 );

	/* Eor each pel with this later.
	 */
	if( !(mask = IM_ARRAY( out, 1, unsigned short )) )
		return( -1 );
	mask[0] = (pm == PHOTOMETRIC_MINISBLACK) ? 0 : 65535;

	out->Bands = 1; 
	out->Bbits = 16; 
	out->BandFmt = IM_BANDFMT_USHORT; 
	out->Coding = IM_CODING_NONE; 
	out->Type = IM_TYPE_GREY16; 

	rtiff->sfn = greyscale16_line;
	rtiff->client = mask;

	return( 0 );
}

/* Per-scanline process function for 32-bit floating point greyscale images.
 */
static void
greyscale32f_line( PEL *q, PEL *p, int n )
{
	float *p1 = (float *) p;
	float *q1 = (float *) q;
	int x;

	for( x = 0; x < n; x++ )
		q1[x] = p1[x];
}

/* Read a 32-bit floating point greyscale TIFF image. What do we do about
 * MINISWHITE/MINISBLACK (pm)? Not sure ... just ignore it.
 */
static int
parse_greyscale32f( ReadTiff *rtiff, int pm, IMAGE *out )
{
	if( !tfequals( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 1 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 32 ) )
		return( -1 );

	out->Bands = 1; 
	out->Bbits = 32;
	out->BandFmt = IM_BANDFMT_FLOAT;
	out->Coding = IM_CODING_NONE; 
	out->Type = IM_TYPE_B_W; 

	rtiff->sfn = (scanline_process_fn) greyscale32f_line;
	rtiff->client = NULL;

	return( 0 );
}

/* Per-scanline process function for palette images.
 */
static void
palette_line( PEL *q, PEL *p, int n, void *flg )
{
	/* Extract maps.
	 */
	PEL *red = ((PEL **) flg)[0];
	PEL *green = ((PEL **) flg)[1];
	PEL *blue = ((PEL **) flg)[2];
	int x;

	/* Read bytes, generating colour.
	 */
	for( x = 0; x < n; x++ ) {
		int i = *p++;

		q[0] = red[i];
		q[1] = green[i];
		q[2] = blue[i];

		q += 3;
	}
}

/* Read a palette-ised TIFF image. Again, we only allow 8-bits for now.
 */
static int
parse_palette( ReadTiff *rtiff, IMAGE *out )
{
	uint16 *tred, *tgreen, *tblue;
	PEL *red, *green, *blue;
	PEL **maps;
	int i;

	if( !tfequals( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 1 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 8 ) )
		return( -1 );
	
	/* Allocate mem for VIPS colour maps.
	 */
	if( !(red = IM_ARRAY( out, 256, PEL )) ||
		!(green = IM_ARRAY( out, 256, PEL )) ||
		!(blue = IM_ARRAY( out, 256, PEL )) ||
		!(maps = IM_ARRAY( out, 3, PEL * )) )
		return( -1 );

	/* Get maps, convert to 8-bit data.
	 */
	if( !TIFFGetField( rtiff->tiff, 
		TIFFTAG_COLORMAP, &tred, &tgreen, &tblue ) ) {
		im_error( "im_tiff2vips", _( "bad colormap" ) );
		return( -1 );
	}
	for( i = 0; i < 256; i++ ) {
		red[i] = tred[i] >> 8;
		green[i] = tgreen[i] >> 8;
		blue[i] = tblue[i] >> 8;
	}
	maps[0] = red; 
	maps[1] = green; 
	maps[2] = blue;

	out->Bands = 3; 
	out->Bbits = 8; 
	out->BandFmt = IM_BANDFMT_UCHAR; 
	out->Coding = IM_CODING_NONE; 
	out->Type = IM_TYPE_sRGB; 

	rtiff->sfn = palette_line;
	rtiff->client = maps;

	return( 0 );
}

/* Per-scanline process function for 8-bit RGB/RGBA.
 */
static void
rgb8_line( PEL *q, PEL *p, int n, IMAGE *im )
{
	int x, b;

	for( x = 0; x < n; x++ ) {
		for( b = 0; b < im->Bands; b++ )
			q[b] = p[b];

		q += im->Bands;
		p += im->Bands;
	}
}

/* Read an 8-bit RGB/RGBA image.
 */
static int
parse_rgb8( ReadTiff *rtiff, IMAGE *out )
{
	int bands;

	/* Check other TIFF fields to make sure we can read this. Can have 4
	 * bands for RGBA.
	 */
	if( !tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 8 ) ||
		!tfget16( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, &bands ) )
		return( -1 );
	if( bands != 3 && bands != 4 ) {
		im_error( "im_tiff2vips", _( "3 or 4 bands RGB TIFF only" ) );
		return( -1 );
	}

	out->Bands = bands; 
	out->Bbits = 8; 
	out->BandFmt = IM_BANDFMT_UCHAR; 
	out->Coding = IM_CODING_NONE; 
	out->Type = IM_TYPE_sRGB; 

	rtiff->sfn = (scanline_process_fn) rgb8_line;
	rtiff->client = out;

	return( 0 );
}

/* Per-scanline process function for RGB/RGBA 16.
 */
static void
rgb16_line( PEL *q, PEL *p, int n, IMAGE *im )
{
	int x, b;
	unsigned short *p1 = (unsigned short *) p;
	unsigned short *q1 = (unsigned short *) q;

	for( x = 0; x < n; x++ ) {
		for( b = 0; b < im->Bands; b++ )
			q1[b] = p1[b];

		q1 += im->Bands;
		p1 += im->Bands;
	}
}

/* Read a 16-bit RGB/RGBA image.
 */
static int
parse_rgb16( ReadTiff *rtiff, IMAGE *out )
{
	int bands;

	/* Check other TIFF fields to make sure we can read this. Can have 4
	 * bands for RGBA.
	 */
	if( !tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 16 ) ||
		!tfget16( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, &bands ) )
		return( -1 );
	if( bands != 3 && bands != 4 ) {
		im_error( "im_tiff2vips", _( "3 or 4 bands RGB TIFF only" ) );
		return( -1 );
	}

	out->Bands = bands; 
	out->Bbits = 16; 
	out->BandFmt = IM_BANDFMT_USHORT; 
	out->Coding = IM_CODING_NONE; 
	out->Type = IM_TYPE_RGB16; 

	rtiff->sfn = (scanline_process_fn) rgb16_line;
	rtiff->client = out;

	return( 0 );
}

/* Per-scanline process function for 32f.
 */
static void
r32f_line( PEL *q, PEL *p, int n, void *dummy )
{
	int x;
	float *p1 = (float *) p;
	float *q1 = (float *) q;

	for( x = 0; x < n; x++ ) {
		q1[0] = p1[0];
		q1[1] = p1[1];
		q1[2] = p1[2];

		q1 += 3;
		p1 += 3;
	}
}

/* Read a 32-bit float image. RGB or LAB, with or without alpha.
 */
static int
parse_32f( ReadTiff *rtiff, int pm, IMAGE *out )
{
	int bands;

	if( !tfget16( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, &bands ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 32 ) )
		return( -1 );

	/* Can be 4 for images with an alpha channel.
	 */
	assert( bands == 3 || bands == 4 );

	out->Bands = bands; 
	out->Bbits = 32; 
	out->BandFmt = IM_BANDFMT_FLOAT; 
	out->Coding = IM_CODING_NONE; 

	switch( pm ) {
	case PHOTOMETRIC_CIELAB:
		out->Type = IM_TYPE_LAB; 
		break;

	case PHOTOMETRIC_RGB:
		out->Type = IM_TYPE_sRGB; 
		break;

	default:
		assert( 0 );
	}

	rtiff->sfn = r32f_line;
	rtiff->client = NULL;

	return( 0 );
}

/* Per-scanline process function for CMYK8.
 */
static void
cmyk8_line( PEL *q, PEL *p, int n, void *dummy )
{
	int x;

	for( x = 0; x < n; x++ ) {
		q[0] = p[0];
		q[1] = p[1];
		q[2] = p[2];
		q[3] = p[3];

		q += 4;
		p += 4;
	}
}

/* Read a CMYK image.
 */
static int
parse_cmyk( ReadTiff *rtiff, IMAGE *out )
{
	if( !tfequals( rtiff->tiff, TIFFTAG_SAMPLESPERPIXEL, 4 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, 8 ) ||
		!tfequals( rtiff->tiff, TIFFTAG_INKSET, INKSET_CMYK ) )
		return( -1 );

	out->Bands = 4; 
	out->Bbits = 8; 
	out->BandFmt = IM_BANDFMT_UCHAR; 
	out->Coding = IM_CODING_NONE; 
	out->Type = IM_TYPE_CMYK; 

	rtiff->sfn = cmyk8_line;
	rtiff->client = NULL;

	return( 0 );
}

/* Read resolution from a TIFF image.
 */
static int
parse_resolution( TIFF *tiff, IMAGE *out )
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
			break;

		case RESUNIT_CENTIMETER:
			/* In pixels-per-centimetre ... convert to mm.
			 */
			x /= 10.0;
			y /= 10.0;
			break;

		default:
			im_error( "im_tiff2vips", 
				_( "unknown resolution unit" ) );
			return( -1 );
		}
	}
	else {
		im_warning( "im_tiff2vips: no resolution information for "
			"TIFF image \"%s\" -- defaulting to 1 pixel per mm", 
			TIFFFileName( tiff ) );
		x = 1.0;
		y = 1.0;
	}

	out->Xres = x;
	out->Yres = y;

	return( 0 );
}

/* Look at PhotometricInterpretation and BitsPerPixel, and try to figure out 
 * which of the image classes this is.
 */
static int
parse_header( ReadTiff *rtiff, IMAGE *out )
{
	int pm, bps, format;
	uint32 data_length;
	void *data;

	/* Ban separate planes, too annoying.
	 */
	if( tfexists( rtiff->tiff, TIFFTAG_PLANARCONFIG ) && 
		!tfequals( rtiff->tiff, 
			TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG ) ) 
		return( -1 );

	/* Always need dimensions.
	 */
	if( !tfget32( rtiff->tiff, TIFFTAG_IMAGEWIDTH, &out->Xsize ) ||
		!tfget32( rtiff->tiff, TIFFTAG_IMAGELENGTH, &out->Ysize ) ||
		parse_resolution( rtiff->tiff, out ) )
		return( -1 );

	/* Try to find out which type of TIFF image it is.
	 */
	if( !tfget16( rtiff->tiff, TIFFTAG_PHOTOMETRIC, &pm ) ||
		!tfget16( rtiff->tiff, TIFFTAG_BITSPERSAMPLE, &bps ) )
		return( -1 );

	switch( pm ) {
	case PHOTOMETRIC_CIELAB:
		switch( bps ) {
		case 8:
			if( parse_labpack( rtiff, out ) )
				return( -1 );
			break;

		case 16:
			if( parse_labs( rtiff, out ) )
				return( -1 );
			break;

		case 32:
			if( !tfget16( rtiff->tiff, 
				TIFFTAG_SAMPLEFORMAT, &format ) ) 
				return( -1 );

			if( format == SAMPLEFORMAT_IEEEFP ) {
				if( parse_32f( rtiff, pm, out ) )
					return( -1 );
			}
			else {
				im_error( "im_tiff2vips", 
					_( "unsupported sample "
					"format %d for lab image" ),
					format );
				return( -1 );
			}

			break;

		default:
			im_error( "im_tiff2vips", 
				_( "unsupported depth %d for LAB image" ), 
				bps );
			return( -1 );
		}

		break;

	case PHOTOMETRIC_YCBCR:
		/* Easy decision!
		 */
		if( parse_ycbcr( rtiff, out ) )
			return( -1 );

		break;

	case PHOTOMETRIC_MINISWHITE:
	case PHOTOMETRIC_MINISBLACK:
		switch( bps ) {
		case 1:
			if( parse_onebit( rtiff, pm, out ) )
				return( -1 );

			break;

		case 8:
			if( parse_greyscale8( rtiff, pm, out ) )
				return( -1 );

			break;

		case 16:
			if( parse_greyscale16( rtiff, pm, out ) )
				return( -1 );

			break;

		case 32:
			if( !tfget16( rtiff->tiff, 
				TIFFTAG_SAMPLEFORMAT, &format ) ) 
				return( -1 );

			if( format == SAMPLEFORMAT_IEEEFP ) {
				if( parse_greyscale32f( rtiff, pm, out ) )
					return( -1 );
			}
			else {
				im_error( "im_tiff2vips", 
					_( "unsupported sample format "
					"%d for greyscale image" ),
					format );
				return( -1 );
			}

			break;

		default:
			im_error( "im_tiff2vips", _( "unsupported depth %d "
				"for greyscale image" ), bps );
			return( -1 );
		}

		break;

	case PHOTOMETRIC_PALETTE:
		/* Full colour pallette.
		 */
		if( parse_palette( rtiff, out ) )
			return( -1 );

		break;

	case PHOTOMETRIC_RGB:
		/* Plain RGB.
		 */
		switch( bps ) {
		case 8:
			if( parse_rgb8( rtiff, out ) )
				return( -1 );
			break;

		case 16:
			if( parse_rgb16( rtiff, out ) )
				return( -1 );
			break;

		case 32:
			if( !tfget16( rtiff->tiff, 
				TIFFTAG_SAMPLEFORMAT, &format ) ) 
				return( -1 );

			if( format == SAMPLEFORMAT_IEEEFP ) {
				if( parse_32f( rtiff, pm, out ) )
					return( -1 );
			}
			else {
				im_error( "im_tiff2vips", 
					_( "unsupported sample "
					"format %d for rgb image" ),
					format );
				return( -1 );
			}

			break;

		default:
			im_error( "im_tiff2vips", _( "unsupported depth %d "
				"for RGB image" ), bps );
			return( -1 );
		}

		break;

	case PHOTOMETRIC_SEPARATED:
		if( parse_cmyk( rtiff, out ) )
			return( -1 );

		break;

	default:
		im_error( "im_tiff2vips", _( "unknown photometric "
			"interpretation %d" ), pm );
		return( -1 );
	}

	/* Read any ICC profile.
	 */
	if( TIFFGetField( rtiff->tiff, 
		TIFFTAG_ICCPROFILE, &data_length, &data ) ) {
		void *data_copy;

		if( !(data_copy = im_malloc( NULL, data_length )) ) 
			return( -1 );
		memcpy( data_copy, data, data_length );
		if( im_meta_set_blob( out, IM_META_ICC_NAME, 
			(im_callback_fn) im_free, data_copy, data_length ) ) {
			im_free( data_copy );
			return( -1 );
		}
	}

	return( 0 );
}

/* Allocate a tile buffer. Have one of these for each thread so we can unpack
 * to vips in parallel.
 */
static void *
seq_start( IMAGE *out, void *a, void *b )
{
	ReadTiff *rtiff = (ReadTiff *) a;
	tdata_t *buf;

	if( !(buf = im_malloc( NULL, TIFFTileSize( rtiff->tiff ) )) )
		return( NULL );

	return( (void *) buf );
}

/* Loop over the output region, painting in tiles from the file.
 */
static int
fill_region( REGION *out, void *seq, void *a, void *b )
{
	tdata_t *buf = (tdata_t *) seq;
	ReadTiff *rtiff = (ReadTiff *) a;
	Rect *r = &out->valid;

	/* Find top left of tiles we need.
	 */
	int xs = (r->left / rtiff->twidth) * rtiff->twidth;
	int ys = (r->top / rtiff->theight) * rtiff->theight;

	/* Sizeof a line of bytes in the TIFF tile.
	 */
	int tls = TIFFTileSize( rtiff->tiff ) / rtiff->theight;

	/* Sizeof a pel in the TIFF file. This won't work for formats which
	 * are <1 byte per pel, like onebit :-( Fortunately, it's only used
	 * to calculate addresses within a tile, and because we are wrapped in
	 * im_tile_cache(), we will never have to calculate positions within a
	 * tile.
	 */
	int tps = tls / rtiff->twidth;

	int x, y, z;

	for( y = ys; y < IM_RECT_BOTTOM( r ); y += rtiff->theight )
		for( x = xs; x < IM_RECT_RIGHT( r ); x += rtiff->twidth ) {
			Rect tile;
			Rect hit;

			/* Read that tile.
			 */
			g_mutex_lock( rtiff->tlock );
			if( TIFFReadTile( rtiff->tiff, buf, 
				x, y, 0, 0 ) < 0 ) {
				g_mutex_unlock( rtiff->tlock );
				return( -1 );
			}
			g_mutex_unlock( rtiff->tlock );

			/* The tile we read.
			 */
			tile.left = x;
			tile.top = y;
			tile.width = rtiff->twidth;
			tile.height = rtiff->twidth;

			/* The section that hits the region we are building.
			 */
			im_rect_intersectrect( &tile, r, &hit );

			/* Unpack to VIPS format. We can do this in parallel.
			 * Just unpack the section of the tile we need.
			 */
			for( z = 0; z < hit.height; z++ ) {
				PEL *p = (PEL *) buf +
					(hit.left - tile.left) * tps +
					(hit.top - tile.top + z) * tls;
				PEL *q = (PEL *) IM_REGION_ADDR( out, 
					hit.left, hit.top + z );

				rtiff->sfn( q, p, hit.width, rtiff->client );
			}
		}

	return( 0 );
}

static int
seq_stop( void *seq, void *a, void *b )
{
	im_free( seq );

	return( 0 );
}

/* Tile-type TIFF reader core - pass in a per-tile transform. Generate into
 * the im and do it all partially.
 */
static int
read_tilewise( ReadTiff *rtiff, IMAGE *out )
{
	IMAGE *raw;

	/* Tile cache: keep enough for two complete rows of tiles.
	 * This lets us do (smallish) area ops, like im_conv(), while
	 * still only hitting each TIFF tile once.
	 */
	if( !(raw = im_open_local( out, "cache", "p" )) )
		return( -1 );

	/* Get tiling geometry.
	 */
	if( !tfget32( rtiff->tiff, TIFFTAG_TILEWIDTH, &rtiff->twidth ) ||
		!tfget32( rtiff->tiff, TIFFTAG_TILELENGTH, &rtiff->theight ) )
		return( -1 );

	/* Make sure we can write PIO-style.
	 */
	if( im_poutcheck( raw ) )
		return( -1 );

	/* Parse the TIFF header and set up raw.
	 */
	if( parse_header( rtiff, raw ) )
		return( -1 );

	/* Process and save as VIPS.
	 */
	if( im_demand_hint( raw, IM_SMALLTILE, NULL ) ||
		im_generate( raw, 
			seq_start, fill_region, seq_stop, rtiff, NULL ) )
		return( -1 );

	/* Copy to out, adding a cache. Enough tiles for two complete rows.
	 */
	if( im_tile_cache( raw, out, 
		rtiff->twidth, rtiff->theight,
		2 * (1 + raw->Xsize / rtiff->twidth) ) ) 
		return( -1 );

	return( 0 );
}

/* Scanline-type TIFF reader core - pass in a per-scanline transform.
 */
static int
read_scanlinewise( ReadTiff *rtiff, IMAGE *out )
{
	PEL *vbuf;
	tdata_t tbuf;
	int y;

	if( parse_header( rtiff, out ) )
		return( -1 );

	/* Make sure we can write WIO-style.
	 */
	if( im_outcheck( out ) || im_setupout( out ) )
		return( -1 );

	/* Make VIPS output buffer.
	 */
	if( !(vbuf = IM_ARRAY( out, IM_IMAGE_SIZEOF_LINE( out ), PEL )) )
		return( -1 );

	/* Make TIFF line input buffer.
	 */
	if( !(tbuf = im_malloc( out, TIFFScanlineSize( rtiff->tiff ) )) ) 
		return( -1 );

	for( y = 0; y < out->Ysize; y++ ) {
		/* Read TIFF scanline.
		 */
		if( TIFFReadScanline( rtiff->tiff, tbuf, y, 0 ) < 0 ) {
			im_error( "im_tiff2vips", _( "read error" ) );
			return( -1 );
		}

		/* Process and save as VIPS.
		 */
		rtiff->sfn( vbuf, tbuf, out->Xsize, rtiff->client );
		if( im_writeline( y, out, vbuf ) ) 
			return( -1 );
	}

	return( 0 );
}

/* Free a ReadTiff.
 */
static int
readtiff_destroy( ReadTiff *rtiff )
{
	IM_FREEF( TIFFClose, rtiff->tiff );
	IM_FREEF( g_mutex_free, rtiff->tlock );

	return( 0 );
}

/* Make a ReadTiff.
 */
static ReadTiff *
readtiff_new( const char *filename, IMAGE *out )
{
	ReadTiff *rtiff;
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *p, *q;

	if( !(rtiff = IM_NEW( out, ReadTiff )) )
		return( NULL );
	rtiff->filename = NULL;
	rtiff->out = out;
	im_filename_split( filename, name, mode );
	rtiff->filename = im_strdup( out, name );
	rtiff->page = 0;
	rtiff->tiff = NULL;
	rtiff->sfn = NULL;
	rtiff->client = NULL;
	rtiff->twidth = 0;
	rtiff->theight = 0;
	rtiff->tlock = g_mutex_new();

	if( im_add_close_callback( out, 
		(im_callback_fn) readtiff_destroy, rtiff, NULL ) ) {
		readtiff_destroy( rtiff );
		return( NULL );
	}

	/* Parse out params.
	 */
	p = &mode[0];
	if( (q = im_getnextoption( &p )) ) {
		rtiff->page = atoi( q );

		if( rtiff->page < 0 || rtiff->page > 1000 ) {
			im_error( "im_tiff2vips", _( "bad page number %d" ),
				rtiff->page );
			return( NULL );
		}
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

	/* No need to use "b" and it means something different anyway.
	 */
	if( !(tif = TIFFOpen( filename, "r" )) ) {
		im_error( "im_tiff2vips", 
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

int
im_istiffpyramid( const char *name )
{
	TIFF *tif;

	TIFFSetErrorHandler( (TIFFErrorHandler) thandler_error );
	TIFFSetWarningHandler( (TIFFErrorHandler) thandler_warning );

	if( (tif = get_directory( name, 2 )) ) {
		/* We can see page 2 ... assume it is.
		 */
		TIFFClose( tif );
		return( 1 );
	}

	return( 0 );
}

int
im_tiff2vips( const char *filename, IMAGE *out )
{
	ReadTiff *rtiff;

#ifdef DEBUG
	printf( "im_tiff2vips: libtiff version is \"%s\"\n", TIFFGetVersion() );
#endif /*DEBUG*/

	TIFFSetErrorHandler( (TIFFErrorHandler) thandler_error );
	TIFFSetWarningHandler( (TIFFErrorHandler) thandler_warning );

	if( !(rtiff = readtiff_new( filename, out )) )
		return( -1 );

	if( !(rtiff->tiff = get_directory( rtiff->filename, rtiff->page )) ) {
		im_error( "im_tiff2vips", _( "TIFF file does not "
			"contain page %d" ), rtiff->page );
		return( -1 );
	}

	if( TIFFIsTiled( rtiff->tiff ) ) {
		if( read_tilewise( rtiff, out ) )
			return( -1 );
	}
	else {
		if( read_scanlinewise( rtiff, out ) )
			return( -1 );
	}

	return( 0 );
}

/* Just parse the header.
 */
int
im_tiff2vips_header( const char *filename, IMAGE *out )
{
	ReadTiff *rtiff;

	TIFFSetErrorHandler( (TIFFErrorHandler) thandler_error );
	TIFFSetWarningHandler( (TIFFErrorHandler) thandler_warning );

	if( !(rtiff = readtiff_new( filename, out )) )
		return( -1 );

	if( !(rtiff->tiff = get_directory( rtiff->filename, rtiff->page )) ) {
		im_error( "im_tiff2vips", 
			_( "TIFF file does not contain page %d" ), 
			rtiff->page );
		return( -1 );
	}

	if( parse_header( rtiff, out ) )
		return( -1 );

	return( 0 );
}

#endif /*HAVE_TIFF*/
