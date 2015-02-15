/* TIFF PARTS:
 * Copyright (c) 1988, 1990 by Sam Leffler.
 * All rights reserved.
 *
 * This file is provided for unrestricted use provided that this
 * legend is included on all tape media and as a part of the
 * software program in whole or part.  Users may copy, modify or
 * distribute this file at will.
 *
 * MODIFICATION FOR VIPS Copyright 1991, K.Martinez 
 *
 * software may be distributed FREE, with these copyright notices
 * no responsibility/warantee is implied or given
 *
 *
 * Modified and added im_LabQ2LabC() function. It can write IM_TYPE_LABQ image
 * in vips format  to LAB in tiff format.
 *  Copyright 1994 Ahmed Abbood.
 *
 * 19/9/95 JC
 *	- calls TIFFClose() more reliably
 *	- tidied up
 * 12/4/97 JC
 *	- thrown away and rewritten for TIFF 6 lib
 * 22/4/97 JC
 *	- writes a pyramid!
 *	- to separate TIFF files tho'
 * 23/4/97 JC
 *	- does 2nd gather pass to put pyramid into a single TIFF file
 *	- ... and shrinks IM_CODING_LABQ too
 * 26/10/98 JC
 *	- binary open for stupid systems
 * 7/6/99 JC
 *	- 16bit TIFF write too
 * 9/7/99 JC
 *	- ZIP tiff added
 * 11/5/00 JC
 *	- removed TIFFmalloc/TIFFfree
 * 5/8/00 JC
 *	- mode string now part of filename
 * 23/4/01 JC
 *	- HAVE_TIFF turns on TIFFness
 * 19/3/02 ruven
 *	- pyramid stops at tile size, not 64x64
 * 29/4/02 JC
 * 	- write any number of bands (but still with photometric RGB, so not
 * 	  very useful)
 * 10/9/02 JC
 *	- oops, handle TIFF errors better
 *	- now writes CMYK correctly
 * 13/2/03 JC
 *	- tries not to write mad resolutions
 * 7/5/03 JC
 *	- only write CMYK if Type == CMYK
 *	- writes EXTRASAMPLES ALPHA for bands == 2 or 4 (if we're writing RGB)
 * 17/11/03 JC
 *	- write float too
 * 28/11/03 JC
 *	- read via a "p" so we work from mmap window images
 *	- uses threadgroups for speedup
 * 9/3/04 JC
 *	- 1 bit write mode added
 * 5/4/04
 *	- better handling of edge tiles (thanks Ruven)
 * 18/5/04 Andrey Kiselev
 *	- added res_inch/res_cm option
 * 20/5/04 JC
 *	- allow single res number too
 * 19/7/04
 *	- write several scanlines at once, good speed up for some cases
 * 22/9/04
 *	- got rid of wrapper image so nip gets progress feedback 
 * 	- fixed tiny read-beyond-buffer issue for edge tiles
 * 7/10/04
 * 	- added ICC profile embedding
 * 13/12/04
 *	- can now pyramid any non-complex type (thanks Ruven)
 * 27/1/05
 *	- added ccittfax4 as a compression option
 * 9/3/05
 *	- set PHOTOMETRIC_CIELAB for vips TYPE_LAB images ... so we can write
 *	  float LAB as well as float RGB
 *	- also LABS images 
 * 22/6/05
 *	- 16 bit LAB write was broken
 * 9/9/05
 * 	- write any icc profile from meta 
 * 3/3/06
 * 	- raise tile buffer limit (thanks Ruven)
 * 11/11/06
 * 	- set ORIENTATION_TOPLEFT (thanks Josef)
 * 18/7/07 Andrey Kiselev
 * 	- remove "b" option on TIFFOpen()
 * 	- support TIFFTAG_PREDICTOR types for lzw and deflate compression
 * 3/11/07
 * 	- use im_wbuffer() for background writes
 * 15/2/08
 * 	- set TIFFTAG_JPEGQUALITY explicitly when we copy TIFF files, since 
 * 	  libtiff doesn't keep this in the header (thanks Joe)
 * 20/2/08
 * 	- use tiff error handler from im_tiff2vips.c
 * 27/2/08
 * 	- don't try to copy icc profiles when building pyramids (thanks Joe)
 * 9/4/08
 * 	- use IM_META_RESOLUTION_UNIT to set default resunit
 * 17/4/08
 * 	- allow CMYKA (thanks Doron)
 * 5/9/08
 *	- trigger eval callbacks during tile write
 * 4/2/10
 * 	- gtkdoc
 * 26/2/10
 * 	- option to turn on bigtiff output
 * 16/4/10
 * 	- use vips_sink_*() instead of threadgroup and friends
 * 22/6/10
 * 	- make no-owner regions for the tile cache, since we share these
 * 	  between threads
 * 12/7/11
 * 	- use im__temp_name() for intermediates rather than polluting the
 * 	  output directory
 * 5/9/11
 * 	- enable YCbCr compression for jpeg write
 * 23/11/11
 * 	- set reduced-resolution subfile type on pyramid layers
 * 2/12/11
 * 	- make into a simple function call ready to be wrapped as a new-style
 * 	  VipsForeign class
 * 21/3/12
 * 	- bump max layer buffer up
 * 2/6/12
 * 	- copy jpeg pyramid in gather in RGB mode ... tiff4 doesn't do ycbcr
 * 	  mode
 * 7/8/12
 * 	- be more cautious enabling YCbCr mode
 * 24/9/13
 * 	- support many more vips formats, eg. complex, 32-bit int, any number
 * 	  of bands, etc., see the tiff loader
 * 26/1/14
 * 	- add RGB as well as YCbCr write
 * 20/11/14
 * 	- cache input in tile write mode to keep us sequential
 * 3/12/14
 * 	- embed XMP in output
 * 10/12/14
 * 	- zero out edge tile buffers before jpeg write, thanks iwbh15
 * 19/1/15
 * 	- disable chroma subsample if Q >= 90
 * 13/2/15
 * 	- append later layers, don't copy the base image
 * 14/2/15
 * 	- use the nice dzsave pyramid code
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
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifdef HAVE_TIFF

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include <tiffio.h>

#include "tiff.h"

typedef struct pyramid_layer PyramidLayer;
typedef struct tiff_write TiffWrite;

/* A layer in the pyramid.
 */
struct pyramid_layer {
	TiffWrite *tw;			/* Main TIFF write struct */

	int width, height;		/* Layer size */
	int sub;			/* Subsample factor for this layer */
	char *lname;			/* Name of this TIFF file */
	TIFF *tif;			/* TIFF file we write this layer to */

	/* The image we build. We only keep a few scanlines of this around in
	 * @strip. 
	 */
	VipsImage *image;

	/* The y position of strip in image.
	 */
	int y;

	/* The next line we write to in strip. 
	 */
	int write_y;

	VipsRegion *strip;		/* The current strip of pixels */
	VipsRegion *copy;		/* Pixels we copy to the next strip */

	PyramidLayer *below;		/* The smaller layer below us */
	PyramidLayer *above;		/* The larger layer above */
};

/* A TIFF image in the process of being written.
 */
struct tiff_write {
	VipsImage *im;			/* Original input image */
	char *name;			/* Name we write to */

	PyramidLayer *layer;		/* Top of pyramid */
	VipsPel *tbuf;			/* TIFF output buffer */

	int compression;		/* Compression type */
	int jpqual;			/* JPEG q-factor */
	int predictor;			/* Predictor value */
	int tile;			/* Tile or not */
	int tilew, tileh;		/* Tile size */
	int pyramid;			/* Write pyramid */
	int onebit;			/* Write as 1-bit TIFF */
        int resunit;                    /* Resolution unit (inches or cm) */
        double xres;                   	/* Resolution in X */
        double yres;                   	/* Resolution in Y */
	char *icc_profile;		/* Profile to embed */
	int bigtiff;			/* True for bigtiff write */
	int rgbjpeg;			/* True for RGB not YCbCr */
};

/* Open TIFF for output.
 */
static TIFF *
tiff_openout( TiffWrite *tw, const char *name )
{
	TIFF *tif;
	const char *mode = tw->bigtiff ? "w8" : "w";

#ifdef DEBUG
	printf( "TIFFOpen( \"%s\", \"%s\" )\n", name, mode );
#endif /*DEBUG*/

	if( !(tif = TIFFOpen( name, mode )) ) {
		vips_error( "vips2tiff", 
			_( "unable to open \"%s\" for output" ), name );
		return( NULL );
	}

	return( tif );
}

/* Open TIFF for input.
 */
static TIFF *
tiff_openin( const char *name )
{
	TIFF *tif;

	if( !(tif = TIFFOpen( name, "r" )) ) {
		vips_error( "vips2tiff", 
			_( "unable to open \"%s\" for input" ), name );
		return( NULL );
	}

	return( tif );
}

/* Convert VIPS LabQ to TIFF LAB. Just take the first three bands.
 */
static void
LabQ2LabC( VipsPel *q, VipsPel *p, int n )
{
        int x;

        for( x = 0; x < n; x++ ) {
                /* Get most significant 8 bits of lab.
                 */
                q[0] = p[0];
                q[1] = p[1];
                q[2] = p[2];

                p += 4;
                q += 3;
        }
}

/* Pack 8 bit VIPS to 1 bit TIFF.
 */
static void
eightbit2onebit( VipsPel *q, VipsPel *p, int n )
{
        int x;
	VipsPel bits;

	bits = 0;
        for( x = 0; x < n; x++ ) {
		bits <<= 1;
		if( p[x] )
			bits |= 1;

		if( (x & 0x7) == 0x7 ) {
			*q++ = bits;
			bits = 0;
		}
        }

	/* Any left-over bits? Need to be left-aligned.
	 */
	if( (x & 0x7) != 0 ) 
		*q++ = bits << (8 - (x & 0x7));
}

/* Convert VIPS LABS to TIFF 16 bit LAB.
 */
static void
LabS2Lab16( VipsPel *q, VipsPel *p, int n )
{
        int x;
	short *p1 = (short *) p;
	unsigned short *q1 = (unsigned short *) q;

        for( x = 0; x < n; x++ ) {
                /* TIFF uses unsigned 16 bit ... move zero, scale up L.
                 */
                q1[0] = (int) p1[0] << 1;
                q1[1] = p1[1];
                q1[2] = p1[2];

                p1 += 3;
                q1 += 3;
        }
}

/* Pack a VIPS region into a TIFF tile buffer.
 */
static void
pack2tiff( TiffWrite *tw, VipsRegion *in, VipsPel *q, VipsRect *area )
{
	int y;

	/* JPEG compression can read outside the pixel area for edge tiles. It
	 * always compresses 8x8 blocks, so if the image width or height is
	 * not a multiple of 8, it can look beyond the pixels we will write.
	 *
	 * Black out the tile first to make sure these edge pixels are always
	 * zero.
	 */
	if( tw->compression == COMPRESSION_JPEG &&
		(area->width < tw->tilew || 
		 area->height < tw->tileh) )
		memset( q, 0, TIFFTileSize( tw->tif ) );

	for( y = area->top; y < VIPS_RECT_BOTTOM( area ); y++ ) {
		VipsPel *p = (VipsPel *) VIPS_REGION_ADDR( in, area->left, y );

		if( in->im->Coding == VIPS_CODING_LABQ )
			LabQ2LabC( q, p, area->width );
		else if( tw->onebit ) 
			eightbit2onebit( q, p, area->width );
		else if( in->im->BandFmt == VIPS_FORMAT_SHORT &&
			in->im->Type == VIPS_INTERPRETATION_LABS )
			LabS2Lab16( q, p, area->width );
		else
			memcpy( q, p, 
				area->width * VIPS_IMAGE_SIZEOF_PEL( in->im ) );

		q += tw->tls;
	}
}

/* Embed an ICC profile from a file.
 */
static int
embed_profile_file( TIFF *tif, const char *profile )
{
	char *buffer;
	size_t length;

	if( !(buffer = vips__file_read_name( profile, VIPS_ICC_DIR, &length )) )
		return( -1 );
	TIFFSetField( tif, TIFFTAG_ICCPROFILE, length, buffer );
	vips_free( buffer );

#ifdef DEBUG
	printf( "vips2tiff: attached profile \"%s\"\n", profile );
#endif /*DEBUG*/

	return( 0 );
}

/* Embed an ICC profile from VipsImage metadata.
 */
static int
embed_profile_meta( TIFF *tif, VipsImage *im )
{
	void *data;
	size_t data_length;

	if( vips_image_get_blob( im, VIPS_META_ICC_NAME, &data, &data_length ) )
		return( -1 );
	TIFFSetField( tif, TIFFTAG_ICCPROFILE, data_length, data );

#ifdef DEBUG
	printf( "vips2tiff: attached profile from meta\n" );
#endif /*DEBUG*/

	return( 0 );
}

static int
embed_profile( TiffWrite *tw, TIFF *tif )
{
	if( tw->icc_profile && 
		strcmp( tw->icc_profile, "none" ) != 0 &&
		embed_profile_file( tif, tw->icc_profile ) )
		return( -1 );

	if( !tw->icc_profile && 
		vips_image_get_typeof( tw->im, VIPS_META_ICC_NAME ) &&
		embed_profile_meta( tif, tw->im ) )
		return( -1 );

	return( 0 );
}

/* Embed any XMP metadata. 
 */
static int
embed_xmp( TiffWrite *tw, TIFF *tif )
{
	void *data;
	size_t data_length;

	if( !vips_image_get_typeof( tw->im, VIPS_META_XMP_NAME ) )
		return( 0 );
	if( vips_image_get_blob( tw->im, VIPS_META_XMP_NAME, 
		&data, &data_length ) )
		return( -1 );
	TIFFSetField( tif, TIFFTAG_XMLPACKET, data_length, data );

#ifdef DEBUG
	printf( "vips2tiff: attached XMP from meta\n" );
#endif /*DEBUG*/

	return( 0 );
}

/* Write a TIFF header. width and height are the size of the VipsImage we are
 * writing (it may have been shrunk).
 */
static int
write_tiff_header( TiffWrite *tw, PyramidLayer *layer )
{
	TIFF *tif = layer->tif;

	uint16 v[1];
	int format; 

	/* Output base header fields.
	 */
	TIFFSetField( tif, TIFFTAG_IMAGEWIDTH, layer->width );
	TIFFSetField( tif, TIFFTAG_IMAGELENGTH, layer->height );
	TIFFSetField( tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG );
	TIFFSetField( tif, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT );
	TIFFSetField( tif, TIFFTAG_COMPRESSION, tw->compression );

	if( tw->compression == COMPRESSION_JPEG ) 
		TIFFSetField( tif, TIFFTAG_JPEGQUALITY, tw->jpqual );

	if( tw->predictor != VIPS_FOREIGN_TIFF_PREDICTOR_NONE ) 
		TIFFSetField( tif, TIFFTAG_PREDICTOR, tw->predictor );

	/* Don't write mad resolutions (eg. zero), it confuses some programs.
	 */
	TIFFSetField( tif, TIFFTAG_RESOLUTIONUNIT, tw->resunit );
	TIFFSetField( tif, TIFFTAG_XRESOLUTION, 
		VIPS_CLIP( 0.01, tw->xres, 1000000 ) );
	TIFFSetField( tif, TIFFTAG_YRESOLUTION, 
		VIPS_CLIP( 0.01, tw->yres, 1000000 ) );

	if( embed_profile( tw, tif ) )
		return( -1 );
	if( embed_xmp( tw, tif ) )
		return( -1 );

	/* And colour fields.
	 */
	if( tw->im->Coding == VIPS_CODING_LABQ ) {
		TIFFSetField( tif, TIFFTAG_SAMPLESPERPIXEL, 3 );
		TIFFSetField( tif, TIFFTAG_BITSPERSAMPLE, 8 );
		TIFFSetField( tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_CIELAB );
	}
	else if( tw->onebit ) {
		TIFFSetField( tif, TIFFTAG_SAMPLESPERPIXEL, 1 );
		TIFFSetField( tif, TIFFTAG_BITSPERSAMPLE, 1 );
		TIFFSetField( tif, 
			TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK );
	}
	else {
		int photometric;

		TIFFSetField( tif, TIFFTAG_SAMPLESPERPIXEL, tw->im->Bands );
		TIFFSetField( tif, TIFFTAG_BITSPERSAMPLE, 
			vips_format_sizeof( tw->im->BandFmt ) << 3 );

		switch( tw->im->Bands ) {
		case 1:
		case 2:
			photometric = PHOTOMETRIC_MINISBLACK;
			if( tw->im->Bands == 2 ) {
				v[0] = EXTRASAMPLE_ASSOCALPHA;
				TIFFSetField( tif, TIFFTAG_EXTRASAMPLES, 1, v );
			}
			break;

		case 3:
		case 4:
			/* could be: RGB, RGBA, CMYK, LAB, LABA, generic
			 * multi-band image.
			 */
			if( tw->im->Type == VIPS_INTERPRETATION_LAB || 
				tw->im->Type == VIPS_INTERPRETATION_LABS ) 
				photometric = PHOTOMETRIC_CIELAB;
			else if( tw->im->Type == VIPS_INTERPRETATION_CMYK ) {
				photometric = PHOTOMETRIC_SEPARATED;
				TIFFSetField( tif, 
					TIFFTAG_INKSET, INKSET_CMYK );
			}
			else if( tw->compression == COMPRESSION_JPEG &&
				tw->im->Bands == 3 &&
				tw->im->BandFmt == VIPS_FORMAT_UCHAR &&
				(!tw->rgbjpeg && tw->jpqual < 90) ) { 
				/* This signals to libjpeg that it can do
				 * YCbCr chrominance subsampling from RGB, not
				 * that we will supply the image as YCbCr.
				 */
				photometric = PHOTOMETRIC_YCBCR;
				TIFFSetField( tif, TIFFTAG_JPEGCOLORMODE, 
					JPEGCOLORMODE_RGB );
			}
			else
				photometric = PHOTOMETRIC_RGB;

			if( tw->im->Type != VIPS_INTERPRETATION_CMYK && 
				tw->im->Bands == 4 ) {
				v[0] = EXTRASAMPLE_ASSOCALPHA;
				TIFFSetField( tif, TIFFTAG_EXTRASAMPLES, 1, v );
			}

			break;

		case 5:
			/* Only CMYKA
			 */
			photometric = PHOTOMETRIC_SEPARATED;
			TIFFSetField( tif, TIFFTAG_INKSET, INKSET_CMYK );
			v[0] = EXTRASAMPLE_ASSOCALPHA;
			TIFFSetField( tif, TIFFTAG_EXTRASAMPLES, 1, v );
			break;

		default:
			/* Who knows. Just call it RGB.
			 */
			photometric = PHOTOMETRIC_RGB;
			break; 
		}

		TIFFSetField( tif, TIFFTAG_PHOTOMETRIC, photometric );
	}

	/* Layout.
	 */
	if( tw->tile ) {
		TIFFSetField( tif, TIFFTAG_TILEWIDTH, tw->tilew );
		TIFFSetField( tif, TIFFTAG_TILELENGTH, tw->tileh );
	}
	else
		TIFFSetField( tif, TIFFTAG_ROWSPERSTRIP, 16 );
	if( tif != tw->tif ) {
		/* Pyramid layer.
		 */
		TIFFSetField( tif, TIFFTAG_SUBFILETYPE, FILETYPE_REDUCEDIMAGE );
	}

	/* Sample format.
	 */
	format = SAMPLEFORMAT_UINT;
	if( vips_band_format_isuint( tw->im->BandFmt ) )
		format = SAMPLEFORMAT_UINT;
	else if( vips_band_format_isint( tw->im->BandFmt ) )
		format = SAMPLEFORMAT_INT;
	else if( vips_band_format_isfloat( tw->im->BandFmt ) )
		format = SAMPLEFORMAT_IEEEFP;
	else if( vips_band_format_iscomplex( tw->im->BandFmt ) )
		format = SAMPLEFORMAT_COMPLEXIEEEFP;

	TIFFSetField( tif, TIFFTAG_SAMPLEFORMAT, format );

	return( 0 );
}

/* Free a pyramid layer.
 */
static void
free_layer( PyramidLayer *layer )
{
	VIPS_FREE( layer->lname );

	VIPS_UNREF( layer->strip );
	VIPS_UNREF( layer->copy );
	VIPS_UNREF( layer->image );

	VIPS_FREEF( TIFFClose, layer->tif );
}

/* Free an entire pyramid.
 */
static void
free_pyramid( PyramidLayer *layer )
{
	if( layer->below ) 
		free_pyramid( layer->below );

	free_layer( layer );
}

static PyramidLayer *
build_pyramid( TiffWrite *tw, PyramidLayer *above, int width, int height )
{
	PyramidLayer *layer;
	int i;

	layer = VIPS_NEW( tw->im, PyramidLayer );
	layer->tw = tw;
	layer->width = width;
	layer->height = height; 

	if( !above )
		/* Top of pyramid.
		 */
		layer->sub = 1;	
	else
		layer->sub = above->sub * 2;

	layer->lname = NULL;
	layer->tif = NULL;
	layer->image = NULL;
	layer->write_y = 0;
	layer->y = 0;
	layer->strip = NULL;
	layer->copy = NULL;

	layer->below = NULL;
	layer->above = above;

	if( tw->pyramid )
		if( layer->width > tw->tilew || 
			layer->height > tw->tileh ) 
			layer->below = build_pyramid( tw, layer, 
				width / 2, height / 2 );

	return( layer );
}

	if( !(layer->lname = vips__temp_name( "%s.tif" )) )
		return( -1 );

	if( !(layer->tif = tiff_openout( tw, layer->lname )) ) 
		return( -1 );

	if( write_tiff_header( tw, layer ) )
		return( -1 );

	return( 0 );
}

/* Write a tile from a layer.
 */
static int
save_tile( TiffWrite *tw, 
	TIFF *tif, VipsPel *tbuf, VipsRegion *reg, VipsRect *area )
{
	/* Have to repack pixels.
	 */
	pack2tiff( tw, reg, tbuf, area );

#ifdef DEBUG_VERBOSE
	printf( "Writing %dx%d pixels at position %dx%d to image %s\n",
		tw->tilew, tw->tileh, area->left, area->top,
		TIFFFileName( tif ) );
#endif /*DEBUG_VERBOSE*/

	/* Write to TIFF! easy.
	 */
	if( TIFFWriteTile( tif, tbuf, area->left, area->top, 0, 0 ) < 0 ) {
		vips_error( "vips2tiff", "%s", _( "TIFF write tile failed" ) );
		return( -1 );
	}

	return( 0 );
}

/* A new tile has arrived! Shrink into this layer, if we fill a region, write
 * it and recurse.
 */
static int
new_tile( PyramidLayer *layer, VipsRegion *tile, VipsRect *area )
{
	TiffWrite *tw = layer->tw;
	int xoff, yoff;

	int t, ri, bo;
	VipsRect out, new;
	PyramidBits bit;

	/* Calculate pos and size of new pixels we make inside this layer.
	 */
	new.left = area->left / 2;
	new.top = area->top / 2;
	new.width = area->width / 2;
	new.height = area->height / 2;

	/* Has size fallen to zero? Can happen if this is a one-pixel-wide
	 * strip.
	 */
	if( vips_rect_isempty( &new ) )
		return( 0 );

	/* Offset into this tile ... ie. which quadrant we are writing.
	 */
	xoff = new.left % layer->tw->tilew;
	yoff = new.top % layer->tw->tileh;

	/* Calculate pos for tile we shrink into in this layer.
	 */
	out.left = new.left - xoff;
	out.top = new.top - yoff;

	/* Clip against edge of image.
	 */
	ri = VIPS_MIN( layer->width, out.left + layer->tw->tilew );
	bo = VIPS_MIN( layer->height, out.top + layer->tw->tileh );
	out.width = ri - out.left;
	out.height = bo - out.top;

	if( (t = find_tile( layer, &out )) < 0 )
		return( -1 );

	/* Shrink into place.
	 */
	if( tw->im->Coding == VIPS_CODING_NONE )
		shrink_region( tile, area, 
			layer->tiles[t].tile, xoff, yoff );
	else
		shrink_region_labpack( tile, area, 
			layer->tiles[t].tile, xoff, yoff );

	/* Set that bit.
	 */
	if( xoff )
		if( yoff )
			bit = PYR_BR;
		else
			bit = PYR_TR;
	else
		if( yoff )
			bit = PYR_BL;
		else
			bit = PYR_TL;
	if( layer->tiles[t].bits & bit ) {
		vips_error( "vips2tiff", 
			"%s", _( "internal error #9876345" ) );
		return( -1 );
	}
	layer->tiles[t].bits |= bit;

	if( layer->tiles[t].bits == PYR_ALL ) {
		/* Save this complete tile.
		 */
		if( save_tile( tw, layer->tif, layer->tbuf, 
			layer->tiles[t].tile, &layer->tiles[t].tile->valid ) )
			return( -1 );

		/* And recurse down the pyramid!
		 */
		if( layer->below &&
			new_tile( layer->below, 
				layer->tiles[t].tile, 
				&layer->tiles[t].tile->valid ) )
			return( -1 );
	}

	return( 0 );
}

/* Write as tiles. This is called by vips_sink_tile() for every tile
 * generated.
 */
static int
write_tif_tile( VipsRegion *out, void *seq, void *a, void *b, gboolean *stop )
{
	TiffWrite *tw = (TiffWrite *) a;

	g_mutex_lock( tw->write_lock );

	/* Write to TIFF.
	 */
	if( save_tile( tw, tw->tif, tw->tbuf, out, &out->valid ) ) {
		g_mutex_unlock( tw->write_lock );
		return( -1 );
	}

	/* Is there a pyramid? Write to that too.
	 */
	if( tw->layer && 
		new_tile( tw->layer, out, &out->valid ) ) {
		g_mutex_unlock( tw->write_lock );
		return( -1 );
	}

	g_mutex_unlock( tw->write_lock );

	return( 0 );
}

/* Write as tiles.
 */
static int
write_tif_tilewise( TiffWrite *tw )
{
	VipsImage *im = tw->im;

	/* Double check: buffers should match in size, except for onebit and
	 * labq modes.  
	 */
{
	size_t vips_tile_size = 
		VIPS_IMAGE_SIZEOF_PEL( im ) * tw->tilew * tw->tileh; 

	if( tw->im->Coding != VIPS_CODING_LABQ &&
		!tw->onebit &&
		TIFFTileSize( tw->tif ) != vips_tile_size ) { 
		vips_error( "vips2tiff", 
			"%s", _( "unsupported image format" ) );
		return( -1 );
	}
}

	g_assert( !tw->tbuf );
	if( !(tw->tbuf = vips_malloc( NULL, TIFFTileSize( tw->tif ) )) ) 
		return( -1 );

	g_assert( !tw->write_lock );
	tw->write_lock = vips_g_mutex_new();

	if( vips_sink_tile( im, tw->tilew, tw->tileh,
		NULL, write_tif_tile, NULL, tw, NULL ) ) 
		return( -1 );

	return( 0 );
}

static int
write_tif_block( VipsRegion *region, VipsRect *area, void *a )
{
	TiffWrite *tw = (TiffWrite *) a;
	VipsImage *im = tw->im;

	int y;

	for( y = 0; y < area->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( region, 0, area->top + y );

		/* Any repacking necessary.
		 */
		if( im->Coding == VIPS_CODING_LABQ ) {
			LabQ2LabC( tw->tbuf, p, im->Xsize );
			p = tw->tbuf;
		}
		else if( im->BandFmt == VIPS_FORMAT_SHORT &&
			im->Type == VIPS_INTERPRETATION_LABS ) {
			LabS2Lab16( tw->tbuf, p, im->Xsize );
			p = tw->tbuf;
		}
		else if( tw->onebit ) {
			eightbit2onebit( tw->tbuf, p, im->Xsize );
			p = tw->tbuf;
		}

		if( TIFFWriteScanline( tw->tif, p, area->top + y, 0 ) < 0 ) 
			return( -1 );
	}

	return( 0 );
}

/* Write as scan-lines.
 */
static int
write_tif_stripwise( TiffWrite *tw )
{
	g_assert( !tw->tbuf );

	/* Double check: buffers should match in size, except for onebit and
	 * labq modes.  
	 */
	if( tw->im->Coding != VIPS_CODING_LABQ &&
		!tw->onebit &&
		TIFFScanlineSize( tw->tif ) != 
			VIPS_IMAGE_SIZEOF_LINE( tw->im ) ) { 
		vips_error( "vips2tiff", 
			"%s", _( "unsupported image format" ) );
		return( -1 );
	}

	if( !(tw->tbuf = vips_malloc( NULL, TIFFScanlineSize( tw->tif ) )) ) 
		return( -1 );

	if( vips_sink_disc( tw->im, write_tif_block, tw ) )
		return( -1 );

	return( 0 );
}






static int strip_arrived( Layer *layer );

/* Shrink what pixels we can from this strip into the layer below. If the
 * strip below fills, recurse.
 */
static int
strip_shrink( Layer *layer )
{
	VipsForeignSaveDz *dz = layer->dz;
	VipsForeignSave *save = VIPS_FOREIGN_SAVE( dz );
	Layer *below = layer->below;
	VipsRegion *from = layer->strip;
	VipsRegion *to = below->strip;

	VipsRect target;
	VipsRect source;

	/* We may have an extra column of pixels on the right or
	 * bottom that need filling: generate them.
	 */
	layer_generate_extras( layer );

	/* Our pixels might cross a strip boundary in the layer below, so we
	 * have to write repeatedly until we run out of pixels.
	 */
	for(;;) {
		/* The pixels the layer below needs.
		 */
		target.left = 0;
		target.top = below->write_y;
		target.width = below->image->Xsize;
		target.height = to->valid.height;
		vips_rect_intersectrect( &target, &to->valid, &target );

		/* Those pixels need this area of this layer. 
		 */
		source.left = target.left * 2;
		source.top = target.top * 2;
		source.width = target.width * 2;
		source.height = target.height * 2;

		/* Of which we have these available.
		 */
		vips_rect_intersectrect( &source, &from->valid, &source );

		/* So these are the pixels in the layer below we can provide.
		 */
		target.left = source.left / 2;
		target.top = source.top / 2;
		target.width = source.width / 2;
		target.height = source.height / 2;

		/* None? All done.
		 */
		if( vips_rect_isempty( &target ) ) 
			break;

		(void) vips_region_shrink( from, to, &target );

		below->write_y += target.height;

		/* If we've filled the strip below, let it know.
		 * We can either fill the region, if it's somewhere half-way
		 * down the image, or, if it's at the bottom, get to the last
		 * real line of pixels.
		 */
		if( below->write_y == VIPS_RECT_BOTTOM( &to->valid ) ||
			below->write_y == below->height ) {
			if( strip_arrived( below ) )
				return( -1 );
		}
	}

	return( 0 );
}

/* A new strip has arrived! The strip has at least enough pixels in to 
 * write a line of tiles or a set of scanlines.  
 *
 * - write a line of tiles / set of scanlines
 * - shrink what we can to the layer below
 * - move our strip down by the tile height
 * - copy the overlap with the previous strip
 */
static int
strip_arrived( PyramidLayer *layer )
{
	TiffWrite *tw = layer->tw;

	VipsRect new_strip;
	VipsRect overlap;

	if( strip_save( layer ) )
		return( -1 );

	if( layer->below &&
		strip_shrink( layer ) )
		return( -1 );

	/* Position our strip down the image.  
	 *
	 * Expand the strip if necessary to make sure we have an even 
	 * number of lines. 
	 */
	layer->y += tw->tileh;
	new_strip.left = 0;
	new_strip.top = layer->y;
	new_strip.width = layer->image->Xsize;
	new_strip.height = tw->tileh;
	if( (new_strip.height & 1) == 1 )
		new_strip.height += 1;

	/* What pixels that we will need do we already have? Save them in 
	 * overlap.
	 */
	vips_rect_intersectrect( &new_strip, &layer->strip->valid, &overlap );
	if( !vips_rect_isempty( &overlap ) ) {
		if( vips_region_buffer( layer->copy, &overlap ) )
			return( -1 );
		vips_region_copy( layer->strip, layer->copy, 
			&overlap, overlap.left, overlap.top );
	}

	if( vips_region_buffer( layer->strip, &new_strip ) )
		return( -1 );

	/* And copy back again.
	 */
	if( !vips_rect_isempty( &overlap ) ) 
		vips_region_copy( layer->copy, layer->strip, 
			&overlap, overlap.left, overlap.top );

	return( 0 );
}

/* Another strip of image pixels from vips_sink_disc(). Write into the top
 * pyramid layer. 
 */
static int
write_strip( VipsRegion *region, VipsRect *area, void *a )
{
	TiffWrite *tw = (TiffWrite *) a;
	PyramidLayer *layer = tw->layer; 

#ifdef DEBUG
	printf( "write_strip: strip at %d, height %d\n", 
		area->top, area->height );
#endif/*DEBUG*/

	for(;;) {
		VipsRect *to = &layer->strip->valid;
		VipsRect target;

		/* The bit of strip that needs filling.
		 */
		target.left = 0;
		target.top = layer->write_y;
		target.width = layer->image->Xsize;
		target.height = to->height;
		vips_rect_intersectrect( &target, to, &target );

		/* Clip against what we have available.
		 */
		vips_rect_intersectrect( &target, area, &target );

		/* Are we empty? All done.
		 */
		if( vips_rect_isempty( &target ) ) 
			break;

		/* And copy those pixels in.
		 *
		 * FIXME: If the strip fits inside the region we've just 
		 * received, we could skip the copy. Will this happen very
		 * often? Unclear.
		 */
		vips_region_copy( region, layer->strip, 
			&target, target.left, target.top );

		layer->write_y += target.height;

		/* We can either fill the strip, if it's somewhere half-way
		 * down the image, or, if it's at the bottom, get to the last
		 * real line of pixels.
		 */
		if( layer->write_y == VIPS_RECT_BOTTOM( to ) ||
			layer->write_y == layer->height ) {
			if( strip_arrived( layer ) ) 
				return( -1 );
		}
	}

	return( 0 );
}

/* Delete any temp files we wrote.
 */
static void
delete_files( TiffWrite *tw )
{
	PyramidLayer *layer;

	for( layer = tw->layer; layer; layer = layer->below ) 
		if( layer->lname ) {
#ifndef DEBUG
			unlink( layer->lname );
#else
			printf( "delete_files: leaving %s\n", layer->lname );
#endif /*DEBUG*/

			layer->lname = NULL;
		}
}

/* Free a TiffWrite.
 */
static void
free_tiff_write( TiffWrite *tw )
{
	delete_files( tw );

	VIPS_FREEF( TIFFClose, tw->tif );
	VIPS_FREEF( vips_free, tw->tbuf );
	VIPS_FREEF( vips_g_mutex_free, tw->write_lock );
	VIPS_FREEF( free_pyramid, tw->layer );
	VIPS_UNREF( tw->cache );
	VIPS_FREEF( vips_free, tw->icc_profile );
}

/* Round N down to P boundary. 
 */
#define ROUND_DOWN(N,P) ((N) - ((N) % P)) 

/* Round N up to P boundary. 
 */
#define ROUND_UP(N,P) (ROUND_DOWN( (N) + (P) - 1, (P) ))

static int
get_compression( VipsForeignTiffCompression compression )
{
	switch( compression ) {
	case VIPS_FOREIGN_TIFF_COMPRESSION_NONE:
		return( COMPRESSION_NONE );
	case VIPS_FOREIGN_TIFF_COMPRESSION_JPEG:
		return( COMPRESSION_JPEG );
	case VIPS_FOREIGN_TIFF_COMPRESSION_DEFLATE:
		return( COMPRESSION_ADOBE_DEFLATE );
	case VIPS_FOREIGN_TIFF_COMPRESSION_PACKBITS:
		return( COMPRESSION_PACKBITS );
	case VIPS_FOREIGN_TIFF_COMPRESSION_CCITTFAX4:
		return( COMPRESSION_CCITTFAX4 );
	case VIPS_FOREIGN_TIFF_COMPRESSION_LZW:
		return( COMPRESSION_LZW );
	
	default:
		g_assert( 0 );
	}

	/* Keep -Wall happy.
	 */
	return( -1 );
}

static int
get_resunit( VipsForeignTiffResunit resunit )
{
	switch( resunit ) {
	case VIPS_FOREIGN_TIFF_RESUNIT_CM:
		return( RESUNIT_CENTIMETER );
	case VIPS_FOREIGN_TIFF_RESUNIT_INCH:
		return( RESUNIT_INCH );

	default:
		g_assert( 0 );
	}

	/* Keep -Wall happy.
	 */
	return( -1 );
}

/* Make and init a TiffWrite.
 */
static TiffWrite *
make_tiff_write( VipsImage *im, const char *filename,
	VipsForeignTiffCompression compression, int Q, 
		VipsForeignTiffPredictor predictor,
	char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	gboolean squash,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg )
{
	TiffWrite *tw;

	if( !(tw = VIPS_NEW( im, TiffWrite )) )
		return( NULL );
	tw->im = im;
	tw->name = vips_strdup( VIPS_OBJECT( im ), filename );
	tw->tif = NULL;
	tw->layer = NULL;
	tw->tbuf = NULL;
	tw->compression = get_compression( compression );
	tw->jpqual = Q;
	tw->predictor = predictor;
	tw->tile = tile;
	tw->tilew = tile_width;
	tw->tileh = tile_height;
	tw->pyramid = pyramid;
	tw->onebit = squash;
	tw->icc_profile = profile;
	tw->bigtiff = bigtiff;
	tw->rgbjpeg = rgbjpeg;
	tw->write_lock = NULL;
	tw->cache = NULL;

	tw->resunit = get_resunit( resunit );
	tw->xres = xres;
	tw->yres = yres;

	if( (tw->tilew & 0xf) != 0 || 
		(tw->tileh & 0xf) != 0 ) {
		vips_error( "vips2tiff", 
			"%s", _( "tile size not a multiple of 16" ) );
		return( NULL );
	}

	if( !tw->tile && tw->pyramid ) {
		vips_warn( "vips2tiff", 
			"%s", _( "can't have strip pyramid -- "
			"enabling tiling" ) );
		tw->tile = 1;
	}

	/* We can only pyramid LABQ and non-complex images. 
	 */
	if( tw->pyramid ) {
		if( im->Coding == VIPS_CODING_NONE && 
			vips_band_format_iscomplex( im->BandFmt ) ) {
			vips_error( "vips2tiff", 
				"%s", _( "can only pyramid LABQ and "
				"non-complex images" ) );
			return( NULL );
		}
	}

	/* Only 1-bit-ize 8 bit mono images.
	 */
	if( tw->onebit &&
		(im->Coding != VIPS_CODING_NONE || 
			im->BandFmt != VIPS_FORMAT_UCHAR ||
			im->Bands != 1) ) {
		vips_warn( "vips2tiff", 
			"%s", _( "can only squash 1 band uchar images -- "
				"disabling squash" ) );
		tw->onebit = 0;
	}

	if( tw->onebit && 
		tw->compression == COMPRESSION_JPEG ) {
		vips_warn( "vips2tiff", 
			"%s", _( "can't have 1-bit JPEG -- disabling JPEG" ) );
		tw->compression = COMPRESSION_NONE;
	}

	/* Sizeof a line of bytes in the TIFF tile.
	 */
	if( im->Coding == VIPS_CODING_LABQ )
		tw->tls = tw->tilew * 3;
	else if( tw->onebit )
		tw->tls = ROUND_UP( tw->tilew, 8 ) / 8;
	else
		tw->tls = VIPS_IMAGE_SIZEOF_PEL( im ) * tw->tilew;

	/* We always need at least a base layer.
	 */
	tw->layer = build_pyramid( tw, NULL, im->Xsize, im->Ysize );

	return( tw );
}

/* Copy fields.
 */
#define CopyField( tag, v ) \
	if( TIFFGetField( in, tag, &v ) ) TIFFSetField( out, tag, v )

/* Copy a TIFF file ... we know we wrote it, so just copy the tags we know 
 * we might have set.
 */
static int
tiff_copy( TiffWrite *tw, TIFF *out, TIFF *in )
{
	uint32 i32;
	uint16 i16;
	float f;
	tdata_t buf;
	ttile_t tile;
	ttile_t n;

	/* All the fields we might have set.
	 */
	CopyField( TIFFTAG_IMAGEWIDTH, i32 );
	CopyField( TIFFTAG_IMAGELENGTH, i32 );
	CopyField( TIFFTAG_PLANARCONFIG, i16 );
	CopyField( TIFFTAG_ORIENTATION, i16 );
	CopyField( TIFFTAG_XRESOLUTION, f );
	CopyField( TIFFTAG_YRESOLUTION, f );
	CopyField( TIFFTAG_RESOLUTIONUNIT, i16 );
	CopyField( TIFFTAG_COMPRESSION, i16 );
	CopyField( TIFFTAG_SAMPLESPERPIXEL, i16 );
	CopyField( TIFFTAG_BITSPERSAMPLE, i16 );
	CopyField( TIFFTAG_PHOTOMETRIC, i16 );
	CopyField( TIFFTAG_TILEWIDTH, i32 );
	CopyField( TIFFTAG_TILELENGTH, i32 );
	CopyField( TIFFTAG_ROWSPERSTRIP, i32 );
	CopyField( TIFFTAG_SUBFILETYPE, i32 );

	if( tw->predictor != VIPS_FOREIGN_TIFF_PREDICTOR_NONE ) 
		TIFFSetField( out, TIFFTAG_PREDICTOR, tw->predictor );

	/* TIFFTAG_JPEGQUALITY is a pesudo-tag, so we can't copy it.
	 * Set explicitly from TiffWrite.
	 */
	if( tw->compression == COMPRESSION_JPEG ) {
		TIFFSetField( out, TIFFTAG_JPEGQUALITY, tw->jpqual );

		/* Only for three-band, 8-bit images.
		 */
		if( tw->im->Bands == 3 &&
			tw->im->BandFmt == VIPS_FORMAT_UCHAR ) { 
			/* Enable rgb->ycbcr conversion in the jpeg write. 
			 */
			if( !tw->rgbjpeg &&
				tw->jpqual < 90 ) 
				TIFFSetField( out, 
					TIFFTAG_JPEGCOLORMODE, 
						JPEGCOLORMODE_RGB );

			/* And we want ycbcr expanded to rgb on read. Otherwise
			 * TIFFTileSize() will give us the size of a chrominance
			 * subsampled tile.
			 */
			TIFFSetField( in, 
				TIFFTAG_JPEGCOLORMODE, JPEGCOLORMODE_RGB );
		}
	}

	/* We can't copy profiles or xmp :( Set again from TiffWrite.
	 */
	if( embed_profile( tw, out ) )
		return( -1 );
	if( embed_xmp( tw, out ) )
		return( -1 );

	buf = vips_malloc( NULL, TIFFTileSize( in ) );
	n = TIFFNumberOfTiles( in );
	for( tile = 0; tile < n; tile++ ) {
		tsize_t len;

		/* It'd be good to use TIFFReadRawTile()/TIFFWriteRawTile() 
		 * here to save compression/decompression, but sadly it seems
		 * not to work :-( investigate at some point.
		 */
		len = TIFFReadEncodedTile( in, tile, buf, -1 );
		if( len < 0 ||
			TIFFWriteEncodedTile( out, tile, buf, len ) < 0 ) {
			vips_free( buf );
			return( -1 );
		}
	}
	vips_free( buf );

	return( 0 );
}

/* Append all of the lower layers we wrote to the output.
 */
static int
gather_pyramid( TiffWrite *tw )
{
	PyramidLayer *layer;

	for( layer = tw->layer; layer; layer = layer->below ) {
		TIFF *in;

#ifdef DEBUG
		printf( "Appending layer %s ...\n", layer->lname );
#endif /*DEBUG*/

		if( !(in = tiff_openin( layer->lname )) ) 
			return( -1 );

		if( tiff_copy( tw, tw->tif, in ) ) {
			TIFFClose( in );
			return( -1 );
		}
		TIFFClose( in );

		if( !TIFFWriteDirectory( tw->tif ) ) 
			return( -1 );
	}

	return( 0 );
}

int 
vips__tiff_write( VipsImage *in, const char *filename, 
	VipsForeignTiffCompression compression, int Q, 
		VipsForeignTiffPredictor predictor,
	char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	gboolean squash,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg )
{
	TiffWrite *tw;
	PyramidLayer *layer;
	int res;

#ifdef DEBUG
	printf( "tiff2vips: libtiff version is \"%s\"\n", TIFFGetVersion() );
#endif /*DEBUG*/

	vips__tiff_init();

	if( vips_check_coding_known( "vips2tiff", in ) )
		return( -1 );

	/* Make output image. 
	 */
	if( !(tw = make_tiff_write( in, filename,
		compression, Q, predictor, profile,
		tile, tile_width, tile_height, pyramid, squash,
		resunit, xres, yres, bigtiff, rgbjpeg )) )
		return( -1 );
	layer = tw->layer;
	layer->lname = g_strdup( filename );

	if( !(layer->tif = tiff_openout( tw, layer->lname )) ||
		write_tiff_header( tw, layer ) ||
		vips_sink_disc( tw->im, write_strip, tw ) ) {
		free_tiff_write( tw );
		return( -1 );
	}

	if( tw->pyramid ) { 
		if( !TIFFWriteDirectory( layer->tif ) ) 
			return( -1 );

		/* Free lower pyramid resources ... this will TIFFClose() the 
		 * smaller layers ready for us to read from them again.
		 */
		free_pyramid( layer->below );

		/* Append smaller layers to the main file.
		 */
		if( gather_pyramid( tw ) ) {
			free_tiff_write( tw );
			return( -1 );
		}
	}

	free_tiff_write( tw );

	return( 0 );
}

#endif /*HAVE_TIFF*/
