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
 * 	- zero out edge tile buffers before jpeg wtiff, thanks iwbh15
 * 19/1/15
 * 	- disable chroma subsample if Q >= 90
 * 13/2/15
 * 	- append later layers, don't copy the base image
 * 	- use the nice dzsave pyramid code, much faster and simpler
 * 	- we now allow strip pyramids
 * 27/3/15
 * 	- squash >128 rather than >0, nicer results for shrink
 * 	- add miniswhite option
 * 29/9/15
 * 	- try to write IPTC metadata
 * 	- try to write photoshop metadata
 * 11/11/15
 * 	- better alpha handling, thanks sadaqatullahn
 * 21/12/15
 * 	- write TIFFTAG_IMAGEDESCRIPTION
 * 2/6/16
 * 	- support strip option
 * 4/7/16
 * 	- tag alpha as UNASSALPHA since it's not pre-multiplied, thanks Peter
 * 17/8/16
 * 	- use wchar_t TIFFOpen on Windows
 * 14/10/16
 * 	- add buffer output
 * 29/1/17
 * 	- enable bigtiff automatically for large, uncompressed writes, thanks 
 * 	  AndreasSchmid1 
 * 26/8/17
 * 	- support pyramid creation to buffer, thanks bubba
 * 24/10/17
 * 	- no error on page-height not a factor of image height, just don't
 * 	  write multipage
 * 13/6/18
 * 	- add region_shrink
 * 2/7/18
 * 	- copy EXTRASAMPLES to pyramid layers
 * 21/12/18
 * 	- stop pyr layers if width or height drop to 1
 * 8/7/19
 * 	- add webp and zstd support
 * 	- add @level and @lossless
 * 18/12/19
 * 	- "squash" now squashes 3-band float LAB down to LABQ
 * 26/1/20
 * 	- add "depth" to set pyr depth
 * 27/1/20
 * 	- write XYZ images as logluv
 * 7/2/20 [jclavoie-jive]
 * 	- add PAGENUMBER support
 * 23/5/20
 * 	- add support for subifd pyramid layers
 * 6/6/20 MathemanFlo
 * 	- add bitdepth support for 2 and 4 bit greyscale images
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

#include "pforeign.h"
#include "tiff.h"

/* TODO:
 *
 * - add a flag for plane-separate write
 *
 *   	At the moment, we write bioformats-style TIFFs by splitting bands up,
 *   	making a toilet-roll image and writing out in pages. The TIFFs we make
 *   	are not tagged as plane-separate and do not have (eg.) RGB photometric
 *   	interpretation. Moreover, when working from an RGB source, we'll end
 *   	up reading the input three times.
 *
 *   	A write-plane-separate flag to the TIFF writer could let us set the
 *   	photometric interpretation correctly, and save all planes in a single
 *   	pass before doing a final gather sweep.
 */

/* Max number of alpha channels we allow.
 */
#define MAX_ALPHA (64)

/* Bioformats uses this tag for lossy jp2k compressed tiles.
 */
#define JP2K_LOSSY 33004

/* Compression types we handle ourselves.
 */
static int wtiff_we_compress[] = {
	JP2K_LOSSY
};

typedef struct _Layer Layer;
typedef struct _Wtiff Wtiff;

/* A layer in the pyramid.
 */
struct _Layer {
	Wtiff *wtiff;			/* Main wtiff struct */

	/* The filename for this layer, for file output.
	 */
	char *lname;			

	/* The memory area for this layer, for memory output.
	 */
	void *buf;
	size_t len;

	int width, height;		/* Layer size */
	int sub;			/* Subsample factor for this layer */
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

	Layer *below;			/* The smaller layer below us */
	Layer *above;			/* The larger layer above */
};

/* A TIFF image in the process of being written.
 */
struct _Wtiff {
	VipsImage *input;		/* Original input image */

	/* Image transformed ready for write.
	 */
	VipsImage *ready;

	/* File to write to, or NULL.
	 */
	char *filename;			/* Name we write to */

	/* Memory area to output, or NULL.
	 */
	void **obuf;
	size_t *olen; 

	Layer *layer;			/* Top of pyramid */
	VipsPel *tbuf;			/* TIFF output buffer */
	int tls;			/* Tile line size */

	int compression;		/* libtiff compression type */
	int Q;				/* JPEG q-factor, webp level */
	int predictor;			/* libtiff predictor type */
	int tile;			/* Tile or not */
	int tilew, tileh;		/* Tile size */
	int pyramid;			/* Wtiff pyramid */
	int bitdepth;                   /* Write as 1, 2 or 4 bit */
	int miniswhite;			/* Wtiff as 0 == white */
        int resunit;                    /* Resolution unit (inches or cm) */
        double xres;                   	/* Resolution in X */
        double yres;                   	/* Resolution in Y */
	const char *profile;		/* Profile to embed */
	int bigtiff;			/* True for bigtiff write */
	int rgbjpeg;			/* True for RGB not YCbCr */
	int properties;			/* Set to save XML props */
	int strip;			/* Don't write metadata */
	VipsRegionShrink region_shrink; /* How to shrink regions */
	int level;			/* zstd compression level */
	gboolean lossless;		/* lossless mode */
	VipsForeignDzDepth depth;	/* Pyr depth */
	gboolean subifd;		/* Write pyr layers into subifds */
	gboolean premultiply;		/* Premultiply alpha */

	/* True if we've detected a toilet-roll image, plus the page height,
	 * which has been checked to be a factor of im->Ysize. page_number
	 * starts at zero and ticks up as we write each page.
	 */
	gboolean toilet_roll;
	int page_height;
	int page_number;
	int n_pages;

	/* The height of the TIFF we write. Equal to page_height in toilet
	 * roll mode.
	 */
	int image_height;

	/* TRUE if the compression type is not supported by libtiff directly
	 * and we must compress ourselves. 
	 */
	gboolean we_compress;

	/* If we are copying, we need a buffer to read the compressed tile to.
	 */
	tdata_t compressed_buf;
	tsize_t compressed_buf_length;
};

/* Write an ICC Profile from a file into the JPEG stream.
 */
static int
embed_profile_file( TIFF *tif, const char *profile )
{
	VipsBlob *blob;

	if( vips_profile_load( profile, &blob, NULL ) )
		return( -1 );

	if( blob ) {
		size_t length;
		const void *data = vips_blob_get( blob, &length );

		TIFFSetField( tif, TIFFTAG_ICCPROFILE, length, data );

#ifdef DEBUG
		printf( "vips2tiff: attached profile \"%s\"\n", profile );
#endif /*DEBUG*/

		vips_area_unref( (VipsArea *) blob );
	}

	return( 0 );
}

/* Embed an ICC profile from VipsImage metadata.
 */
static int
embed_profile_meta( TIFF *tif, VipsImage *im )
{
	const void *data;
	size_t length;

	if( vips_image_get_blob( im, VIPS_META_ICC_NAME, &data, &length ) )
		return( -1 );
	TIFFSetField( tif, TIFFTAG_ICCPROFILE, length, data );

#ifdef DEBUG
	printf( "vips2tiff: attached profile from meta\n" );
#endif /*DEBUG*/

	return( 0 );
}

static void
wtiff_layer_init( Wtiff *wtiff, Layer **layer, Layer *above, 
	int width, int height )
{
	if( !*layer ) {
		*layer = VIPS_NEW( wtiff->ready, Layer );
		(*layer)->wtiff = wtiff;
		(*layer)->width = width;
		(*layer)->height = height; 

		if( !above )
			/* Top of pyramid.
			 */
			(*layer)->sub = 1;	
		else
			(*layer)->sub = above->sub * 2;

		(*layer)->lname = NULL;
		(*layer)->buf = NULL;
		(*layer)->len = 0;
		(*layer)->tif = NULL;
		(*layer)->image = NULL;
		(*layer)->write_y = 0;
		(*layer)->y = 0;
		(*layer)->strip = NULL;
		(*layer)->copy = NULL;

		(*layer)->below = NULL;
		(*layer)->above = above;

		/* The name for the top layer is the output filename.
		 *
		 * We need lname to be freed automatically: it has to stay 
		 * alive until after wtiff_gather().
		 */
		if( wtiff->filename ) { 
			if( !above ) 
				(*layer)->lname = vips_strdup( 
					VIPS_OBJECT( wtiff->ready ),
					wtiff->filename );
			else {
				char *lname;

				lname = vips__temp_name( "%s.tif" );
				(*layer)->lname = vips_strdup( 
					VIPS_OBJECT( wtiff->ready ),
					lname );
				g_free( lname );
			}
		}

		/*
		printf( "wtiff_layer_init: sub = %d, width = %d, height = %d\n",
			(*layer)->sub, width, height );
		 */
	}

	if( wtiff->pyramid ) {
		int limitw, limith;

		switch( wtiff->depth ) {
		case VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL:
			limitw = limith = 1;
			break;

		case VIPS_FOREIGN_DZ_DEPTH_ONETILE:
			limitw = wtiff->tilew;
			limith = wtiff->tileh;
			break;

		case VIPS_FOREIGN_DZ_DEPTH_ONE:
			limitw = wtiff->ready->Xsize;
			limith = wtiff->ready->Ysize;
			break;

		default:
			g_assert_not_reached();
		}

		/* We make another layer if the image is too large to fit in a
		 * single tile, and if neither axis is greater than 1.
		 *
		 * Very tall or wide images might end up with a smallest layer
		 * larger than one tile.
		 */
		if( ((*layer)->width > limitw || 
			(*layer)->height > limith) && 
		 	(*layer)->width > 1 && 
		 	(*layer)->height > 1 ) 
			wtiff_layer_init( wtiff, &(*layer)->below, *layer, 
				width / 2, height / 2 );
	}
}

static int
wtiff_embed_profile( Wtiff *wtiff, TIFF *tif )
{
	if( wtiff->profile &&
		embed_profile_file( tif, wtiff->profile ) )
		return( -1 );

	if( !wtiff->profile && 
		vips_image_get_typeof( wtiff->ready, VIPS_META_ICC_NAME ) &&
		embed_profile_meta( tif, wtiff->ready ) )
		return( -1 );

	return( 0 );
}

static int
wtiff_embed_xmp( Wtiff *wtiff, TIFF *tif )
{
	const void *data;
	size_t size;

	if( !vips_image_get_typeof( wtiff->ready, VIPS_META_XMP_NAME ) )
		return( 0 );
	if( vips_image_get_blob( wtiff->ready, VIPS_META_XMP_NAME, 
		&data, &size ) )
		return( -1 );
	TIFFSetField( tif, TIFFTAG_XMLPACKET, size, data );

#ifdef DEBUG
	printf( "vips2tiff: attached XMP from meta\n" );
#endif /*DEBUG*/

	return( 0 );
}

static int
wtiff_embed_iptc( Wtiff *wtiff, TIFF *tif )
{
	const void *data;
	size_t size;

	if( !vips_image_get_typeof( wtiff->ready, VIPS_META_IPTC_NAME ) )
		return( 0 );
	if( vips_image_get_blob( wtiff->ready, VIPS_META_IPTC_NAME, 
		&data, &size ) )
		return( -1 );

	/* For no very good reason, libtiff stores IPTC as an array of
	 * long, not byte.
	 */
	if( size & 3 ) {
		g_warning( "%s", _( "rounding up IPTC data length" ) );
		size /= 4;
		size += 1;
	}
	else
		size /= 4;

	TIFFSetField( tif, TIFFTAG_RICHTIFFIPTC, size, data );

#ifdef DEBUG
	printf( "vips2tiff: attached IPTC from meta\n" );
#endif /*DEBUG*/

	return( 0 );
}

static int
wtiff_embed_photoshop( Wtiff *wtiff, TIFF *tif )
{
	const void *data;
	size_t size;

	if( !vips_image_get_typeof( wtiff->ready, VIPS_META_PHOTOSHOP_NAME ) )
		return( 0 );
	if( vips_image_get_blob( wtiff->ready, VIPS_META_PHOTOSHOP_NAME, 
		&data, &size ) )
		return( -1 );
	TIFFSetField( tif, TIFFTAG_PHOTOSHOP, size, data );

#ifdef DEBUG
	printf( "vips2tiff: attached photoshop data from meta\n" );
#endif /*DEBUG*/

	return( 0 );
}

/* Set IMAGEDESCRIPTION, if it's there.  If @properties is TRUE, set from
 * vips' metadata.
 */
static int
wtiff_embed_imagedescription( Wtiff *wtiff, TIFF *tif )
{
	if( wtiff->properties ) {
		char *doc;

		if( !(doc = vips__xml_properties( wtiff->ready )) )
			return( -1 );
		TIFFSetField( tif, TIFFTAG_IMAGEDESCRIPTION, doc );
		g_free( doc );
	}
	else {
		const char *imagedescription;

		if( !vips_image_get_typeof( wtiff->ready,
			VIPS_META_IMAGEDESCRIPTION ) )
			return( 0 );
		if( vips_image_get_string( wtiff->ready,
			VIPS_META_IMAGEDESCRIPTION, &imagedescription ) )
			return( -1 );
		TIFFSetField( tif, TIFFTAG_IMAGEDESCRIPTION, imagedescription );
	}

#ifdef DEBUG
	printf( "vips2tiff: attached imagedescription from meta\n" );
#endif /*DEBUG*/

	return( 0 );
}

/* Write a TIFF header for this layer. 
 */
static int
wtiff_write_header( Wtiff *wtiff, Layer *layer )
{
	TIFF *tif = layer->tif;

	int i;
	int orientation; 

#ifdef DEBUG
	printf( "wtiff_write_header: sub %d, width %d, height %d\n",
		layer->sub, layer->width, layer->height );
#endif /*DEBUG*/

	/* Output base header fields.
	 */
	TIFFSetField( tif, TIFFTAG_IMAGEWIDTH, layer->width );
	TIFFSetField( tif, TIFFTAG_IMAGELENGTH, layer->height );
	TIFFSetField( tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG );
	TIFFSetField( tif, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT );
	TIFFSetField( tif, TIFFTAG_COMPRESSION, wtiff->compression );

	if( wtiff->compression == COMPRESSION_JPEG ) 
		TIFFSetField( tif, TIFFTAG_JPEGQUALITY, wtiff->Q );

#ifdef HAVE_TIFF_COMPRESSION_WEBP
	if( wtiff->compression == COMPRESSION_WEBP ) {
		TIFFSetField( tif, TIFFTAG_WEBP_LEVEL, wtiff->Q );
		TIFFSetField( tif, TIFFTAG_WEBP_LOSSLESS, wtiff->lossless );
	}
	if( wtiff->compression == COMPRESSION_ZSTD ) {
		TIFFSetField( tif, TIFFTAG_ZSTD_LEVEL, wtiff->level );
		if( wtiff->predictor != VIPS_FOREIGN_TIFF_PREDICTOR_NONE ) 
			TIFFSetField( tif, 
				TIFFTAG_PREDICTOR, wtiff->predictor );
	}
#endif /*HAVE_TIFF_COMPRESSION_WEBP*/

	if( (wtiff->compression == COMPRESSION_ADOBE_DEFLATE ||
		wtiff->compression == COMPRESSION_LZW) &&
		wtiff->predictor != VIPS_FOREIGN_TIFF_PREDICTOR_NONE ) 
		TIFFSetField( tif, TIFFTAG_PREDICTOR, wtiff->predictor );

	for( i = 0; i < VIPS_NUMBER( wtiff_we_compress ); i++ )
		if( wtiff->compression == wtiff_we_compress[i] ) {
			wtiff->we_compress = TRUE;
			break;
		}

	/* Don't write mad resolutions (eg. zero), it confuses some programs.
	 */
	TIFFSetField( tif, TIFFTAG_RESOLUTIONUNIT, wtiff->resunit );
	TIFFSetField( tif, TIFFTAG_XRESOLUTION, 
		VIPS_FCLIP( 0.01, wtiff->xres, 1000000 ) );
	TIFFSetField( tif, TIFFTAG_YRESOLUTION, 
		VIPS_FCLIP( 0.01, wtiff->yres, 1000000 ) );

	if( !wtiff->strip ) 
		if( wtiff_embed_profile( wtiff, tif ) ||
			wtiff_embed_xmp( wtiff, tif ) ||
			wtiff_embed_iptc( wtiff, tif ) ||
			wtiff_embed_photoshop( wtiff, tif ) ||
			wtiff_embed_imagedescription( wtiff, tif ) )
			return( -1 ); 

	if( vips_image_get_typeof( wtiff->ready, VIPS_META_ORIENTATION ) &&
		!vips_image_get_int( wtiff->ready, 
			VIPS_META_ORIENTATION, &orientation ) )
		TIFFSetField( tif, TIFFTAG_ORIENTATION, orientation );

	/* And colour fields.
	 */
	if( wtiff->ready->Coding == VIPS_CODING_LABQ ) {
		TIFFSetField( tif, TIFFTAG_SAMPLESPERPIXEL, 3 );
		TIFFSetField( tif, TIFFTAG_BITSPERSAMPLE, 8 );
		TIFFSetField( tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_CIELAB );
	}
	else if( wtiff->bitdepth == 1 || wtiff->bitdepth == 2 ||
                 wtiff->bitdepth == 4 ) {
		TIFFSetField( tif, TIFFTAG_SAMPLESPERPIXEL, 1 );
		TIFFSetField( tif, TIFFTAG_BITSPERSAMPLE, wtiff->bitdepth );
		TIFFSetField( tif, TIFFTAG_PHOTOMETRIC,
			wtiff->miniswhite ?
				PHOTOMETRIC_MINISWHITE :
				PHOTOMETRIC_MINISBLACK );
	}
	else {
		int photometric;

		/* Number of bands that have colour in .. other bands are saved
		 * as alpha.
		 */
		int colour_bands;

		int alpha_bands;

		TIFFSetField( tif, TIFFTAG_SAMPLESPERPIXEL, 
			wtiff->ready->Bands );
		TIFFSetField( tif, TIFFTAG_BITSPERSAMPLE, 
			vips_format_sizeof( wtiff->ready->BandFmt ) << 3 );

		if( wtiff->ready->Type == VIPS_INTERPRETATION_B_W ||
			wtiff->ready->Type == VIPS_INTERPRETATION_GREY16 ||
			wtiff->ready->Bands < 3 ) { 
			/* Mono or mono + alpha.
			 */
			photometric = wtiff->miniswhite ?
				PHOTOMETRIC_MINISWHITE :
				PHOTOMETRIC_MINISBLACK;
			colour_bands = 1;
		}
		else if( wtiff->ready->Type == VIPS_INTERPRETATION_LAB || 
			wtiff->ready->Type == VIPS_INTERPRETATION_LABS ) {
			photometric = PHOTOMETRIC_CIELAB;
			colour_bands = 3;
		}
		else if( wtiff->input->Type == VIPS_INTERPRETATION_XYZ ) { 
			double stonits;

			photometric = PHOTOMETRIC_LOGLUV;
			/* Tell libtiff we will write as float XYZ.
			 */
			TIFFSetField( tif, 
				TIFFTAG_SGILOGDATAFMT, SGILOGDATAFMT_FLOAT );
			stonits = 1.0;
			if( vips_image_get_typeof( wtiff->ready, "stonits" ) )
				vips_image_get_double( wtiff->ready, 
					"stonits", &stonits );
			TIFFSetField( tif, TIFFTAG_STONITS, stonits );
			colour_bands = 3;
		}
		else if( wtiff->ready->Type == VIPS_INTERPRETATION_CMYK &&
			wtiff->ready->Bands >= 4 ) {
			photometric = PHOTOMETRIC_SEPARATED;
			TIFFSetField( tif, TIFFTAG_INKSET, INKSET_CMYK );
			colour_bands = 4;
		}
		else if( wtiff->compression == COMPRESSION_JPEG &&
			wtiff->ready->Bands == 3 &&
			wtiff->ready->BandFmt == VIPS_FORMAT_UCHAR &&
			(!wtiff->rgbjpeg && wtiff->Q < 90) ) { 
			/* This signals to libjpeg that it can do
			 * YCbCr chrominance subsampling from RGB, not
			 * that we will supply the image as YCbCr.
			 */
			photometric = PHOTOMETRIC_YCBCR;
			TIFFSetField( tif, TIFFTAG_JPEGCOLORMODE, 
				JPEGCOLORMODE_RGB );
			colour_bands = 3;
		}
		else {
			/* Some kind of generic multi-band image with three or
			 * more bands ... save the first three bands as RGB, 
			 * the rest as alpha.
			 */
			photometric = PHOTOMETRIC_RGB;
			colour_bands = 3;
		}

		alpha_bands = VIPS_CLIP( 0, 
			wtiff->ready->Bands - colour_bands, MAX_ALPHA );
		if( alpha_bands > 0 ) { 
			uint16 v[MAX_ALPHA];
			int i;

			/* EXTRASAMPLE_UNASSALPHA means generic extra
			 * alpha-like channels. ASSOCALPHA means pre-multipled
			 * alpha only. 
			 *
			 * Make the first channel the premultiplied alpha, if
			 * we are premultiplying.
			 */
			for( i = 0; i < alpha_bands; i++ )
				v[i] = i == 0 && wtiff->premultiply ? 
					EXTRASAMPLE_ASSOCALPHA :
					EXTRASAMPLE_UNASSALPHA;
			TIFFSetField( tif, 
				TIFFTAG_EXTRASAMPLES, alpha_bands, v );
		}

		TIFFSetField( tif, TIFFTAG_PHOTOMETRIC, photometric );
	}

	/* Layout.
	 */
	if( wtiff->tile ) {
		TIFFSetField( tif, TIFFTAG_TILEWIDTH, wtiff->tilew );
		TIFFSetField( tif, TIFFTAG_TILELENGTH, wtiff->tileh );
	}
	else
		TIFFSetField( tif, TIFFTAG_ROWSPERSTRIP, wtiff->tileh );

	if( layer->above ) 
		/* Pyramid layer.
		 */
		TIFFSetField( tif, TIFFTAG_SUBFILETYPE, FILETYPE_REDUCEDIMAGE );

	if( wtiff->toilet_roll ) {
		/* One page of many.
		 */
		TIFFSetField( tif, TIFFTAG_SUBFILETYPE, FILETYPE_PAGE );

		TIFFSetField( tif, TIFFTAG_PAGENUMBER, 
			wtiff->page_number, wtiff->n_pages );
	}

	/* Sample format.
	 *
	 * Don't set for logluv: libtiff does this for us.
	 */
	if( wtiff->input->Type != VIPS_INTERPRETATION_XYZ ) { 
		int format; 

		format = SAMPLEFORMAT_UINT;
		if( vips_band_format_isuint( wtiff->ready->BandFmt ) )
			format = SAMPLEFORMAT_UINT;
		else if( vips_band_format_isint( wtiff->ready->BandFmt ) )
			format = SAMPLEFORMAT_INT;
		else if( vips_band_format_isfloat( wtiff->ready->BandFmt ) )
			format = SAMPLEFORMAT_IEEEFP;
		else if( vips_band_format_iscomplex( wtiff->ready->BandFmt ) )
			format = SAMPLEFORMAT_COMPLEXIEEEFP;
		TIFFSetField( tif, TIFFTAG_SAMPLEFORMAT, format );
	}

	return( 0 );
}

static int
wtiff_layer_rewind( Wtiff *wtiff, Layer *layer )
{
	VipsRect strip_size;

	/* Build a line of tiles here. 
	 *
	 * Expand the strip if necessary to make sure we have an even 
	 * number of lines. 
	 */
	strip_size.left = 0;
	strip_size.top = 0;
	strip_size.width = layer->image->Xsize;
	strip_size.height = wtiff->tileh;
	if( (strip_size.height & 1) == 1 )
		strip_size.height += 1;
	if( vips_region_buffer( layer->strip, &strip_size ) ) 
		return( -1 );

	layer->y = 0;
	layer->write_y = 0;

	return( 0 );
}

static int
wtiff_allocate_layers( Wtiff *wtiff )
{
	Layer *layer;

	g_assert( wtiff->layer );

	for( layer = wtiff->layer; layer; layer = layer->below ) {
		if( !layer->image ) {
			layer->image = vips_image_new();
			if( vips_image_pipelinev( layer->image, 
				VIPS_DEMAND_STYLE_ANY, wtiff->ready, NULL ) ) 
				return( -1 );
			layer->image->Xsize = layer->width;
			layer->image->Ysize = layer->height;

			layer->strip = vips_region_new( layer->image );
			layer->copy = vips_region_new( layer->image );

			/* The regions will get used in the bg thread callback,
			 * so make sure we don't own them.
			 */
			vips__region_no_ownership( layer->strip );
			vips__region_no_ownership( layer->copy );

			if( layer->lname ) 
				layer->tif = vips__tiff_openout( 
					layer->lname, wtiff->bigtiff );
			else {
				layer->tif = vips__tiff_openout_buffer( 
					wtiff->ready, wtiff->bigtiff, 
					&layer->buf, &layer->len );
			}
			if( !layer->tif ) 
				return( -1 );
		}

		if( wtiff_layer_rewind( wtiff, layer ) )
			return( -1 ); 

		if( wtiff_write_header( wtiff, layer ) )  
			return( -1 );
	}

	if( !wtiff->tbuf ) { 
		if( wtiff->tile ) 
			wtiff->tbuf = vips_malloc( NULL, 
				TIFFTileSize( wtiff->layer->tif ) );
		else
			wtiff->tbuf = vips_malloc( NULL, 
				TIFFScanlineSize( wtiff->layer->tif ) );
		if( !wtiff->tbuf ) 
			return( -1 );
	}

	/* If we will be copying layers we need a buffer large enough to hold
	 * the largest compressed tile in any page.
	 *
	 * Allocate a buffer 2x the uncompressed tile size ... much simpler
	 * than searching every page for the largest tile with
	 * TIFFTAG_TILEBYTECOUNTS.
	 */
	if( wtiff->pyramid ) {
		wtiff->compressed_buf_length = 2 * wtiff->tls * wtiff->tileh;
		if( !(wtiff->compressed_buf = vips_malloc( NULL,
			wtiff->compressed_buf_length )) )
			return( -1 );
	}

	return( 0 );
}

/* Delete any temp files we wrote.
 */
static void
wtiff_delete_temps( Wtiff *wtiff )
{
	Layer *layer;

	/* Don't delete the top layer: that's the output file.
	 */
	if( wtiff->layer &&
		wtiff->layer->below )
		for( layer = wtiff->layer->below; layer; layer = layer->below ) 
			if( layer->lname ) {
#ifndef DEBUG
				unlink( layer->lname );
				VIPS_FREE( layer->buf );
#else
				printf( "wtiff_delete_temps: leaving %s\n", 
					layer->lname );
#endif /*DEBUG*/

				layer->lname = NULL;
			}
}

/* Free a single pyramid layer.
 */
static void
layer_free( Layer *layer )
{
	VIPS_UNREF( layer->strip );
	VIPS_UNREF( layer->copy );
	VIPS_UNREF( layer->image );
	VIPS_FREE( layer->buf );
	VIPS_FREEF( TIFFClose, layer->tif );
}

/* Free an entire pyramid.
 */
static void
layer_free_all( Layer *layer )
{
	if( layer->below ) 
		layer_free_all( layer->below );

	layer_free( layer );
}

static void
wtiff_free( Wtiff *wtiff )
{
	wtiff_delete_temps( wtiff );
	VIPS_UNREF( wtiff->ready );
	VIPS_FREE( wtiff->tbuf );
	VIPS_FREEF( layer_free_all, wtiff->layer );
	VIPS_FREE( wtiff->filename );
	VIPS_FREE( wtiff->compressed_buf );
	VIPS_FREE( wtiff );
}

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
#ifdef HAVE_TIFF_COMPRESSION_WEBP
	case VIPS_FOREIGN_TIFF_COMPRESSION_WEBP:
		return( COMPRESSION_WEBP );
	case VIPS_FOREIGN_TIFF_COMPRESSION_ZSTD:
		return( COMPRESSION_ZSTD );
#endif /*HAVE_TIFF_COMPRESSION_WEBP*/
	case VIPS_FOREIGN_TIFF_COMPRESSION_JP2K:
		return( JP2K_LOSSY );
	
	default:
		return( COMPRESSION_NONE );
	}
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
		g_assert_not_reached();
	}

	/* Keep -Wall happy.
	 */
	return( -1 );
}

/* Get the image ready to be written.
 */
static int
ready_to_write( Wtiff *wtiff )
{
	VipsImage *input;
	VipsImage *x;

	input = wtiff->input;
	g_object_ref( input );

	if( vips_check_coding_known( "vips2tiff", input ) ) {
		VIPS_UNREF( input );
		return( -1 );
	}

	/* Premultiply any alpha, if necessary.
	 */
	if( wtiff->premultiply &&
		vips_image_hasalpha( input ) ) {
		VipsBandFormat start_format = input->BandFmt;

		if( vips_premultiply( input, &x, NULL ) ) {
			VIPS_UNREF( input );
			return( -1 );
		}
		VIPS_UNREF( input );
		input = x;

		/* Premultiply always makes a float -- cast back again.
		 */
		if( vips_cast( input, &x, start_format, NULL ) ) {
			VIPS_UNREF( input );
			return( -1 );
		}
		VIPS_UNREF( input );
		input = x;
	}

	/* "squash" float LAB down to LABQ.
	 */
	if( wtiff->bitdepth &&
		input->Bands == 3 &&
		input->BandFmt == VIPS_FORMAT_FLOAT &&
		input->Type == VIPS_INTERPRETATION_LAB ) {
		if( vips_Lab2LabQ( input, &x, NULL ) ) {
			VIPS_UNREF( input );
			return( -1 );
		}
		VIPS_UNREF( input );
		input = x;
	}

	wtiff->ready = input;

	return( 0 );
}

static Wtiff *
wtiff_new( VipsImage *input, const char *filename, 
	VipsForeignTiffCompression compression, int Q, 
	VipsForeignTiffPredictor predictor,
	const char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	int bitdepth,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties,
	gboolean strip,
	VipsRegionShrink region_shrink,
	int level, 
	gboolean lossless,
	VipsForeignDzDepth depth, 
	gboolean subifd,
	gboolean premultiply )
{
	Wtiff *wtiff;

	if( !(wtiff = VIPS_NEW( NULL, Wtiff )) )
		return( NULL );
	wtiff->input = input;
	wtiff->ready = NULL;
	wtiff->filename = filename ? vips_strdup( NULL, filename ) : NULL;
	wtiff->layer = NULL;
	wtiff->tbuf = NULL;
	wtiff->compression = get_compression( compression );
	wtiff->Q = Q;
	wtiff->predictor = predictor;
	wtiff->tile = tile;
	wtiff->tilew = tile_width;
	wtiff->tileh = tile_height;
	wtiff->pyramid = pyramid;
	wtiff->bitdepth = bitdepth;
	wtiff->miniswhite = miniswhite;
	wtiff->resunit = get_resunit( resunit );
	wtiff->xres = xres;
	wtiff->yres = yres;
	wtiff->profile = profile;
	wtiff->bigtiff = bigtiff;
	wtiff->rgbjpeg = rgbjpeg;
	wtiff->properties = properties;
	wtiff->strip = strip;
	wtiff->region_shrink = region_shrink;
	wtiff->level = level;
	wtiff->lossless = lossless;
	wtiff->depth = depth;
	wtiff->subifd = subifd;
	wtiff->premultiply = premultiply;
	wtiff->toilet_roll = FALSE;
	wtiff->page_height = vips_image_get_page_height( input );
	wtiff->page_number = 0;
	wtiff->n_pages = 1;
	wtiff->image_height = input->Ysize;

	/* Any pre-processing on the image.
	 */
	if( ready_to_write( wtiff ) ) {
		wtiff_free( wtiff );
		return( NULL );
	}

	/* XYZ images are written as libtiff LOGLUV.
	 */
	if( wtiff->ready->Type == VIPS_INTERPRETATION_XYZ ) 
		wtiff->compression = COMPRESSION_SGILOG;

	/* Multipage image?
	 */
	if( wtiff->page_height < wtiff->ready->Ysize ) {
#ifdef DEBUG
		printf( "wtiff_new: detected toilet roll image, "
			"page-height=%d\n", 
			wtiff->page_height );
		printf( "wtiff_new: pages=%d\n", 
			wtiff->ready->Ysize / wtiff->page_height );
#endif/*DEBUG*/

		wtiff->toilet_roll = TRUE;
		wtiff->image_height = wtiff->page_height;
		wtiff->n_pages = wtiff->ready->Ysize / wtiff->page_height;
	}

	/* We can only pyramid LABQ and non-complex images. 
	 */
	if( wtiff->pyramid ) {
		if( wtiff->ready->Coding == VIPS_CODING_NONE && 
			vips_band_format_iscomplex( wtiff->ready->BandFmt ) ) {
			wtiff_free( wtiff );
			vips_error( "vips2tiff", 
				"%s", _( "can only pyramid LABQ and "
				"non-complex images" ) );
			return( NULL );
		}
	}

	/* Pyramid images must be tiled.
	 */
	if( wtiff->pyramid &&
		!wtiff->tile )
		wtiff->tile = TRUE;

	/* Multi-page pyramids must be in subifd mode.
	 */
	if( wtiff->pyramid &&
		wtiff->toilet_roll )
		wtiff->subifd = TRUE;

	/* If compression is off and we're writing a >4gb image, automatically
	 * enable bigtiff.
	 *
	 * This won't always work. If the image data is just under 4gb but
	 * there's a lot of metadata, we could be pushed over the 4gb limit.
	 */
	if( wtiff->compression == COMPRESSION_NONE &&
		VIPS_IMAGE_SIZEOF_IMAGE( wtiff->ready ) > UINT_MAX )
		wtiff->bigtiff = TRUE;

	/* In strip mode we use tileh to set rowsperstrip, and that does not
	 * have the multiple-of-16 restriction.
	 */
	if( wtiff->tile ) { 
		if( (wtiff->tilew & 0xf) != 0 || 
			(wtiff->tileh & 0xf) != 0 ) {
			wtiff_free( wtiff );
			vips_error( "vips2tiff", 
				"%s", _( "tile size not a multiple of 16" ) );
			return( NULL );
		}
	}

	/* Depth 8 is handled above.
	 */
	if( wtiff->bitdepth && 
		!(wtiff->bitdepth == 1 || 
		  wtiff->bitdepth == 2 || 
		  wtiff->bitdepth == 4) ) {
		g_warning( "%s",
			_( "bitdepth 1, 2 or 4 only -- disabling bitdepth") );
		wtiff->bitdepth = 0;
	}

	/* Can only have byte fractional bit depths for 8 bit mono.
	 * 3-band float should have been packed above.
	 */
	if( wtiff->bitdepth && 
		!(wtiff->ready->Coding == VIPS_CODING_NONE &&
		  wtiff->ready->BandFmt == VIPS_FORMAT_UCHAR && 
		  wtiff->ready->Bands == 1) ) { 
		g_warning( "%s",
			( "can only set bitdepth for 1-band uchar and "
                        "3-band float lab -- disabling bitdepth" ) );
		wtiff->bitdepth = 0;
	}

	if( wtiff->bitdepth &&
		wtiff->compression == COMPRESSION_JPEG ) {
		g_warning( "%s", 
			_( "can't have <8 bit JPEG -- disabling JPEG" ) );
		wtiff->compression = COMPRESSION_NONE;
	}
 
	/* We can only MINISWHITE non-complex images of 1 or 2 bands.
	 */
	if( wtiff->miniswhite &&
		(wtiff->ready->Coding != VIPS_CODING_NONE || 
			vips_band_format_iscomplex( wtiff->ready->BandFmt ) ||
			wtiff->ready->Bands > 2) ) {
		g_warning( "%s", 
			_( "can only save non-complex greyscale images "
				"as miniswhite -- disabling miniswhite" ) );
		wtiff->miniswhite = FALSE;
	}

	/* Sizeof a line of bytes in the TIFF tile.
	 */
	if( wtiff->ready->Coding == VIPS_CODING_LABQ )
		wtiff->tls = wtiff->tilew * 3;
	else if( wtiff->bitdepth == 1 )
		wtiff->tls = VIPS_ROUND_UP( wtiff->tilew, 8 ) / 8;
	else if( wtiff->bitdepth == 2 )
		wtiff->tls = VIPS_ROUND_UP( wtiff->tilew, 4 ) / 4;
	else if( wtiff->bitdepth == 4 )
		wtiff->tls = VIPS_ROUND_UP( wtiff->tilew, 2 ) / 2;
	else
		wtiff->tls = VIPS_IMAGE_SIZEOF_PEL( wtiff->ready ) * 
			wtiff->tilew;

	return( wtiff );
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

/* Pack 8 bit VIPS to N bit TIFF.
 */
static void
eightbit2nbit( Wtiff *wtiff, VipsPel *q, VipsPel *p, int n )
{
	/* Invert in miniswhite mode.
	 */
	VipsPel mask = wtiff->miniswhite ? 255 : 0;
	int pixel_mask = 8 / wtiff->bitdepth - 1;
	int shift = 8 - wtiff->bitdepth;

	VipsPel bits;
        int x;

	bits = 0;
        for( x = 0; x < n; x++ ) {
		bits <<= wtiff->bitdepth;
		bits |= p[x] >> shift;

		if( (x & pixel_mask) == pixel_mask ) 
			*q++ = bits ^ mask;
        }

	/* Any left-over bits? Need to be left-aligned.
	 */
	if( (x & pixel_mask) != 0 ) {
		/* The number of bits we've collected in bits and must
		 * left-align and flush.
		 */
		int collected_bits = (x & pixel_mask) << (wtiff->bitdepth - 1);

		*q++ = (bits ^ mask) << (8 - collected_bits);
	}
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
		for( i = 1; i < im->Bands; i++ ) \
			q1[i] = p1[i]; \
		\
		q1 += im->Bands; \
		p1 += im->Bands; \
	} \
}

/* If we're writing a 1 or 2 band image as a greyscale and MINISWHITE, we need
 * to swap the sense of the first band. See tiff2vips.c, greyscale_line() for
 * the opposite conversion.
 */
static void
invert_band0( Wtiff *wtiff, VipsPel *q, VipsPel *p, int n )
{
	VipsImage *im = wtiff->ready;
	gboolean invert = wtiff->miniswhite;

        int x, i;

	switch( im->BandFmt ) {
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

/* Convert VIPS LABS to TIFF 16 bit LAB.
 */
static void
LabS2Lab16( VipsPel *q, VipsPel *p, int n, int samples_per_pixel )
{
	short *p1 = (short *) p;
	unsigned short *q1 = (unsigned short *) q;

	int x;

        for( x = 0; x < n; x++ ) {
		int i;

                /* LABS L can be negative.
                 */
                q1[0] = VIPS_LSHIFT_INT( VIPS_MAX( 0, p1[0] ), 1 );

		for( i = 1; i < samples_per_pixel; i++ )
			q1[i] = p1[i];

		q1 += samples_per_pixel;
		p1 += samples_per_pixel;
	}
}

/* Convert VIPS D65 XYZ to TIFF scaled float illuminant-free xyz.
 */
static void
XYZ2tiffxyz( VipsPel *q, VipsPel *p, int n, int samples_per_pixel )
{
	float *p1 = (float *) p;
	float *q1 = (float *) q;

	int x;

        for( x = 0; x < n; x++ ) {
		int i;

                q1[0] = p1[0] / VIPS_D65_X0;
                q1[1] = p1[1] / VIPS_D65_Y0;
                q1[2] = p1[2] / VIPS_D65_Z0;

		for( i = 3; i < samples_per_pixel; i++ )
			q1[i] = p1[i];

		q1 += samples_per_pixel;
		p1 += samples_per_pixel;
	}
}

/* Pack the pixels in @area from @in into a TIFF tile buffer.
 */
static void
wtiff_pack2tiff( Wtiff *wtiff, Layer *layer, 
	VipsRegion *in, VipsRect *area, VipsPel *q )
{
	int y;

	/* JPEG compression can read outside the pixel area for edge tiles. It
	 * always compresses 8x8 blocks, so if the image width or height is
	 * not a multiple of 8, it can look beyond the pixels we will write.
	 *
	 * Black out the tile first to make sure these edge pixels are always
	 * zero.
	 */
	if( wtiff->compression == COMPRESSION_JPEG &&
		(area->width < wtiff->tilew || 
		 area->height < wtiff->tileh) )
		memset( q, 0, TIFFTileSize( layer->tif ) );

	for( y = area->top; y < VIPS_RECT_BOTTOM( area ); y++ ) {
		VipsPel *p = (VipsPel *) VIPS_REGION_ADDR( in, area->left, y );

		if( wtiff->ready->Coding == VIPS_CODING_LABQ )
			LabQ2LabC( q, p, area->width );
		else if( wtiff->bitdepth > 0 )
			eightbit2nbit( wtiff, q, p, area->width );
		else if( wtiff->input->Type == VIPS_INTERPRETATION_XYZ )
			XYZ2tiffxyz( q, p, area->width, in->im->Bands );
		else if( (in->im->Bands == 1 || in->im->Bands == 2) && 
			wtiff->miniswhite ) 
			invert_band0( wtiff, q, p, area->width );
		else if( wtiff->ready->BandFmt == VIPS_FORMAT_SHORT &&
			wtiff->ready->Type == VIPS_INTERPRETATION_LABS )
			LabS2Lab16( q, p, area->width, in->im->Bands );
		else
			memcpy( q, p, 
				area->width * 
					VIPS_IMAGE_SIZEOF_PEL( wtiff->ready ) );

		q += wtiff->tls;
	}
}

/* Write a set of tiles across the strip.
 */
static int
wtiff_layer_write_tiles( Wtiff *wtiff, Layer *layer, VipsRegion *strip )
{
	VipsImage *im = layer->image;
	VipsRect *area = &strip->valid;

	VipsRect image;
	int x;

	image.left = 0;
	image.top = 0;
	image.width = im->Xsize;
	image.height = im->Ysize;

	for( x = 0; x < im->Xsize; x += wtiff->tilew ) {
		VipsRect tile;

		tile.left = x;
		tile.top = area->top;
		tile.width = wtiff->tilew;
		tile.height = wtiff->tileh;
		vips_rect_intersectrect( &tile, &image, &tile );

#ifdef DEBUG_VERBOSE
		printf( "Writing %dx%d tile at position %dx%d to image %s\n",
			tile.width, tile.height, tile.left, tile.top,
			TIFFFileName( layer->tif ) );
#endif /*DEBUG_VERBOSE*/

		if( wtiff->we_compress ) {
			ttile_t tile_no = TIFFComputeTile( layer->tif,
				tile.left, tile.top, 0, 0 );

			VipsTarget *target;
			int result;
			unsigned char *buffer;
			size_t length;

			target = vips_target_new_to_memory();

			switch( wtiff->compression ) {
			case JP2K_LOSSY:
				/* Sadly chroma subsample seems not to work
				 * for edge tiles in tiff with jp2k
				 * compression, so we always pass FALSE
				 * instead of:
				 *
				 * 	!wtiff->rgbjpeg && wtiff->Q < 90,
				 *
				 * I've verified that the libvips jp2k
				 * encode and decode subsample operations fill
				 * the comps[i].data arrays correctly, so it
				 * seems to be a openjpeg bug.
				 *
				 * FIXME ... try again with openjpeg 2.5,
				 * when that comes.
				 */
				result = vips__foreign_load_jp2k_compress( 
					strip, &tile, target,
					wtiff->tilew, wtiff->tileh,
					!wtiff->rgbjpeg,
				 	// !wtiff->rgbjpeg && wtiff->Q < 90,
					FALSE,
					wtiff->lossless, 
					wtiff->Q );
				break;

			default:
				result = -1;
				g_assert_not_reached();
				break;
			}

			if( result ) {
				g_object_unref( target );
				return( -1 );
			}

			buffer = vips_target_steal( target, &length );

			g_object_unref( target );

			result = TIFFWriteRawTile( layer->tif, tile_no, 
				buffer, length );

			g_free( buffer );
		
			if( result < 0 ) {
				vips_error( "vips2tiff", 
					"%s", _( "TIFF write tile failed" ) );
				return( -1 );
			}
		}
		else {
			/* Have to repack pixels for libtiff.
			 */
			wtiff_pack2tiff( wtiff, 
				layer, strip, &tile, wtiff->tbuf );

			if( TIFFWriteTile( layer->tif, wtiff->tbuf, 
				tile.left, tile.top, 0, 0 ) < 0 ) {
				vips_error( "vips2tiff", 
					"%s", _( "TIFF write tile failed" ) );
				return( -1 );
			}
		}
	}

	return( 0 );
}

/* Write tileh scanlines, less for the last strip.
 */
static int
wtiff_layer_write_strip( Wtiff *wtiff, Layer *layer, VipsRegion *strip )
{
	VipsImage *im = layer->image;
	VipsRect *area = &strip->valid;
	int height = VIPS_MIN( wtiff->tileh, area->height ); 

	int y;

#ifdef DEBUG_VERBOSE
	printf( "Writing %d pixel strip at height %d to image %s\n",
		height, area->top, TIFFFileName( layer->tif ) );
#endif /*DEBUG_VERBOSE*/

	for( y = 0; y < height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( strip, 0, area->top + y );

		/* Any repacking necessary.
		 */
		if( im->Coding == VIPS_CODING_LABQ ) {
			LabQ2LabC( wtiff->tbuf, p, im->Xsize );
			p = wtiff->tbuf;
		}
		else if( im->BandFmt == VIPS_FORMAT_SHORT &&
			im->Type == VIPS_INTERPRETATION_LABS ) {
			LabS2Lab16( wtiff->tbuf, p, im->Xsize, im->Bands );
			p = wtiff->tbuf;
		}
		else if( wtiff->input->Type == VIPS_INTERPRETATION_XYZ ) {
			XYZ2tiffxyz( wtiff->tbuf, p, im->Xsize, im->Bands );
			p = wtiff->tbuf;
		}
		else if( wtiff->bitdepth > 0 ) {
			eightbit2nbit( wtiff, wtiff->tbuf, p, im->Xsize );
			p = wtiff->tbuf;
		}
		else if( (im->Bands == 1 || im->Bands == 2) && 
			wtiff->miniswhite ) {
			invert_band0( wtiff, wtiff->tbuf, p, im->Xsize );
			p = wtiff->tbuf;
		}

		if( TIFFWriteScanline( layer->tif, p, area->top + y, 0 ) < 0 ) 
			return( -1 );
	}

	return( 0 );
}

static int layer_strip_arrived( Layer *layer );

/* Shrink what pixels we can from this strip into the layer below. If the
 * strip below fills, recurse.
 */
static int
layer_strip_shrink( Layer *layer )
{
	Layer *below = layer->below;
	VipsRegion *from = layer->strip;
	VipsRegion *to = below->strip;

	VipsRect target;
	VipsRect source;

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

		(void) vips_region_shrink_method( from, to, &target,
			layer->wtiff->region_shrink );

		below->write_y += target.height;

		/* If we've filled the strip below, let it know.
		 * We can either fill the region, if it's somewhere half-way
		 * down the image, or, if it's at the bottom, get to the last
		 * real line of pixels.
		 */
		if( below->write_y == VIPS_RECT_BOTTOM( &to->valid ) ||
			below->write_y == below->height ) {
			if( layer_strip_arrived( below ) )
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
layer_strip_arrived( Layer *layer )
{
	Wtiff *wtiff = layer->wtiff;

	int result;
	VipsRect new_strip;
	VipsRect overlap;
	VipsRect image_area;

	if( wtiff->tile ) 
		result = wtiff_layer_write_tiles( wtiff, layer, layer->strip );
	else
		result = wtiff_layer_write_strip( wtiff, layer, layer->strip );
	if( result )
		return( -1 );

	if( layer->below &&
		layer_strip_shrink( layer ) ) 
		return( -1 );

	/* Position our strip down the image.  
	 *
	 * Expand the strip if necessary to make sure we have an even 
	 * number of lines. 
	 */
	layer->y += wtiff->tileh;
	new_strip.left = 0;
	new_strip.top = layer->y;
	new_strip.width = layer->image->Xsize;
	new_strip.height = wtiff->tileh;

	image_area.left = 0;
	image_area.top = 0;
	image_area.width = layer->image->Xsize;
	image_area.height = layer->image->Ysize;
	vips_rect_intersectrect( &new_strip, &image_area, &new_strip ); 

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

	if( !vips_rect_isempty( &new_strip ) ) {
		if( vips_region_buffer( layer->strip, &new_strip ) ) 
			return( -1 );

		/* And copy back again.
		 */
		if( !vips_rect_isempty( &overlap ) ) 
			vips_region_copy( layer->copy, layer->strip, 
				&overlap, overlap.left, overlap.top );
	}

	return( 0 );
}

/* Another strip of image pixels from vips_sink_disc(). Write into the top
 * pyramid layer. 
 */
static int
write_strip( VipsRegion *region, VipsRect *area, void *a )
{
	Wtiff *wtiff = (Wtiff *) a;
	Layer *layer = wtiff->layer; 

#ifdef DEBUG_VERBOSE
	printf( "write_strip: strip at %d, height %d\n", 
		area->top, area->height );
#endif/*DEBUG_VERBOSE*/

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
			if( layer_strip_arrived( layer ) ) 
				return( -1 );
		}
	}

	return( 0 );
}

/* Copy fields.
 */
#define CopyField( tag, v ) \
	if( TIFFGetField( in, tag, &v ) ) TIFFSetField( out, tag, v )

/* Copy a TIFF file ... we know we wrote it, so just copy the tags we know 
 * we might have set.
 */
static int
wtiff_copy_tiff( Wtiff *wtiff, TIFF *out, TIFF *in )
{
	uint32 ui32;
	uint16 ui16;
	uint16 ui16_2;
	float f;
	tdata_t buf;
	ttile_t tile_no;
	ttile_t n;
	uint16 *a;

	/* All the fields we might have set.
	 */
	CopyField( TIFFTAG_IMAGEWIDTH, ui32 );
	CopyField( TIFFTAG_IMAGELENGTH, ui32 );
	CopyField( TIFFTAG_PLANARCONFIG, ui16 );
	CopyField( TIFFTAG_ORIENTATION, ui16 );
	CopyField( TIFFTAG_XRESOLUTION, f );
	CopyField( TIFFTAG_YRESOLUTION, f );
	CopyField( TIFFTAG_RESOLUTIONUNIT, ui16 );
	CopyField( TIFFTAG_COMPRESSION, ui16 );
	CopyField( TIFFTAG_SAMPLESPERPIXEL, ui16 );
	CopyField( TIFFTAG_BITSPERSAMPLE, ui16 );
	CopyField( TIFFTAG_PHOTOMETRIC, ui16 );
	CopyField( TIFFTAG_ORIENTATION, ui16 );
	CopyField( TIFFTAG_TILEWIDTH, ui32 );
	CopyField( TIFFTAG_TILELENGTH, ui32 );
	CopyField( TIFFTAG_ROWSPERSTRIP, ui32 );
	CopyField( TIFFTAG_SUBFILETYPE, ui32 );

	if( TIFFGetField( in, TIFFTAG_EXTRASAMPLES, &ui16, &a ) ) 
		TIFFSetField( out, TIFFTAG_EXTRASAMPLES, ui16, a );

	if( TIFFGetField( in, TIFFTAG_PAGENUMBER, &ui16, &ui16_2 ) ) 
		TIFFSetField( out, TIFFTAG_PAGENUMBER, ui16, ui16_2 );

	/* TIFFTAG_JPEGQUALITY is a pesudo-tag, so we can't copy it.
	 * Set explicitly from Wtiff.
	 */
	if( wtiff->compression == COMPRESSION_JPEG ) {
		TIFFSetField( out, TIFFTAG_JPEGQUALITY, wtiff->Q );

		/* Only for three-band, 8-bit images.
		 */
		if( wtiff->ready->Bands == 3 &&
			wtiff->ready->BandFmt == VIPS_FORMAT_UCHAR ) { 
			/* Enable rgb->ycbcr conversion in the jpeg write. 
			 */
			if( !wtiff->rgbjpeg &&
				wtiff->Q < 90 ) 
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

#ifdef HAVE_TIFF_COMPRESSION_WEBP
	/* More pseudotags we can't copy.
	 */
	if( wtiff->compression == COMPRESSION_WEBP ) {
		TIFFSetField( out, TIFFTAG_WEBP_LEVEL, wtiff->Q );
		TIFFSetField( out, TIFFTAG_WEBP_LOSSLESS, wtiff->lossless );
	}
	if( wtiff->compression == COMPRESSION_ZSTD ) {
		TIFFSetField( out, TIFFTAG_ZSTD_LEVEL, wtiff->level );
		if( wtiff->predictor != VIPS_FOREIGN_TIFF_PREDICTOR_NONE ) 
			TIFFSetField( out, 
				TIFFTAG_PREDICTOR, wtiff->predictor );
	}
#endif /*HAVE_TIFF_COMPRESSION_WEBP*/

	if( (wtiff->compression == COMPRESSION_ADOBE_DEFLATE ||
		wtiff->compression == COMPRESSION_LZW) &&
		wtiff->predictor != VIPS_FOREIGN_TIFF_PREDICTOR_NONE ) 
		TIFFSetField( out, TIFFTAG_PREDICTOR, wtiff->predictor );

	/* We can't copy profiles or xmp :( Set again from wtiff.
	 */
	if( !wtiff->strip ) 
		if( wtiff_embed_profile( wtiff, out ) ||
			wtiff_embed_xmp( wtiff, out ) ||
			wtiff_embed_iptc( wtiff, out ) ||
			wtiff_embed_photoshop( wtiff, out ) ||
			wtiff_embed_imagedescription( wtiff, out ) )
			return( -1 );

	buf = vips_malloc( NULL, TIFFTileSize( in ) );
	n = TIFFNumberOfTiles( in );
	for( tile_no = 0; tile_no < n; tile_no++ ) {
		tsize_t len;

		len = TIFFReadRawTile( in, tile_no, 
			wtiff->compressed_buf, wtiff->compressed_buf_length );
		if( len <= 0 ||
			TIFFWriteRawTile( out, tile_no, 
				wtiff->compressed_buf, len ) < 0 )
			return( -1 );
	}
	g_free( buf );

	return( 0 );
}

/* Append all of the layers we wrote to the output.
 */
static int
wtiff_gather( Wtiff *wtiff )
{
	Layer *layer;

	if( wtiff->layer &&
		wtiff->layer->below )
		for( layer = wtiff->layer->below; layer; 
			layer = layer->below ) {
			VipsSource *source;
			TIFF *in;

#ifdef DEBUG
			printf( "appending layer %s ...\n", layer->lname );
#endif /*DEBUG*/

			if( layer->lname ) {
				if( !(source = vips_source_new_from_file( 
					layer->lname )) ) 
					return( -1 );
			}
			else {
				if( !(source = vips_source_new_from_memory(
					layer->buf, layer->len )) )
					return( -1 );
			}

			if( !(in = vips__tiff_openin_source( source )) ) {
				VIPS_UNREF( source );
				return( -1 );
			}

			VIPS_UNREF( source );

			if( wtiff_copy_tiff( wtiff, wtiff->layer->tif, in ) ) {
				TIFFClose( in );
				return( -1 );
			}

			TIFFClose( in );

			if( !TIFFWriteDirectory( wtiff->layer->tif ) ) 
				return( -1 );
		}

	return( 0 );
}

/* Write one page from our input image, optionally pyramiding it.
 */
static int
wtiff_write_page( Wtiff *wtiff, VipsImage *page )
{
#ifdef DEBUG
	printf( "wtiff_write_page:\n" ); 
#endif /*DEBUG*/

	/* Init the pyramid framework for this page. This will just make a 
	 * single layer if we're not pyramiding.
	 */
	wtiff_layer_init( wtiff, &wtiff->layer, NULL, 
		page->Xsize, page->Ysize );

	/* Fill all the layers and write the TIFF headers.
	 */
	if( wtiff_allocate_layers( wtiff ) ) 
		return( -1 );

	/* In ifd mode, we write the pyramid layers as subdirectories of this
	 * page.
	 */
	if( wtiff->subifd ) {
		int n_layers;
		toff_t *subifd_offsets;
		Layer *p;

#ifdef DEBUG
		printf( "wtiff_write_page: OME pyr mode\n" ); 
#endif /*DEBUG*/

		/* This magic tag makes the n_layers directories we write 
		 * after this one into subdirectories. We set the offsets to 0
		 * and libtiff will fill them in automatically.
		 */
		for( n_layers = 0, p = wtiff->layer->below; p; p = p->below )
			n_layers += 1;
		subifd_offsets = VIPS_ARRAY( NULL, n_layers, toff_t );
		memset( subifd_offsets, 0, n_layers * sizeof( toff_t ) );
		TIFFSetField( wtiff->layer->tif, TIFFTAG_SUBIFD, 
			n_layers, subifd_offsets );
		g_free( subifd_offsets );
	}

	if( vips_sink_disc( page, write_strip, wtiff ) ) 
		return( -1 );

	if( !TIFFWriteDirectory( wtiff->layer->tif ) ) 
		return( -1 );

	/* Append any pyr layers, if necessary.
	 */
	if( wtiff->layer->below ) {
		/* Free any lower pyramid resources ... this will 
		 * TIFFClose() (but not delete) the smaller layers 
		 * ready for us to read from them again.
		 */
		layer_free_all( wtiff->layer->below );

		/* Append smaller layers to the main file.
		 */
		if( wtiff_gather( wtiff ) ) 
			return( -1 );

		/* We can delete any temps now ready for the next page.
		 */
		wtiff_delete_temps( wtiff );

		/* And free all lower pyr layers ready to be rebuilt for the
		 * next page.
		 */
		VIPS_FREEF( layer_free_all, wtiff->layer->below );
	}

	return( 0 );
}

/* Write all pages.
 */
static int
wtiff_write_image( Wtiff *wtiff )
{
	int y;

	for( y = 0; y < wtiff->ready->Ysize; y += wtiff->page_height ) {
		VipsImage *page;

#ifdef DEBUG
		printf( "writing page %d ...\n", wtiff->page_number );
#endif /*DEBUG*/

		if( vips_crop( wtiff->ready, &page, 
			0, y, wtiff->ready->Xsize, wtiff->page_height,
			NULL ) )
			return( -1 ); 
		if( wtiff_write_page( wtiff, page ) ) {
			g_object_unref( page );
			return( -1 );
		}
		g_object_unref( page );

		wtiff->page_number += 1;
	}

	return( 0 );
}

int 
vips__tiff_write( VipsImage *input, const char *filename, 
	VipsForeignTiffCompression compression, int Q, 
	VipsForeignTiffPredictor predictor,
	const char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	int bitdepth,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties, gboolean strip,
	VipsRegionShrink region_shrink,
	int level, 
	gboolean lossless,
	VipsForeignDzDepth depth,
	gboolean subifd,
	gboolean premultiply )
{
	Wtiff *wtiff;

#ifdef DEBUG
	printf( "tiff2vips: libtiff version is \"%s\"\n", TIFFGetVersion() );
#endif /*DEBUG*/

	vips__tiff_init();

	if( !(wtiff = wtiff_new( input, filename, 
		compression, Q, predictor, profile,
                tile, tile_width, tile_height, pyramid, bitdepth,
		miniswhite, resunit, xres, yres, bigtiff, rgbjpeg, 
		properties, strip, region_shrink, level, lossless, depth,
		subifd, premultiply )) )
		return( -1 );

	if( wtiff_write_image( wtiff ) ) { 
		wtiff_free( wtiff );
		return( -1 );
	}

	wtiff_free( wtiff );

	return( 0 );
}

int 
vips__tiff_write_buf( VipsImage *input, 
	void **obuf, size_t *olen, 
	VipsForeignTiffCompression compression, int Q, 
	VipsForeignTiffPredictor predictor,
	const char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	int bitdepth,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties, gboolean strip, 
	VipsRegionShrink region_shrink,
	int level, 
	gboolean lossless,
	VipsForeignDzDepth depth,
	gboolean subifd,
	gboolean premultiply )
{
	Wtiff *wtiff;

	vips__tiff_init();

	if( !(wtiff = wtiff_new( input, NULL, 
		compression, Q, predictor, profile,
                tile, tile_width, tile_height, pyramid, bitdepth,
		miniswhite, resunit, xres, yres, bigtiff, rgbjpeg, 
		properties, strip, region_shrink, level, lossless, depth,
		subifd, premultiply )) )
		return( -1 );

	wtiff->obuf = obuf;
	wtiff->olen = olen;

	if( wtiff_write_image( wtiff ) ) { 
		wtiff_free( wtiff );
		return( -1 );
	}

	/* Now close the top layer, and we'll get a pointer we can return
	 * to our caller.
	 */
	VIPS_FREEF( TIFFClose, wtiff->layer->tif );

	*obuf = wtiff->layer->buf;
	*olen = wtiff->layer->len;

	/* Now our caller owns it, we must not free it.
	 */
	wtiff->layer->buf = NULL;

	wtiff_free( wtiff );

	return( 0 );
}

#endif /*HAVE_TIFF*/
