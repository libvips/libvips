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
 * 	- try to write IPCT metadata
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
 * 21/6/17
 * 	- add a lanczos3 shrink option
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

/* Max number of alpha channels we allow.
 */
#define MAX_ALPHA (64)

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
	VipsImage *im;			/* Original input image */

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

	int compression;		/* Compression type */
	int jpqual;			/* JPEG q-factor */
	int predictor;			/* Predictor value */
	int tile;			/* Tile or not */
	int tilew, tileh;		/* Tile size */
	int pyramid;			/* Wtiff pyramid */
	int onebit;			/* Wtiff as 1-bit TIFF */
	int miniswhite;			/* Wtiff as 0 == white */
        int resunit;                    /* Resolution unit (inches or cm) */
        double xres;                   	/* Resolution in X */
        double yres;                   	/* Resolution in Y */
	char *icc_profile;		/* Profile to embed */
	int bigtiff;			/* True for bigtiff write */
	int rgbjpeg;			/* True for RGB not YCbCr */
	int properties;			/* Set to save XML props */
	int strip;			/* Don't write metadata */

	/* True if we've detected a toilet-roll image, plus the page height,
	 * which has been checked to be a factor of im->Ysize.
	 */
	gboolean toilet_roll;
	int page_height;

	/* The height of the TIFF we write. Equal to page_height in toilet
	 * roll mode.
	 */
	int image_height;
};

/* Embed an ICC profile from a file.
 */
static int
embed_profile_file( TIFF *tif, const char *profile )
{
	char *buffer;
	size_t length;

	if( !(buffer = vips__file_read_name( profile, 
		vips__icc_dir(), &length )) )
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

static Layer *
wtiff_layer_new( Wtiff *wtiff, Layer *above, int width, int height )
{
	Layer *layer;

	layer = VIPS_NEW( wtiff->im, Layer );
	layer->wtiff = wtiff;
	layer->width = width;
	layer->height = height; 

	if( !above )
		/* Top of pyramid.
		 */
		layer->sub = 1;	
	else
		layer->sub = above->sub * 2;

	layer->lname = NULL;
	layer->buf = NULL;
	layer->len = 0;
	layer->tif = NULL;
	layer->image = NULL;
	layer->write_y = 0;
	layer->y = 0;
	layer->strip = NULL;
	layer->copy = NULL;

	layer->below = NULL;
	layer->above = above;

	if( wtiff->pyramid )
		if( layer->width > wtiff->tilew || 
			layer->height > wtiff->tileh ) 
			layer->below = wtiff_layer_new( wtiff, layer, 
				width / 2, height / 2 );

	/* The name for the top layer is the output filename.
	 *
	 * We need lname to be freed automatically: it has to stay 
	 * alive until after wtiff_gather().
	 */
	if( wtiff->filename ) { 
		if( !above ) 
			layer->lname = vips_strdup( VIPS_OBJECT( wtiff->im ), 
				wtiff->filename );
		else {
			char *lname;

			lname = vips__temp_name( "%s.tif" );
			layer->lname = 
				vips_strdup( VIPS_OBJECT( wtiff->im ), lname );
			g_free( lname );
		}
	}

	return( layer );
}

static int
wtiff_embed_profile( Wtiff *wtiff, TIFF *tif )
{
	if( wtiff->icc_profile && 
		strcmp( wtiff->icc_profile, "none" ) != 0 &&
		embed_profile_file( tif, wtiff->icc_profile ) )
		return( -1 );

	if( !wtiff->icc_profile && 
		vips_image_get_typeof( wtiff->im, VIPS_META_ICC_NAME ) &&
		embed_profile_meta( tif, wtiff->im ) )
		return( -1 );

	return( 0 );
}

static int
wtiff_embed_xmp( Wtiff *wtiff, TIFF *tif )
{
	void *data;
	size_t data_length;

	if( !vips_image_get_typeof( wtiff->im, VIPS_META_XMP_NAME ) )
		return( 0 );
	if( vips_image_get_blob( wtiff->im, VIPS_META_XMP_NAME, 
		&data, &data_length ) )
		return( -1 );
	TIFFSetField( tif, TIFFTAG_XMLPACKET, data_length, data );

#ifdef DEBUG
	printf( "vips2tiff: attached XMP from meta\n" );
#endif /*DEBUG*/

	return( 0 );
}

static int
wtiff_embed_ipct( Wtiff *wtiff, TIFF *tif )
{
	void *data;
	size_t data_length;

	if( !vips_image_get_typeof( wtiff->im, VIPS_META_IPCT_NAME ) )
		return( 0 );
	if( vips_image_get_blob( wtiff->im, VIPS_META_IPCT_NAME, 
		&data, &data_length ) )
		return( -1 );

	/* For no very good reason, libtiff stores IPCT as an array of
	 * long, not byte.
	 */
	if( data_length & 3 ) {
		g_warning( "%s", _( "rounding up IPCT data length" ) );
		data_length /= 4;
		data_length += 1;
	}
	else
		data_length /= 4;

	TIFFSetField( tif, TIFFTAG_RICHTIFFIPTC, data_length, data );

#ifdef DEBUG
	printf( "vips2tiff: attached IPCT from meta\n" );
#endif /*DEBUG*/

	return( 0 );
}

static int
wtiff_embed_photoshop( Wtiff *wtiff, TIFF *tif )
{
	void *data;
	size_t data_length;

	if( !vips_image_get_typeof( wtiff->im, VIPS_META_PHOTOSHOP_NAME ) )
		return( 0 );
	if( vips_image_get_blob( wtiff->im, 
		VIPS_META_PHOTOSHOP_NAME, &data, &data_length ) )
		return( -1 );
	TIFFSetField( tif, TIFFTAG_PHOTOSHOP, data_length, data );

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

		if( !(doc = vips__xml_properties( wtiff->im )) )
			return( -1 );
		TIFFSetField( tif, TIFFTAG_IMAGEDESCRIPTION, doc );
		g_free( doc );
	}
	else {
		const char *imagedescription;

		if( !vips_image_get_typeof( wtiff->im, 
			VIPS_META_IMAGEDESCRIPTION ) )
			return( 0 );
		if( vips_image_get_string( wtiff->im, 
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

	int format; 
	int orientation; 

	/* Output base header fields.
	 */
	TIFFSetField( tif, TIFFTAG_IMAGEWIDTH, layer->width );
	TIFFSetField( tif, TIFFTAG_IMAGELENGTH, layer->height );
	TIFFSetField( tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG );
	TIFFSetField( tif, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT );
	TIFFSetField( tif, TIFFTAG_COMPRESSION, wtiff->compression );

	if( wtiff->compression == COMPRESSION_JPEG ) 
		TIFFSetField( tif, TIFFTAG_JPEGQUALITY, wtiff->jpqual );

	if( wtiff->predictor != VIPS_FOREIGN_TIFF_PREDICTOR_NONE ) 
		TIFFSetField( tif, TIFFTAG_PREDICTOR, wtiff->predictor );

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
			wtiff_embed_ipct( wtiff, tif ) ||
			wtiff_embed_photoshop( wtiff, tif ) ||
			wtiff_embed_imagedescription( wtiff, tif ) )
			return( -1 ); 

	if( vips_image_get_typeof( wtiff->im, VIPS_META_ORIENTATION ) &&
		!vips_image_get_int( wtiff->im, 
			VIPS_META_ORIENTATION, &orientation ) )
		TIFFSetField( tif, TIFFTAG_ORIENTATION, orientation );

	/* And colour fields.
	 */
	if( wtiff->im->Coding == VIPS_CODING_LABQ ) {
		TIFFSetField( tif, TIFFTAG_SAMPLESPERPIXEL, 3 );
		TIFFSetField( tif, TIFFTAG_BITSPERSAMPLE, 8 );
		TIFFSetField( tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_CIELAB );
	}
	else if( wtiff->onebit ) {
		TIFFSetField( tif, TIFFTAG_SAMPLESPERPIXEL, 1 );
		TIFFSetField( tif, TIFFTAG_BITSPERSAMPLE, 1 );
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

		TIFFSetField( tif, TIFFTAG_SAMPLESPERPIXEL, wtiff->im->Bands );
		TIFFSetField( tif, TIFFTAG_BITSPERSAMPLE, 
			vips_format_sizeof( wtiff->im->BandFmt ) << 3 );

		if( wtiff->im->Bands < 3 ) {
			/* Mono or mono + alpha.
			 */
			photometric = wtiff->miniswhite ? 
				PHOTOMETRIC_MINISWHITE :  
				PHOTOMETRIC_MINISBLACK;
			colour_bands = 1;
		}
		else {
			/* Could be: RGB, CMYK, LAB, perhaps with extra alpha.
			 */
			if( wtiff->im->Type == VIPS_INTERPRETATION_LAB || 
				wtiff->im->Type == VIPS_INTERPRETATION_LABS ) {
				photometric = PHOTOMETRIC_CIELAB;
				colour_bands = 3;
			}
			else if( wtiff->im->Type == VIPS_INTERPRETATION_CMYK &&
				wtiff->im->Bands >= 4 ) {
				photometric = PHOTOMETRIC_SEPARATED;
				TIFFSetField( tif, 
					TIFFTAG_INKSET, INKSET_CMYK );
				colour_bands = 4;
			}
			else if( wtiff->compression == COMPRESSION_JPEG &&
				wtiff->im->Bands == 3 &&
				wtiff->im->BandFmt == VIPS_FORMAT_UCHAR &&
				(!wtiff->rgbjpeg && wtiff->jpqual < 90) ) { 
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
				/* Some kind of generic multi-band image ..
				 * save the first three bands as RGB, the rest
				 * as alpha.
				 */
				photometric = PHOTOMETRIC_RGB;
				colour_bands = 3;
			}
		}

		alpha_bands = VIPS_CLIP( 0, 
			wtiff->im->Bands - colour_bands, MAX_ALPHA );
		if( alpha_bands > 0 ) { 
			uint16 v[MAX_ALPHA];
			int i;

			/* EXTRASAMPLE_UNASSALPHA means generic extra
			 * alpha-like channels. ASSOCALPHA means pre-multipled
			 * alpha only. 
			 */
			for( i = 0; i < alpha_bands; i++ )
				v[i] = EXTRASAMPLE_UNASSALPHA;
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

	/* Sample format.
	 */
	format = SAMPLEFORMAT_UINT;
	if( vips_band_format_isuint( wtiff->im->BandFmt ) )
		format = SAMPLEFORMAT_UINT;
	else if( vips_band_format_isint( wtiff->im->BandFmt ) )
		format = SAMPLEFORMAT_INT;
	else if( vips_band_format_isfloat( wtiff->im->BandFmt ) )
		format = SAMPLEFORMAT_IEEEFP;
	else if( vips_band_format_iscomplex( wtiff->im->BandFmt ) )
		format = SAMPLEFORMAT_COMPLEXIEEEFP;
	TIFFSetField( tif, TIFFTAG_SAMPLEFORMAT, format );

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

	for( layer = wtiff->layer; layer; layer = layer->below ) {
		layer->image = vips_image_new();
		if( vips_image_pipelinev( layer->image, 
			VIPS_DEMAND_STYLE_ANY, wtiff->im, NULL ) ) 
			return( -1 );
		layer->image->Xsize = layer->width;
		layer->image->Ysize = layer->height;

		layer->strip = vips_region_new( layer->image );
		layer->copy = vips_region_new( layer->image );

		/* The regions will get used in the bg thread callback, so 
		 * make sure we don't own them.
		 */
		vips__region_no_ownership( layer->strip );
		vips__region_no_ownership( layer->copy );

		if( wtiff_layer_rewind( wtiff, layer ) )
			return( -1 ); 

		if( layer->lname ) 
			layer->tif = vips__tiff_openout( 
				layer->lname, wtiff->bigtiff );
		else {
			layer->tif = vips__tiff_openout_buffer( wtiff->im, 
				wtiff->bigtiff, &layer->buf, &layer->len );
		}
		if( !layer->tif ) 
			return( -1 );

		if( wtiff_write_header( wtiff, layer ) )  
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

	VIPS_FREEF( vips_free, wtiff->tbuf );
	VIPS_FREEF( layer_free_all, wtiff->layer );
	VIPS_FREEF( vips_free, wtiff->icc_profile );
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
	
	default:
		g_assert_not_reached();
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
		g_assert_not_reached();
	}

	/* Keep -Wall happy.
	 */
	return( -1 );
}

static Wtiff *
wtiff_new( VipsImage *im, const char *filename, 
	VipsForeignTiffCompression compression, int Q, 
	VipsForeignTiffPredictor predictor,
	char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	gboolean squash,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties,
	gboolean strip )
{
	Wtiff *wtiff;

	if( !(wtiff = VIPS_NEW( im, Wtiff )) )
		return( NULL );
	wtiff->im = im;
	wtiff->filename = filename ? 
		vips_strdup( VIPS_OBJECT( im ), filename ) : NULL;
	wtiff->layer = NULL;
	wtiff->tbuf = NULL;
	wtiff->compression = get_compression( compression );
	wtiff->jpqual = Q;
	wtiff->predictor = predictor;
	wtiff->tile = tile;
	wtiff->tilew = tile_width;
	wtiff->tileh = tile_height;
	wtiff->pyramid = pyramid;
	wtiff->onebit = squash;
	wtiff->miniswhite = miniswhite;
	wtiff->resunit = get_resunit( resunit );
	wtiff->xres = xres;
	wtiff->yres = yres;
	wtiff->icc_profile = vips_strdup( NULL, profile );
	wtiff->bigtiff = bigtiff;
	wtiff->rgbjpeg = rgbjpeg;
	wtiff->properties = properties;
	wtiff->strip = strip;
	wtiff->toilet_roll = FALSE;
	wtiff->page_height = -1;

	/* Updated below if we discover toilet roll mode.
	 */
	wtiff->image_height = im->Ysize;

	/* Check for a toilet roll image.
	 */
	if( vips_image_get_typeof( im, VIPS_META_PAGE_HEIGHT ) &&
		vips_image_get_int( im, 
			VIPS_META_PAGE_HEIGHT, &wtiff->page_height ) ) {
		wtiff_free( wtiff );
		return( NULL );
	}

	/* If page_height <= Ysize, treat as a single-page image.
	 */
	if( wtiff->page_height > 0 &&
		wtiff->page_height < im->Ysize ) { 
#ifdef DEBUG
		printf( "wtiff_new: detected toilet roll image, "
			"page-height=%d\n", 
			wtiff->page_height );
#endif/*DEBUG*/

		wtiff->toilet_roll = TRUE;
		wtiff->image_height = wtiff->page_height;

		if( im->Ysize % wtiff->page_height != 0 ) { 
			vips_error( "vips2tiff",
				_( "image height %d is not a factor of "
					"page-height %d" ),
				im->Ysize, wtiff->page_height );
			wtiff_free( wtiff );
			return( NULL );
		}

#ifdef DEBUG
		printf( "wtiff_new: pages=%d\n", 
			im->Ysize / wtiff->page_height );
#endif/*DEBUG*/

		/* We can't pyramid toilet roll images.
		 */
		if( wtiff->pyramid ) {
			g_warning( "%s", 
				_( "can't pyramid multi page images --- "
					"disabling pyramid" ) ); 
			wtiff->pyramid = FALSE;
		}
	}

	/* In strip mode we use tileh to set rowsperstrip, and that does not
	 * have the multiple-of-16 restriction.
	 */
	if( tile ) { 
		if( (wtiff->tilew & 0xf) != 0 || 
			(wtiff->tileh & 0xf) != 0 ) {
			vips_error( "vips2tiff", 
				"%s", _( "tile size not a multiple of 16" ) );
			return( NULL );
		}
	}

	/* We can only pyramid LABQ and non-complex images. 
	 */
	if( wtiff->pyramid ) {
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
	if( wtiff->onebit &&
		(im->Coding != VIPS_CODING_NONE || 
			im->BandFmt != VIPS_FORMAT_UCHAR ||
			im->Bands != 1) ) {
		g_warning( "%s",
			_( "can only squash 1 band uchar images -- "
				"disabling squash" ) );
		wtiff->onebit = 0;
	}

	if( wtiff->onebit && 
		wtiff->compression == COMPRESSION_JPEG ) {
		g_warning( "%s", 
			_( "can't have 1-bit JPEG -- disabling JPEG" ) );
		wtiff->compression = COMPRESSION_NONE;
	}
 
	/* We can only MINISWHITE non-complex images of 1 or 2 bands.
	 */
	if( wtiff->miniswhite &&
		(im->Coding != VIPS_CODING_NONE || 
			vips_band_format_iscomplex( im->BandFmt ) ||
			im->Bands > 2) ) {
		g_warning( "%s", 
			_( "can only save non-complex greyscale images "
				"as miniswhite -- disabling miniswhite" ) );
		wtiff->miniswhite = FALSE;
	}

	/* Sizeof a line of bytes in the TIFF tile.
	 */
	if( im->Coding == VIPS_CODING_LABQ )
		wtiff->tls = wtiff->tilew * 3;
	else if( wtiff->onebit )
		wtiff->tls = VIPS_ROUND_UP( wtiff->tilew, 8 ) / 8;
	else
		wtiff->tls = VIPS_IMAGE_SIZEOF_PEL( im ) * wtiff->tilew;

	/* If compression is off and we're writing a >4gb image, automatically
	 * enable bigtiff.
	 *
	 * This won't always work. If the image data is just under 4gb but
	 * there's a lot of metadata, we could be pushed over the 4gb limit.
	 */
	if( wtiff->compression == COMPRESSION_NONE &&
		VIPS_IMAGE_SIZEOF_IMAGE( wtiff->im ) > UINT_MAX && 
		!wtiff->bigtiff ) { 
		g_warning( "%s", _( "image over 4gb, enabling bigtiff" ) );
		wtiff->bigtiff = TRUE;
	}

	/* Build the pyramid framework.
	 */
	wtiff->layer = wtiff_layer_new( wtiff, NULL, 
		im->Xsize, wtiff->image_height );

	/* Fill all the layers.
	 */
	if( wtiff_allocate_layers( wtiff ) ) {
		wtiff_free( wtiff );
		return( NULL );
	}

	if( tile ) 
		wtiff->tbuf = vips_malloc( NULL, 
			TIFFTileSize( wtiff->layer->tif ) );
	else
		wtiff->tbuf = vips_malloc( NULL, 
			TIFFScanlineSize( wtiff->layer->tif ) );
	if( !wtiff->tbuf ) {
		wtiff_free( wtiff );
		return( NULL );
	}

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

/* Pack 8 bit VIPS to 1 bit TIFF.
 */
static void
eightbit2onebit( Wtiff *wtiff, VipsPel *q, VipsPel *p, int n )
{
        int x;
	VipsPel bits;

	/* Invert in miniswhite mode.
	 */
	int white = wtiff->miniswhite ? 0 : 1;
	int black = white ^ 1;

	bits = 0;
        for( x = 0; x < n; x++ ) {
		bits <<= 1;
		if( p[x] > 128 )
			bits |= white;
		else
			bits |= black;

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
	VipsImage *im = wtiff->im;
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

		if( wtiff->im->Coding == VIPS_CODING_LABQ )
			LabQ2LabC( q, p, area->width );
		else if( wtiff->onebit ) 
			eightbit2onebit( wtiff, q, p, area->width );
		else if( (in->im->Bands == 1 || in->im->Bands == 2) && 
			wtiff->miniswhite ) 
			invert_band0( wtiff, q, p, area->width );
		else if( wtiff->im->BandFmt == VIPS_FORMAT_SHORT &&
			wtiff->im->Type == VIPS_INTERPRETATION_LABS )
			LabS2Lab16( q, p, area->width );
		else
			memcpy( q, p, 
				area->width * 
				 VIPS_IMAGE_SIZEOF_PEL( wtiff->im ) );

		q += wtiff->tls;
	}
}

/* Write a set of tiles across the strip.
 */
static int
wtiff_layer_write_tile( Wtiff *wtiff, Layer *layer, VipsRegion *strip )
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

		/* Have to repack pixels.
		 */
		wtiff_pack2tiff( wtiff, layer, strip, &tile, wtiff->tbuf );

#ifdef DEBUG_VERBOSE
		printf( "Writing %dx%d tile at position %dx%d to image %s\n",
			tile.width, tile.height, tile.left, tile.top,
			TIFFFileName( layer->tif ) );
#endif /*DEBUG_VERBOSE*/

		if( TIFFWriteTile( layer->tif, wtiff->tbuf, 
			tile.left, tile.top, 0, 0 ) < 0 ) {
			vips_error( "vips2tiff", 
				"%s", _( "TIFF write tile failed" ) );
			return( -1 );
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
			LabS2Lab16( wtiff->tbuf, p, im->Xsize );
			p = wtiff->tbuf;
		}
		else if( wtiff->onebit ) {
			eightbit2onebit( wtiff, wtiff->tbuf, p, im->Xsize );
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

		(void) vips_region_shrink( from, to, &target );

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
		result = wtiff_layer_write_tile( wtiff, layer, layer->strip );
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
	CopyField( TIFFTAG_ORIENTATION, i16 );
	CopyField( TIFFTAG_TILEWIDTH, i32 );
	CopyField( TIFFTAG_TILELENGTH, i32 );
	CopyField( TIFFTAG_ROWSPERSTRIP, i32 );
	CopyField( TIFFTAG_SUBFILETYPE, i32 );

	if( wtiff->predictor != VIPS_FOREIGN_TIFF_PREDICTOR_NONE ) 
		TIFFSetField( out, TIFFTAG_PREDICTOR, wtiff->predictor );

	/* TIFFTAG_JPEGQUALITY is a pesudo-tag, so we can't copy it.
	 * Set explicitly from Wtiff.
	 */
	if( wtiff->compression == COMPRESSION_JPEG ) {
		TIFFSetField( out, TIFFTAG_JPEGQUALITY, wtiff->jpqual );

		/* Only for three-band, 8-bit images.
		 */
		if( wtiff->im->Bands == 3 &&
			wtiff->im->BandFmt == VIPS_FORMAT_UCHAR ) { 
			/* Enable rgb->ycbcr conversion in the jpeg write. 
			 */
			if( !wtiff->rgbjpeg &&
				wtiff->jpqual < 90 ) 
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

	/* We can't copy profiles or xmp :( Set again from Wtiff.
	 */
	if( !wtiff->strip ) 
		if( wtiff_embed_profile( wtiff, out ) ||
			wtiff_embed_xmp( wtiff, out ) ||
			wtiff_embed_ipct( wtiff, out ) ||
			wtiff_embed_photoshop( wtiff, out ) ||
			wtiff_embed_imagedescription( wtiff, out ) )
			return( -1 );

	buf = vips_malloc( NULL, TIFFTileSize( in ) );
	n = TIFFNumberOfTiles( in );
	for( tile = 0; tile < n; tile++ ) {
		tsize_t len;

		/* It'd be good to use TIFFReadRawTile()/TIFFWtiffRawTile() 
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
wtiff_gather( Wtiff *wtiff )
{
	Layer *layer;

	if( wtiff->layer &&
		wtiff->layer->below )
		for( layer = wtiff->layer->below; layer; 
			layer = layer->below ) {
			TIFF *in;

#ifdef DEBUG
			printf( "Appending layer %s ...\n", layer->lname );
#endif /*DEBUG*/

			if( !(in = vips__tiff_openin( layer->lname )) ) 
				return( -1 );
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

/* Three types of write: single image, multipage and pyramid. 
 */
static int
wtiff_write_image( Wtiff *wtiff )
{
	if( wtiff->toilet_roll ) {
		int y;

#ifdef DEBUG
		printf( "wtiff_write_image: toilet-roll mode\n" ); 
#endif /*DEBUG*/

		y = 0;
		for(;;) {
			VipsImage *page;

			if( vips_crop( wtiff->im, &page, 
				0, y, wtiff->im->Xsize, wtiff->page_height,
				NULL ) )
				return( -1 ); 
			if( vips_sink_disc( page, write_strip, wtiff ) ) {
				g_object_unref( page );
				return( -1 );
			}
			g_object_unref( page );

			y += wtiff->page_height;
			if( y >= wtiff->im->Ysize )
				break;

			if( !TIFFWriteDirectory( wtiff->layer->tif ) || 
				wtiff_layer_rewind( wtiff, 
					wtiff->layer ) ||
				wtiff_write_header( wtiff, 
					wtiff->layer ) )
				return( -1 );
		}
	}
	else if( wtiff->pyramid ) {
#ifdef DEBUG
		printf( "wtiff_write_image: pyramid mode\n" ); 
#endif /*DEBUG*/

		if( vips_sink_disc( wtiff->im, write_strip, wtiff ) ) 
			return( -1 );

		if( !TIFFWriteDirectory( wtiff->layer->tif ) ) 
			return( -1 );

		if( wtiff->pyramid ) { 
			/* Free lower pyramid resources ... this will 
			 * TIFFClose() (but not delete) the smaller layers 
			 * ready for us to read from them again.
			 */
			if( wtiff->layer->below )
				layer_free_all( wtiff->layer->below );

			/* Append smaller layers to the main file.
			 */
			if( wtiff_gather( wtiff ) ) 
				return( -1 );
		}
	}
	else {
#ifdef DEBUG
		printf( "wtiff_write_image: single-image mode\n" ); 
#endif /*DEBUG*/

		if( vips_sink_disc( wtiff->im, write_strip, wtiff ) ) 
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
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties, gboolean strip )
{
	Wtiff *wtiff;

#ifdef DEBUG
	printf( "tiff2vips: libtiff version is \"%s\"\n", TIFFGetVersion() );
#endif /*DEBUG*/

	vips__tiff_init();

	if( vips_check_coding_known( "vips2tiff", in ) )
		return( -1 );

	if( !(wtiff = wtiff_new( in, filename, 
		compression, Q, predictor, profile,
		tile, tile_width, tile_height, pyramid, squash,
		miniswhite, resunit, xres, yres, bigtiff, rgbjpeg, 
		properties, strip )) )
		return( -1 );

	if( wtiff_write_image( wtiff ) ) { 
		wtiff_free( wtiff );
		return( -1 );
	}

	wtiff_free( wtiff );

	return( 0 );
}

int 
vips__tiff_write_buf( VipsImage *in, 
	void **obuf, size_t *olen, 
	VipsForeignTiffCompression compression, int Q, 
	VipsForeignTiffPredictor predictor,
	char *profile,
	gboolean tile, int tile_width, int tile_height,
	gboolean pyramid,
	gboolean squash,
	gboolean miniswhite,
	VipsForeignTiffResunit resunit, double xres, double yres,
	gboolean bigtiff,
	gboolean rgbjpeg,
	gboolean properties, gboolean strip )
{
	Wtiff *wtiff;

	vips__tiff_init();

	if( vips_check_coding_known( "vips2tiff", in ) )
		return( -1 );

	if( !(wtiff = wtiff_new( in, NULL, 
		compression, Q, predictor, profile,
		tile, tile_width, tile_height, pyramid, squash,
		miniswhite, resunit, xres, yres, bigtiff, rgbjpeg, 
		properties, strip )) )
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
