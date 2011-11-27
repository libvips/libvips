/* Read a virtual microscope slide using OpenSlide.
 *
 * Benjamin Gilbert
 *
 * Copyright (c) 2011 Carnegie Mellon University
 *
 * 26/11/11
 *	- initial version
 * 27/11/11
 *	- fix black background in transparent areas
 *	- no need to set *stop on fill_region() error return
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/

#ifdef HAVE_OPENSLIDE

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <openslide.h>

#include <vips/vips.h>
#include <vips/intl.h>

typedef struct {
	openslide_t *osr;
	uint32_t background;
} ReadSlide;

static void
close_slide( VipsImage *image, openslide_t *osr )
{
	openslide_close( osr );
}

static int
load_header( openslide_t *osr, VipsImage *out )
{
	int64_t w, h;

	openslide_get_layer0_dimensions( osr, &w, &h );
	if( w < 0 || h < 0 ) {
		vips_error( "im_openslide2vips", _( "getting dimensions: %s" ),
			openslide_get_error( osr ));
		return( -1 );
	}
	if( w > INT_MAX || h > INT_MAX ) {
		vips_error( "im_openslide2vips",
			_( "image dimensions overflow int" ));
		return( -1 );
	}
	vips_image_init_fields( out, (int) w, (int) h, 4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_RGB, 1.0, 1.0 );
	return( 0 );
}

static int
fill_region( VipsRegion *out, void *seq, void *_rslide, void *unused,
	gboolean *stop )
{
	ReadSlide *rslide = _rslide;
	uint32_t *buf;
	const char *error;
	PEL *pel;
	uint32_t sample;
	uint8_t a;
	int x, y;

	buf = vips_malloc( NULL, out->valid.width * out->valid.height *
		sizeof( *buf ));
	openslide_read_region( rslide->osr, buf, out->valid.left,
		out->valid.top, 0, out->valid.width, out->valid.height );
	for( y = 0; y < out->valid.height; y++ ) {
		for( x = 0; x < out->valid.width; x++ ) {
			/* Convert from ARGB to RGBA and undo
			 * premultiplication.
			 */
			pel = VIPS_REGION_ADDR( out, out->valid.left + x,
				out->valid.top + y );
			sample = buf[y * out->valid.height + x];
			a = sample >> 24;
			if( a != 0 ) {
				pel[0] = 255 * ((sample >> 16) & 255) / a;
				pel[1] = 255 * ((sample >> 8) & 255) / a;
				pel[2] = 255 * (sample & 255) / a;
			} else {
				/* Use background color.
				 */
				pel[0] = (rslide->background >> 16) & 255;
				pel[1] = (rslide->background >> 8) & 255;
				pel[2] = rslide->background & 255;
			}
			pel[3] = a;
		}
	}
	vips_free( buf );

	error = openslide_get_error( rslide->osr );
	if( error ) {
		vips_error( "im_openslide2vips", _( "reading region: %s" ),
			error );
		return( -1 );
	}
	return( 0 );
}

static int
openslide2vips_header( const char *filename, VipsImage *out )
{
	openslide_t *osr;
	int ret;

	osr = openslide_open( filename );
	if( osr == NULL ) {
		vips_error( "im_openslide2vips", _( "failure opening slide" ));
		return( -1 );
	}
	ret = load_header( osr, out );
	openslide_close( osr );
	return( ret );
}

/**
 * im_openslide2vips:
 * @filename: file to load
 * @out: image to write to
 *
 * Read a virtual slide supported by the OpenSlide library into a VIPS image.
 * OpenSlide supports images in Aperio, Hamamatsu VMS, Hamamatsu VMU, MIRAX,
 * and Trestle formats.  It also supports generic tiled TIFF images, but
 * im_openslide2vips() does not.
 *
 * Currently, only layer 0 (the highest-resolution slide layer) is used.
 *
 * See also: #VipsFormat
 *
 * Returns: 0 on success, -1 on error.
 */
static int
im_openslide2vips( const char *filename, VipsImage *out )
{
	ReadSlide *rslide;
	const char *background;

	rslide = VIPS_NEW( out, ReadSlide );

	rslide->osr = openslide_open( filename );
	if( rslide->osr == NULL ) {
		vips_error( "im_openslide2vips", _( "failure opening slide" ));
		return( -1 );
	}
	g_signal_connect( out, "close", G_CALLBACK( close_slide ),
		rslide->osr );

	background = openslide_get_property_value( rslide->osr,
		OPENSLIDE_PROPERTY_NAME_BACKGROUND_COLOR );
	if( background != NULL )
		rslide->background = strtoul( background, NULL, 16 );
	else
		rslide->background = 0xffffff;

	if( load_header( rslide->osr, out ) || vips_image_pio_output( out ))
		return( -1 );
	vips_demand_hint( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );
	return vips_image_generate( out, NULL, fill_region, NULL, rslide,
		NULL );
}

static int
isslide( const char *filename )
{
	openslide_t *osr;
	const char *vendor;
	int ok;

	ok = 1;
	osr = openslide_open(filename);
	if( osr != NULL ) {
		/* If this is a generic tiled TIFF image, decline to support
		 * it, since im_tiff2vips can do better.
		 */
		vendor = openslide_get_property_value( osr,
			OPENSLIDE_PROPERTY_NAME_VENDOR );
		if( vendor == NULL ||
			strcmp( vendor, "generic-tiff" ) == 0 )
			ok = 0;
		openslide_close( osr );
	} else {
		ok = 0;
	}
	return( ok );
}

static VipsFormatFlags
slide_flags( const char *filename )
{
	return( VIPS_FORMAT_PARTIAL );
}

/* openslide format adds no new members.
 */
typedef VipsFormat VipsFormatOpenslide;
typedef VipsFormatClass VipsFormatOpenslideClass;

static const char *slide_suffs[] = {
	".svs",			/* Aperio */
	".vms", ".vmu",		/* Hamamatsu */
	".mrxs",		/* MIRAX */
	".tif",			/* Trestle */
	NULL
};

static void
vips_format_openslide_class_init( VipsFormatOpenslideClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "openslide";
	object_class->description = _( "OpenSlide-supported" );

	format_class->is_a = isslide;
	format_class->header = openslide2vips_header;
	format_class->load = im_openslide2vips;
	format_class->get_flags = slide_flags;
	format_class->suffs = slide_suffs;

	/* Some TIFF files are virtual slides with odd vendor extensions
	 * (or outright format violations!).  Ensure we look at them before
	 * im_tiff2vips does.  OpenSlide tries very hard to reject files it
	 * doesn't understand, so this should be safe.
	 */
	format_class->priority = 100;
}

static void
vips_format_openslide_init( VipsFormatOpenslide *object )
{
}

G_DEFINE_TYPE( VipsFormatOpenslide, vips_format_openslide, VIPS_TYPE_FORMAT );

#endif /*HAVE_OPENSLIDE*/
