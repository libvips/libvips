/* Convert OpenEXR to VIPS
 *
 * 1/5/06
 * 	- from im_png2vips.c
 * 17/5/06
 * 	- oops, buffer calcs were wrong
 * 19/5/06
 * 	- added tiled read, with a separate cache
 * 	- removed *255 we had before, better to do something clever with
 * 	  chromaticities
 * 4/2/10
 * 	- gtkdoc
 * 12/12/11
 * 	- redo as a set of fns ready for wrapping in a new-style class
 * 17/9/16
 * 	- tag output as scRGB
 */

/*

  TODO

	- colour management
	- attributes 
	- more of OpenEXR's pixel formats 
	- more than just RGBA channels
	- turn alpha to vips 0 - 255 from exr 0 - 1

	the openexr C API is very limited ... it seems RGBA half pixels is 
	all you can do

	openexr lets you have different formats in different channels :-(

	there's no API to read the "chromaticities" attribute :-(

	best redo with the C++ API now we support C++ operations

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

#ifdef HAVE_OPENEXR

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/thread.h>
#include <vips/internal.h>

#include <ImfCRgbaFile.h>

#include "openexr2vips.h"

/* What we track during a OpenEXR read.
 */
typedef struct {
	char *filename;
	VipsImage *out;

	ImfTiledInputFile *tiles;
	ImfInputFile *lines;
	const ImfHeader *header;
	VipsRect window;
	int tile_width;
	int tile_height;
} Read;

gboolean
vips__openexr_isexr( const char *filename )
{
	unsigned char buf[4];

	if( vips__get_bytes( filename, buf, 4 ) )
		if( buf[0] == 0x76 && buf[1] == 0x2f &&
			buf[2] == 0x31 && buf[3] == 0x01 )
			return( TRUE );

	return( FALSE );
}

static void
get_imf_error( void )
{
	vips_error( "exr2vips", _( "EXR error: %s" ), ImfErrorMessage() );
}

static void
read_destroy( VipsImage *out, Read *read )
{
	VIPS_FREE( read->filename );

	VIPS_FREEF( ImfCloseTiledInputFile, read->tiles );
	VIPS_FREEF( ImfCloseInputFile, read->lines );

	vips_free( read );
}

static Read *
read_new( const char *filename, VipsImage *out )
{
	Read *read;
	int xmin, ymin;
	int xmax, ymax;

	if( !(read = VIPS_NEW( NULL, Read )) )
		return( NULL );
	read->filename = vips_strdup( NULL, filename );
	read->out = out;
	read->tiles = NULL;
	read->lines = NULL;
	if( out ) 
		g_signal_connect( out, "close", 
			G_CALLBACK( read_destroy ), read ); 

	/* Try to open tiled first ... if that fails, fall back to scanlines.

	   	FIXME ... seems a bit ugly, but how else can you spot a tiled 
		EXR image?

	 */
	if( !(read->tiles = ImfOpenTiledInputFile( read->filename )) ) {
		if( !(read->lines = ImfOpenInputFile( read->filename )) ) {
			get_imf_error();
			return( NULL );
		}
	}

#ifdef DEBUG
	if( read->tiles )
		printf( "exr2vips: opening in tiled mode\n" );
	else
		printf( "exr2vips: opening in scanline mode\n" );
#endif /*DEBUG*/

	if( read->tiles ) {
		read->header = ImfTiledInputHeader( read->tiles );
		read->tile_width = ImfTiledInputTileXSize( read->tiles );
		read->tile_height = ImfTiledInputTileYSize( read->tiles );
	}
	else
		read->header = ImfInputHeader( read->lines );

	ImfHeaderDataWindow( read->header, &xmin, &ymin, &xmax, &ymax );
	read->window.left = xmin;
	read->window.top = ymin;
	read->window.width = xmax - xmin + 1;
	read->window.height = ymax - ymin + 1;

	return( read );
}

gboolean
vips__openexr_istiled( const char *filename )
{
	Read *read;
	gboolean tiled;

	if( !(read = read_new( filename, NULL )) )
		return( FALSE );
	tiled = read->tiles != NULL;
	read_destroy( NULL, read );

	return( tiled );
}

/* Read a OpenEXR file (header) into a VIPS (header).
 */
static void
read_header( Read *read, VipsImage *out )
{
	/* 

	   FIXME ... not really scRGB, you should get the chromaticities 
	   from the header and transform 

	 */
	vips_image_init_fields( out,
		 read->window.width, read->window.height, 4,
		 VIPS_FORMAT_FLOAT,
		 VIPS_CODING_NONE, VIPS_INTERPRETATION_scRGB, 1.0, 1.0 );
	if( read->tiles )
		vips_image_pipelinev( out, VIPS_DEMAND_STYLE_SMALLTILE, NULL );
	else
		vips_image_pipelinev( out, VIPS_DEMAND_STYLE_FATSTRIP, NULL );
}

int
vips__openexr_read_header( const char *filename, VipsImage *out )
{
	Read *read;

	if( !(read = read_new( filename, out )) )
		return( -1 );
	read_header( read, out );

	return( 0 );
}

/* Allocate a tile buffer.
 */
static void *
vips__openexr_start( VipsImage *out, void *a, void *b )
{
	Read *read = (Read *) a;
	ImfRgba *imf_buffer;

	if( !(imf_buffer = VIPS_ARRAY( out,
		read->tile_width * read->tile_height, ImfRgba )) )
		return( NULL );

	return( imf_buffer );
}

static int
vips__openexr_generate( VipsRegion *out, 
	void *seq, void *a, void *b, gboolean *top )
{
	ImfRgba *imf_buffer = (ImfRgba *) seq;
	Read *read = (Read *) a;
	VipsRect *r = &out->valid;

	const int tw = read->tile_width;
	const int th = read->tile_height;

	/* Find top left of tiles we need.
	 */
	const int xs = (r->left / tw) * tw;
	const int ys = (r->top / th) * th;

	int x, y, z;
	VipsRect image;

	/* Area of image.
	 */
	image.left = 0;
	image.top = 0;
	image.width = read->out->Xsize;
	image.height = read->out->Ysize;

	for( y = ys; y < VIPS_RECT_BOTTOM( r ); y += th )
		for( x = xs; x < VIPS_RECT_RIGHT( r ); x += tw ) {
			VipsRect tile;
			VipsRect hit;
			int result;

			if( !ImfTiledInputSetFrameBuffer( read->tiles,
				imf_buffer - 
					(read->window.left + x) -
					(read->window.top + y) * tw,
				1, tw ) ) {
				get_imf_error();
				return( -1 );
			}

#ifdef DEBUG
			printf( "exr2vips: requesting tile %d x %d\n", 
				x / tw, y / th );
#endif /*DEBUG*/

			result = ImfTiledInputReadTile( read->tiles, 
				x / tw, y / th, 0, 0 );

			if( !result ) {
				get_imf_error();
				return( -1 );
			}

			/* The tile in the file, in VIPS coordinates.
			 */
			tile.left = x;
			tile.top = y;
			tile.width = tw;
			tile.height = th;
			vips_rect_intersectrect( &tile, &image, &tile );

			/* The part of this tile that hits the region.
			 */
			vips_rect_intersectrect( &tile, r, &hit );

			/* Convert to float and write to the region.
			 */
			for( z = 0; z < hit.height; z++ ) {
				ImfRgba *p = imf_buffer + 
					(hit.left - tile.left) +
					(hit.top - tile.top + z) * tw;
				float *q = (float *) VIPS_REGION_ADDR( out,
					hit.left, hit.top + z );

				ImfHalfToFloatArray( 4 * hit.width, 
					(ImfHalf *) p, q );
			}
		}

	return( 0 );
}

int
vips__openexr_read( const char *filename, VipsImage *out )
{
	Read *read;

	if( !(read = read_new( filename, out )) )
		return( -1 );

	if( read->tiles ) {
		VipsImage *raw;
		VipsImage *t;

		/* Tile cache: keep enough for two complete rows of tiles.
		 */
		raw = vips_image_new();
		vips_object_local( out, raw );

		read_header( read, raw );

		if( vips_image_generate( raw, 
			vips__openexr_start, vips__openexr_generate, NULL, 
			read, NULL ) )
			return( -1 );

		/* Copy to out, adding a cache. Enough tiles for a complete 
		 * row, plus 50%.
		 */
		if( vips_tilecache( raw, &t, 
			"tile_width", read->tile_width, 
			"tile_height", read->tile_height,
			"max_tiles", (int) 
				(1.5 * (1 + raw->Xsize / read->tile_width)),
			NULL ) ) 
			return( -1 );
		if( vips_image_write( t, out ) ) {
			g_object_unref( t );
			return( -1 );
		}
		g_object_unref( t );
	}
	else {
		const int left = read->window.left;
		const int top = read->window.top;
		const int width = read->window.width;
		const int height = read->window.height;

		ImfRgba *imf_buffer;
		float *vips_buffer;
		int y;

		if( !(imf_buffer = VIPS_ARRAY( out, width, ImfRgba )) ||
			!(vips_buffer = VIPS_ARRAY( out, 4 * width, float )) )
			return( -1 );

		read_header( read, out );

		for( y = 0; y < height; y++ ) {
			if( !ImfInputSetFrameBuffer( read->lines,
				imf_buffer - left - (top + y) * width,
				1, width ) ) {
				get_imf_error();
				return( -1 );
			}
			if( !ImfInputReadPixels( read->lines, 
				top + y, top + y ) ) {
				get_imf_error();
				return( -1 );
			}

			ImfHalfToFloatArray( 4 * width, 
				(ImfHalf *) imf_buffer, vips_buffer );

			if( vips_image_write_line( out, y, 
				(VipsPel *) vips_buffer ) )
				return( -1 );
		}
	}

	return( 0 );
}

#endif /*HAVE_OPENEXR*/
