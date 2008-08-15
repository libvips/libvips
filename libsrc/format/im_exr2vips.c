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

	- colour management
	- attributes 
	- more of OpenEXR's pixel formats 
	- more than just RGBA channels

	the openexr C API is very limited ... it seems RGBA half pixels is 
	all you can do

	openexr lets you have different formats in different channels :-(

	there's no API to read the "chromaticities" attribute :-(

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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#ifndef HAVE_OPENEXR

#include <vips/vips.h>

int
im_exr2vips( const char *name, IMAGE *out )
{
	im_error( "im_exr2vips", _( "OpenEXR support disabled" ) );
	return( -1 );
}

int
im_exr2vips_header( const char *name, IMAGE *out )
{
	im_error( "im_exr2vips_header", _( "OpenEXR support disabled" ) );
	return( -1 );
}

int
im_isexrtiled( const char *name )
{
	im_error( "im_isexrtiled", _( "OpenEXR support disabled" ) );
	return( -1 );
}

#else /*HAVE_OPENEXR*/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/thread.h>

#include <ImfCRgbaFile.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* What we track during a OpenEXR read.
 */
typedef struct {
	char *name;
	IMAGE *out;

	ImfTiledInputFile *tiles;
	ImfInputFile *lines;
	const ImfHeader *header;
	Rect window;
	int tile_width;
	int tile_height;

	/* Need to single-thread calls to ReadTile.
	 */
	GMutex *lock;
} Read;

static void
get_imf_error( void )
{
	im_error( "im_exr2vips", _( "EXR error: %s" ), ImfErrorMessage() );
}

static void
read_destroy( Read *read )
{
	IM_FREE( read->name );

	IM_FREEF( ImfCloseTiledInputFile, read->tiles );
	IM_FREEF( ImfCloseInputFile, read->lines );

	IM_FREEF( g_mutex_free, read->lock );

	im_free( read );
}

static Read *
read_new( const char *name, IMAGE *out )
{
	Read *read;
	int xmin, ymin;
	int xmax, ymax;

	if( !(read = IM_NEW( NULL, Read )) )
		return( NULL );

	read->name = im_strdup( NULL, name );
	read->out = out;
	read->tiles = NULL;
	read->lines = NULL;
	read->lock = NULL;

	if( im_add_close_callback( out, 
		(im_callback_fn) read_destroy, read, NULL ) ) {
		read_destroy( read );
		return( NULL );
	}

	/* Try to open tiled first ... if that fails, fall back to scanlines.

	   	FIXME ... seems a bit ugly, but how else can you spot a tiled 
		EXR image?

	 */
	if( !(read->tiles = ImfOpenTiledInputFile( read->name )) ) {
		if( !(read->lines = ImfOpenInputFile( read->name )) ) {
			get_imf_error();
			return( NULL );
		}
	}

#ifdef DEBUG
	if( read->tiles )
		printf( "im_exr2vips: opening in tiled mode\n" );
	else
		printf( "im_exr2vips: opening in scanline mode\n" );
#endif /*DEBUG*/

	if( read->tiles ) {
		read->header = ImfTiledInputHeader( read->tiles );
		read->lock = g_mutex_new();
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

/* Read a OpenEXR file (header) into a VIPS (header).
 */
static int
exr2vips_header( Read *read, IMAGE *out )
{
	/* 

	   FIXME ... not really sRGB. I think EXR is actually linear (no 
	   gamma). We ought to read the chromaticities from the header, put 
	   through a 3x3 matrix and output as XYZ

	 */
	im_initdesc( out,
		 read->window.width, read->window.height, 4,
		 IM_BBITS_FLOAT, IM_BANDFMT_FLOAT,
		 IM_CODING_NONE, IM_TYPE_sRGB, 1.0, 1.0, 0, 0 );

	return( 0 );
}

/* Read a OpenEXR file header into a VIPS header.
 */
int
im_exr2vips_header( const char *name, IMAGE *out )
{
	Read *read;

	if( !(read = read_new( name, out )) ||
		exr2vips_header( read, out ) ) 
		return( -1 );

	return( 0 );
}

/* Test for tiled EXR.
 */
int
im_isexrtiled( const char *name )
{
	Read *read;
	int tiled;

	if( !(read = read_new( name, NULL )) )
		return( -1 );
	tiled = read->tiles != NULL;
	read_destroy( read );

	return( tiled );
}

static int
fill_region( REGION *out, void *seq, void *a, void *b )
{
	ImfRgba *imf_buffer = (ImfRgba *) seq;
	Read *read = (Read *) a;
	Rect *r = &out->valid;

	const int tw = read->tile_width;
	const int th = read->tile_height;

	/* Find top left of tiles we need.
	 */
	const int xs = (r->left / tw) * tw;
	const int ys = (r->top / th) * th;

	int x, y, z;
	Rect image;

	/* Area of image.
	 */
	image.left = 0;
	image.top = 0;
	image.width = read->out->Xsize;
	image.height = read->out->Ysize;

	for( y = ys; y < IM_RECT_BOTTOM( r ); y += th )
		for( x = xs; x < IM_RECT_RIGHT( r ); x += tw ) {
			Rect tile;
			Rect hit;
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
			printf( "im_exr2vips: requesting tile %d x %d\n", 
				x / tw, y / th );
#endif /*DEBUG*/

			g_mutex_lock( read->lock );
			result = ImfTiledInputReadTile( read->tiles, 
				x / tw, y / th, 0, 0 );
			g_mutex_unlock( read->lock );

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
			im_rect_intersectrect( &tile, &image, &tile );

			/* The part of this tile that hits the region.
			 */
			im_rect_intersectrect( &tile, r, &hit );

			/* Convert to float and write to the region.
			 */
			for( z = 0; z < hit.height; z++ ) {
				ImfRgba *p = imf_buffer + 
					(hit.left - tile.left) +
					(hit.top - tile.top + z) * tw;
				float *q = (float *) IM_REGION_ADDR( out,
					hit.left, hit.top + z );

				ImfHalfToFloatArray( 4 * hit.width, 
					(ImfHalf *) p, q );
			}
		}

	return( 0 );
}

/* Allocate a tile buffer.
 */
static void *
seq_start( IMAGE *out, void *a, void *b )
{
	Read *read = (Read *) a;
	ImfRgba *imf_buffer;

	if( !(imf_buffer = IM_ARRAY( out,
		read->tile_width * read->tile_height, ImfRgba )) )
		return( NULL );

	return( imf_buffer );
}

/* Read tilewise.
 */
static int
exr2vips_tiles( Read *read, IMAGE *out )
{
	if( exr2vips_header( read, out ) || 
		im_poutcheck( out ) ||
		im_demand_hint( out, IM_SMALLTILE, NULL ) ||
		im_generate( out, seq_start, fill_region, NULL, read, NULL ) )
		return( -1 );

	return( 0 );
}

/* Read scanlinewise.
 */
static int
exr2vips_lines( Read *read, IMAGE *out )
{
	const int left = read->window.left;
	const int top = read->window.top;
	const int width = read->window.width;
	const int height = read->window.height;

	ImfRgba *imf_buffer;
	float *vips_buffer;
	int y;

	if( !(imf_buffer = IM_ARRAY( out, width, ImfRgba )) ||
		!(vips_buffer = IM_ARRAY( out, 4 * width, float )) ||
		exr2vips_header( read, out ) ||
		im_outcheck( out ) || 
		im_setupout( out ) )
		return( -1 );

	for( y = 0; y < height; y++ ) {
		if( !ImfInputSetFrameBuffer( read->lines,
			imf_buffer - left - (top + y) * width,
			1, width ) ) {
			get_imf_error();
			return( -1 );
		}
		if( !ImfInputReadPixels( read->lines, top + y, top + y ) ) {
			get_imf_error();
			return( -1 );
		}

		ImfHalfToFloatArray( 4 * width, 
			(ImfHalf *) imf_buffer, vips_buffer );

		if( im_writeline( y, out, (PEL *) vips_buffer ) )
			return( -1 );
	}

	return( 0 );
}

static int
exr2vips( Read *read )
{
	if( read->tiles ) {
		IMAGE *raw;

		/* Tile cache: keep enough for two complete rows of tiles.
		 * This lets us do (smallish) area ops, like im_conv(), while
		 * still only hitting each OpenEXR tile once.
		 */
		if( !(raw = im_open_local( read->out, "cache", "p" )) )
			return( -1 );
		if( exr2vips_tiles( read, raw ) ) 
			return( -1 );
		if( im_tile_cache( raw, read->out, 
			read->tile_width, read->tile_height,
			2 * (1 + raw->Xsize / read->tile_width) ) ) 
			return( -1 );
	}
	else {
		if( exr2vips_lines( read, read->out ) ) 
			return( -1 );
	}

	return( 0 );
}

/* Read a OpenEXR file into a VIPS image.
 */
int
im_exr2vips( const char *name, IMAGE *out )
{
	Read *read;

#ifdef DEBUG
	printf( "im_exr2vips: reading \"%s\"\n", name );
#endif /*DEBUG*/

	if( !(read = read_new( name, out )) ||
		exr2vips( read ) ) 
		return( -1 );

	return( 0 );
}

#endif /*HAVE_OPENEXR*/
