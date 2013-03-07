/* save to deep zoom format
 *
 * 21/3/12
 * 	- from the tiff pyramid writer
 * 5/7/12 (thanks Alexander Koshman)
 * 	- make tiles down to 1x1 pixels 
 *	- oop make right-hand edge tiles 
 *	- improve overlap handling 
 * 7/7/12
 * 	- threaded write
 * 6/8/12 (thanks to Benjamin Gilbert for pointing out the errors)
 * 	- shrink down to a 1x1 pixel tile, even for very long and thin images
 * 	- round image size up on shrink
 * 	- write a .dzi file with the pyramid params
 * 	- default tile size and overlap now matches the openslide writer
 * 7/8/12 (thanks to Benjamin Gilbert again for more testing)
 * 	- reorganise the directory structure
 * 	- rename to basename and tile_size
 * 	- deprecate tile_width/_height and dirname 
 * 1/10/12
 * 	- did not write low pyramid layers for images with an odd number of
 * 	  scan lines (thanks Martin)
 * 2/10/12
 * 	- remove filename options from format string in .dzi (thanks Martin)
 * 3/10/12
 * 	- add zoomify and google maps output
 * 10/10/12
 * 	- add @background option
 * 1/11/12
 * 	- add @depth option
 * 21/1/13
 * 	- add @centre option
 * 26/2/13
 * 	- fix another corner case, thanks Martin
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

   This is difficult to test, there are so many options.

   It's failed in the past in these cases. These have layers with strips which 
   exactly align with image edges, or which have orphan scanlines which need 
   adding for the shrink. 

   1.	$ header test.v
	test.v: 14016x16448 uchar, 3 bands, srgb, openin VipsImage (0x11e7060)
	$ time vips dzsave test.v x --overlap 0

	Not all layers written.

   2.	$ header ~/Desktop/leicaimage.scn 
	/home/john/Desktop/leicaimage.scn: 4225x7905 uchar, 4 bands, rgb

	Not all layers written. 

    3.	$ header ~/leicatest1.scn 
	/home/john/leicatest1.scn: 11585x8449 uchar, 4 bands, rgb

	Not all layers written. 

   various combinations of odd and even tile-size and overlap need testing too.

 */

/*
#define DEBUG_VERBOSE
#define DEBUG
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

/* Round N down to P boundary. 
 */
#define ROUND_DOWN(N,P) ((N) - ((N) % P)) 

/* Round N up to P boundary. 
 */
#define ROUND_UP(N,P) (ROUND_DOWN( (N) + (P) - 1, (P) ))

typedef struct _VipsForeignSaveDz VipsForeignSaveDz;
typedef struct _Layer Layer;

/* A layer in the pyramid.
 */
struct _Layer {
	VipsForeignSaveDz *dz;

	/* The real size of the image. image->Xsize and image->Ysize are
	 * always even to make x2 shrink easy. The real image may be a 
	 * smaller, odd size, 
	 */
	int width;
	int height;

	/* Number of tiles across and down in this layer. Zoomify needs this
	 * to calculate the directory to put each tile in.
	 */
	int tiles_across;
	int tiles_down;

	VipsImage *image;		/* The image we build */

	/* The top of this strip of tiles, excluding the overlap. Go up from
	 * this to get to the top pixel we write in each one.
	 */
	int y;

	/* The next line we write to in this strip. 
	 */
	int write_y;

	VipsRegion *strip;		/* The current strip of pixels */
	VipsRegion *copy;		/* Pixels we copy to the next strip */

	int sub;			/* Subsample factor for this layer */
	int n;				/* Layer number ... 0 for smallest */

	Layer *below;			/* Tiles go to here */
	Layer *above;			/* Tiles come from here */
};

struct _VipsForeignSaveDz {
	VipsForeignSave parent_object;

	/* Name to write to. 
	 */
	char *basename; 

	char *suffix;
	int overlap;
	int tile_size;
	VipsForeignDzLayout layout;
	VipsArrayDouble *background;
	VipsForeignDzDepth depth;
	gboolean centre;

	Layer *layer;			/* x2 shrink pyr layer */

	/* Count zoomify tiles we write.
	 */
	int tile_count;
};

typedef VipsForeignSaveClass VipsForeignSaveDzClass;

G_DEFINE_TYPE( VipsForeignSaveDz, vips_foreign_save_dz, 
	VIPS_TYPE_FOREIGN_SAVE );

/* Free a pyramid.
 */
static void
layer_free( Layer *layer )
{
	VIPS_FREEF( g_object_unref, layer->strip );
	VIPS_FREEF( g_object_unref, layer->copy );
	VIPS_FREEF( g_object_unref, layer->image );

	VIPS_FREEF( layer_free, layer->below ); 
}

static void
vips_foreign_save_dz_dispose( GObject *gobject )
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) gobject;

	VIPS_FREEF( layer_free, dz->layer );

	G_OBJECT_CLASS( vips_foreign_save_dz_parent_class )->dispose( gobject );
}

/* Build a pyramid. 
 */
static Layer *
pyramid_build( VipsForeignSaveDz *dz, Layer *above, int width, int height )
{
	VipsForeignSave *save = VIPS_FOREIGN_SAVE( dz );
	Layer *layer = VIPS_NEW( dz, Layer );

	VipsRect strip;
	int limit; 

	layer->dz = dz;
	layer->width = width;
	layer->height = height;

	layer->tiles_across = ROUND_UP( width, dz->tile_size ) / dz->tile_size;
	layer->tiles_down = ROUND_UP( height, dz->tile_size ) / dz->tile_size;

	layer->image = NULL;
	layer->strip = NULL;
	layer->copy = NULL;

	if( !above )
		/* Top of pyramid.
		 */
		layer->sub = 1;	
	else
		layer->sub = above->sub * 2;

	layer->below = NULL;
	layer->above = above;

	/* We round the image size up to an even number to make x2 shrink
	 * easy.
	 */
	layer->image = vips_image_new();
	if( vips_image_copy_fields( layer->image, save->ready ) ) {
		layer_free( layer );
		return( NULL );
	}
	layer->image->Xsize = width + (width & 1);
	layer->image->Ysize = height + (height & 1);

	layer->strip = vips_region_new( layer->image );
	layer->copy = vips_region_new( layer->image );

	/* The regions will get used in the bg thread callback, so make sure
	 * we don't own them.
	 */
	vips__region_no_ownership( layer->strip );
	vips__region_no_ownership( layer->copy );

	/* Build a line of tiles here. Normally strips are height + 2 *
	 * overlap, but the first row is missing the top edge.
	 *
	 * Expand the strip if necessary to make sure we have an even 
	 * number of lines. 
	 */
	layer->y = 0;
	layer->write_y = 0;
	strip.left = 0;
	strip.top = 0;
	strip.width = layer->image->Xsize;
	strip.height = dz->tile_size + dz->overlap;
	if( (strip.height & 1) == 1 )
		strip.height += 1;
	if( vips_region_buffer( layer->strip, &strip ) ) {
		layer_free( layer );
		return( NULL );
	}

	switch( dz->depth ) {
	case VIPS_FOREIGN_DZ_DEPTH_1PIXEL:
		limit = 1;
		break;

	case VIPS_FOREIGN_DZ_DEPTH_1TILE:
		limit = dz->tile_size;
		break;

	case VIPS_FOREIGN_DZ_DEPTH_1:
		limit = VIPS_MAX( width, height );
		break;

	default:
		g_assert( 0 );
		limit = dz->tile_size;
		break;
	}

	if( width > limit || 
		height > limit ) {
		/* Round up, so eg. a 5 pixel wide image becomes 3 a layer
		 * down.
		 */
		if( !(layer->below = pyramid_build( dz, 
			layer, (width + 1) / 2, (height + 1) / 2 )) ) {
			layer_free( layer );
			return( NULL );
		}
		layer->n = layer->below->n + 1;
	}
	else
		layer->n = 0;

#ifdef DEBUG
	printf( "pyramid_build:\n" );
	printf( "\tn = %d\n", layer->n );
	printf( "\twidth = %d, height = %d\n", width, height );
	printf( "\tXsize = %d, Ysize = %d\n", 
		layer->image->Xsize, layer->image->Ysize );
#endif

	return( layer );
}

static int
pyramid_mkdir( VipsForeignSaveDz *dz )
{
	char buf[PATH_MAX];

	if( dz->layout == VIPS_FOREIGN_DZ_LAYOUT_DZ )
		vips_snprintf( buf, PATH_MAX, "%s_files", dz->basename );
	else
		vips_snprintf( buf, PATH_MAX, "%s", dz->basename );

	if( vips_existsf( "%s", buf ) ) { 
		vips_error( "dzsave", 
			_( "Directory \"%s\" exists" ), buf );
		return( -1 );
	}
	if( vips_mkdirf( "%s", buf ) ) 
		return( -1 );

	return( 0 );
}

static int
write_dzi( VipsForeignSaveDz *dz )
{
	FILE *fp;
	char buf[PATH_MAX];
	char *p;

	vips_snprintf( buf, PATH_MAX, "%s.dzi", dz->basename );
	if( !(fp = vips__file_open_write( buf, TRUE )) )
		return( -1 );

	vips_snprintf( buf, PATH_MAX, "%s", dz->suffix + 1 );
	if( (p = (char *) vips__find_rightmost_brackets( buf )) )
		*p = '\0';

	fprintf( fp, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ); 
	fprintf( fp, "<Image "
		"xmlns=\"http://schemas.microsoft.com/deepzoom/2008\"\n" );
	fprintf( fp, "  Format=\"%s\"\n", buf );
	fprintf( fp, "  Overlap=\"%d\"\n", dz->overlap );
	fprintf( fp, "  TileSize=\"%d\"\n", dz->tile_size );
	fprintf( fp, "  >\n" ); 
	fprintf( fp, "  <Size \n" );
	fprintf( fp, "    Height=\"%d\"\n", dz->layer->height );
	fprintf( fp, "    Width=\"%d\"\n", dz->layer->width );
	fprintf( fp, "  />\n" ); 
	fprintf( fp, "</Image>\n" );

	fclose( fp );

	return( 0 );
}

static int
write_properties( VipsForeignSaveDz *dz )
{
	FILE *fp;
	char buf[PATH_MAX];

	vips_snprintf( buf, PATH_MAX, "%s/ImageProperties.xml", dz->basename );
	if( !(fp = vips__file_open_write( buf, TRUE )) )
		return( -1 );

	fprintf( fp, "<IMAGE_PROPERTIES "
		"WIDTH=\"%d\" HEIGHT=\"%d\" NUMTILES=\"%d\" "
		"NUMIMAGES=\"1\" VERSION=\"1.8\" TILESIZE=\"%d\" />\n",
		dz->layer->width,
		dz->layer->height,
		dz->tile_count,
		dz->tile_size );

	fclose( fp );

	return( 0 );
}

static int
write_blank( VipsForeignSaveDz *dz )
{
	char buf[PATH_MAX];
	VipsImage *x, *t;
	int n;
	VipsArea *ones;
	double *d;
	int i;

	vips_snprintf( buf, PATH_MAX, "%s/blank.png", dz->basename );
	if( vips_black( &x, dz->tile_size, dz->tile_size, NULL ) ) 
		return( -1 );

	vips_area_get_data( (VipsArea *) dz->background, NULL, &n, NULL, NULL );
	ones = vips_area_new_array( G_TYPE_DOUBLE, sizeof( double ), n );
	d = (double *) vips_area_get_data( ones, NULL, NULL, NULL, NULL );
	for( i = 0; i < n; i++ )
		d[i] = 1.0; 
	if( vips_linear( x, &t, 
		d, 
		(double *) vips_area_get_data( (VipsArea *) dz->background, 
			NULL, NULL, NULL, NULL ),
		n, NULL ) ) {
		vips_area_unref( ones );
		g_object_unref( x );
		return( -1 );
	}
	vips_area_unref( ones );
	g_object_unref( x );
	x = t;

	if( vips_image_write_to_file( x, buf ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

/* Generate area @target in @to using pixels in @from. VIPS_CODING_LABQ only.
 */
static void
shrink_region_labpack( VipsRegion *from, VipsRegion *to, VipsRect *target )
{
	int ls = VIPS_REGION_LSKIP( from );

	int x, y;

	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			target->left * 2, (target->top + y) * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, 
			target->left, target->top + y );

		/* Ignore the extra bits for speed.
		 */
		for( x = 0; x < target->width; x++ ) {
			signed char *sp = (signed char *) p;
			unsigned char *up = (unsigned char *) p;

			int l = up[0] + up[4] + 
				up[ls] + up[ls + 4];
			int a = sp[1] + sp[5] + 
				sp[ls + 1] + sp[ls + 5];
			int b = sp[2] + sp[6] + 
				sp[ls + 2] + sp[ls + 6];

			q[0] = l >> 2;
			q[1] = a >> 2;
			q[2] = b >> 2;
			q[3] = 0;

			q += 4;
			p += 8;
		}
	}
}

#define SHRINK_TYPE_INT( TYPE ) \
	for( x = 0; x < target->width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tp1 = (TYPE *) (p + ls); \
		TYPE *tq = (TYPE *) q; \
 		\
		for( z = 0; z < nb; z++ ) { \
			int tot = tp[z] + tp[z + nb] +  \
				tp1[z] + tp1[z + nb]; \
			\
			tq[z] = tot >> 2; \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		p += ps << 1; \
		q += ps; \
	}

#define SHRINK_TYPE_FLOAT( TYPE )  \
	for( x = 0; x < target->width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tp1 = (TYPE *) (p + ls); \
		TYPE *tq = (TYPE *) q; \
		\
		for( z = 0; z < nb; z++ ) { \
			double tot = tp[z] + tp[z + nb] +  \
				tp1[z] + tp1[z + nb]; \
			\
			tq[z] = tot / 4; \
		} \
		\
		/* Move on two pels in input. \
		 */ \
		p += ps << 1; \
		q += ps; \
	}

/* Generate area @target in @to using pixels in @from. Non-complex.
 */
static void
shrink_region_uncoded( VipsRegion *from, VipsRegion *to, VipsRect *target )
{
	int ls = VIPS_REGION_LSKIP( from );
	int ps = VIPS_IMAGE_SIZEOF_PEL( from->im );
	int nb = from->im->Bands;

	int x, y, z;

	for( y = 0; y < target->height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			target->left * 2, (target->top + y) * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, 
			target->left, target->top + y );

		/* Process this line of pels.
		 */
		switch( from->im->BandFmt ) {
		case VIPS_FORMAT_UCHAR:	
			SHRINK_TYPE_INT( unsigned char );  break; 
		case VIPS_FORMAT_CHAR:	
			SHRINK_TYPE_INT( signed char );  break; 
		case VIPS_FORMAT_USHORT:	
			SHRINK_TYPE_INT( unsigned short );  break; 
		case VIPS_FORMAT_SHORT:	
			SHRINK_TYPE_INT( signed short );  break; 
		case VIPS_FORMAT_UINT:	
			SHRINK_TYPE_INT( unsigned int );  break; 
		case VIPS_FORMAT_INT:	
			SHRINK_TYPE_INT( signed int );  break; 
		case VIPS_FORMAT_FLOAT:	
			SHRINK_TYPE_FLOAT( float );  break; 
		case VIPS_FORMAT_DOUBLE:	
			SHRINK_TYPE_FLOAT( double );  break; 

		default:
			g_assert( 0 );
		}
	}
}

/* Our state during a threaded write of a strip.
 */
typedef struct _Strip {
	Layer *layer; 

	VipsImage *image;

	/* Allocate the next tile on this boundary. 
	 */
	int x;
} Strip;

static void
strip_free( Strip *strip )
{
	g_object_unref( strip->image );
}

static void
strip_init( Strip *strip, Layer *layer )
{
	VipsForeignSaveDz *dz = layer->dz;

	VipsRect line, image;

	strip->layer = layer;
	strip->image = NULL;
	strip->x = 0;

	/* The image we wrap around our pixel buffer must be the full width,
	 * including any rounding up, since we must have contiguous pixels.
	 * We can trim the height down though.
	 *
	 * When we loop across the strip writing tiles we have to look out for
	 * the smaller width.
	 */
	image.left = 0;
	image.top = 0;
	image.width = layer->image->Xsize;
	image.height = layer->height;

	line.left = 0;
	line.top = layer->y - dz->overlap;
	line.width = image.width;
	line.height = dz->tile_size + 2 * dz->overlap;

	vips_rect_intersectrect( &image, &line, &line );

	if( !(strip->image = vips_image_new_from_memory( 
		VIPS_REGION_ADDR( layer->strip, 0, line.top ),
		line.width, line.height, 
		layer->image->Bands, layer->image->BandFmt )) ) {
		strip_free( strip );
		return;
	}
}

static int
strip_allocate( VipsThreadState *state, void *a, gboolean *stop )
{
	Strip *strip = (Strip *) a;
	Layer *layer = strip->layer;
	VipsForeignSaveDz *dz = layer->dz;

	VipsRect image;

#ifdef DEBUG_VERBOSE
	printf( "strip_allocate\n" );
#endif /*DEBUG_VERBOSE*/

	image.left = 0;
	image.top = 0;
	image.width = layer->width;
	image.height = layer->height;

	/* Position this tile.
	 */
	state->pos.left = strip->x - dz->overlap;
	state->pos.top = 0;
	state->pos.width = dz->tile_size + 2 * dz->overlap;
	state->pos.height = state->im->Ysize;

	vips_rect_intersectrect( &image, &state->pos, &state->pos );
	state->x = strip->x;
	state->y = layer->y;

	strip->x += dz->tile_size;

	if( vips_rect_isempty( &state->pos ) ) {
		*stop = TRUE;
#ifdef DEBUG_VERBOSE
		printf( "strip_allocate: done\n" );
#endif /*DEBUG_VERBOSE*/

		return( 0 );
	}

	return( 0 );
}

/* Create a tile name in the current layout.
 */
static int
tile_name( Layer *layer, char *buf, int x, int y )
{
	/* Need to lock around exists()/mkdir() or there's a race. 
	 */
	static GMutex *file_lock = NULL;
	static GOnce file_lock_once = G_ONCE_INIT;

	VipsForeignSaveDz *dz = layer->dz;

	char dirname[PATH_MAX];
	char dirname2[PATH_MAX];
	Layer *p;
	int n;

	file_lock = g_once( &file_lock_once, 
		(GThreadFunc) vips_g_mutex_new, NULL );
	g_mutex_lock( file_lock );

	switch( dz->layout ) {
	case VIPS_FOREIGN_DZ_LAYOUT_DZ:
		vips_snprintf( dirname, PATH_MAX, "%s_files/%d", 
			dz->basename, layer->n );
		vips_snprintf( buf, PATH_MAX, "%s/%d_%d%s", 
			dirname, x, y, dz->suffix );

		if( !vips_existsf( "%s", dirname ) &&
			vips_mkdirf( "%s", dirname ) ) {
			g_mutex_unlock( file_lock );
			return( -1 );
		}

		break;

	case VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY:
		/* We need to work out the tile number so we can calculate the
		 * directory to put this tile in.
		 *
		 * Tiles are numbered from 0 for the most-zoomed-out tile. 
		 */
		n = 0;

		/* Count all tiles in layers below this one. 
		 */
		for( p = layer->below; p; p = p->below )
			n += p->tiles_across * p->tiles_down;

		/* And count tiles so far in this layer.
		 */
		n += y * layer->tiles_across + x;

		vips_snprintf( dirname, PATH_MAX, "%s/TileGroup%d", 
			dz->basename, n / 256 );
		vips_snprintf( buf, PATH_MAX, "%s/%d-%d-%d%s", 
			dirname, layer->n, x, y, dz->suffix );

		/* Used at the end in ImageProperties.xml
		 */
		dz->tile_count += 1;

		if( !vips_existsf( "%s", dirname ) &&
			vips_mkdirf( "%s", dirname ) ) {
			g_mutex_unlock( file_lock );
			return( -1 );
		}

		break;

	case VIPS_FOREIGN_DZ_LAYOUT_GOOGLE:
		vips_snprintf( dirname, PATH_MAX, "%s/%d", 
			dz->basename, layer->n );
		vips_snprintf( dirname2, PATH_MAX, "%s/%d", 
			dirname, y );
		vips_snprintf( buf, PATH_MAX, "%s/%d%s", 
			dirname2, x, dz->suffix );

		if( !vips_existsf( "%s", dirname ) &&
			vips_mkdirf( "%s", dirname ) ) {
			g_mutex_unlock( file_lock );
			return( -1 );
		}

		if( !vips_existsf( "%s", dirname2 ) &&
			vips_mkdirf( "%s", dirname2 ) ) {
			g_mutex_unlock( file_lock );
			return( -1 );
		}

		break;

	default:
		g_assert( 0 );
		g_mutex_unlock( file_lock );
		return( -1 );
	}

	g_mutex_unlock( file_lock );

	return( 0 );
}

static int
strip_work( VipsThreadState *state, void *a )
{
	Strip *strip = (Strip *) a;
	Layer *layer = strip->layer;
	VipsForeignSaveDz *dz = layer->dz;

	char buf[PATH_MAX];
	VipsImage *x;
	VipsImage *t;

#ifdef DEBUG_VERBOSE
	printf( "strip_work\n" );
#endif /*DEBUG_VERBOSE*/

	if( tile_name( layer, buf, 
		state->x / dz->tile_size, state->y / dz->tile_size ) )
		return( -1 );

	vips_object_sanity( VIPS_OBJECT( strip->image ) );

	/* Extract relative to the strip top-left corner.
	 */
	if( vips_extract_area( strip->image, &x, 
		state->pos.left, 0, 
		state->pos.width, state->pos.height, NULL ) ) 
		return( -1 );

	/* Google tiles need to be padded up to tilesize.
	 */
	if( dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE ) {
		if( vips_embed( x, &t, 0, 0, dz->tile_size, dz->tile_size,
			"background", dz->background,
			NULL ) ) {
			g_object_unref( x );
			return( -1 );
		}
		g_object_unref( x );

		x = t;
	}

	/* If we are centreing we may have a tile which is entirely blank.
	 * Skip the write in this case, the viewer will use blank.png instead.
	 */
	if( dz->centre ) {
		double *d;
		int n;
		double m;

		d = (double *) vips_area_get_data( (VipsArea *) dz->background, 
			NULL, &n, NULL, NULL );
		if( vips_equal_const( x, &t, d, n, NULL ) ) {
			g_object_unref( x );
			return( -1 );
		}

		if( vips_min( t, &m, NULL ) ) {
			g_object_unref( x );
			g_object_unref( t );
			return( -1 );
		}
		g_object_unref( t );

		if( m == 255 ) {
			g_object_unref( x );
			return( 0 );
		}
	}

#ifdef DEBUG_VERBOSE
	printf( "strip_work: writing to %s\n", buf );
#endif /*DEBUG_VERBOSE*/

	if( vips_image_write_to_file( x, buf ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

#ifdef DEBUG_VERBOSE
	printf( "strip_work: success\n" );
#endif /*DEBUG_VERBOSE*/

	return( 0 );
}

/* Write a line of tiles with a threadpool. 
 */
static int
strip_save( Layer *layer )
{
	Strip strip;

#ifdef DEBUG
	printf( "strip_save: n = %d, y = %d\n", layer->n, layer->y );
#endif /*DEBUG*/

	strip_init( &strip, layer );
	if( vips_threadpool_run( strip.image, 
		vips_thread_state_new, strip_allocate, strip_work, NULL, 
		&strip ) ) {
		strip_free( &strip );
		return( -1 );
	}
	strip_free( &strip );

	return( 0 );
}

/* A strip has filled, but the rightmost column and the bottom-most row may
 * not have been if we've rounded the size up.
 *
 * Fill them, if necessary, by copying the previous row/column.
 */
static void
layer_generate_extras( Layer *layer )
{
	VipsRegion *strip = layer->strip;

	/* We only work for full-width strips.
	 */
	g_assert( strip->valid.width == layer->image->Xsize );

	if( layer->width < layer->image->Xsize ) {
		int ps = VIPS_IMAGE_SIZEOF_PEL( strip->im );

		int b, y;

		/* Need to add a right-most column.
		 */
		for( y = 0; y < strip->valid.height; y++ ) {
			VipsPel *p = VIPS_REGION_ADDR( strip, 
				layer->width - 1, strip->valid.top + y );
			VipsPel *q = p + ps;

			for( b = 0; b < ps; b++ )
				q[b] = p[b];
		}
	}

	if( layer->height < layer->image->Ysize ) {
		VipsRect last;

		/* The last two lines of the image.
		 */
		last.left = 0;
		last.top = layer->image->Ysize - 2;
		last.width = layer->image->Xsize;
		last.height = 2;
	
		/* Do we have them both? Fill the last with the next-to-last.
		 */
		vips_rect_intersectrect( &last, &strip->valid, &last );
		if( last.height == 2 ) {
			last.height = 1;

			vips_region_copy( strip, strip, &last, 
				0, last.top + 1 );
		}
	}
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

		if( save->ready->Coding == VIPS_CODING_NONE )
			shrink_region_uncoded( from, to, &target );
		else
			shrink_region_labpack( from, to, &target );

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

/* A new strip has arrived! The strip has enough pixels in to write a line of 
 * tiles. 
 *
 * - write a line of tiles
 * - shrink what we can to the layer below
 * - move our strip down by the tile height
 * - copy the overlap with the previous strip
 */
static int
strip_arrived( Layer *layer )
{
	VipsForeignSaveDz *dz = layer->dz;
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
	layer->y += dz->tile_size;
	new_strip.left = 0;
	new_strip.top = layer->y - dz->overlap;
	new_strip.width = layer->image->Xsize;
	new_strip.height = dz->tile_size + 2 * dz->overlap;
	if( (new_strip.height & 1) == 1 )
		new_strip.height += 1;

	/* We may exactly hit the bottom of the real image (ie. before borders
	 * have been possibly expanded by 1 pixel). In this case, we'll not 
	 * be able to do the expansion in layer_generate_extras(), since the 
	 * region won't be large enough, and we'll not get another chance 
	 * since this is the bottom. 
	 *
	 * Add another scanline if this has happened.
	 */
	if( VIPS_RECT_BOTTOM( &new_strip ) == layer->height )
		new_strip.height = layer->image->Ysize - new_strip.top;

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
pyramid_strip( VipsRegion *region, VipsRect *area, void *a )
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) a;
	Layer *layer = dz->layer;

#ifdef DEBUG
	printf( "pyramid_strip: strip at %d, height %d\n", 
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

static int
vips_foreign_save_dz_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) object;

	/* Google and zoomify default to zero overlap, ".jpg".
	 */
	if( dz->layout == VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY ||
		dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE ) {
		if( !vips_object_argument_isset( object, "overlap" ) )
			dz->overlap = 0;
		if( !vips_object_argument_isset( object, "suffix" ) )
			VIPS_SETSTR( dz->suffix, ".jpg" );
	}

	/* Default to white background. 
	 */
	if( dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE &&
		!vips_object_argument_isset( object, "background" ) ) {
		VipsArrayDouble *background; 

		background = vips_array_double_newv( 1, 255.0 );
		g_object_set( object, "background", background, NULL );
		vips_area_unref( background ); 
	}

	if( dz->overlap >= dz->tile_size || 
		dz->overlap >= dz->tile_size ) {
		vips_error( "dzsave", 
			"%s", _( "overlap must be less than tile "
				"width and height" ) ) ;
		return( -1 );
	}

	/* DeepZoom stops at 1x1 pixels, others when the image fits within a
	 * tile.
	 */
	if( dz->layout == VIPS_FOREIGN_DZ_LAYOUT_DZ ) {
		if( !vips_object_argument_isset( object, "depth" ) )
			dz->depth = VIPS_FOREIGN_DZ_DEPTH_1PIXEL;
	}
	else
		if( !vips_object_argument_isset( object, "depth" ) )
			dz->depth = VIPS_FOREIGN_DZ_DEPTH_1TILE;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_dz_parent_class )->
		build( object ) )
		return( -1 );

	/* For centred images, imagine shrinking so that the image fits in a
	 * single tile, centering in that tile, then expanding back again.
	 */
	if( dz->layout == VIPS_FOREIGN_DZ_LAYOUT_GOOGLE &&
		dz->centre ) {
		VipsImage *z;
		Layer *layer;
		int n_layers;
		int size;

		if( !(layer = pyramid_build( dz, 
			NULL, save->ready->Xsize, save->ready->Ysize )) )
			return( -1 );
		n_layers = layer->n;
		/* This would cause interesting problems.
		 */
		g_assert( n_layers < 30 );
		layer_free( layer );
		size = dz->tile_size * (1 << n_layers);

		if( vips_embed( save->ready, &z, 
			(size - save->ready->Xsize) / 2, 
			(size - save->ready->Ysize) / 2, 
			size, size,
			"background", dz->background,
			NULL ) ) 
			return( -1 );

		VIPS_UNREF( save->ready );
		save->ready = z;


#ifdef DEBUG
		printf( "centre: centreing within a %d x %d image\n", 
			size, size );
#endif

	}

#ifdef DEBUG
	printf( "vips_foreign_save_dz_build: tile_size == %d\n", 
		dz->tile_size );
	printf( "vips_foreign_save_dz_build: overlap == %d\n", 
		dz->overlap );
#endif

	/* Build the skeleton of the image pyramid.
	 */
	if( !(dz->layer = pyramid_build( dz, 
		NULL, save->ready->Xsize, save->ready->Ysize )) )
		return( -1 );
	if( pyramid_mkdir( dz ) )
		return( -1 );

	if( vips_sink_disc( save->ready, pyramid_strip, dz ) )
		return( -1 );

	switch( dz->layout ) {
	case VIPS_FOREIGN_DZ_LAYOUT_DZ:
		if( write_dzi( dz ) )
			return( -1 );
		break;

	case VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY:
		if( write_properties( dz ) )
			return( -1 );
		break;

	case VIPS_FOREIGN_DZ_LAYOUT_GOOGLE:
		if( write_blank( dz ) )
			return( -1 );
		break;

	default:
		g_assert( 0 );
		return( -1 );
	}

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static int bandfmt_dz[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, C,  US, S,  UI, I,  F,  F,  D,  D
};

const char *dz_suffs[] = { ".dz", NULL };

static void
vips_foreign_save_dz_class_init( VipsForeignSaveDzClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_dz_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "dzsave";
	object_class->description = _( "save image to deep zoom format" );
	object_class->build = vips_foreign_save_dz_build;

	foreign_class->suffs = dz_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_dz;
	save_class->coding[VIPS_CODING_LABQ] = TRUE;

	VIPS_ARG_STRING( class, "basename", 1, 
		_( "Base name" ),
		_( "Base name to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveDz, basename ),
		NULL );

	VIPS_ARG_ENUM( class, "layout", 8, 
		_( "Layout" ), 
		_( "Directory layout" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveDz, layout ),
		VIPS_TYPE_FOREIGN_DZ_LAYOUT, 
			VIPS_FOREIGN_DZ_LAYOUT_DZ ); 

	VIPS_ARG_STRING( class, "suffix", 9, 
		_( "suffix" ), 
		_( "Filename suffix for tiles" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveDz, suffix ),
		".jpg" );

	VIPS_ARG_INT( class, "overlap", 10, 
		_( "Overlap" ), 
		_( "Tile overlap in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveDz, overlap ),
		0, 8192, 0 );

	VIPS_ARG_INT( class, "tile_size", 11, 
		_( "Tile size" ), 
		_( "Tile size in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveDz, tile_size ),
		1, 1024, 256 );

	VIPS_ARG_BOXED( class, "background", 12, 
		_( "Background" ), 
		_( "Colour for background pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveDz, background ),
		VIPS_TYPE_ARRAY_DOUBLE );

	VIPS_ARG_ENUM( class, "depth", 13, 
		_( "Depth" ), 
		_( "Pyramid depth" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveDz, depth ),
		VIPS_TYPE_FOREIGN_DZ_DEPTH, 
			VIPS_FOREIGN_DZ_DEPTH_1PIXEL ); 

	VIPS_ARG_BOOL( class, "centre", 13, 
		_( "Center" ), 
		_( "Center image in tile" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveDz, centre ),
		FALSE );

	/* How annoying. We stupidly had these in earlier versions.
	 */

	VIPS_ARG_STRING( class, "dirname", 1, 
		_( "Base name" ),
		_( "Base name to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT | VIPS_ARGUMENT_DEPRECATED, 
		G_STRUCT_OFFSET( VipsForeignSaveDz, basename ),
		NULL );

	VIPS_ARG_INT( class, "tile_width", 12, 
		_( "Tile width" ), 
		_( "Tile width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignSaveDz, tile_size ),
		1, 1024, 256 );

	VIPS_ARG_INT( class, "tile_height", 12, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignSaveDz, tile_size ),
		1, 1024, 256 );

}

static void
vips_foreign_save_dz_init( VipsForeignSaveDz *dz )
{
	VIPS_SETSTR( dz->suffix, ".jpeg" );
	dz->layout = VIPS_FOREIGN_DZ_LAYOUT_DZ; 
	dz->overlap = 1;
	dz->tile_size = 256;
	dz->tile_count = 0;
	dz->depth = VIPS_FOREIGN_DZ_DEPTH_1PIXEL; 
}

/**
 * vips_dzsave:
 * @in: image to save 
 * @basename: basename to save to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @layout; directory layout convention
 * @suffix: suffix for tile tiles 
 * @overlap; set tile overlap 
 * @tile_size; set tile size 
 * @background: background colour
 * @depth: how deep to make the pyramid
 * @centre: centre the tiles 
 *
 * Save an image as a set of tiles at various resolutions. By default dzsave
 * uses DeepZoom layout -- use @layout to pick other conventions.
 *
 * In DeepZoom layout a directory called
 * "@basename_files" is created to hold the tiles, and an XML file called
 * "@basename.dzi" is written with the image metadata, 
 *
 * In Zoomify and Google layout, a directory called @basename is created to 
 * hold the tile structure. 
 *
 * You can set @suffix to something like ".jpg[Q=85]" to control the tile write
 * options. 
 * 
 * In Google layout mode, edge tiles are expanded to @tile_size by @tile_size 
 * pixels. Normally they are filled with white, but you can set another colour
 * with @background. Images are usually placed at the top-left of the tile,
 * but you can have them centred by turning on @centre. 
 *
 * You can set the size and overlap of tiles with @tile_size and @overlap.
 * They default to the correct settings for the selected @layout. 
 *
 * Use @depth to control how low the pyramid goes. This defaults to the
 * correct setting for the @layout you select.
 *
 * See also: vips_tiffsave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_dzsave( VipsImage *in, const char *basename, ... )
{
	va_list ap;
	int result;

	va_start( ap, basename );
	result = vips_call_split( "dzsave", ap, in, basename ); 
	va_end( ap );

	return( result );
}

