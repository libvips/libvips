/* save to deep zoom format
 *
 * 21/3/12
 * 	- from the dz pyramid writer
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
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

typedef struct _VipsForeignSaveDz VipsForeignSaveDz;
typedef struct _Layer Layer;

/* A layer in the pyramid.
 */
struct _Layer {
	VipsForeignSaveDz *dz;

	VipsImage *image;		/* The image we build */
	VipsRegion *strip;		/* The current strip of pixels */
	int sub;			/* Subsample factor for this layer */
	int n;				/* Layer number ... 0 for smallest */

	Layer *below;			/* Tiles go to here */
	Layer *above;			/* Tiles come from here */
};

struct _VipsForeignSaveDz {
	VipsForeignSave parent_object;

	/* Directory to create and write to.
	 */
	char *dirname; 

	char *suffix;
	int overlap;
	int tile_width;
	int tile_height;

	Layer *layer;			/* x2 shrink pyr layer */

	GMutex *lock;			/* we single-thread the shrinker */
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
	VIPS_FREEF( g_object_unref, layer->image );

	VIPS_FREE( layer->below, layer_free ); 
}

static void
vips_foreign_save_dz_dispose( GObject *gobject )
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) gobject;

	VIPS_FREE( dz->layer, layer_free ); 
	VIPS_FREEF( g_mutex_free, tw->lock );

	G_OBJECT_CLASS( vips_foreign_save_dz_parent_class )->dispose( gobject );
}

/* Build a pyramid. 
 */
static Layer *
pyramid_build( VipsForeignSaveDz *dz, Layer *above, int w, int h )
{
	Layer *layer = VIPS_NEW( dz, Layer );
	int i;

	layer->dz = dz;

	if( !above )
		/* Top of pyramid.
		 */
		layer->sub = 1;	
	else
		layer->sub = above->sub * 2;

	layer->below = NULL;
	layer->above = above;

	layer->image = vips_image_new();
	if( vips_image_copy_fields( layer->image, dz->image ) ) {
		layer_free( layer );
		return( NULL );
	}
	layer->image->Xsize = w;
	layer->image->Ysize = h;
	layer->region = vips_region_new( layer->image );

	if( layer->width > dz->tile_width || 
		layer->height > dz->tile_height ) {
		if( !(layer->below = pyramid_build( dz, 
			layer, w / 2, h / 2 )) ) {
			layer_free( layer );
			return( -1 );
		}
		layer->n = layer->below + 1;
	}
	else
		layer->n = 0;

	return( layer );
}

static int
pyramid_mkdir( VipsForeignSaveDz *dz )
{
	Layer *layer;

	if( vips_existsf( "%s", dz->dirname ) ) { 
		vips_error( "dzsave", 
			_( "Directory \"%s\" exists" ), dz->dirname );
		return( -1 );
	}
	if( vips_mkdirf( "%s", dz->dirname ) ) 
		return( -1 );
	for( layer = dz->layer; layer; layer = layer->below )
		if( vips_mkdirf( "%s/%s", dz->dirname, layer->n ) ) 
			return( -1 );

	return( 0 );
}

/* Shrink a region by a factor of two, writing the result to a specified 
 * offset in another region. VIPS_CODING_LABQ only.
 */
static void
shrink_region_labpack( VipsRegion *from, VipsRect *area, 
	VipsRegion *to, int xoff, int yoff )
{
	int ls = VIPS_REGION_LSKIP( from );
	VipsRect *t = &to->valid;

	int x, y;
	VipsRect out;

	/* Calculate output size and position.
	 */
	out.left = t->left + xoff;
	out.top = t->top + yoff;
	out.width = area->width / 2;
	out.height = area->height / 2;

	/* Shrink ... ignore the extension byte for speed.
	 */
	for( y = 0; y < out.height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			area->left, area->top + y * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, out.left, out.top + y );

		for( x = 0; x < out.width; x++ ) {
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
	for( x = 0; x < out.width; x++ ) { \
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

#define SHRINK_TYPE_FLOAT( TYPE ) \
	for( x = 0; x < out.width; x++ ) { \
		TYPE *tp = (TYPE *) p; \
		TYPE *tp1 = (TYPE *) (p + ls); \
		TYPE *tq = (TYPE *) q; \
 		\
		for( z = 0; z < nb; z++ ) { \
			double tot = (double) tp[z] + tp[z + nb] +  \
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

/* Shrink a region by a factor of two, writing the result to a specified 
 * offset in another region. n-band, non-complex.
 */
static void
shrink_region( VipsRegion *from, VipsRect *area,
	VipsRegion *to, int xoff, int yoff )
{
	int ls = VIPS_REGION_LSKIP( from );
	int ps = VIPS_IMAGE_SIZEOF_PEL( from->im );
	int nb = from->im->Bands;
	VipsRect *t = &to->valid;

	int x, y, z;
	VipsRect out;

	/* Calculate output size and position.
	 */
	out.left = t->left + xoff;
	out.top = t->top + yoff;
	out.width = area->width / 2;
	out.height = area->height / 2;

	for( y = 0; y < out.height; y++ ) {
		VipsPel *p = VIPS_REGION_ADDR( from, 
			area->left, area->top + y * 2 );
		VipsPel *q = VIPS_REGION_ADDR( to, 
			out.left, out.top + y );

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

/* Write an area of a region to a file.
 */
static int
tile_save( Layer *layer, VipsArea *area )
{
	VipsForeignSaveDz *dz = layer->dz;
	VipsRegion *strip = layer->strip;

	VipsImage *image;
	VipsImage *extr;
	char str[1000];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	if( !(image = vips_image_new_from_memory( 
		VIPS_REGION_ADDR( strip, strip->valid.left, strip->valid.top ),
		strip->valid.width, strip->valid.height,
		strip->im.Bands, strip->im.BandFmt )) )
		return( -1 );
	if( vips_extract_area( 

	vips_buf_appendf( &buf, "%s/%d/%d_%d%s",
		dz->dirname, 
		layer->n,
		tile->valid.left / dz->tile_width,
		tile->valid.top / dz->tile_height,
		dz->suffix );

	if( vips_image_write_file( image, vips_buf_all( &buf ) ) ) {
		g_object_unref( image );
		return( -1 );
	}
	g_object_unref( image );

	return( 0 );
}

/* A new strip of pixels has arrived! Add to our buffers, as each one fills,
 * write a line of tiles and recurse down the pyramid. 
 */
static int
strip_arrived( Layer *layer, VipsRegion *region, VipsRect *area )
{
	VipsForeignSaveDz *dz = layer->dz;

	int xoff, yoff;
	int t, ri, bo;
	VipsRect out, new;
	PyramidBits bit;

	if( tile_save( layer, tile ) )
		return( -1 );

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

/* Another strip of image pixels. Recursively write down the pyramid.
 */
static int
pyramid_strip( VipsRegion *region, VipsRect *area, void *a )
{
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) a;
	int y;

	y = 0;
	while( y < area->height ) { 
		VipsRect olp;

		vips_rect_intersectrect( area, &dz->layer->region.valid, &olp );
		vips_region_copy( region, dz->layer->region, 
			&olp, olp.left, olp.top );

		/* If we've filled the layer strip.
		 */
		if( VIPS_RECT_BOTTOM( &olp ) == 
			VIPS_RECT_BOTTOM( &dz->layer->region.valid ) &&
			strip_arrived( dz->layer ) )
			return( -1 );

		y += olp.height;
	}

	return( 0 );
}

static int
vips_foreign_save_dz_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) object;

	char *p;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_dz_parent_class )->
		build( object ) )
		return( -1 );

	/* Build the skeleton of the image pyramid.
	 */
	if( !(dz->layer = pyramid_build( dz, 
		NULL, save->read->Xsize, save->read->Ysize )) )
		return( -1 );
	if( pyramid_mkdir( dz ) )
		return( -1 );

	if( vips_sink_disc( save->read, pyramid_strip, dz ) )
		return( -1 );

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

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_dz;
	save_class->coding[VIPS_CODING_LABQ] = TRUE;

	VIPS_ARG_STRING( class, "dirname", 1, 
		_( "Directory name" ),
		_( "Directory name to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveDz, dirname ),
		NULL );

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
		1, 1024, 1 );

	VIPS_ARG_INT( class, "tile_width", 11, 
		_( "Tile width" ), 
		_( "Tile width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveDz, tile_width ),
		1, 1024, 128 );

	VIPS_ARG_INT( class, "tile_height", 12, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveDz, tile_height ),
		1, 1024, 128 );

}

static void
vips_foreign_save_dz_init( VipsForeignSaveDz *dz )
{
	VIPS_SETSTR( dz->suffix, ".jpg" );
	dz->overlap = 1;
	dz->tile_width = 128;
	dz->tile_height = 128;
	dz->lock = g_mutex_new();
}
