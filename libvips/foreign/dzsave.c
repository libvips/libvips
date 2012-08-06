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
 */
#define DEBUG_VERBOSE
#define DEBUG
#define VIPS_DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

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

	/* Directory to create and write to.
	 */
	char *dirname; 

	char *suffix;
	int overlap;
	int tile_width;
	int tile_height;

	Layer *layer;			/* x2 shrink pyr layer */
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

	layer->dz = dz;
	layer->width = width;
	layer->height = height;

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
	 * We add one so that we will have the extra scan line for the shrink 
	 * in case tile_height is odd and there's no overlap. 
	 */
	layer->y = 0;
	layer->write_y = 0;
	strip.left = 0;
	strip.top = 0;
	strip.width = layer->image->Xsize;
	strip.height = dz->tile_height + dz->overlap + 1;
	if( vips_region_buffer( layer->strip, &strip ) ) {
		layer_free( layer );
		return( NULL );
	}

	if( width > 1 ||
		height > 1 ) {
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
		if( vips_mkdirf( "%s/%d", dz->dirname, layer->n ) ) 
			return( -1 );

	return( 0 );
}

static int
write_dzi( VipsForeignSaveDz *dz )
{
	FILE *fp;
	char buf[PATH_MAX];
	char *name;

	name = g_path_get_basename( dz->dirname );
	vips_snprintf( buf, PATH_MAX, "%s/%s.dzi", dz->dirname, name );
	g_free( name );
	if( !(fp = vips__file_open_write( buf, TRUE )) )
		return( -1 );

	fprintf( fp, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ); 
	fprintf( fp, "<Image "
		"xmlns=\"http://schemas.microsoft.com/deepzoom/2008\"\n" );
	fprintf( fp, "  Format=\"%s\"\n", dz->suffix + 1 );
	fprintf( fp, "  Overlap=\"%d\"\n", dz->overlap );
	fprintf( fp, "  TileSize=\"%d\"\n", dz->tile_width );
	fprintf( fp, "  >\n" ); 
	fprintf( fp, "  <Size \n" );
	fprintf( fp, "    Height=\"%d\"\n", dz->layer->height );
	fprintf( fp, "    Width=\"%d\"\n", dz->layer->width );
	fprintf( fp, "  />\n" ); 
	fprintf( fp, "</Image>\n" );

	fclose( fp );

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
	line.height = dz->tile_height + 2 * dz->overlap;

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

	image.left = 0;
	image.top = 0;
	image.width = layer->width;
	image.height = layer->height;

	/* Position this tile.
	 */
	state->pos.left = strip->x - dz->overlap;
	state->pos.top = 0;
	state->pos.width = dz->tile_width + 2 * dz->overlap;
	state->pos.height = state->im->Ysize;

	vips_rect_intersectrect( &image, &state->pos, &state->pos );
	state->x = strip->x;
	state->y = layer->y;

	strip->x += dz->tile_width;

	if( vips_rect_isempty( &state->pos ) ) {
		*stop = TRUE;
		return( 0 );
	}

	return( 0 );
}

static int
strip_work( VipsThreadState *state, void *a )
{
	Strip *strip = (Strip *) a;
	Layer *layer = strip->layer;
	VipsForeignSaveDz *dz = layer->dz;

	VipsImage *extr;
	char str[1000];
	VipsBuf buf = VIPS_BUF_STATIC( str );

	/* Extract relative to the strip top-left corner.
	 */
	if( vips_extract_area( state->im, &extr, 
		state->pos.left, 0, 
		state->pos.width, state->pos.height, NULL ) ) 
		return( -1 );

	vips_buf_appendf( &buf, "%s/%d/%d_%d%s",
		dz->dirname, layer->n,
		state->x / dz->tile_width, 
		state->y / dz->tile_height, 
		dz->suffix );

	if( vips_image_write_to_file( extr, vips_buf_all( &buf ) ) ) {
		g_object_unref( extr );
		return( -1 );
	}

	g_object_unref( extr );

	return( 0 );
}

/* Write a line of tiles with a threadpool. 
 */
static int
strip_save( Layer *layer )
{
	Strip strip;

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
 * not have if we've rounded the size up!
 *
 * Fill them, if necessary, by copyping the previous row/column.
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

/* Shrink what pixels we can from this layer into the layer below. If the
 * layer below fills, recurse.
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
		if( source.height < 2 ) 
			break;

		if( save->ready->Coding == VIPS_CODING_NONE )
			shrink_region_uncoded( from, to, &target );
		else
			shrink_region_labpack( from, to, &target );

		below->write_y += target.height;

		/* If we've filled the strip of the layer below, let it know.
		 * We can either fill the region, if it's somewhere half-way
		 * down the image, or, if it's at the bottom, get to the last
		 * writeable line.
		 */
		if( below->write_y == VIPS_RECT_BOTTOM( &to->valid ) ||
			below->write_y == below->height ) {
			if( strip_arrived( below ) )
				return( -1 );
		}
	}

	return( 0 );
}

/* A new strip of pixels has arrived! The strip region has enough pixels in to
 * write a line of tiles. 
 *
 * - write a line of tiles
 * - shrink what we can to the layer below
 * - move our strip down ready for more stuff, copying the overlap
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

	/* Position our strip down the image.  We add one to the strip height
	 * to make sure we will have enough pixels for any shrinking even if
	 * tile_height is odd and there's no overlap.
	 */
	layer->y += dz->tile_height;
	new_strip.left = 0;
	new_strip.top = layer->y - dz->overlap;
	new_strip.width = layer->image->Xsize;
	new_strip.height = dz->tile_height + 2 * dz->overlap + 1;

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

	for(;;) {
		VipsRect target;

		/* The bit of strip that needs filling.
		 */
		target.left = 0;
		target.top = layer->write_y;
		target.width = layer->image->Xsize;
		target.height = layer->strip->valid.height;
		vips_rect_intersectrect( &target, 
			&layer->strip->valid, &target );

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

		/* If we've filled the strip, let it know.
		 */
		if( layer->write_y == 
			VIPS_RECT_BOTTOM( &layer->strip->valid ) &&
			strip_arrived( layer ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_foreign_save_dz_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveDz *dz = (VipsForeignSaveDz *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_dz_parent_class )->
		build( object ) )
		return( -1 );

	if( dz->overlap >= dz->tile_width || 
		dz->overlap >= dz->tile_height ) {
		vips_error( "dzsave", 
			"%s", _( "overlap must be less than tile "
				"width and height" ) ) ;
		return( -1 );
	}

	/* Build the skeleton of the image pyramid.
	 */
	if( !(dz->layer = pyramid_build( dz, 
		NULL, save->ready->Xsize, save->ready->Ysize )) )
		return( -1 );
	if( pyramid_mkdir( dz ) ||
		write_dzi( dz ) )
		return( -1 );

	if( vips_sink_disc( save->ready, pyramid_strip, dz ) )
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
		0, 1024, 0 );

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
	VIPS_SETSTR( dz->suffix, ".jpeg" );
	dz->overlap = 1;
	dz->tile_width = 256;
	dz->tile_height = 256;
}
