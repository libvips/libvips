/* save as GIF
 *
 * 22/8/21 lovell
 * 18/1/22 TheEssem
 * 	- fix change detector
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
#define DEBUG_PERCENT
#define DEBUG_VERBOSE
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <vips/vips.h>

#include "pforeign.h"
#include "quantise.h"

#if defined(HAVE_CGIF) && defined(HAVE_QUANTIZATION)

#include <cgif.h>

typedef struct _VipsForeignSaveCgif {
	VipsForeignSave parent_object;

	double dither;
	int effort;
	int bitdepth;
	double maxerror;
	VipsTarget *target;

	/* Derived write params.
	 */
	VipsImage *in;				/* Not a reference */
	gboolean has_transparency;
	int *delay;
	int delay_length;
	int loop;

	/* We save ->ready a frame at a time, regenerating the 
	 * palette if we see a significant frame to frame change. 
	 */

	/* The current frame coming from libvips, the y position we write to,
	 * and some spare pixels we copy down when we move to the next frame.
	 */
	VipsRegion *frame;
	int write_y;

	/* The frame as seen by libimagequant.
	 */
	VipsQuantiseAttr *attr;
	VipsQuantiseImage *input_image;
	VipsQuantiseResult *quantisation_result;
	const VipsQuantisePalette *lp;

	/* The current colourmap, updated on a significant frame change.
	 */
	VipsPel *palette_rgb;
	gint64 frame_sum;

	/* The index frame we get libimagequant to generate.
	 */
	VipsPel *index;

	/* frame_bytes head (needed for transparency trick).
	*/
	VipsPel *frame_bytes_head;

	/* The frame as written by libcgif.
	 */
	CGIF *cgif_context;
	CGIF_Config cgif_config;

#ifdef DEBUG_PERCENT
	int n_cmaps_generated;
#endif/*DEBUG_PERCENT*/

} VipsForeignSaveCgif;

typedef VipsForeignSaveClass VipsForeignSaveCgifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveCgif, vips_foreign_save_cgif,
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_cgif_dispose( GObject *gobject )
{
	VipsForeignSaveCgif *cgif = (VipsForeignSaveCgif *) gobject;

#ifdef DEBUG_PERCENT
	if( cgif->frame ) {
		printf( "%d frames\n", 
			cgif->frame->im->Ysize / cgif->frame->valid.height );
		printf( "%d cmaps\n", cgif->n_cmaps_generated );
	}
#endif/*DEBUG_PERCENT*/

	VIPS_FREEF( cgif_close, cgif->cgif_context );

	VIPS_FREEF( vips__quantise_result_destroy, cgif->quantisation_result );
	VIPS_FREEF( vips__quantise_image_destroy, cgif->input_image );
	VIPS_FREEF( vips__quantise_attr_destroy, cgif->attr );

	VIPS_UNREF( cgif->frame );

	VIPS_UNREF( cgif->target );

	VIPS_FREE( cgif->palette_rgb );
	VIPS_FREE( cgif->index );
	VIPS_FREE( cgif->frame_bytes_head );

	G_OBJECT_CLASS( vips_foreign_save_cgif_parent_class )->
		dispose( gobject );
}

/* Minimal callback wrapper around vips_target_write
 */
static int vips__cgif_write( void *target, const uint8_t *buffer,
	const size_t length ) {
	return vips_target_write( (VipsTarget *) target,
		(const void *) buffer, (size_t) length );
}

/* Compare pixels in a lossy way (allow a slight colour difference).
 * In combination with the GIF transparency optimization this leads to
 * less difference between frames and therefore improves the compression ratio.
 */
static gboolean
vips_foreign_save_cgif_pixels_are_equal( const VipsPel *cur, const VipsPel *bef,
	double maxerror )
{
	if( bef[3] != 0xFF )
		/* Solid pixels only.
		 */
		return FALSE;

	/* Test Euclidean distance between the two points.
	*/
	const int dR = cur[0] - bef[0];
	const int dG = cur[1] - bef[1];
	const int dB = cur[2] - bef[2];

	return( sqrt( dR * dR + dG * dG + dB * dB ) <= maxerror );
}

/* We have a complete frame --- write!
 */
static int
vips_foreign_save_cgif_write_frame( VipsForeignSaveCgif *cgif )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( cgif );
	VipsRect *frame_rect = &cgif->frame->valid;
	int page_index = frame_rect->top / frame_rect->height;
	/* We know this fits in an int since we limit frame size.
	 */
	int n_pels = frame_rect->height * frame_rect->width;
	VipsPel *frame_bytes = 
		VIPS_REGION_ADDR( cgif->frame, 0, frame_rect->top );

	VipsPel * restrict p;
	VipsPel *rgb;
	gint64 sum;
	double change;
	int i;
	CGIF_FrameConfig frame_config;

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_save_cgif_write_frame: %d\n", page_index );
#endif/*DEBUG_VERBOSE*/

	/* Set up new frame for libimagequant.
	 */
	VIPS_FREEF( vips__quantise_image_destroy, cgif->input_image );
	cgif->input_image = vips__quantise_image_create_rgba( cgif->attr,
		frame_bytes, frame_rect->width, frame_rect->height, 0 );

	/* Threshold the alpha channel. It's safe to modify the region since 
	 * it's a buffer we made.
	 */
	p = frame_bytes;
	for( i = 0; i < n_pels; i++ ) {
		p[3] = p[3] >= 128 ? 255 : 0;
		p += 4;
	}

	/* Do we need to compute a new palette? Do it if the frame sum
	 * changes.
	 *
	 * frame_sum 0 means no current colourmap.
	 */
	sum = 0;
	p = frame_bytes;
	for( i = 0; i < n_pels; i++ ) {
		/* Scale RGBA differently so that changes like [0, 255, 0] 
		 * to [255, 0, 0] are detected.
		 */
		sum += p[0] * 1000; 
		sum += p[1] * 100; 
		sum += p[2] * 10; 
		sum += p[3]; 

		p += 4;
	}
	change = VIPS_ABS( ((double) sum - cgif->frame_sum) ) / n_pels;

	if( cgif->frame_sum == 0 ||
		change > 0 ) { 
		cgif->frame_sum = sum;

		/* If this is not our first cmap, make a note that we need to
		 * attach it as a local cmap when we write.
		 */
		if( cgif->quantisation_result ) 
			cgif->cgif_config.attrFlags |= 
				CGIF_ATTR_NO_GLOBAL_TABLE;

		VIPS_FREEF( vips__quantise_result_destroy, 
			cgif->quantisation_result );
		if( vips__quantise_image_quantize( cgif->input_image, 
			cgif->attr, &cgif->quantisation_result ) ) { 
			vips_error( class->nickname, 
				"%s", _( "quantisation failed" ) );
			return( -1 );
		}

#ifdef DEBUG_PERCENT
		cgif->n_cmaps_generated += 1;
#endif/*DEBUG_PERCENT*/
	}

	/* Dither frame.
	 */
	vips__quantise_set_dithering_level( cgif->quantisation_result, 
		cgif->dither );
	if( vips__quantise_write_remapped_image( cgif->quantisation_result,
		cgif->input_image, cgif->index, n_pels ) ) {
		vips_error( class->nickname, "%s", _( "dither failed" ) );
		return( -1 );
	}

	/* Call vips__quantise_get_palette() after 
	 * vips__quantise_write_remapped_image(), as palette is improved 
	 * during remapping.
	 */
	cgif->lp = vips__quantise_get_palette( cgif->quantisation_result );
	rgb = cgif->palette_rgb;
	g_assert( cgif->lp->count <= 256 );
	for( i = 0; i < cgif->lp->count; i++ ) {
		rgb[0] = cgif->lp->entries[i].r;
		rgb[1] = cgif->lp->entries[i].g;
		rgb[2] = cgif->lp->entries[i].b;

		rgb += 3;
	}

#ifdef DEBUG_PERCENT
	if( change > 0 )
		printf( "frame %d, change %g, new %d item colourmap\n",
			page_index, change, cgif->lp->count );
	else
		printf( "frame %d, reusing previous %d item colourmap\n",
			page_index, cgif->lp->count );
#endif/*DEBUG_PERCENT*/

	/* If there's a transparent pixel, it's always first.
	 */
	cgif->has_transparency = cgif->lp->entries[0].a == 0;

	/* Set up cgif on first use, so we can set the first cmap as the global
	 * one.
	 *
	 * We switch to local tables if we find we need a new palette.
	 */
	if( !cgif->cgif_context ) {
		cgif->cgif_config.pGlobalPalette = cgif->palette_rgb;
#ifdef HAVE_CGIF_ATTR_NO_LOOP
		cgif->cgif_config.attrFlags = CGIF_ATTR_IS_ANIMATED | ( cgif->loop == 1 ? CGIF_ATTR_NO_LOOP : 0 );
#else
		cgif->cgif_config.attrFlags = CGIF_ATTR_IS_ANIMATED;
#endif/*HAVE_CGIF_ATTR_NO_LOOP*/
		cgif->cgif_config.width = frame_rect->width;
		cgif->cgif_config.height = frame_rect->height;
		cgif->cgif_config.numGlobalPaletteEntries = cgif->lp->count;
#ifdef HAVE_CGIF_ATTR_NO_LOOP
		cgif->cgif_config.numLoops = cgif->loop > 1 ? cgif->loop - 1 : cgif->loop;
#else
		cgif->cgif_config.numLoops = cgif->loop;
#endif/*HAVE_CGIF_ATTR_NO_LOOP*/
		cgif->cgif_config.pWriteFn = vips__cgif_write;
		cgif->cgif_config.pContext = (void *) cgif->target;

		cgif->cgif_context = cgif_newgif( &cgif->cgif_config );
	}

	/* Write frame to cgif.
	 */
	memset( &frame_config, 0, sizeof( CGIF_FrameConfig ) );
	frame_config.pImageData = cgif->index;

	/* Allow cgif to optimise by adding transparency. These optimisations
	 * will be automatically disabled if they are not possible.
	 */
	frame_config.genFlags = 
		CGIF_FRAME_GEN_USE_TRANSPARENCY | 
		CGIF_FRAME_GEN_USE_DIFF_WINDOW;
	frame_config.attrFlags = 0;

	/* Switch per-frame alpha channel on.
	 * Index 0 is used for pixels with alpha channel.
	 */
	if( cgif->has_transparency ) {
		frame_config.attrFlags |= CGIF_FRAME_ATTR_HAS_ALPHA;
		frame_config.transIndex = 0;
	}

	/* Pixels which are equal to pixels in the previous frame can be made
	 * transparent.
	*/
	if( cgif->frame_bytes_head ) {
		VipsPel *cur, *bef;

		cur = frame_bytes;
		bef = cgif->frame_bytes_head;
		if( !cgif->has_transparency ) {
			const uint8_t trans_index = cgif->lp->count;

			int i;

			for( i = 0; i < n_pels; i++ ) {
				if( vips_foreign_save_cgif_pixels_are_equal( 
					cur, bef, cgif->maxerror ) )
					cgif->index[i] = trans_index;
				else {
					bef[0] = cur[0];
					bef[1] = cur[1];
					bef[2] = cur[2];
					bef[3] = cur[3];
				}

				cur += 4;
				bef += 4;
			}

			frame_config.attrFlags |= 
				CGIF_FRAME_ATTR_HAS_SET_TRANS;
			frame_config.transIndex = trans_index;
		} 
		else {
			/* Transparency trick not possible (alpha channel 
			 * present). Update head.
			 */
			memcpy( bef, cur, 4 * n_pels);
		}
	}

	if( cgif->delay &&
		page_index < cgif->delay_length )
		frame_config.delay = 
			VIPS_RINT( cgif->delay[page_index] / 10.0 );

	/* Attach a local palette, if we need one.
	 */
	if( cgif->cgif_config.attrFlags & CGIF_ATTR_NO_GLOBAL_TABLE ) {
		frame_config.attrFlags |= CGIF_FRAME_ATTR_USE_LOCAL_TABLE;
		frame_config.pLocalPalette = cgif->palette_rgb;
		frame_config.numLocalPaletteEntries = cgif->lp->count;
	}

	cgif_addframe( cgif->cgif_context, &frame_config );

	if( !cgif->frame_bytes_head ) {
		/* Keep head frame_bytes in memory for transparency trick
		*  which avoids the size explosion (#2576).
		*/
		cgif->frame_bytes_head = g_malloc( 4 * n_pels );
		memcpy( cgif->frame_bytes_head, frame_bytes, 4 * n_pels );
	}

	return( 0 );
}

/* Another chunk of pixels have arrived from the pipeline. Add to frame, and
 * if the frame completes, compress and write to the target.
 */
static int
vips_foreign_save_cgif_sink_disc( VipsRegion *region, VipsRect *area, void *a )
{
	VipsForeignSaveCgif *cgif = (VipsForeignSaveCgif *) a;

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_save_cgif_sink_disc: strip at %d, height %d\n", 
		area->top, area->height );
#endif/*DEBUG_VERBOSE*/

	/* Write the new pixels into frame.
	 */
	do {
		VipsRect *to = &cgif->frame->valid;

		VipsRect hit;

		/* The bit of the frame that we can fill.
		 */
		vips_rect_intersectrect( area, to, &hit );

		/* Write the new pixels into the frame.
		 */
		vips_region_copy( region, cgif->frame, 
			&hit, hit.left, hit.top );

		cgif->write_y += hit.height;

		/* If we've filled the frame, write and move it down.
		 */
		if( VIPS_RECT_BOTTOM( &hit ) == VIPS_RECT_BOTTOM( to ) ) {
			VipsRect new_frame;
			VipsRect image;

			if( vips_foreign_save_cgif_write_frame( cgif ) ) 
				return( -1 );

			new_frame.left = 0;
			new_frame.top = cgif->write_y;
			new_frame.width = to->width;
			new_frame.height = to->height;
			image.left = 0;
			image.top = 0;
			image.width = cgif->in->Xsize;
			image.height = cgif->in->Ysize;
			vips_rect_intersectrect( &new_frame, &image, 
				&new_frame );
			if( !vips_rect_isempty( &new_frame ) &&
				vips_region_buffer( cgif->frame, &new_frame ) ) 
				return( -1 );
		}
	} while( VIPS_RECT_BOTTOM( area ) > cgif->write_y );

	return( 0 );
}

static int
vips_foreign_save_cgif_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveCgif *cgif = (VipsForeignSaveCgif *) object;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( cgif );
	VipsImage **t = (VipsImage **)
		vips_object_local_array( VIPS_OBJECT( cgif ), 2 );

	int page_height;
	VipsRect frame_rect;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_cgif_parent_class )->
		build( object ) )
		return( -1 );

	cgif->in = save->ready;

	/* libimagequant only works with RGBA images.
	 */
	if( cgif->in->Type != VIPS_INTERPRETATION_sRGB ) {
		if( vips_colourspace( cgif->in, &t[0], 
			VIPS_INTERPRETATION_sRGB, NULL ) ) 
			return( -1 );
		cgif->in = t[0];
	}

	/* Add alpha channel if missing. 
	 */
	if( !vips_image_hasalpha( cgif->in ) ) {
		if( vips_addalpha( cgif->in, &t[1], NULL ) ) 
			return( -1 );
		cgif->in = t[1];
	}

	/* Animation properties.
	 */
	page_height = vips_image_get_page_height( cgif->in );
	if( vips_image_get_typeof( cgif->in, "delay" ) )
		vips_image_get_array_int( cgif->in, "delay",
			&cgif->delay, &cgif->delay_length );
	if( vips_image_get_typeof( cgif->in, "loop" ) )
		vips_image_get_int( cgif->in, "loop", &cgif->loop );
	frame_rect.left = 0;
	frame_rect.top = 0;
	frame_rect.width = cgif->in->Xsize;
	frame_rect.height = page_height;
	if( (guint64) frame_rect.width * frame_rect.height > 5000 * 5000 ) {
		vips_error( class->nickname, "%s", _( "frame too large" ) );
		return( -1 );
	}

	/* Assemble frames here.
	 */
	cgif->frame = vips_region_new( cgif->in );
	if( vips_region_buffer( cgif->frame, &frame_rect ) ) 
		return( -1 );

	/* The regions will get used in the bg thread callback,
	 * so make sure we don't own them.
	 */
	vips__region_no_ownership( cgif->frame );

	/* The RGB cmap we write with, sometimes updated on frame write, and
	 * the frame index buffer.
	 */
	cgif->palette_rgb = g_malloc0( 256 * 3 );
	cgif->index = g_malloc0( frame_rect.width * frame_rect.height );

	/* Set up libimagequant.
	 */
	cgif->attr = vips__quantise_attr_create();
	vips__quantise_set_max_colors( cgif->attr, (1 << cgif->bitdepth) - 1 );
	vips__quantise_set_quality( cgif->attr, 0, 100 );
	vips__quantise_set_speed( cgif->attr, 11 - cgif->effort );

	/* Set up cgif on first use.
	 */

	/* Loop down the image, computing it in chunks.
	 */
	if( vips_sink_disc( cgif->in, 
		vips_foreign_save_cgif_sink_disc, cgif ) ) 
		return( -1 );

	VIPS_FREEF( cgif_close, cgif->cgif_context );
	vips_target_finish( cgif->target );

	return( 0 );
}

static const char *vips__save_cgif_suffs[] = { ".gif", NULL };

#define UC VIPS_FORMAT_UCHAR
static int bandfmt_gif[10] = {
	UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_foreign_save_cgif_class_init( VipsForeignSaveCgifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_cgif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifsave_base";
	object_class->description = _( "save as gif" );
	object_class->build = vips_foreign_save_cgif_build;

	foreign_class->suffs = vips__save_cgif_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGBA_ONLY;
	save_class->format_table = bandfmt_gif;

	VIPS_ARG_DOUBLE( class, "dither", 10,
		_( "Dithering" ),
		_( "Amount of dithering" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, dither ),
		0.0, 1.0, 1.0 );

	VIPS_ARG_INT( class, "effort", 11,
		_( "Effort" ),
		_( "Quantisation effort" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, effort ),
		1, 10, 7 );

	VIPS_ARG_INT( class, "bitdepth", 12,
		_( "Bit depth" ),
		_( "Number of bits per pixel" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, bitdepth ),
		1, 8, 8 );

	VIPS_ARG_DOUBLE( class, "maxerror", 13,
		_( "Maximum error" ),
		_( "Maximum inter-frame error for transparency" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, maxerror ),
		0, 32, 0.0 );
}

static void
vips_foreign_save_cgif_init( VipsForeignSaveCgif *gif )
{
	gif->dither = 1.0;
	gif->effort = 7;
	gif->bitdepth = 8;
	gif->maxerror = 0.0;
}

typedef struct _VipsForeignSaveCgifTarget {
	VipsForeignSaveCgif parent_object;

	VipsTarget *target;
} VipsForeignSaveCgifTarget;

typedef VipsForeignSaveCgifClass VipsForeignSaveCgifTargetClass;

G_DEFINE_TYPE( VipsForeignSaveCgifTarget, vips_foreign_save_cgif_target,
	vips_foreign_save_cgif_get_type() );

static int
vips_foreign_save_cgif_target_build( VipsObject *object )
{
	VipsForeignSaveCgif *gif = (VipsForeignSaveCgif *) object;
	VipsForeignSaveCgifTarget *target = 
		(VipsForeignSaveCgifTarget *) object;

	gif->target = target->target;
	g_object_ref( gif->target );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_cgif_target_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_cgif_target_class_init( 
	VipsForeignSaveCgifTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifsave_target";
	object_class->build = vips_foreign_save_cgif_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgifTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_cgif_target_init( VipsForeignSaveCgifTarget *target )
{
}

typedef struct _VipsForeignSaveCgifFile {
	VipsForeignSaveCgif parent_object;
	char *filename;
} VipsForeignSaveCgifFile;

typedef VipsForeignSaveCgifClass VipsForeignSaveCgifFileClass;

G_DEFINE_TYPE( VipsForeignSaveCgifFile, vips_foreign_save_cgif_file,
	vips_foreign_save_cgif_get_type() );

static int
vips_foreign_save_cgif_file_build( VipsObject *object )
{
	VipsForeignSaveCgif *gif = (VipsForeignSaveCgif *) object;
	VipsForeignSaveCgifFile *file = (VipsForeignSaveCgifFile *) object;

	if( !(gif->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_cgif_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_cgif_file_class_init( VipsForeignSaveCgifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifsave";
	object_class->build = vips_foreign_save_cgif_file_build;

	VIPS_ARG_STRING( class, "filename", 1,
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgifFile, filename ),
		NULL );
}

static void
vips_foreign_save_cgif_file_init( VipsForeignSaveCgifFile *file )
{
}

typedef struct _VipsForeignSaveCgifBuffer {
	VipsForeignSaveCgif parent_object;
	VipsArea *buf;
} VipsForeignSaveCgifBuffer;

typedef VipsForeignSaveCgifClass VipsForeignSaveCgifBufferClass;

G_DEFINE_TYPE( VipsForeignSaveCgifBuffer, vips_foreign_save_cgif_buffer,
	vips_foreign_save_cgif_get_type() );

static int
vips_foreign_save_cgif_buffer_build( VipsObject *object )
{
	VipsForeignSaveCgif *gif = (VipsForeignSaveCgif *) object;
	VipsForeignSaveCgifBuffer *buffer = 
		(VipsForeignSaveCgifBuffer *) object;

	VipsBlob *blob;

	if( !(gif->target = vips_target_new_to_memory()) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_cgif_buffer_parent_class )->
		build( object ) )
		return( -1 );

	g_object_get( gif->target, "blob", &blob, NULL );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_cgif_buffer_class_init( 
	VipsForeignSaveCgifBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "gifsave_buffer";
	object_class->build = vips_foreign_save_cgif_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1,
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgifBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_save_cgif_buffer_init( VipsForeignSaveCgifBuffer *buffer )
{
}

#endif /*defined(HAVE_CGIF) && defined(HAVE_IMAGEQUANT)*/

/**
 * vips_gifsave: (method)
 * @in: image to save
 * @filename: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dither: %gdouble, quantisation dithering level
 * * @effort: %gint, quantisation CPU effort
 * * @bitdepth: %gint, number of bits per pixel
 * * @maxerror: %gdouble, maximum inter-frame error for transparency
 *
 * Write to a file in GIF format.
 *
 * Use @dither to set the degree of Floyd-Steinberg dithering
 * and @effort to control the CPU effort (1 is the fastest,
 * 10 is the slowest, 7 is the default).
 *
 * Use @bitdepth (from 1 to 8, default 8) to control the number
 * of colours in the palette. The first entry in the palette is
 * always reserved for transparency. For example, a bitdepth of
 * 4 will allow the output to contain up to 15 colours.
 *
 * Use @maxerror to set the threshold below which pixels are considered equal.
 * Pixels which don't change from frame to frame can be made transparent,
 * improving the compression rate. Default 0.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "gifsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_gifsave_buffer: (method)
 * @in: image to save
 * @buf: (array length=len) (element-type guint8): return output buffer here
 * @len: (type gsize): return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dither: %gdouble, quantisation dithering level
 * * @effort: %gint, quantisation CPU effort
 * * @bitdepth: %gint, number of bits per pixel
 * * @maxerror: %gdouble, maximum inter-frame error for transparency
 *
 * As vips_gifsave(), but save to a memory buffer.
 *
 * The address of the buffer is returned in @buf, the length of the buffer in
 * @len. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_gifsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL;

	va_start( ap, len );
	result = vips_call_split( "gifsave_buffer", ap, in, &area );
	va_end( ap );

	if( !result &&
		area ) {
		if( buf ) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if( len )
			*len = area->length;

		vips_area_unref( area );
	}

	return( result );
}

/**
 * vips_gifsave_target: (method)
 * @in: image to save
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @dither: %gdouble, quantisation dithering level
 * * @effort: %gint, quantisation CPU effort
 * * @bitdepth: %gint, number of bits per pixel
 * * @maxerror: %gdouble, maximum inter-frame error for transparency
 *
 * As vips_gifsave(), but save to a target.
 *
 * See also: vips_gifsave(), vips_image_write_to_target().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_gifsave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "gifsave_target", ap, in, target );
	va_end( ap );

	return( result );
}
