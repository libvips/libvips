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
#define DEBUG_VERBOSE
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "pforeign.h"
#include "quantise.h"

#if defined(HAVE_CGIF) && defined(HAVE_QUANTIZATION)

#include <cgif.h>

/* The modes we work in.
 *
 * VIPS_FOREIGN_SAVE_CGIF_MODE_GLOBAL:
 * 	
 * 	Each frame is dithered to single global colour table taken from the 
 * 	input image "gif-palette" metadata item. 
 *
 * VIPS_FOREIGN_SAVE_CGIF_MODE_LOCAL:
 *
 * 	We find a global palette from the first frame, then write subsequent
 * 	frames with a local palette if they start to drift too far from the
 * 	first frame.
 *
 * We pick GLOBAL if "gif-palette" is set. We pick LOCAL if there is
 * no "gif-palette", or if @reoptimise is set.
 */
typedef enum _VipsForeignSaveCgifMode {
	VIPS_FOREIGN_SAVE_CGIF_MODE_GLOBAL,
	VIPS_FOREIGN_SAVE_CGIF_MODE_LOCAL
} VipsForeignSaveCgifMode;

typedef struct _VipsForeignSaveCgif {
	VipsForeignSave parent_object;

	double dither;
	int effort;
	int bitdepth;
	double interframe_maxerror;
	gboolean reoptimise;
	gboolean interlace;
	double interpalette_maxerror;
	VipsTarget *target;

	/* Derived write params.
	 */
	VipsForeignSaveCgifMode mode;
	VipsImage *in;				/* Not a reference */
	int *delay;
	int delay_length;
	int loop;

	/* The RGBA palette attached to the input image (if any).
	 */
	int *palette;
	int n_colours;

	/* The current frame coming from libvips, and the y position 
	 * in the input image.
	 */
	VipsRegion *frame;
	int write_y;

	/* VipsRegion is not always contiguious, but we need contiguious RGBA
	 * forthe quantizer. We need to copy each frame to a local buffer.
	 */
	VipsPel *frame_bytes;

	/* The current frame as seen by libimagequant.
	 */
	VipsQuantiseAttr *attr;
	VipsQuantiseResult *quantisation_result;

	/* The palette we used for the previous frame. This can be equal to 
	 * quantisation_result if we used the global palette for the previous
	 * frame, so don't free this.
	 */
	VipsQuantiseResult *previous_quantisation_result;

	/* ... and a palette we will need to free.
	 */
	VipsQuantiseResult *free_quantisation_result;

	/* The index frame we get libimagequant to generate.
	 */
	VipsPel *index;

	/* The previous RGBA frame (needed for transparency trick).
	*/
	VipsPel *previous_frame;

	/* The frame as written by libcgif.
	 */
	CGIF *cgif_context;
	CGIF_Config cgif_config;

	int n_palettes_generated;
} VipsForeignSaveCgif;

typedef VipsForeignSaveClass VipsForeignSaveCgifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveCgif, vips_foreign_save_cgif,
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_cgif_dispose( GObject *gobject )
{
	VipsForeignSaveCgif *cgif = (VipsForeignSaveCgif *) gobject;

	if( cgif->frame ) {
		g_info( "cgifsave: %d frames", 
			cgif->frame->im->Ysize / cgif->frame->valid.height );
		g_info( "cgifsave: %d unique palettes", 
			cgif->n_palettes_generated );
	}

	VIPS_FREEF( cgif_close, cgif->cgif_context );

	VIPS_FREEF( vips__quantise_result_destroy, cgif->quantisation_result );
	VIPS_FREEF( vips__quantise_result_destroy, cgif->
		free_quantisation_result );
	VIPS_FREEF( vips__quantise_attr_destroy, cgif->attr );

	VIPS_UNREF( cgif->frame );

	VIPS_UNREF( cgif->target );

	VIPS_FREE( cgif->index );
	VIPS_FREE( cgif->frame_bytes );
	VIPS_FREE( cgif->previous_frame );

	G_OBJECT_CLASS( vips_foreign_save_cgif_parent_class )->
		dispose( gobject );
}

static int 
vips__cgif_write( void *client, const uint8_t *buffer, const size_t length ) 
{
	VipsTarget *target = VIPS_TARGET( client );

	return vips_target_write( target,
		(const void *) buffer, (size_t) length );
}

/* Set pixels in index transparent if they are equal RGB to the previous 
 * frame.
 *
 * In combination with the GIF transparency optimization this leads to
 * less difference between frames and therefore improves the compression ratio.
 */
static void
vips_foreign_save_cgif_set_transparent( VipsForeignSaveCgif *cgif,
	VipsPel *old, VipsPel *new, VipsPel *index, int n_pels, int trans )
{
	int sq_maxerror = cgif->interframe_maxerror * cgif->interframe_maxerror;

	int i;

	for( i = 0; i < n_pels; i++ ) {
		/* Alpha must match
		 */
		if( old[3] == new[3] ) {
			/* Both transparent ... no need to check RGB.
			 */
			if( !old[3] && !new[3] )
				index[i] = trans;
			else {
				/* Compare RGB.
				 */
				const int dR = old[0] - new[0];
				const int dG = old[1] - new[1];
				const int dB = old[2] - new[2];

				if( dR * dR + dG * dG + dB * dB <= sq_maxerror )
					index[i] = trans;
			}
		}

		if( index[i] != trans ) {
			old[0] = new[0];
			old[1] = new[1];
			old[2] = new[2];
			old[3] = new[3];
		}

		old += 4;
		new += 4;
	}
}

static double
vips__cgif_compare_palettes( const VipsQuantisePalette *new,
	const VipsQuantisePalette *old )
{
	int i, j;
	double best_dist, dist, rd, gd, bd;
	double total_dist;

	g_assert( new->count <= 256 );
	g_assert( old->count <= 256 );

	total_dist = 0;
	for( i = 0; i < new->count; i++ ) {
		best_dist = 255 * 255 * 3;

		for( j = 0; j < old->count; j++ ) {
			if( new->entries[i].a ) {
				/* The new entry is solid.
				 * If the old entry is transparent, ignore it.
				 * Otherwise, compare RGB.
				*/
				if( !old->entries[j].a )
					continue;

				rd = new->entries[i].r - old->entries[j].r;
				gd = new->entries[i].g - old->entries[j].g;
				bd = new->entries[i].b - old->entries[j].b;
				dist = rd * rd + gd * gd + bd * bd;

				best_dist = VIPS_MIN( best_dist, dist );

				/* We found the closest entry
				 */
				if( best_dist == 0 )
					break;
			} 
			else {
				/* The new entry is transparent.
				 * If the old entry is transparent too, it's
				 * the closest color. Otherwise, ignore it.
				 */
				if( !old->entries[j].a ) {
					best_dist = 0;
					break;
				}
			}
		}

		total_dist += best_dist;
	}

	return( sqrt( total_dist / (3 * new->count) ) );
}

/* Extract the generated palette as RGB.
 */
static void
vips_foreign_save_cgif_get_rgb_palette( VipsForeignSaveCgif *cgif,
	VipsQuantiseResult *quantisation_result, VipsPel *rgb )
{
	const VipsQuantisePalette *lp = 
		vips__quantise_get_palette( quantisation_result );

	int i;

	g_assert( lp->count <= 256 );

	for( i = 0; i < lp->count; i++ ) {
		rgb[0] = lp->entries[i].r;
		rgb[1] = lp->entries[i].g;
		rgb[2] = lp->entries[i].b;

		rgb += 3;
	}
}

/* Pick a quantiser for LOCAL mode.
 */
int
vips_foreign_save_cgif_pick_quantiser( VipsForeignSaveCgif *cgif, 
	VipsQuantiseImage *image,
	VipsQuantiseResult **result, gboolean *use_local )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( cgif );

	VipsQuantiseResult *this_result;

	if( vips__quantise_image_quantize_fixed( image, cgif->attr, 
		&this_result ) ) {
		vips_error( class->nickname, "%s", _( "quantisation failed" ) );
		return( -1 );
	}

	/* No global quantiser set up yet? Use this.
	 */
	if( !cgif->quantisation_result ) {
#ifdef DEBUG_VERBOSE
		printf( "vips_foreign_save_cgif_pick_quantiser: "
			"global palette from first frame\n" );
#endif/*DEBUG_VERBOSE*/

		cgif->quantisation_result = this_result;
		cgif->n_palettes_generated += 1;

		*result = this_result;
		*use_local = FALSE;
	}
	else {
		/* Compare the palette we just made to the palette
		 * for the previous frame, and to the global palette.
		 */
		const VipsQuantisePalette *global = vips__quantise_get_palette( 
			cgif->quantisation_result );
		const VipsQuantisePalette *this = vips__quantise_get_palette( 
			this_result );
		const VipsQuantisePalette *prev = vips__quantise_get_palette( 
			cgif->previous_quantisation_result );

		double global_diff = vips__cgif_compare_palettes( this, global );
		double prev_diff = ( prev == global ) ? global_diff :
			vips__cgif_compare_palettes( this, prev );

#ifdef DEBUG_VERBOSE
		printf( "vips_foreign_save_cgif_write_frame: "
			"this -> global distance = %g\n",
			global_diff );
		printf( "vips_foreign_save_cgif_write_frame: "
			"this -> prev distance = %g\n",
			prev_diff );
		printf( "vips_foreign_save_cgif_write_frame: "
			"threshold = %g\n", cgif->interpalette_maxerror );
#endif/*DEBUG_VERBOSE*/

		if( global_diff <= prev_diff &&
			global_diff < cgif->interpalette_maxerror ) {
			/* Global is good enough, use that.
			 */
#ifdef DEBUG_VERBOSE
			printf( "vips_foreign_save_cgif_write_frame: "
				"using global palette\n" );
#endif/*DEBUG_VERBOSE*/

			VIPS_FREEF( vips__quantise_result_destroy, 
				this_result );
			VIPS_FREEF( vips__quantise_result_destroy, 
				cgif->free_quantisation_result );

			*result = cgif->quantisation_result;
			*use_local = FALSE;
		}
		else if( prev_diff < cgif->interpalette_maxerror ) {
			/* Previous is good enough, use that again.
			 */
#ifdef DEBUG_VERBOSE
			printf( "vips_foreign_save_cgif_write_frame: "
				"using previous palette\n" );
#endif/*DEBUG_VERBOSE*/

			VIPS_FREEF( vips__quantise_result_destroy, 
				this_result );

			*result = cgif->previous_quantisation_result;
			*use_local = TRUE;
		}
		else {
			/* Nothing else works, we need a new local
			 * palette.
			 */
#ifdef DEBUG_VERBOSE
			printf( "vips_foreign_save_cgif_write_frame: "
				"using new local palette\n" );
#endif/*DEBUG_VERBOSE*/

			VIPS_FREEF( vips__quantise_result_destroy, 
				cgif->free_quantisation_result );
			cgif->free_quantisation_result = this_result;
			cgif->n_palettes_generated += 1;

			*result = this_result;
			*use_local = TRUE;
		}
	}

	cgif->previous_quantisation_result = *result;

	return( 0 );
}

/* We have a complete frame --- write!
 */
static int
vips_foreign_save_cgif_write_frame( VipsForeignSaveCgif *cgif )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( cgif );
	VipsRect *frame_rect = &cgif->frame->valid;
	int page_index = frame_rect->top / frame_rect->height;
	int n_pels = frame_rect->height * frame_rect->width;

	gboolean has_transparency;
	gboolean has_alpha_constraint;
	VipsPel * restrict p;
	int i;
	int y;
	VipsQuantiseImage *image;
	gboolean use_local;
	VipsQuantiseResult *quantisation_result;
	const VipsQuantisePalette *lp;
	CGIF_FrameConfig frame_config = { 0 };
	int n_colours;
	VipsPel palette_rgb[256 * 3];

#ifdef DEBUG_VERBOSE
	printf( "vips_foreign_save_cgif_write_frame: %d\n", page_index );
#endif/*DEBUG_VERBOSE*/

	/* We need the frame as a contiguious RGBA buffer for the quantiser.
	 */
	for( y = 0; y < frame_rect->height; y++ )
		memcpy( cgif->frame_bytes + y * 4 * frame_rect->width,
			VIPS_REGION_ADDR( cgif->frame, 0, frame_rect->top + y ),
			4 * frame_rect->width );

	/* Threshold the alpha channel. 
	 *
	 * Also, check if the alpha channel of the current frame matches the
	 * frame before.
	 *
	 * If the current frame has an alpha component which is not identical
	 * to the previous frame we are forced to use the transparency index
	 * for the alpha channel instead of for the transparency size
	 * optimization (maxerror).
	 */
	p = cgif->frame_bytes;
	has_alpha_constraint = FALSE;
	for( i = 0; i < n_pels; i++ ) {
		if( p[3] >= 128 )
			p[3] = 255;
		else {
			/* Helps the quantiser generate a better palette.
			 */
			p[0] = 0;
			p[1] = 0;
			p[2] = 0;
			p[3] = 0;

			if( page_index > 0 &&
				cgif->previous_frame[i * 4 + 3] )
				has_alpha_constraint = TRUE;
		}

		p += 4;
	}

	/* Set up new frame for libimagequant.
	 */
	image = vips__quantise_image_create_rgba( cgif->attr,
		cgif->frame_bytes, frame_rect->width, frame_rect->height, 0 );

	/* Quantise.
	 */
	if( cgif->mode == VIPS_FOREIGN_SAVE_CGIF_MODE_GLOBAL ) {
		/* Global mode: use the global palette.
		 */
		quantisation_result = cgif->quantisation_result;
		use_local = FALSE;
	}
	else {
		/* Local mode. Pick the global, this or previous palette.
		 */
		if( vips_foreign_save_cgif_pick_quantiser( cgif, 
			image, &quantisation_result, &use_local ) )
			return( -1 );
	}

	lp = vips__quantise_get_palette( quantisation_result );
	/* If there's a transparent pixel, it's always first.
	 */
	has_transparency = lp->entries[0].a == 0;
	n_colours = lp->count;
	vips_foreign_save_cgif_get_rgb_palette( cgif,
		quantisation_result, palette_rgb );

	/* Dither frame into @index.
	 */
	vips__quantise_set_dithering_level( quantisation_result, cgif->dither );
	if( vips__quantise_write_remapped_image( quantisation_result,
		image, cgif->index, n_pels ) ) {
		vips_error( class->nickname, "%s", _( "dither failed" ) );
		VIPS_FREEF( vips__quantise_image_destroy, image );
		return( -1 );
	}

	VIPS_FREEF( vips__quantise_image_destroy, image );

	/* Set up cgif on first use.
	 */
	if( !cgif->cgif_context ) {
#ifdef HAVE_CGIF_ATTR_NO_LOOP
		cgif->cgif_config.attrFlags = 
			CGIF_ATTR_IS_ANIMATED | 
			(cgif->loop == 1 ? CGIF_ATTR_NO_LOOP : 0);
		cgif->cgif_config.numLoops = cgif->loop > 1 ? 
			cgif->loop - 1 : cgif->loop;
#else /*!HAVE_CGIF_ATTR_NO_LOOP*/
		cgif->cgif_config.attrFlags = CGIF_ATTR_IS_ANIMATED;
		cgif->cgif_config.numLoops = cgif->loop;
#endif/*HAVE_CGIF_ATTR_NO_LOOP*/

		cgif->cgif_config.width = frame_rect->width;
		cgif->cgif_config.height = frame_rect->height;
		cgif->cgif_config.pGlobalPalette = palette_rgb;
		cgif->cgif_config.numGlobalPaletteEntries = n_colours;
		cgif->cgif_config.pWriteFn = vips__cgif_write;
		cgif->cgif_config.pContext = (void *) cgif->target;

		cgif->cgif_context = cgif_newgif( &cgif->cgif_config );
	}

	/* Allow cgif to optimise by adding transparency. These optimisations
	 * will be automatically disabled if they are not possible.
	 */
	frame_config.genFlags = 
		CGIF_FRAME_GEN_USE_TRANSPARENCY | 
		CGIF_FRAME_GEN_USE_DIFF_WINDOW;
	frame_config.attrFlags = 0;

	/* Switch per-frame alpha channel on. Index 0 is used for pixels 
	 * with alpha channel.
	 */
	if( has_transparency ) {
		frame_config.attrFlags |= CGIF_FRAME_ATTR_HAS_ALPHA;
		frame_config.transIndex = 0;
	}

	/* Pixels which are equal to pixels in the previous frame can be made
	 * transparent, provided no alpha channel constraint is present.
	 */
	if( page_index > 0 &&
		!has_alpha_constraint ) {
		int trans = has_transparency ? 0 : n_colours;

		vips_foreign_save_cgif_set_transparent( cgif,
			cgif->previous_frame, cgif->frame_bytes, cgif->index, 
			n_pels, trans );

		if( has_transparency ) 
			frame_config.attrFlags &= ~CGIF_FRAME_ATTR_HAS_ALPHA;
		frame_config.attrFlags |= CGIF_FRAME_ATTR_HAS_SET_TRANS;
		frame_config.transIndex = trans;
	}
	else {
		/* Take a copy of the RGBA frame.
		 */
		memcpy( cgif->previous_frame, cgif->frame_bytes, 4 * n_pels );
	}

	if( cgif->delay &&
		page_index < cgif->delay_length )
		frame_config.delay = 
			VIPS_RINT( cgif->delay[page_index] / 10.0 );

	/* Attach a local palette, if we need one.
	 */
	if( use_local ) {
		frame_config.attrFlags |= CGIF_FRAME_ATTR_USE_LOCAL_TABLE;
		frame_config.pLocalPalette = palette_rgb;
		frame_config.numLocalPaletteEntries = n_colours;
	}

	/* Write an interlaced GIF, if requested.
	*/
	if( cgif->interlace ) {
#ifdef HAVE_CGIF_FRAME_ATTR_INTERLACED
		frame_config.attrFlags |= CGIF_FRAME_ATTR_INTERLACED;
#else /*!HAVE_CGIF_FRAME_ATTR_INTERLACED*/
		g_warning( "%s: cgif >= v0.3.0 required for interlaced GIF write", class->nickname );
#endif /*HAVE_CGIF_FRAME_ATTR_INTERLACED*/
	}

	/* Write frame to cgif.
	 */
	frame_config.pImageData = cgif->index;
	cgif_addframe( cgif->cgif_context, &frame_config );

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

			/* End of image?
			 */
			if( vips_rect_isempty( &new_frame ) )
				break;

			if( vips_region_buffer( cgif->frame, &new_frame ) ) 
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

	/* Reject images that exceed the pixel limit of libimagequant,
	 * or that exceed the GIF limit of 64k per axis.
	 *
	 * Frame width * height will fit in an int, though frame size will
	 * need at least a uint.
	 */
	if( (guint64) frame_rect.width * frame_rect.height > INT_MAX / 4 || 
		frame_rect.width > 65535 || 
		frame_rect.height > 65535 ) {
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

	/* This RGBA frame as a contiguious buffer.
	 */
	cgif->frame_bytes = g_malloc0( (size_t) 4 * 
		frame_rect.width * frame_rect.height );

	/* The previous RGBA frame (for spotting pixels which haven't changed).
	 */
	cgif->previous_frame = g_malloc0( (size_t) 4 * 
		frame_rect.width * frame_rect.height );

	/* The frame index buffer.
	 */
	cgif->index = g_malloc0( (size_t) frame_rect.width * 
		frame_rect.height );

	/* Set up libimagequant.
	 */
	cgif->attr = vips__quantise_attr_create();
	/* Limit the number of colours to 255, so there is always one index
	 * free for the transparency optimization.
	 */
	vips__quantise_set_max_colors( cgif->attr,
		VIPS_MIN( 255, 1 << cgif->bitdepth ) );
	vips__quantise_set_quality( cgif->attr, 0, 100 );
	vips__quantise_set_speed( cgif->attr, 11 - cgif->effort );

	/* Read the palette on the input, if any.
	 */
	if( vips_image_get_typeof( cgif->in, "gif-palette" ) ) {
		if( vips_image_get_array_int( cgif->in, "gif-palette",
			&cgif->palette, &cgif->n_colours ) )
			return( -1 );

		if( cgif->n_colours > 256 ) {
		       vips_error( class->nickname,
				"%s", _( "gif-palette too large" ) );
		       return( -1 );
		}
	}

	/* LOCAL mode if there's no input palette, or reoptimise is set.
	 */
	if( cgif->reoptimise ||
		!cgif->palette ) 
		cgif->mode = VIPS_FOREIGN_SAVE_CGIF_MODE_LOCAL;

	/* Set up GLOBAL mode. Init the quantisation_result we will
	 * use to dither frames with a fixed palette taken from the input
	 * image.
	 */
	if( cgif->mode == VIPS_FOREIGN_SAVE_CGIF_MODE_GLOBAL ) {
		/* Make a fake image from the input palette, and quantise that. 
		 * Add a zero pixel (transparent) in case the input image has
		 * transparency.
		 *
		 * We know palette fits in 256 entries.
		 */
		guint32 fake_image[257];
		VipsQuantiseImage *image;

		memcpy( fake_image, cgif->palette, 
			cgif->n_colours * sizeof( int ) );
		fake_image[cgif->n_colours] = 0;
		image = vips__quantise_image_create_rgba( cgif->attr,
			fake_image, cgif->n_colours + 1, 1, 0 );

		if( vips__quantise_image_quantize_fixed( image,
		       cgif->attr, &cgif->quantisation_result ) ) {
		       vips_error( class->nickname,
				"%s", _( "quantisation failed" ) );
		       return( -1 );
		}

		VIPS_FREEF( vips__quantise_image_destroy, image );
	}

	if( vips_sink_disc( cgif->in, 
		vips_foreign_save_cgif_sink_disc, cgif ) ) 
		return( -1 );

	VIPS_FREEF( cgif_close, cgif->cgif_context );

	if( vips_target_end( cgif->target ) )
		return( -1 );

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

	VIPS_ARG_DOUBLE( class, "interframe_maxerror", 13,
		_( "Maximum inter-frame error" ),
		_( "Maximum inter-frame error for transparency" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, interframe_maxerror ),
		0, 32, 0.0 );

	VIPS_ARG_BOOL( class, "reoptimise", 14,
		_( "Reoptimise palettes" ),
		_( "Reoptimise colour palettes" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, reoptimise ),
		FALSE );

	VIPS_ARG_DOUBLE( class, "interpalette_maxerror", 15,
		_( "Maximum inter-palette error" ),
		_( "Maximum inter-palette error for palette reusage" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, interpalette_maxerror ),
		0, 256, 3.0 );

	VIPS_ARG_BOOL( class, "interlace", 16,
		_( "Interlaced" ),
		_( "Generate an interlaced (progressive) GIF" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveCgif, interlace ),
		FALSE );

}

static void
vips_foreign_save_cgif_init( VipsForeignSaveCgif *gif )
{
	gif->dither = 1.0;
	gif->effort = 7;
	gif->bitdepth = 8;
	gif->interframe_maxerror = 0.0;
	gif->reoptimise = FALSE;
	gif->interlace = FALSE;
	gif->interpalette_maxerror = 3.0;
	gif->mode = VIPS_FOREIGN_SAVE_CGIF_MODE_GLOBAL;
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
 * * @interframe_maxerror: %gdouble, maximum inter-frame error for transparency
 * * @reoptimise: %gboolean, reoptimise colour palettes
 * * @interlace: %gboolean, write an interlaced (progressive) GIF
 * * @interpalette_maxerror: %gdouble, maximum inter-palette error for palette
 *   reusage
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
 * Use @interframe_maxerror to set the threshold below which pixels are
 * considered equal.
 * Pixels which don't change from frame to frame can be made transparent,
 * improving the compression rate. Default 0.
 *
 * If @reoptimise is TRUE, new palettes will be generated. Use
 * @interpalette_maxerror to set the threshold below which one of the previously
 * generated palettes will be reused.
 *
 * If @interlace is TRUE, the GIF file will be interlaced (progressive GIF).
 * These files may be better for display over a slow network
 * conection, but need more memory to encode.
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
 * * @interframe_maxerror: %gdouble, maximum inter-frame error for transparency
 * * @reoptimise: %gboolean, reoptimise colour palettes
 * * @interlace: %gboolean, write an interlaced (progressive) GIF
 * * @interpalette_maxerror: %gdouble, maximum inter-palette error for palette
 *   reusage
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
 * * @interframe_maxerror: %gdouble, maximum inter-frame error for transparency
 * * @reoptimise: %gboolean, reoptimise colour palettes
 * * @interlace: %gboolean, write an interlaced (progressive) GIF
 * * @interpalette_maxerror: %gdouble, maximum inter-palette error for palette
 *   reusage
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
