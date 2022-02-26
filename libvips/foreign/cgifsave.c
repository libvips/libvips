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
	 *
	 * frame_sum is 32-bit, so we can handle a max of about 2000 x 2000 
	 * RGB pixel per frame.
	 */
	VipsPel *palette_rgb;
	guint frame_sum;

	/* The index frame we get libimagequant to generate.
	 */
	VipsPel *index;

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

	VIPS_UNREF( cgif->target );
	VIPS_UNREF( cgif->frame );

	VIPS_FREEF( vips__quantise_result_destroy, cgif->quantisation_result );
	VIPS_FREEF( vips__quantise_image_destroy, cgif->input_image );
	VIPS_FREEF( vips__quantise_attr_destroy, cgif->attr );

	VIPS_FREE( cgif->palette_rgb );
	VIPS_FREE( cgif->index );

	VIPS_FREEF( cgif_close, cgif->cgif_context );

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
	guint max_sum = 256 * n_pels * 4;
	VipsPel *frame_bytes = 
		VIPS_REGION_ADDR( cgif->frame, 0, frame_rect->top );

	VipsPel * restrict p;
	VipsPel *rgb;
	guint sum;
	double percent_change;
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
	for( i = 0; i < n_pels * 4; i++ )
		sum += p[i]; 
	percent_change = 100 * 
		fabs( ((double) sum / max_sum) - 
			((double) cgif->frame_sum / max_sum) );

	if( cgif->frame_sum == 0 ||
		percent_change > 0 ) { 
		cgif->frame_sum = sum;

		/* If this is not our first cmap, make a note that we need to
		 * attach it as a local cmap when we write.
		 */
		if( cgif->quantisation_result ) 
			cgif->cgif_config.attrFlags |= CGIF_ATTR_NO_GLOBAL_TABLE;

		VIPS_FREEF( vips__quantise_result_destroy, cgif->quantisation_result );
		if( vips__quantise_image_quantize( cgif->input_image, cgif->attr,
			&cgif->quantisation_result ) ) { 
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
	vips__quantise_set_dithering_level( cgif->quantisation_result, cgif->dither );
	if( vips__quantise_write_remapped_image( cgif->quantisation_result,
		cgif->input_image, cgif->index, n_pels ) ) {
		vips_error( class->nickname, "%s", _( "dither failed" ) );
		return( -1 );
	}

	/* Call vips__quantise_get_palette() after vips__quantise_write_remapped_image(),
	 * as palette is improved during remapping.
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

	/* If there's a transparent pixel, it's always first.
	 */
	cgif->has_transparency = cgif->lp->entries[0].a == 0;

#ifdef DEBUG_PERCENT
	if( percent_change > 0 )
		printf( "frame %d, %.4g%% change, new %d item colourmap\n",
			page_index, percent_change, cgif->lp->count );
	else
		printf( "frame %d, reusing previous %d item colourmap\n",
			page_index, cgif->lp->count );
#endif/*DEBUG_PERCENT*/

	/* Set up cgif on first use, so we can set the first cmap as the global
	 * one.
	 *
	 * We switch to local tables if we find we need a new palette.
	 */
	if( !cgif->cgif_context ) {
		cgif->cgif_config.pGlobalPalette = cgif->palette_rgb;
		cgif->cgif_config.attrFlags = CGIF_ATTR_IS_ANIMATED;
		cgif->cgif_config.attrFlags |= 
			cgif->has_transparency ? CGIF_ATTR_HAS_TRANSPARENCY : 0;
		cgif->cgif_config.width = frame_rect->width;
		cgif->cgif_config.height = frame_rect->height;
		cgif->cgif_config.numGlobalPaletteEntries = cgif->lp->count;
		cgif->cgif_config.numLoops = cgif->loop;
		cgif->cgif_config.pWriteFn = vips__cgif_write;
		cgif->cgif_config.pContext = (void *) cgif->target;

		cgif->cgif_context = cgif_newgif( &cgif->cgif_config );
	}

	/* Reset global transparency flag.
	 */
	cgif->cgif_config.attrFlags = 
		(cgif->cgif_config.attrFlags & ~CGIF_ATTR_HAS_TRANSPARENCY) |
		(cgif->has_transparency ? CGIF_ATTR_HAS_TRANSPARENCY : 0);

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

	if( cgif->delay &&
		page_index < cgif->delay_length )
		frame_config.delay = 
			VIPS_RINT( cgif->delay[page_index] / 10.0 );

	/* Attach a local palette, if we need one.
	 */
	if( cgif->cgif_config.attrFlags & CGIF_ATTR_NO_GLOBAL_TABLE ) {
		frame_config.attrFlags = CGIF_FRAME_ATTR_USE_LOCAL_TABLE;
		frame_config.pLocalPalette = cgif->palette_rgb;
		frame_config.numLocalPaletteEntries = cgif->lp->count;
	}

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
	for(;;) {
		VipsRect *to = &cgif->frame->valid;
		VipsRect target;

		/* The bit of the frame that needs filling.
		 */
		target.left = 0;
		target.top = cgif->write_y;
		target.width = to->width;
		target.height = to->height;
		vips_rect_intersectrect( &target, to, &target );

		/* Clip against the pixels we have just been given.
		 */
		vips_rect_intersectrect( &target, area, &target );

		/* Have we used up all the pixels libvips just gave us? We are 
		 * done.
		 */
		if( vips_rect_isempty( &target ) ) 
			break;

		/* Write the new pixels into the frame.
		 */
		vips_region_copy( region, cgif->frame, 
			&target, target.left, target.top );

		cgif->write_y += target.height;

		/* If frame has filled, write it, and move the frame down the
		 * image.
		 */
		if( cgif->write_y == VIPS_RECT_BOTTOM( to ) ) {
			VipsRect frame_rect;

			if( vips_foreign_save_cgif_write_frame( cgif ) ) 
				return( -1 );

			frame_rect.left = 0;
			frame_rect.top = cgif->write_y;
			frame_rect.width = to->width;
			frame_rect.height = to->height;
			if( vips_region_buffer( cgif->frame, &frame_rect ) ) 
				return( -1 );
		}
	}

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
	if( (guint64) frame_rect.width * frame_rect.height > 2000 * 2000 ) {
		/* RGBA sum may overflow a 32-bit uint.
		 */
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

}

static void
vips_foreign_save_cgif_init( VipsForeignSaveCgif *gif )
{
	gif->dither = 1.0;
	gif->effort = 7;
	gif->bitdepth = 8;
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
 *
 * Write a VIPS image to a file as GIF.
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
