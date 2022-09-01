/* save as WebP 
 *
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

#ifdef HAVE_LIBWEBP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

#include <webp/encode.h>
#include <webp/types.h>
#include <webp/mux.h>

typedef int (*webp_import)( WebPPicture *picture,
        const uint8_t *rgb, int stride );

typedef enum _VipsForeignSaveWebPMode {
	VIPS_FOREIGN_SAVE_WEBP_MODE_SINGLE,
	VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM
} VipsForeignSaveWebPMode;

typedef struct _VipsForeignSaveWebP {
	VipsForeignSave parent_object;

	/* Animated or single image write mode?
	 * Important, because we use a different API
	 * for animated WebP write.
	 */
	VipsForeignSaveWebPMode mode;
        VipsImage *image;

	int timestamp_ms;
        int Q;
        gboolean lossless;
        VipsForeignWebpPreset preset;
        gboolean smart_subsample;
        gboolean near_lossless;
        int alpha_q;
        int effort;
        gboolean min_size;
        gboolean mixed;
        int kmin;
        int kmax;
	int gif_delay;
	int *delay;
	int delay_length;
        gboolean strip;
        const char *profile;

        WebPConfig config;

        /* Output is written here. We can only support memory write, since we
         * handle metadata.
         */
        WebPMemoryWriter memory_writer;

        /* Write animated webp here.
         */
        WebPAnimEncoder *enc;

        /* Add metadata with this.
         */
        WebPMux *mux;
	VipsTarget *target;

	/* The current frame coming from libvips, and the y position 
	 * in the input image.
	 */
	VipsRegion *frame;
	int write_y;

	/* VipsRegion is not always contiguious, but we need contiguous RGB(A)
	 * for libwebp. We need to copy each frame to a local buffer.
	 */
	VipsPel *frame_bytes;

} VipsForeignSaveWebP;

typedef VipsForeignSaveClass VipsForeignSaveWebPClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveWebP, vips_foreign_save_webp,
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_webp_write_unset( VipsForeignSaveWebP *write )
{
	WebPMemoryWriterClear( &write->memory_writer );
	VIPS_FREEF( WebPAnimEncoderDelete, write->enc );
	VIPS_FREEF( WebPMuxDelete, write->mux );
	VIPS_UNREF( write->image );
}

static void
vips_foreign_save_webp_dispose( GObject *gobject )
{
	VipsForeignSaveWebP *webp= (VipsForeignSaveWebP *) gobject;

	VIPS_UNREF( webp->frame );

	VIPS_UNREF( webp->target );

	VIPS_FREE( webp->frame_bytes );

	G_OBJECT_CLASS( vips_foreign_save_webp_parent_class )->
		dispose( gobject );
}

static gboolean
vips_webp_pic_init( VipsForeignSaveWebP *write, WebPPicture *pic )
{
	if( !WebPPictureInit( pic ) ) {
		vips_error( "webpsave", "%s", _( "picture version error" ) );
		return( FALSE );
	}
	pic->writer = WebPMemoryWrite;
	pic->custom_ptr = (void *) &write->memory_writer;

        /* Smart subsampling needs use_argb because it is applied during 
         * RGB to YUV conversion.
         */
        pic->use_argb = write->lossless ||
                write->near_lossless ||
                write->smart_subsample;

        return( TRUE );
}

/* Write a VipsImage into an unintialised pic.
 */
static int
write_webp_image( VipsForeignSaveWebP *write, const VipsPel *imagedata, WebPPicture *pic )
{
        webp_import import;
	int page_height = vips_image_get_page_height( write->image );

        if( !vips_webp_pic_init( write, pic ) )
                return( -1 );

        pic->width = write->image->Xsize;
        pic->height = page_height; 

        if( write->image->Bands == 4 )
                import = WebPPictureImportRGBA;
        else
                import = WebPPictureImportRGB;

        if( !import( pic, imagedata,
                write->image->Xsize * write->image->Bands ) ) {
                WebPPictureFree( pic );
                vips_error( "webpsave", "%s", _( "picture memory error" ) );
                return( -1 );
        }

        return( 0 );
}

/* We have a complete frame --- write!
 */
static int
vips_foreign_save_webp_write_frame( VipsForeignSaveWebP *webp)
{
	WebPPicture pic;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( webp );
	VipsRect *frame_rect = &webp->frame->valid;
	int page_index = frame_rect->top / frame_rect->height;

	/* We need the frame as a contiguous RGB(A) buffer for libwebp.
	 */
	for( int y = 0; y < frame_rect->height; y++ )
		memcpy( webp->frame_bytes + y * webp->image->Bands * frame_rect->width,
			VIPS_REGION_ADDR( webp->frame, 0, frame_rect->top + y ),
			webp->image->Bands * frame_rect->width );

	if( write_webp_image( webp, webp->frame_bytes, &pic ) ) {
		return( -1 );
	}

	/* Animated write
	 */
	if( webp->mode == VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM ) {
		if( !WebPAnimEncoderAdd( webp->enc,
			&pic, webp->timestamp_ms, &webp->config ) ) {
			WebPPictureFree( &pic );
			vips_error( class->nickname,
				"%s", _( "anim add error" ) );
			return( -1 );
		}
		/* Adjust current timestamp
		 */
		if( webp->delay &&
			page_index < webp->delay_length )
			webp->timestamp_ms += webp->delay[page_index] <= 10 ?
				100 : webp->delay[page_index];
		else
			webp->timestamp_ms += webp->gif_delay * 10;
	} else {
		/* Single image write
		 */
		if( !WebPEncode( &webp->config, &pic ) ) {
			WebPPictureFree( &pic );
			vips_error( "webpsave", "%s", _( "unable to encode" ) );
			return( -1 );
		}
	}

	WebPPictureFree( &pic );

	return( 0 );
}

/* Another chunk of pixels have arrived from the pipeline. Add to frame, and
 * if the frame completes, compress and write to the target.
 */
static int
vips_foreign_save_webp_sink_disc( VipsRegion *region, VipsRect *area, void *a )
{
	VipsForeignSaveWebP *webp = (VipsForeignSaveWebP*) a;

	/* Write the new pixels into frame.
	 */
	do {
		VipsRect *to = &webp->frame->valid;

		VipsRect hit;

		/* The bit of the frame that we can fill.
		 */
		vips_rect_intersectrect( area, to, &hit );

		/* Write the new pixels into the frame.
		 */
		vips_region_copy( region, webp->frame, 
			&hit, hit.left, hit.top );

		webp->write_y += hit.height;

		/* If we've filled the frame, write and move it down.
		 */
		if( VIPS_RECT_BOTTOM( &hit ) == VIPS_RECT_BOTTOM( to ) ) {
			VipsRect new_frame;
			VipsRect image;

			if( vips_foreign_save_webp_write_frame( webp ) ) 
				return( -1 );

			new_frame.left = 0;
			new_frame.top = webp->write_y;
			new_frame.width = to->width;
			new_frame.height = to->height;
			image.left = 0;
			image.top = 0;
			image.width = webp->image->Xsize;
			image.height = webp->image->Ysize;
			vips_rect_intersectrect( &new_frame, &image, 
				&new_frame );

			/* End of image?
			 */
			if( vips_rect_isempty( &new_frame ) )
				break;

			if( vips_region_buffer( webp->frame, &new_frame ) ) 
				return( -1 );
		}
	} while( VIPS_RECT_BOTTOM( area ) > webp->write_y );

	return( 0 );
}

static WebPPreset
get_preset( VipsForeignWebpPreset preset )
{
        switch( preset ) {
        case VIPS_FOREIGN_WEBP_PRESET_DEFAULT:
                return( WEBP_PRESET_DEFAULT );
        case VIPS_FOREIGN_WEBP_PRESET_PICTURE:
                return( WEBP_PRESET_PICTURE );
        case VIPS_FOREIGN_WEBP_PRESET_PHOTO:
                return( WEBP_PRESET_PHOTO );
        case VIPS_FOREIGN_WEBP_PRESET_DRAWING:
                return( WEBP_PRESET_DRAWING );
        case VIPS_FOREIGN_WEBP_PRESET_ICON:
                return( WEBP_PRESET_ICON );
        case VIPS_FOREIGN_WEBP_PRESET_TEXT:
                return( WEBP_PRESET_TEXT );

        default:
                g_assert_not_reached();
        }

        /* Keep -Wall happy.
         */
        return( -1 );
}

static void
vips_webp_set_count( VipsForeignSaveWebP *write, int loop_count )
{
	uint32_t features;

	if( WebPMuxGetFeatures( write->mux, &features ) == WEBP_MUX_OK &&
		(features & ANIMATION_FLAG) ) {
		WebPMuxAnimParams params;

		if( WebPMuxGetAnimationParams( write->mux, &params ) == 
			WEBP_MUX_OK ) {
			params.loop_count = loop_count;
			WebPMuxSetAnimationParams( write->mux, &params );
		}
	}
}

static int
vips_webp_set_chunk( VipsForeignSaveWebP *write, 
	const char *webp_name, const void *data, size_t length )
{
	WebPData chunk;

	chunk.bytes = data;
	chunk.size = length;

	if( WebPMuxSetChunk( write->mux, webp_name, &chunk, 1 ) != 
		WEBP_MUX_OK ) { 
		vips_error( "webpsave", 
			"%s", _( "chunk add error" ) );
		return( -1 );
	}

	return( 0 );
}

static int 
vips_webp_add_chunks( VipsForeignSaveWebP *write )
{
	int i;

	for( i = 0; i < vips__n_webp_names; i++ ) { 
		const char *vips_name = vips__webp_names[i].vips;
		const char *webp_name = vips__webp_names[i].webp;

		if( vips_image_get_typeof( write->image, vips_name ) ) {
			const void *data;
			size_t length;

			if( vips_image_get_blob( write->image, 
				vips_name, &data, &length ) ||
				vips_webp_set_chunk( write, 
					webp_name, data, length ) )
				return( -1 ); 
		}
	}

	return( 0 );
}

static int 
vips_webp_add_metadata( VipsForeignSaveWebP *write )
{
	WebPData data;

	data.bytes = write->memory_writer.mem;
	data.size = write->memory_writer.size;

	/* Parse what we have.
	 */
	if( !(write->mux = WebPMuxCreate( &data, 1 )) ) {
		vips_error( "webpsave", "%s", _( "mux error" ) );
		return( -1 );
	}

	if( vips_image_get_typeof( write->image, "loop" ) ) {
		int loop;

		if( vips_image_get_int( write->image, "loop", &loop ) )
			return( -1 );

		vips_webp_set_count( write, loop );
	}
	/* DEPRECATED "gif-loop"
	 */
	else if ( vips_image_get_typeof( write->image, "gif-loop" ) ) {
		int gif_loop;

		if( vips_image_get_int( write->image, "gif-loop", &gif_loop ) )
			return( -1 );

		vips_webp_set_count( write, gif_loop == 0 ? 0 : gif_loop + 1 );
	}

	/* Add extra metadata.
	 */
	if( !write->strip ) {
		/* We need to rebuild exif from the other image tags before
		 * writing the metadata.
		 */
		if( vips__exif_update( write->image ) )
			return( -1 );

		/* Override profile.
		 */
		if( write->profile &&
			vips__profile_set( write->image, write->profile ) )
			return( -1 );

		if( vips_webp_add_chunks( write ) ) 
			return( -1 );
	}

	if( WebPMuxAssemble( write->mux, &data ) != WEBP_MUX_OK ) {
		vips_error( "webpsave", "%s", _( "mux error" ) );
		return( -1 );
	}

	/* Free old stuff, reinit with new stuff.
	 */
	WebPMemoryWriterClear( &write->memory_writer );
	write->memory_writer.mem = (uint8_t *) data.bytes;
	write->memory_writer.size = data.size;
  
	return( 0 );
}

static int
vips_foreign_save_webp_init_config( VipsForeignSaveWebP *webp ) {
	/* Init WebP config.
	 */
	WebPMemoryWriterInit( &webp->memory_writer );
	if( !WebPConfigInit( &webp->config ) ) {
		vips_webp_write_unset( webp );
		vips_error( "webpsave",
			"%s", _( "config version error" ) );
		return( -1 );
	}

	/* These presets are only for lossy compression. There seems to be
	 * separate API for lossless or near-lossless, see
	 * WebPConfigLosslessPreset().
	 */
	if( !(webp->lossless || webp->near_lossless) &&
		!WebPConfigPreset( &webp->config, get_preset( webp->preset ), webp->Q ) ) {
		vips_webp_write_unset( webp );
		vips_error( "webpsave", "%s", _( "config version error" ) );
		return( -1 );
	}

	webp->config.lossless = webp->lossless || webp->near_lossless;
	webp->config.alpha_quality = webp->alpha_q;
	webp->config.method = webp->effort;

        if( webp->lossless )
                webp->config.quality = webp->Q;
        if( webp->near_lossless )
                webp->config.near_lossless = webp->Q;
        if( webp->smart_subsample )
                webp->config.use_sharp_yuv = 1;

        if( !WebPValidateConfig( &webp->config ) ) {
		vips_webp_write_unset( webp );
                vips_error( "webpsave", "%s", _( "invalid configuration" ) );
                return( -1 );
        }

	return ( 0 );
}

static int
vips_foreign_save_webp_init_anim_enc( VipsForeignSaveWebP *webp ) {
	WebPAnimEncoderOptions anim_config;
	int page_height = vips_image_get_page_height( webp->image );

	/* Init config for animated write
	 */
	if( !WebPAnimEncoderOptionsInit( &anim_config ) ) {
		vips_error( "webpsave",
			"%s", _( "config version error" ) );
		return( -1 );
	}

	anim_config.minimize_size = webp->min_size;
	anim_config.allow_mixed = webp->mixed;
	anim_config.kmin = webp->kmin;
	anim_config.kmax = webp->kmax;
	webp->enc = WebPAnimEncoderNew( webp->image->Xsize, page_height,
		&anim_config );
	if( !webp->enc ) {
		vips_error( "webpsave",
			"%s", _( "unable to init animation" ) );
	        return( -1 );
	}

	/* Get delay array
	 *
	 * There might just be the old gif-delay field. This is centiseconds.
	 */
	webp->gif_delay = 10;
	if( vips_image_get_typeof( webp->image, "gif-delay" ) &&
		vips_image_get_int( webp->image, "gif-delay", &webp->gif_delay ) )
		return( -1 );

	/* Force frames with a small or no duration to 100ms
	 * to be consistent with web browsers and other
	 * transcoding tools.
	 */
	if( webp->gif_delay <= 1 )
		webp->gif_delay = 10;

        /* New images have an array of ints instead.
         */
	webp->delay = NULL;
	if( vips_image_get_typeof( webp->image, "delay" ) &&
		vips_image_get_array_int( webp->image, "delay",
			&webp->delay, &webp->delay_length ) )
		return( -1 );

	webp->timestamp_ms = 0;

	return ( 0 );
}

static int
vips_foreign_save_webp_finish_anim( VipsForeignSaveWebP *webp ) {
	WebPData webp_data;

	/* Closes animated encoder and adds last frame delay.
	 */
	if( !WebPAnimEncoderAdd( webp->enc,
		NULL, webp->timestamp_ms, NULL ) ) {
		vips_error( "webpsave",
			"%s", _( "anim close error" ) );
		return( -1 );
	}

	if( !WebPAnimEncoderAssemble( webp->enc, &webp_data ) ) {
		vips_error( "webpsave",
			"%s", _( "anim build error" ) );
		return( -1 );
	}

        /* Terrible. This will only work if the output buffer is currently
         * empty. 
         */
        if( webp->memory_writer.mem != NULL ) {
                vips_error( "webpsave", "%s", _( "internal error" ) );
                return( -1 );
        }

        webp->memory_writer.mem = (uint8_t *) webp_data.bytes;
        webp->memory_writer.size = webp_data.size;

	return ( 0 );
}

static int
vips_foreign_save_webp_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveWebP *webp= (VipsForeignSaveWebP *) object;

	int page_height;
	VipsRect frame_rect;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_parent_class )->
		build( object ) )
		return( -1 );

	/* We need a copy of the input image in case we change the metadata
	 * eg. in vips__exif_update().
	 */
	if( vips_copy( save->ready, &webp->image, NULL ) ) {
		vips_webp_write_unset( webp );
		return( -1 );
	}

	page_height = vips_image_get_page_height( webp->image );
	frame_rect.left = 0;
	frame_rect.top = 0;
	frame_rect.width = webp->image->Xsize;
	frame_rect.height = page_height;

	/* Assemble frames here.
	 */
	webp->frame = vips_region_new( webp->image );
	if( vips_region_buffer( webp->frame, &frame_rect ) )
		return( -1 );

	/* The regions will get used in the bg thread callback,
	 * so make sure we don't own them.
	 */
	vips__region_no_ownership( webp->frame );

	/* RGB(A) frame as a contiguous buffer.
	 */
	webp->frame_bytes = g_malloc( (size_t) webp->image->Bands *
		frame_rect.width * frame_rect.height );

	/* Init generic WebP config
	 */
	if( vips_foreign_save_webp_init_config( webp ) ) {
		return ( -1 );
	}

	/* Determine the write mode (single image or animated write)
	 */
	webp->mode = VIPS_FOREIGN_SAVE_WEBP_MODE_SINGLE;
	if( page_height != webp->image->Ysize )
		webp->mode = VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM;

	/* Init config for animated write (if necessary)
	 */
	if( webp->mode == VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM )
		if( vips_foreign_save_webp_init_anim_enc( webp ) )
			return ( -1 );

	if( vips_sink_disc( webp->image,
		vips_foreign_save_webp_sink_disc, webp ) )
		return( -1 );

	/* Finish animated write
	 */
	if( webp->mode == VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM )
		if( vips_foreign_save_webp_finish_anim( webp ) )
			return( -1 );

	if( vips_webp_add_metadata( webp ) ) {
		vips_webp_write_unset( webp );
		return( -1 );
	}

	if( vips_target_write( webp->target,
		webp->memory_writer.mem, webp->memory_writer.size ) ) {
		vips_webp_write_unset( webp);
		return( -1 );
	}

	if( vips_target_end( webp->target ) )
		return( -1 );

	vips_webp_write_unset( webp );

	return( 0 );
}

static const char *vips__save_webp_suffs[] = { ".webp", NULL };

#define UC VIPS_FORMAT_UCHAR

/* Type promotion for save ... just always go to uchar.
 */
static int bandfmt_webp[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_foreign_save_webp_class_init( VipsForeignSaveWebPClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_webp_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave_base";
	object_class->description = _( "save as WebP" );
	object_class->build = vips_foreign_save_webp_build;

	foreign_class->suffs = vips__save_webp_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGBA_ONLY;
	save_class->format_table = bandfmt_webp;

	VIPS_ARG_INT( class, "Q", 10, 
		_( "Q" ), 
		_( "Q factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, Q ),
		0, 100, 75 );

	VIPS_ARG_BOOL( class, "lossless", 11, 
		_( "Lossless" ), 
		_( "Enable lossless compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, lossless ),
		FALSE ); 

	VIPS_ARG_ENUM( class, "preset", 12,
		_( "Preset" ),
		_( "Preset for lossy compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, preset ),
		VIPS_TYPE_FOREIGN_WEBP_PRESET,
		VIPS_FOREIGN_WEBP_PRESET_DEFAULT );

	VIPS_ARG_BOOL( class, "smart_subsample", 13,
		_( "Smart subsampling" ),
		_( "Enable high quality chroma subsampling" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, smart_subsample ),
		FALSE );

	VIPS_ARG_BOOL( class, "near_lossless", 14,
		_( "Near lossless" ),
		_( "Enable preprocessing in lossless mode (uses Q)" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, near_lossless ),
		FALSE );

	VIPS_ARG_INT( class, "alpha_q", 15,
		_( "Alpha quality" ),
		_( "Change alpha plane fidelity for lossy compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, alpha_q ),
		0, 100, 100 );

	VIPS_ARG_BOOL( class, "min_size", 16,
		_( "Minimise size" ),
		_( "Optimise for minimum size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, min_size ),
		FALSE );

	VIPS_ARG_INT( class, "kmin", 17,
		_( "Minimum keyframe spacing" ),
		_( "Minimum number of frames between key frames" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, kmin ),
		0, INT_MAX, INT_MAX - 1 );

	VIPS_ARG_INT( class, "kmax", 18,
		_( "Maximum keyframe spacing" ),
		_( "Maximum number of frames between key frames" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, kmax ),
		0, INT_MAX, INT_MAX );

	VIPS_ARG_INT( class, "effort", 19,
		_( "Effort" ),
		_( "Level of CPU effort to reduce file size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, effort ),
		0, 6, 4 );

	VIPS_ARG_STRING( class, "profile", 20, 
		_( "Profile" ), 
		_( "ICC profile to embed" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, profile ),
		NULL );

	VIPS_ARG_INT( class, "reduction_effort", 21,
		_( "Reduction effort" ),
		_( "Level of CPU effort to reduce file size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, effort ),
		0, 6, 4 );

	VIPS_ARG_BOOL( class, "mixed", 22,
		_( "Mixed encoding" ),
		_( "Allow mixed encoding (might reduce file size)" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebP, mixed ),
		FALSE );
}

static void
vips_foreign_save_webp_init( VipsForeignSaveWebP *webp )
{
	webp->Q = 75;
	webp->alpha_q = 100;
	webp->effort = 4;

	/* ie. keyframes disabled by default.
	 */
	webp->kmin = INT_MAX - 1;
	webp->kmax = INT_MAX;
}

typedef struct _VipsForeignSaveWebPTarget {
	VipsForeignSaveWebP parent_object;

	VipsTarget *target;
} VipsForeignSaveWebPTarget;

typedef VipsForeignSaveWebPClass VipsForeignSaveWebPTargetClass;

G_DEFINE_TYPE( VipsForeignSaveWebPTarget, vips_foreign_save_webp_target,
	vips_foreign_save_webp_get_type() );

static int
vips_foreign_save_webp_target_build( VipsObject *object )
{
	VipsForeignSaveWebP *webp = (VipsForeignSaveWebP *) object;
	VipsForeignSaveWebPTarget *target = 
		(VipsForeignSaveWebPTarget *) object;

	webp->target = target->target;
	g_object_ref( webp->target );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_target_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_webp_target_class_init( 
	VipsForeignSaveWebPTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave_target";
	object_class->build = vips_foreign_save_webp_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebPTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_webp_target_init( VipsForeignSaveWebPTarget *target )
{
}

typedef struct _VipsForeignSaveWebPFile {
	VipsForeignSaveWebP parent_object;
	char *filename;
} VipsForeignSaveWebPFile;

typedef VipsForeignSaveWebPClass VipsForeignSaveWebPFileClass;

G_DEFINE_TYPE( VipsForeignSaveWebPFile, vips_foreign_save_webp_file,
	vips_foreign_save_webp_get_type() );

static int
vips_foreign_save_webp_file_build( VipsObject *object )
{
	VipsForeignSaveWebP *webp = (VipsForeignSaveWebP *) object;
	VipsForeignSaveWebPFile *file = (VipsForeignSaveWebPFile *) object;

	if( !(webp->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_webp_file_class_init( VipsForeignSaveWebPFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave";
	object_class->build = vips_foreign_save_webp_file_build;

	VIPS_ARG_STRING( class, "filename", 1,
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebPFile, filename ),
		NULL );
}

static void
vips_foreign_save_webp_file_init( VipsForeignSaveWebPFile *file )
{
}

typedef struct _VipsForeignSaveWebPBuffer {
	VipsForeignSaveWebP parent_object;
	VipsArea *buf;
} VipsForeignSaveWebPBuffer;

typedef VipsForeignSaveWebPClass VipsForeignSaveWebPBufferClass;

G_DEFINE_TYPE( VipsForeignSaveWebPBuffer, vips_foreign_save_webp_buffer,
	vips_foreign_save_webp_get_type() );

static int
vips_foreign_save_webp_buffer_build( VipsObject *object )
{
	VipsForeignSaveWebP *webp = (VipsForeignSaveWebP *) object;
	VipsForeignSaveWebPBuffer *buffer = 
		(VipsForeignSaveWebPBuffer *) object;

	VipsBlob *blob;

	if( !(webp->target = vips_target_new_to_memory()) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_buffer_parent_class )->
		build( object ) )
		return( -1 );

	g_object_get( webp->target, "blob", &blob, NULL );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_webp_buffer_class_init( 
	VipsForeignSaveWebPBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave_buffer";
	object_class->build = vips_foreign_save_webp_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1,
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebPBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_save_webp_buffer_init( VipsForeignSaveWebPBuffer *buffer )
{
}

typedef struct _VipsForeignSaveWebPMime {
	VipsForeignSaveWebP parent_object;

} VipsForeignSaveWebPMime;

typedef VipsForeignSaveWebPClass VipsForeignSaveWebPMimeClass;

G_DEFINE_TYPE( VipsForeignSaveWebPMime, vips_foreign_save_webp_mime, 
	vips_foreign_save_webp_get_type() );

static int
vips_foreign_save_webp_mime_build( VipsObject *object )
{
	VipsForeignSaveWebP *webp = (VipsForeignSaveWebP *) object;

	VipsBlob *blob;
	void *data;
	size_t len;

	if( !(webp->target = vips_target_new_to_memory()) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_mime_parent_class )->
		build( object ) )
		return( -1 );

	g_object_get( webp->target, "blob", &blob, NULL );
	data = VIPS_AREA( blob )->data;
	len = VIPS_AREA( blob )->length;
	vips_area_unref( VIPS_AREA( blob ) );

	printf( "Content-length: %zu\r\n", len );
	printf( "Content-type: image/webp\r\n" );
	printf( "\r\n" );
	(void) fwrite( data, sizeof( char ), len, stdout );
	fflush( stdout );

	VIPS_UNREF( webp->target );

	return( 0 );
}

static void
vips_foreign_save_webp_mime_class_init( VipsForeignSaveWebPMimeClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "webpsave_mime";
	object_class->description = _( "save image to webp mime" );
	object_class->build = vips_foreign_save_webp_mime_build;

}

static void
vips_foreign_save_webp_mime_init( VipsForeignSaveWebPMime *mime )
{
}

#endif /*HAVE_LIBWEBP*/

/**
 * vips_webpsave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enables lossless compression
 * * @preset: #VipsForeignWebpPreset, choose lossy compression preset
 * * @smart_subsample: %gboolean, enables high quality chroma subsampling
 * * @near_lossless: %gboolean, preprocess in lossless mode (controlled by Q)
 * * @alpha_q: %gint, set alpha quality in lossless mode
 * * @effort: %gint, level of CPU effort to reduce file size
 * * @min_size: %gboolean, minimise size
 * * @mixed: %gboolean, allow both lossy and lossless encoding
 * * @kmin: %gint, minimum number of frames between keyframes
 * * @kmax: %gint, maximum number of frames between keyframes
 * * @strip: %gboolean, remove all metadata from image
 * * @profile: %gchararray, filename of ICC profile to attach
 *
 * Write an image to a file in WebP format. 
 *
 * By default, images are saved in lossy format, with 
 * @Q giving the WebP quality factor. It has the range 0 - 100, with the
 * default 75.
 *
 * Use @preset to hint the image type to the lossy compressor. The default is
 * #VIPS_FOREIGN_WEBP_PRESET_DEFAULT. 
 *
 * Set @smart_subsample to enable high quality chroma subsampling.
 *
 * Use @alpha_q to set the quality for the alpha channel in lossy mode. It has
 * the range 1 - 100, with the default 100.
 *
 * Use @effort to control how much CPU time to spend attempting to
 * reduce file size. A higher value means more effort and therefore CPU time
 * should be spent. It has the range 0-6 and a default value of 4.
 *
 * Set @lossless to use lossless compression, or combine @near_lossless
 * with @Q 80, 60, 40 or 20 to apply increasing amounts of preprocessing
 * which improves the near-lossless compression ratio by up to 50%.
 *
 * For animated webp output, @min_size will try to optimize for minimum size.
 *
 * For animated webp output, @kmax sets the maximum number of frames between
 * keyframes. Setting 0 means only keyframes. @kmin sets the minimum number of
 * frames between frames. Setting 0 means no keyframes. By default, keyframes
 * are disabled.
 *
 * For animated webp output, @mixed tries to improve the file size by mixing
 * both lossy and lossless encoding.
 *
 * Use @profile to give the name of a profile to be embedded in the file.
 * This does not affect the pixels which are written, just the way 
 * they are tagged. See vips_profile_load() for details on profile naming. 
 *
 * Use the metadata items `loop` and `delay` to set the number of
 * loops for the animation and the frame delays.
 *
 * The writer will attach ICC, EXIF and XMP metadata, unless @strip is set to
 * %TRUE.
 *
 * See also: vips_webpload(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "webpsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_webpsave_buffer: (method)
 * @in: image to save 
 * @buf: (out) (array length=len) (element-type guint8): return output buffer here
 * @len: return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enables lossless compression
 * * @preset: #VipsForeignWebpPreset, choose lossy compression preset
 * * @smart_subsample: %gboolean, enables high quality chroma subsampling
 * * @near_lossless: %gboolean, preprocess in lossless mode (controlled by Q)
 * * @alpha_q: %gint, set alpha quality in lossless mode
 * * @effort: %gint, level of CPU effort to reduce file size
 * * @min_size: %gboolean, minimise size
 * * @mixed: %gboolean, allow both lossy and lossless encoding
 * * @kmin: %gint, minimum number of frames between keyframes
 * * @kmax: %gint, maximum number of frames between keyframes
 * * @strip: %gboolean, remove all metadata from image
 * * @profile: %gchararray, filename of ICC profile to attach
 *
 * As vips_webpsave(), but save to a memory buffer.
 *
 * The address of the buffer is returned in @buf, the length of the buffer in
 * @len. You are responsible for freeing the buffer with g_free() when you
 * are done with it. 
 *
 * See also: vips_webpsave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "webpsave_buffer", ap, in, &area );
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
 * vips_webpsave_mime: (method)
 * @in: image to save 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enables lossless compression
 * * @preset: #VipsForeignWebpPreset, choose lossy compression preset
 * * @smart_subsample: %gboolean, enables high quality chroma subsampling
 * * @near_lossless: %gboolean, preprocess in lossless mode (controlled by Q)
 * * @alpha_q: %gint, set alpha quality in lossless mode
 * * @effort: %gint, level of CPU effort to reduce file size
 * * @min_size: %gboolean, minimise size
 * * @mixed: %gboolean, allow both lossy and lossless encoding
 * * @kmin: %gint, minimum number of frames between keyframes
 * * @kmax: %gint, maximum number of frames between keyframes
 * * @strip: %gboolean, remove all metadata from image
 * * @profile: %gchararray, filename of ICC profile to attach
 *
 * As vips_webpsave(), but save as a mime webp on stdout.
 *
 * See also: vips_webpsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave_mime( VipsImage *in, ... )
{
	va_list ap;
	int result;

	va_start( ap, in );
	result = vips_call_split( "webpsave_mime", ap, in );
	va_end( ap );

	return( result );
}

/**
 * vips_webpsave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint, quality factor
 * * @lossless: %gboolean, enables lossless compression
 * * @preset: #VipsForeignWebpPreset, choose lossy compression preset
 * * @smart_subsample: %gboolean, enables high quality chroma subsampling
 * * @near_lossless: %gboolean, preprocess in lossless mode (controlled by Q)
 * * @alpha_q: %gint, set alpha quality in lossless mode
 * * @effort: %gint, level of CPU effort to reduce file size
 * * @min_size: %gboolean, minimise size
 * * @mixed: %gboolean, allow both lossy and lossless encoding
 * * @kmin: %gint, minimum number of frames between keyframes
 * * @kmax: %gint, maximum number of frames between keyframes
 * * @strip: %gboolean, remove all metadata from image
 * * @profile: %gchararray, filename of ICC profile to attach
 *
 * As vips_webpsave(), but save to a target.
 *
 * See also: vips_webpsave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "webpsave_target", ap, in, target );
	va_end( ap );

	return( result );
}
