/* wrap libwebp libray for write
 *
 * 6/8/13
 * 	- from vips2jpeg.c
 * 31/5/16
 * 	- buffer write ignored lossless, thanks aaron42net
 * 2/5/16 Felix Bünemann
 * 	- used advanced encoding API, expose controls 
 * 8/11/16
 * 	- add metadata write
 * 29/10/18
 * 	- target libwebp 0.5+ and remove some ifdefs
 * 	- add animated webp write
 * 	- use libwebpmux instead of our own thing, phew
 * 6/7/19 [deftomat]
 * 	- support array of delays 
 * 8/7/19
 * 	- set loop even if we strip
 * 14/10/19
 * 	- revise for target IO
 * 18/7/20
 * 	- add @profile param to match tiff, jpg, etc.
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#ifdef HAVE_LIBWEBP

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

typedef struct {
	VipsImage *image;

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
} VipsWebPWrite;

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
vips_webp_write_unset( VipsWebPWrite *write )
{
	WebPMemoryWriterClear( &write->memory_writer );
	VIPS_FREEF( WebPAnimEncoderDelete, write->enc );
	VIPS_FREEF( WebPMuxDelete, write->mux );
	VIPS_UNREF( write->image );
}

static int
vips_webp_write_init( VipsWebPWrite *write, VipsImage *image,
	int Q, gboolean lossless, VipsForeignWebpPreset preset,
	gboolean smart_subsample, gboolean near_lossless,
	int alpha_q, int effort,
	gboolean min_size, gboolean mixed, int kmin, int kmax,
	gboolean strip, const char *profile )
{
	write->image = NULL;
	write->Q = Q;
	write->lossless = lossless;
	write->preset = preset;
	write->smart_subsample = smart_subsample;
	write->near_lossless = near_lossless;
	write->alpha_q = alpha_q;
	write->effort = effort;
	write->min_size = min_size;
	write->mixed = mixed;
	write->kmin = kmin;
	write->kmax = kmax;
	write->strip = strip;
	write->profile = profile;
	WebPMemoryWriterInit( &write->memory_writer );
	write->enc = NULL;
	write->mux = NULL;

	/* We need a copy of the input image in case we change the metadata
	 * eg. in vips__exif_update().
	 */
	if( vips_copy( image, &write->image, NULL ) ) {
		vips_webp_write_unset( write );
		return( -1 );
	}

	if( !WebPConfigInit( &write->config ) ) {
		vips_webp_write_unset( write );
		vips_error( "vips2webp",
			"%s", _( "config version error" ) );
		return( -1 );
	}

	/* These presets are only for lossy compression. There seems to be
	 * separate API for lossless or near-lossless, see
	 * WebPConfigLosslessPreset().
	 */
	if( !(lossless || near_lossless) &&
		!WebPConfigPreset( &write->config, get_preset( preset ), Q ) ) {
		vips_webp_write_unset( write );
		vips_error( "vips2webp", "%s", _( "config version error" ) );
		return( -1 );
	}

	write->config.lossless = lossless || near_lossless;
	write->config.alpha_quality = alpha_q;
	write->config.method = effort;

	if( lossless )
		write->config.quality = Q;
	if( near_lossless )
		write->config.near_lossless = Q;
	if( smart_subsample )
		write->config.use_sharp_yuv = 1;

	if( !WebPValidateConfig( &write->config ) ) {
		vips_webp_write_unset( write );
		vips_error( "vips2webp", "%s", _( "invalid configuration" ) );
		return( -1 );
	}

	return( 0 );
}

static gboolean
vips_webp_pic_init( VipsWebPWrite *write, WebPPicture *pic )
{
	if( !WebPPictureInit( pic ) ) {
		vips_error( "vips2webp", "%s", _( "picture version error" ) );
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
write_webp_image( VipsWebPWrite *write, VipsImage *image, WebPPicture *pic ) 
{
	VipsImage *memory;
	webp_import import;

	if( !vips_webp_pic_init( write, pic ) ) 
		return( -1 );

	if( !(memory = vips_image_copy_memory( image )) ) {
		WebPPictureFree( pic );
		return( -1 );
	}

	pic->width = memory->Xsize;
	pic->height = memory->Ysize;

	if( memory->Bands == 4 )
		import = WebPPictureImportRGBA;
	else
		import = WebPPictureImportRGB;

	if( !import( pic, VIPS_IMAGE_ADDR( memory, 0, 0 ),
		VIPS_IMAGE_SIZEOF_LINE( memory ) ) ) {
		VIPS_UNREF( memory );
		WebPPictureFree( pic );
		vips_error( "vips2webp", "%s", _( "picture memory error" ) );
		return( -1 );
	}

	VIPS_UNREF( memory );

	return( 0 );
}

/* Write a single image into write->memory_writer.
 */
static int
write_webp_single( VipsWebPWrite *write, VipsImage *image )
{
	WebPPicture pic;

	if( write_webp_image( write, image, &pic ) ) { 
		WebPPictureFree( &pic );
		return( -1 );
	}

	if( !WebPEncode( &write->config, &pic ) ) {
		WebPPictureFree( &pic );
		vips_error( "vips2webp", "%s", _( "unable to encode" ) );
		return( -1 );
	}

	WebPPictureFree( &pic );

	return( 0 );
}

/* Write a set of animated frames into write->memory_writer.
 */
static int
write_webp_anim( VipsWebPWrite *write, VipsImage *image, int page_height )
{
	WebPAnimEncoderOptions anim_config;
	WebPData webp_data;
	int gif_delay;
	int *delay;
	int delay_length;
	int top;
	int timestamp_ms;

	if( !WebPAnimEncoderOptionsInit( &anim_config ) ) {
		vips_error( "vips2webp",
			"%s", _( "config version error" ) );
		return( -1 );
	}

	anim_config.minimize_size = write->min_size;
	anim_config.allow_mixed = write->mixed;
	anim_config.kmin = write->kmin;
	anim_config.kmax = write->kmax;

	write->enc = WebPAnimEncoderNew( image->Xsize, page_height, 
		&anim_config );
	if( !write->enc ) {
		vips_error( "vips2webp", 
			"%s", _( "unable to init animation" ) );
		return( -1 );
	}

	/* There might just be the old gif-delay field. This is centiseconds.
	 */
	gif_delay = 10;
	if( vips_image_get_typeof( image, "gif-delay" ) &&
		vips_image_get_int( image, "gif-delay", &gif_delay ) )
		return( -1 );

	/* Force frames with a small or no duration to 100ms
	 * to be consistent with web browsers and other
	 * transcoding tools.
	 */
	if( gif_delay <= 1 )
		gif_delay = 10;

	/* New images have an array of ints instead.
	 */
	delay = NULL;
	if( vips_image_get_typeof( image, "delay" ) &&
		vips_image_get_array_int( image, "delay", 
			&delay, &delay_length ) )
		return( -1 );

	timestamp_ms = 0;
	for( top = 0; top < image->Ysize; top += page_height ) {
		VipsImage *x;
		WebPPicture pic;
		int page_index;

		if( vips_crop( image, &x, 
			0, top, image->Xsize, page_height, NULL ) )
			return( -1 );

		if( write_webp_image( write, x, &pic ) ) {
			VIPS_UNREF( x ); 
			return( -1 );
		}

		VIPS_UNREF( x ); 

		if( !WebPAnimEncoderAdd( write->enc, 
			&pic, timestamp_ms, &write->config ) ) {
			WebPPictureFree( &pic );
			vips_error( "vips2webp",
				"%s", _( "anim add error" ) );
			return( -1 );
		}

		WebPPictureFree( &pic );

		page_index = top / page_height;
		if( delay &&
			page_index < delay_length )
			timestamp_ms += delay[page_index] <= 10 ?
				100 : delay[page_index];
		else 
			timestamp_ms += gif_delay * 10;
	}

	/* Closes encoder and adds last frame delay.
	 */
	if( !WebPAnimEncoderAdd( write->enc, 
		NULL, timestamp_ms, NULL ) ) {
		vips_error( "vips2webp",
			"%s", _( "anim close error" ) );
		return( -1 );
	}

	if( !WebPAnimEncoderAssemble( write->enc, &webp_data ) ) {
		vips_error( "vips2webp",
			"%s", _( "anim build error" ) );
		return( -1 );
	}

	/* Terrible. This will only work if the output buffer is currently
	 * empty. 
	 */
	if( write->memory_writer.mem != NULL ) {
		vips_error( "vips2webp", "%s", _( "internal error" ) );
		return( -1 );
	}
	write->memory_writer.mem = (uint8_t *) webp_data.bytes;
	write->memory_writer.size = webp_data.size;

	return( 0 );
}

static int
write_webp( VipsWebPWrite *write )
{
	int page_height = vips_image_get_page_height( write->image ); 

	if( page_height < write->image->Ysize )
		return( write_webp_anim( write, write->image, page_height ) );
	else
		return( write_webp_single( write, write->image ) );
}

static void
vips_webp_set_count( VipsWebPWrite *write, int loop_count )
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
vips_webp_set_chunk( VipsWebPWrite *write, 
	const char *webp_name, const void *data, size_t length )
{
	WebPData chunk;

	chunk.bytes = data;
	chunk.size = length;

	if( WebPMuxSetChunk( write->mux, webp_name, &chunk, 1 ) != 
		WEBP_MUX_OK ) { 
		vips_error( "vips2webp", 
			"%s", _( "chunk add error" ) );
		return( -1 );
	}

	return( 0 );
}

static int 
vips_webp_add_chunks( VipsWebPWrite *write )
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
vips_webp_add_metadata( VipsWebPWrite *write )
{
	WebPData data;

	data.bytes = write->memory_writer.mem;
	data.size = write->memory_writer.size;

	/* Parse what we have.
	 */
	if( !(write->mux = WebPMuxCreate( &data, 1 )) ) {
		vips_error( "vips2webp", "%s", _( "mux error" ) );
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
		vips_error( "vips2webp", "%s", _( "mux error" ) );
		return( -1 );
	}

	/* Free old stuff, reinit with new stuff.
	 */
	WebPMemoryWriterClear( &write->memory_writer );
	write->memory_writer.mem = (uint8_t *) data.bytes;
	write->memory_writer.size = data.size;
  
	return( 0 );
}

int
vips__webp_write_target( VipsImage *image, VipsTarget *target,
	int Q, gboolean lossless, VipsForeignWebpPreset preset,
	gboolean smart_subsample, gboolean near_lossless,
	int alpha_q, int effort,
	gboolean min_size, gboolean mixed, int kmin, int kmax,
	gboolean strip, const char *profile )
{
	VipsWebPWrite write;

	if( vips_webp_write_init( &write, image,
		Q, lossless, preset, smart_subsample, near_lossless,
		alpha_q, effort, min_size, mixed, kmin, kmax, strip,
		profile ) )
		return( -1 );

	if( write_webp( &write ) ) {
		vips_webp_write_unset( &write );
		return( -1 );
	}

	if( vips_webp_add_metadata( &write ) ) {
		vips_webp_write_unset( &write );
		return( -1 );
	}

	if( vips_target_write( target, 
		write.memory_writer.mem, write.memory_writer.size ) ) {
		vips_webp_write_unset( &write );
		return( -1 );
	}

	if( vips_target_end( target ) )
		return( -1 );

	vips_webp_write_unset( &write );

	return( 0 );
}

#endif /*HAVE_LIBWEBP*/
