/* save to webp
 *
 * 24/11/11
 * 	- wrap a class around the webp writer
 * 6/8/13
 * 	- from vips2jpeg.c
 * 31/5/16
 * 	- buffer write ignored lossless, thanks aaron42net
 * 2/5/16 Felix Bünemann
 * 	- used advanced encoding API, expose controls
 * 8/11/16
 * 	- add metadata write
 * 29/10/18
 * 	- add animated webp support
 * 29/10/18
 * 	- target libwebp 0.5+ and remove some ifdefs
 * 	- add animated webp write
 * 	- use libwebpmux instead of our own thing, phew
 * 15/1/19 lovell
 * 	- add @effort
 * 6/7/19 [deftomat]
 * 	- support array of delays
 * 8/7/19
 * 	- set loop even if we strip
 * 14/10/19
 * 	- revise for target IO
 * 18/7/20
 * 	- add @profile param to match tiff, jpg, etc.
 * 30/7/21
 * 	- rename "reduction_effort" as "effort"
 * 7/9/22 dloebl
 * 	- switch to sink_disc
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"

#ifdef HAVE_LIBWEBP

#include <webp/encode.h>
#include <webp/types.h>
#include <webp/mux.h>

typedef int (*webp_import)(WebPPicture *picture,
	const uint8_t *rgb, int stride);

typedef enum _VipsForeignSaveWebpMode {
	VIPS_FOREIGN_SAVE_WEBP_MODE_SINGLE,
	VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM
} VipsForeignSaveWebpMode;

typedef struct _VipsForeignSaveWebp {
	VipsForeignSave parent_object;
	VipsTarget *target;

	/* Animated or single image write mode?
	 * Important, because we use a different API
	 * for animated WebP write.
	 */
	VipsForeignSaveWebpMode mode;

	int timestamp_ms;

	/* Quality factor.
	 */
	int Q;

	/* Turn on lossless encode.
	 */
	gboolean lossless;

	/* Lossy compression preset.
	 */
	VipsForeignWebpPreset preset;

	/* Enable smart chroma subsampling.
	 */
	gboolean smart_subsample;

	/* Use preprocessing in lossless mode.
	 */
	gboolean near_lossless;

	/* Alpha quality.
	 */
	int alpha_q;

	/* Level of CPU effort to reduce file size.
	 */
	int effort;

	/* Animated webp options.
	 */

	int gif_delay;
	int *delay;
	int delay_length;

	/* Attempt to minimise size
	 */
	gboolean min_size;

	/* Allow mixed encoding (might reduce file size)
	 */
	gboolean mixed;

	/* Min between key frames.
	 */
	int kmin;

	/* Max between keyframes.
	 */
	int kmax;

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

	/* The current y position in the frame and the current page index.
	 */
	int write_y;
	int page_number;

	/* VipsRegion is not always contiguous, but we need contiguous RGB(A)
	 * for libwebp. We need to copy each frame to a local buffer.
	 */
	VipsPel *frame_bytes;
} VipsForeignSaveWebp;

typedef VipsForeignSaveClass VipsForeignSaveWebpClass;

G_DEFINE_ABSTRACT_TYPE(VipsForeignSaveWebp, vips_foreign_save_webp,
	VIPS_TYPE_FOREIGN_SAVE);

static int
vips_foreign_save_webp_progress_hook(int percent, const WebPPicture *picture)
{
	VipsImage *in = (VipsImage *) picture->user_data;

	/* Trigger any eval callbacks on the image and
	 * check if we need to abort the WebP encoding.
	 */
	vips_image_eval(in, VIPS_IMAGE_N_PELS(in));

	/* Abort WebP encoding if requested.
	 */
	if (vips_image_iskilled(in))
		return 0;

	return 1;
}

static void
vips_foreign_save_webp_unset(VipsForeignSaveWebp *write)
{
	WebPMemoryWriterClear(&write->memory_writer);
	VIPS_FREEF(WebPAnimEncoderDelete, write->enc);
	VIPS_FREEF(WebPMuxDelete, write->mux);
}

static void
vips_foreign_save_webp_dispose(GObject *gobject)
{
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) gobject;

	VIPS_UNREF(webp->target);

	VIPS_FREE(webp->frame_bytes);

	G_OBJECT_CLASS(vips_foreign_save_webp_parent_class)->dispose(gobject);
}

static gboolean
vips_foreign_save_webp_pic_init(VipsForeignSaveWebp *write, WebPPicture *pic)
{
	VipsForeignSave *save = (VipsForeignSave *) write;

	if (!WebPPictureInit(pic)) {
		vips_error("webpsave", "%s", _("picture version error"));
		return FALSE;
	}
	pic->writer = WebPMemoryWrite;
	pic->custom_ptr = (void *) &write->memory_writer;
	pic->progress_hook = vips_foreign_save_webp_progress_hook;
	pic->user_data = (void *) save->in;

	/* Smart subsampling needs use_argb because it is applied during
	 * RGB to YUV conversion.
	 */
	pic->use_argb = write->lossless ||
		write->near_lossless ||
		write->smart_subsample;

	return TRUE;
}

/* Write a VipsImage into an uninitialised pic.
 */
static int
vips_foreign_save_webp_write_webp_image(VipsForeignSaveWebp *write,
	const VipsPel *imagedata, WebPPicture *pic)
{
	VipsForeignSave *save = (VipsForeignSave *) write;

	webp_import import;
	int page_height = vips_image_get_page_height(save->ready);

	if (!vips_foreign_save_webp_pic_init(write, pic))
		return -1;

	pic->width = save->ready->Xsize;
	pic->height = page_height;

	if (save->ready->Bands == 4)
		import = WebPPictureImportRGBA;
	else
		import = WebPPictureImportRGB;

	if (!import(pic, imagedata,
			save->ready->Xsize * save->ready->Bands)) {
		WebPPictureFree(pic);
		vips_error("webpsave", "%s", _("picture memory error"));
		return -1;
	}

	return 0;
}

/* We have a complete frame --- write!
 */
static int
vips_foreign_save_webp_write_frame(VipsForeignSaveWebp *webp)
{
	WebPPicture pic;
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS(webp);

	if (vips_foreign_save_webp_write_webp_image(webp, webp->frame_bytes,
			&pic))
		return -1;

	/* Animated write
	 */
	if (webp->mode == VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM) {
		if (!WebPAnimEncoderAdd(webp->enc,
				&pic, webp->timestamp_ms, &webp->config)) {
			WebPPictureFree(&pic);
			vips_error(class->nickname,
				"%s", _("anim add error"));
			return -1;
		}
		/* Adjust current timestamp
		 */
		if (webp->delay &&
			webp->page_number < webp->delay_length)
			webp->timestamp_ms += webp->delay[webp->page_number];
		else
			webp->timestamp_ms += webp->gif_delay * 10;
	}
	else {
		/* Single image write
		 */
		if (!WebPEncode(&webp->config, &pic)) {
			WebPPictureFree(&pic);
			vips_error("webpsave", "%s",
				_("unable to encode"));
			return -1;
		}
	}

	WebPPictureFree(&pic);

	return 0;
}

/* Another chunk of pixels have arrived from the pipeline. Add to frame, and
 * if the frame completes, compress and write to the target.
 */
static int
vips_foreign_save_webp_sink_disc(VipsRegion *region, VipsRect *area, void *a)
{
	VipsForeignSave *save = (VipsForeignSave *) a;
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) a;
	int i;
	int page_height = vips_image_get_page_height(save->ready);

	/* Write the new pixels into the frame.
	 */
	for (i = 0; i < area->height; i++) {
		memcpy(webp->frame_bytes +
				area->width * webp->write_y * save->ready->Bands,
			VIPS_REGION_ADDR(region, 0, area->top + i),
			area->width * save->ready->Bands);

		webp->write_y += 1;

		/* If we've filled the frame, write and move it down.
		 */
		if (webp->write_y == page_height) {
			if (vips_foreign_save_webp_write_frame(webp))
				return -1;

			webp->write_y = 0;
			webp->page_number += 1;
		}
	}

	return 0;
}

static WebPPreset
get_preset(VipsForeignWebpPreset preset)
{
	switch (preset) {
	case VIPS_FOREIGN_WEBP_PRESET_DEFAULT:
		return WEBP_PRESET_DEFAULT;
	case VIPS_FOREIGN_WEBP_PRESET_PICTURE:
		return WEBP_PRESET_PICTURE;
	case VIPS_FOREIGN_WEBP_PRESET_PHOTO:
		return WEBP_PRESET_PHOTO;
	case VIPS_FOREIGN_WEBP_PRESET_DRAWING:
		return WEBP_PRESET_DRAWING;
	case VIPS_FOREIGN_WEBP_PRESET_ICON:
		return WEBP_PRESET_ICON;
	case VIPS_FOREIGN_WEBP_PRESET_TEXT:
		return WEBP_PRESET_TEXT;

	default:
		g_assert_not_reached();
	}

	/* Keep -Wall happy.
	 */
	return -1;
}

static void
vips_webp_set_count(VipsForeignSaveWebp *write, int loop_count)
{
	uint32_t features;

	if (WebPMuxGetFeatures(write->mux, &features) == WEBP_MUX_OK &&
		(features & ANIMATION_FLAG)) {
		WebPMuxAnimParams params;

		if (WebPMuxGetAnimationParams(write->mux, &params) ==
			WEBP_MUX_OK) {
			params.loop_count = loop_count;
			WebPMuxSetAnimationParams(write->mux, &params);
		}
	}
}

static int
vips_webp_set_chunk(VipsForeignSaveWebp *write,
	const char *webp_name, const void *data, size_t length)
{
	WebPData chunk;

	chunk.bytes = data;
	chunk.size = length;

	if (WebPMuxSetChunk(write->mux, webp_name, &chunk, 1) !=
		WEBP_MUX_OK) {
		vips_error("webpsave",
			"%s", _("chunk add error"));
		return -1;
	}

	return 0;
}

static int
vips_webp_add_original_meta(VipsForeignSaveWebp *write)
{
	VipsForeignSave *save = (VipsForeignSave *) write;

	for (int i = 0; i < vips__n_webp_names; i++) {
		const char *vips_name = vips__webp_names[i].vips;
		const char *webp_name = vips__webp_names[i].webp;

		if (strcmp(vips_name, VIPS_META_ICC_NAME) == 0)
			continue;

		if (vips_image_get_typeof(save->ready, vips_name)) {
			const void *data;
			size_t length;

			if (vips_image_get_blob(save->ready, vips_name, &data, &length) ||
				vips_webp_set_chunk(write, webp_name, data, length))
				return -1;
		}
	}

	return 0;
}

static const char *
vips_webp_get_webp_name(const char *vips_name)
{
	for (int i = 0; i < vips__n_webp_names; i++)
		if (strcmp(vips_name, vips__webp_names[i].vips) == 0)
			return vips__webp_names[i].webp;

	return "";
}

static int
vips_webp_add_icc(VipsForeignSaveWebp *webp,
	const void *profile, size_t length)
{
	const char *webp_name = vips_webp_get_webp_name(VIPS_META_ICC_NAME);

	if (vips_webp_set_chunk(webp, webp_name, profile, length))
		return -1;

	return 0;
}

static int
vips_webp_add_custom_icc(VipsForeignSaveWebp *webp, const char *profile)
{
	VipsBlob *blob;

	if (vips_profile_load(profile, &blob, NULL))
		return -1;

	if (blob) {
		size_t length;
		const void *data = vips_blob_get(blob, &length);

		if (vips_webp_add_icc(webp, data, length)) {
			vips_area_unref((VipsArea *) blob);
			return -1;
		}

		vips_area_unref((VipsArea *) blob);
	}

	return 0;
}

static int
vips_webp_add_original_icc(VipsForeignSaveWebp *webp)
{
	VipsForeignSave *save = (VipsForeignSave *) webp;

	const void *data;
	size_t length;

	if (vips_image_get_blob(save->ready, VIPS_META_ICC_NAME, &data, &length))
		return -1;

	vips_webp_add_icc(webp, data, length);

	return 0;
}

static int
vips_webp_add_metadata(VipsForeignSaveWebp *webp)
{
	VipsForeignSave *save = (VipsForeignSave *) webp;

	WebPData data;

	data.bytes = webp->memory_writer.mem;
	data.size = webp->memory_writer.size;

	/* Parse what we have.
	 */
	if (!(webp->mux = WebPMuxCreate(&data, 1))) {
		vips_error("webpsave", "%s", _("mux error"));
		return -1;
	}

	if (vips_image_get_typeof(save->ready, "loop")) {
		int loop;

		if (vips_image_get_int(save->ready, "loop", &loop))
			return -1;

		vips_webp_set_count(webp, loop);
	}
	else if (vips_image_get_typeof(save->ready, "gif-loop")) {
		/* DEPRECATED "gif-loop"
		 */
		int gif_loop;

		if (vips_image_get_int(save->ready, "gif-loop", &gif_loop))
			return -1;

		vips_webp_set_count(webp, gif_loop == 0 ? 0 : gif_loop + 1);
	}

	/* Metadata
	 */
	if (vips_webp_add_original_meta(webp))
		return -1;

	/* A profile supplied as an argument overrides an embedded
	 * profile.
	 */
	if (save->profile) {
		if (vips_webp_add_custom_icc(webp, save->profile))
			return -1;
	}
	else if (vips_image_get_typeof(save->ready, VIPS_META_ICC_NAME)) {
		if (vips_webp_add_original_icc(webp))
			return -1;
	}

	if (WebPMuxAssemble(webp->mux, &data) != WEBP_MUX_OK) {
		vips_error("webpsave", "%s", _("mux error"));
		return -1;
	}

	/* Free old stuff, reinit with new stuff.
	 */
	WebPMemoryWriterClear(&webp->memory_writer);
	webp->memory_writer.mem = (uint8_t *) data.bytes;
	webp->memory_writer.size = data.size;

	return 0;
}

static int
vips_foreign_save_webp_init_config(VipsForeignSaveWebp *webp)
{
	/* Init WebP config.
	 */
	WebPMemoryWriterInit(&webp->memory_writer);
	if (!WebPConfigInit(&webp->config)) {
		vips_foreign_save_webp_unset(webp);
		vips_error("webpsave",
			"%s", _("config version error"));
		return -1;
	}

	/* These presets are only for lossy compression. There seems to be
	 * separate API for lossless or near-lossless, see
	 * WebPConfigLosslessPreset().
	 */
	if (!(webp->lossless || webp->near_lossless) &&
		!WebPConfigPreset(&webp->config, get_preset(webp->preset),
			webp->Q)) {
		vips_foreign_save_webp_unset(webp);
		vips_error("webpsave", "%s", _("config version error"));
		return -1;
	}

	webp->config.lossless = webp->lossless || webp->near_lossless;
	webp->config.alpha_quality = webp->alpha_q;
	webp->config.method = webp->effort;

	if (webp->lossless)
		webp->config.quality = webp->Q;
	if (webp->near_lossless)
		webp->config.near_lossless = webp->Q;
	if (webp->smart_subsample)
		webp->config.use_sharp_yuv = 1;

	if (!WebPValidateConfig(&webp->config)) {
		vips_foreign_save_webp_unset(webp);
		vips_error("webpsave", "%s", _("invalid configuration"));
		return -1;
	}

	return 0;
}

static int
vips_foreign_save_webp_init_anim_enc(VipsForeignSaveWebp *webp)
{
	VipsForeignSave *save = (VipsForeignSave *) webp;

	WebPAnimEncoderOptions anim_config;
	int i;
	int page_height = vips_image_get_page_height(save->ready);

	/* Init config for animated write
	 */
	if (!WebPAnimEncoderOptionsInit(&anim_config)) {
		vips_error("webpsave",
			"%s", _("config version error"));
		return -1;
	}

	anim_config.minimize_size = webp->min_size;
	anim_config.allow_mixed = webp->mixed;
	anim_config.kmin = webp->kmin;
	anim_config.kmax = webp->kmax;
	webp->enc = WebPAnimEncoderNew(save->ready->Xsize, page_height,
		&anim_config);
	if (!webp->enc) {
		vips_error("webpsave",
			"%s", _("unable to init animation"));
		return -1;
	}

	/* Get delay array
	 *
	 * There might just be the old gif-delay field. This is centiseconds.
	 */
	webp->gif_delay = 10;
	if (vips_image_get_typeof(save->ready, "gif-delay") &&
		vips_image_get_int(save->ready, "gif-delay",
			&webp->gif_delay))
		return -1;

	/* New images have an array of ints instead.
	 */
	webp->delay = NULL;
	if (vips_image_get_typeof(save->ready, "delay") &&
		vips_image_get_array_int(save->ready, "delay",
			&webp->delay, &webp->delay_length))
		return -1;

	/* Force frames with a small or no duration to 100ms
	 * to be consistent with web browsers and other
	 * transcoding tools.
	 */
	if (webp->gif_delay <= 1)
		webp->gif_delay = 10;

	for (i = 0; i < webp->delay_length; i++)
		if (webp->delay[i] <= 10)
			webp->delay[i] = 100;

	return 0;
}

static int
vips_foreign_save_webp_finish_anim(VipsForeignSaveWebp *webp)
{
	WebPData webp_data;

	/* Closes animated encoder and adds last frame delay.
	 */
	if (!WebPAnimEncoderAdd(webp->enc,
			NULL, webp->timestamp_ms, NULL)) {
		vips_error("webpsave",
			"%s", _("anim close error"));
		return -1;
	}

	if (!WebPAnimEncoderAssemble(webp->enc, &webp_data)) {
		vips_error("webpsave",
			"%s", _("anim build error"));
		return -1;
	}

	/* Terrible. This will only work if the output buffer is currently
	 * empty.
	 */
	if (webp->memory_writer.mem != NULL) {
		vips_error("webpsave", "%s", _("internal error"));
		return -1;
	}

	webp->memory_writer.mem = (uint8_t *) webp_data.bytes;
	webp->memory_writer.size = webp_data.size;

	return 0;
}

static int
vips_foreign_save_webp_build(VipsObject *object)
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) object;

	int page_height;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_webp_parent_class)->build(object))
		return -1;

	page_height = vips_image_get_page_height(save->ready);
	if (save->ready->Xsize > 16383 || page_height > 16383) {
		vips_error("webpsave", _("image too large"));
		vips_foreign_save_webp_unset(webp);
		return -1;
	}

	/* RGB(A) frame as a contiguous buffer.
	 */
	size_t frame_size =
		(size_t) save->ready->Bands * save->ready->Xsize * page_height;
	webp->frame_bytes = g_try_malloc(frame_size);
	if (webp->frame_bytes == NULL) {
		vips_error("webpsave",
			_("failed to allocate %zu bytes"), frame_size);
		vips_foreign_save_webp_unset(webp);
		return -1;
	}

	/* Init generic WebP config
	 */
	if (vips_foreign_save_webp_init_config(webp))
		return -1;

	/* Determine the write mode (single image or animated write)
	 */
	webp->mode = VIPS_FOREIGN_SAVE_WEBP_MODE_SINGLE;
	if (page_height != save->ready->Ysize)
		webp->mode = VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM;

	/* Init config for animated write (if necessary)
	 */
	if (webp->mode == VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM)
		if (vips_foreign_save_webp_init_anim_enc(webp))
			return -1;

	if (vips_sink_disc(save->ready,
			vips_foreign_save_webp_sink_disc, webp))
		return -1;

	/* Finish animated write
	 */
	if (webp->mode == VIPS_FOREIGN_SAVE_WEBP_MODE_ANIM)
		if (vips_foreign_save_webp_finish_anim(webp))
			return -1;

	if (vips_webp_add_metadata(webp)) {
		vips_foreign_save_webp_unset(webp);
		return -1;
	}

	if (vips_target_write(webp->target,
			webp->memory_writer.mem, webp->memory_writer.size)) {
		vips_foreign_save_webp_unset(webp);
		return -1;
	}

	if (vips_target_end(webp->target))
		return -1;

	vips_foreign_save_webp_unset(webp);

	return 0;
}

static const char *vips__save_webp_suffs[] = { ".webp", NULL };

#define UC VIPS_FORMAT_UCHAR

/* Type promotion for save ... just always go to uchar.
 */
static VipsBandFormat bandfmt_webp[10] = {
	/* Band format:  UC  C   US  S   UI  I   F   X   D   DX */
	/* Promotion: */ UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_foreign_save_webp_class_init(VipsForeignSaveWebpClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_webp_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave_base";
	object_class->description = _("save as WebP");
	object_class->build = vips_foreign_save_webp_build;

	foreign_class->suffs = vips__save_webp_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGBA_ONLY;
	save_class->format_table = bandfmt_webp;

	VIPS_ARG_INT(class, "Q", 10,
		_("Q"),
		_("Q factor"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, Q),
		0, 100, 75);

	VIPS_ARG_BOOL(class, "lossless", 11,
		_("Lossless"),
		_("Enable lossless compression"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, lossless),
		FALSE);

	VIPS_ARG_ENUM(class, "preset", 12,
		_("Preset"),
		_("Preset for lossy compression"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, preset),
		VIPS_TYPE_FOREIGN_WEBP_PRESET,
		VIPS_FOREIGN_WEBP_PRESET_DEFAULT);

	VIPS_ARG_BOOL(class, "smart_subsample", 13,
		_("Smart subsampling"),
		_("Enable high quality chroma subsampling"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, smart_subsample),
		FALSE);

	VIPS_ARG_BOOL(class, "near_lossless", 14,
		_("Near lossless"),
		_("Enable preprocessing in lossless mode (uses Q)"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, near_lossless),
		FALSE);

	VIPS_ARG_INT(class, "alpha_q", 15,
		_("Alpha quality"),
		_("Change alpha plane fidelity for lossy compression"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, alpha_q),
		0, 100, 100);

	VIPS_ARG_BOOL(class, "min_size", 16,
		_("Minimise size"),
		_("Optimise for minimum size"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, min_size),
		FALSE);

	VIPS_ARG_INT(class, "kmin", 17,
		_("Minimum keyframe spacing"),
		_("Minimum number of frames between key frames"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, kmin),
		0, INT_MAX, INT_MAX - 1);

	VIPS_ARG_INT(class, "kmax", 18,
		_("Maximum keyframe spacing"),
		_("Maximum number of frames between key frames"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, kmax),
		0, INT_MAX, INT_MAX);

	VIPS_ARG_INT(class, "effort", 19,
		_("Effort"),
		_("Level of CPU effort to reduce file size"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, effort),
		0, 6, 4);

	VIPS_ARG_INT(class, "reduction_effort", 21,
		_("Reduction effort"),
		_("Level of CPU effort to reduce file size"),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, effort),
		0, 6, 4);

	VIPS_ARG_BOOL(class, "mixed", 22,
		_("Mixed encoding"),
		_("Allow mixed encoding (might reduce file size)"),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebp, mixed),
		FALSE);
}

static void
vips_foreign_save_webp_init(VipsForeignSaveWebp *webp)
{
	webp->Q = 75;
	webp->alpha_q = 100;
	webp->effort = 4;

	/* ie. keyframes disabled by default.
	 */
	webp->kmin = INT_MAX - 1;
	webp->kmax = INT_MAX;
}

typedef struct _VipsForeignSaveWebpTarget {
	VipsForeignSaveWebp parent_object;

	VipsTarget *target;
} VipsForeignSaveWebpTarget;

typedef VipsForeignSaveWebpClass VipsForeignSaveWebpTargetClass;

G_DEFINE_TYPE(VipsForeignSaveWebpTarget, vips_foreign_save_webp_target,
	vips_foreign_save_webp_get_type());

static int
vips_foreign_save_webp_target_build(VipsObject *object)
{
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) object;
	VipsForeignSaveWebpTarget *target =
		(VipsForeignSaveWebpTarget *) object;

	webp->target = target->target;
	g_object_ref(webp->target);

	if (VIPS_OBJECT_CLASS(vips_foreign_save_webp_target_parent_class)
			->build(object))
		return -1;

	return 0;
}

static void
vips_foreign_save_webp_target_class_init(
	VipsForeignSaveWebpTargetClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave_target";
	object_class->build = vips_foreign_save_webp_target_build;

	VIPS_ARG_OBJECT(class, "target", 1,
		_("Target"),
		_("Target to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebpTarget, target),
		VIPS_TYPE_TARGET);
}

static void
vips_foreign_save_webp_target_init(VipsForeignSaveWebpTarget *target)
{
}

typedef struct _VipsForeignSaveWebpFile {
	VipsForeignSaveWebp parent_object;
	char *filename;
} VipsForeignSaveWebpFile;

typedef VipsForeignSaveWebpClass VipsForeignSaveWebpFileClass;

G_DEFINE_TYPE(VipsForeignSaveWebpFile, vips_foreign_save_webp_file,
	vips_foreign_save_webp_get_type());

static int
vips_foreign_save_webp_file_build(VipsObject *object)
{
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) object;
	VipsForeignSaveWebpFile *file = (VipsForeignSaveWebpFile *) object;

	if (!(webp->target = vips_target_new_to_file(file->filename)))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_webp_file_parent_class)
			->build(object))
		return -1;

	return 0;
}

static void
vips_foreign_save_webp_file_class_init(VipsForeignSaveWebpFileClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave";
	object_class->build = vips_foreign_save_webp_file_build;

	VIPS_ARG_STRING(class, "filename", 1,
		_("Filename"),
		_("Filename to save to"),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebpFile, filename),
		NULL);
}

static void
vips_foreign_save_webp_file_init(VipsForeignSaveWebpFile *file)
{
}

typedef struct _VipsForeignSaveWebpBuffer {
	VipsForeignSaveWebp parent_object;
	VipsArea *buf;
} VipsForeignSaveWebpBuffer;

typedef VipsForeignSaveWebpClass VipsForeignSaveWebpBufferClass;

G_DEFINE_TYPE(VipsForeignSaveWebpBuffer, vips_foreign_save_webp_buffer,
	vips_foreign_save_webp_get_type());

static int
vips_foreign_save_webp_buffer_build(VipsObject *object)
{
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) object;
	VipsForeignSaveWebpBuffer *buffer =
		(VipsForeignSaveWebpBuffer *) object;

	VipsBlob *blob;

	if (!(webp->target = vips_target_new_to_memory()))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_webp_buffer_parent_class)
			->build(object))
		return -1;

	g_object_get(webp->target, "blob", &blob, NULL);
	g_object_set(buffer, "buffer", blob, NULL);
	vips_area_unref(VIPS_AREA(blob));

	return 0;
}

static void
vips_foreign_save_webp_buffer_class_init(
	VipsForeignSaveWebpBufferClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave_buffer";
	object_class->build = vips_foreign_save_webp_buffer_build;

	VIPS_ARG_BOXED(class, "buffer", 1,
		_("Buffer"),
		_("Buffer to save to"),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET(VipsForeignSaveWebpBuffer, buf),
		VIPS_TYPE_BLOB);
}

static void
vips_foreign_save_webp_buffer_init(VipsForeignSaveWebpBuffer *buffer)
{
}

typedef struct _VipsForeignSaveWebpMime {
	VipsForeignSaveWebp parent_object;

} VipsForeignSaveWebpMime;

typedef VipsForeignSaveWebpClass VipsForeignSaveWebpMimeClass;

G_DEFINE_TYPE(VipsForeignSaveWebpMime, vips_foreign_save_webp_mime,
	vips_foreign_save_webp_get_type());

static int
vips_foreign_save_webp_mime_build(VipsObject *object)
{
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) object;

	VipsBlob *blob;
	void *data;
	size_t len;

	if (!(webp->target = vips_target_new_to_memory()))
		return -1;

	if (VIPS_OBJECT_CLASS(vips_foreign_save_webp_mime_parent_class)
			->build(object))
		return -1;

	g_object_get(webp->target, "blob", &blob, NULL);
	data = VIPS_AREA(blob)->data;
	len = VIPS_AREA(blob)->length;
	vips_area_unref(VIPS_AREA(blob));

	printf("Content-length: %zu\r\n", len);
	printf("Content-type: image/webp\r\n");
	printf("\r\n");
	(void) fwrite(data, sizeof(char), len, stdout);
	fflush(stdout);

	VIPS_UNREF(webp->target);

	return 0;
}

static void
vips_foreign_save_webp_mime_class_init(VipsForeignSaveWebpMimeClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "webpsave_mime";
	object_class->description = _("save image to webp mime");
	object_class->build = vips_foreign_save_webp_mime_build;
}

static void
vips_foreign_save_webp_mime_init(VipsForeignSaveWebpMime *mime)
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
 * Use the metadata items `loop` and `delay` to set the number of
 * loops for the animation and the frame delays.
 *
 * See also: vips_webpload(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave(VipsImage *in, const char *filename, ...)
{
	va_list ap;
	int result;

	va_start(ap, filename);
	result = vips_call_split("webpsave", ap, in, filename);
	va_end(ap);

	return result;
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
vips_webpsave_buffer(VipsImage *in, void **buf, size_t *len, ...)
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL;

	va_start(ap, len);
	result = vips_call_split("webpsave_buffer", ap, in, &area);
	va_end(ap);

	if (!result &&
		area) {
		if (buf) {
			*buf = area->data;
			area->free_fn = NULL;
		}
		if (len)
			*len = area->length;

		vips_area_unref(area);
	}

	return result;
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
 *
 * As vips_webpsave(), but save as a mime webp on stdout.
 *
 * See also: vips_webpsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave_mime(VipsImage *in, ...)
{
	va_list ap;
	int result;

	va_start(ap, in);
	result = vips_call_split("webpsave_mime", ap, in);
	va_end(ap);

	return result;
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
 *
 * As vips_webpsave(), but save to a target.
 *
 * See also: vips_webpsave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_webpsave_target(VipsImage *in, VipsTarget *target, ...)
{
	va_list ap;
	int result;

	va_start(ap, target);
	result = vips_call_split("webpsave_target", ap, in, target);
	va_end(ap);

	return result;
}
