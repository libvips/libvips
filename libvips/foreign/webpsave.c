/* save to webp
 *
 * 24/11/11
 * 	- wrap a class around the webp writer
 * 29/10/18 
 * 	- add animated webp support
 * 15/1/19 lovell
 * 	- add @effort 
 * 18/7/20
 * 	- add @profile param to match tiff, jpg, etc.
 * 30/7/21
 * 	- rename "reduction_effort" as "effort"
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

#include <stdlib.h>

#include <vips/vips.h>

#include "pforeign.h"

#ifdef HAVE_LIBWEBP

typedef struct _VipsForeignSaveWebp {
	VipsForeignSave parent_object;

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

	/* Profile to embed.
	 */
	char *profile;

} VipsForeignSaveWebp;

typedef VipsForeignSaveClass VipsForeignSaveWebpClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveWebp, vips_foreign_save_webp, 
	VIPS_TYPE_FOREIGN_SAVE );

#define UC VIPS_FORMAT_UCHAR

/* Type promotion for save ... just always go to uchar.
 */
static int bandfmt_webp[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_foreign_save_webp_class_init( VipsForeignSaveWebpClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave_base";
	object_class->description = _( "save webp" );

	foreign_class->suffs = vips__webp_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGBA_ONLY;
	save_class->format_table = bandfmt_webp;

	VIPS_ARG_INT( class, "Q", 10, 
		_( "Q" ), 
		_( "Q factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, Q ),
		0, 100, 75 );

	VIPS_ARG_BOOL( class, "lossless", 11, 
		_( "Lossless" ), 
		_( "Enable lossless compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, lossless ),
		FALSE ); 

	VIPS_ARG_ENUM( class, "preset", 12,
		_( "Preset" ),
		_( "Preset for lossy compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, preset ),
		VIPS_TYPE_FOREIGN_WEBP_PRESET,
		VIPS_FOREIGN_WEBP_PRESET_DEFAULT );

	VIPS_ARG_BOOL( class, "smart_subsample", 13,
		_( "Smart subsampling" ),
		_( "Enable high quality chroma subsampling" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, smart_subsample ),
		FALSE );

	VIPS_ARG_BOOL( class, "near_lossless", 14,
		_( "Near lossless" ),
		_( "Enable preprocessing in lossless mode (uses Q)" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, near_lossless ),
		FALSE );

	VIPS_ARG_INT( class, "alpha_q", 15,
		_( "Alpha quality" ),
		_( "Change alpha plane fidelity for lossy compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, alpha_q ),
		0, 100, 100 );

	VIPS_ARG_BOOL( class, "min_size", 16,
		_( "Minimise size" ),
		_( "Optimise for minimum size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, min_size ),
		FALSE );

	VIPS_ARG_INT( class, "kmin", 17,
		_( "Minimum keyframe spacing" ),
		_( "Minimum number of frames between key frames" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, kmin ),
		0, INT_MAX, INT_MAX - 1 );

	VIPS_ARG_INT( class, "kmax", 18,
		_( "Maximum keyframe spacing" ),
		_( "Maximum number of frames between key frames" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, kmax ),
		0, INT_MAX, INT_MAX );

	VIPS_ARG_INT( class, "effort", 19,
		_( "Effort" ),
		_( "Level of CPU effort to reduce file size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, effort ),
		0, 6, 4 );

	VIPS_ARG_STRING( class, "profile", 20, 
		_( "Profile" ), 
		_( "ICC profile to embed" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, profile ),
		NULL );

	VIPS_ARG_INT( class, "reduction_effort", 21,
		_( "Reduction effort" ),
		_( "Level of CPU effort to reduce file size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT | VIPS_ARGUMENT_DEPRECATED,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, effort ),
		0, 6, 4 );

	VIPS_ARG_BOOL( class, "mixed", 22,
		_( "Mixed encoding" ),
		_( "Allow mixed encoding (might reduce file size)" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, mixed ),
		FALSE );
}

static void
vips_foreign_save_webp_init( VipsForeignSaveWebp *webp )
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

G_DEFINE_TYPE( VipsForeignSaveWebpTarget, vips_foreign_save_webp_target, 
	vips_foreign_save_webp_get_type() );

static int
vips_foreign_save_webp_target_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) object;
	VipsForeignSaveWebpTarget *target = 
		(VipsForeignSaveWebpTarget *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_target_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__webp_write_target( save->ready, target->target, 
		webp->Q, webp->lossless, webp->preset,
		webp->smart_subsample, webp->near_lossless,
		webp->alpha_q, webp->effort,
		webp->min_size, webp->mixed, webp->kmin, webp->kmax,
		save->strip, webp->profile ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_webp_target_class_init( 
	VipsForeignSaveWebpTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave_target";
	object_class->description = _( "save image to webp target" );
	object_class->build = vips_foreign_save_webp_target_build;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveWebpTarget, target ),
		VIPS_TYPE_TARGET );
}

static void
vips_foreign_save_webp_target_init( VipsForeignSaveWebpTarget *target )
{
}


typedef struct _VipsForeignSaveWebpFile {
	VipsForeignSaveWebp parent_object;

	/* Filename for save.
	 */
	char *filename; 

} VipsForeignSaveWebpFile;

typedef VipsForeignSaveWebpClass VipsForeignSaveWebpFileClass;

G_DEFINE_TYPE( VipsForeignSaveWebpFile, vips_foreign_save_webp_file, 
	vips_foreign_save_webp_get_type() );

static int
vips_foreign_save_webp_file_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) object;
	VipsForeignSaveWebpFile *file = (VipsForeignSaveWebpFile *) object;

	VipsTarget *target;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_file_parent_class )->
		build( object ) )
		return( -1 );

	if( !(target = vips_target_new_to_file( file->filename )) )
		return( -1 );
	if( vips__webp_write_target( save->ready, target,
		webp->Q, webp->lossless, webp->preset,
		webp->smart_subsample, webp->near_lossless,
		webp->alpha_q, webp->effort,
		webp->min_size, webp->mixed, webp->kmin, webp->kmax,
		save->strip, webp->profile ) ) {
		VIPS_UNREF( target );
		return( -1 );
	}
	VIPS_UNREF( target );

	return( 0 );
}

static void
vips_foreign_save_webp_file_class_init( VipsForeignSaveWebpFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave";
	object_class->description = _( "save image to webp file" );
	object_class->build = vips_foreign_save_webp_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveWebpFile, filename ),
		NULL );
}

static void
vips_foreign_save_webp_file_init( VipsForeignSaveWebpFile *file )
{
}

typedef struct _VipsForeignSaveWebpBuffer {
	VipsForeignSaveWebp parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;

} VipsForeignSaveWebpBuffer;

typedef VipsForeignSaveWebpClass VipsForeignSaveWebpBufferClass;

G_DEFINE_TYPE( VipsForeignSaveWebpBuffer, vips_foreign_save_webp_buffer, 
	vips_foreign_save_webp_get_type() );

static int
vips_foreign_save_webp_buffer_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) object;
	VipsForeignSaveWebpBuffer *buffer = 
		(VipsForeignSaveWebpBuffer *) object;

	VipsTarget *target;
	VipsBlob *blob;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_buffer_parent_class )->
		build( object ) )
		return( -1 );

	if( !(target = vips_target_new_to_memory()) )
		return( -1 );

	if( vips__webp_write_target( save->ready, target,
		webp->Q, webp->lossless, webp->preset,
		webp->smart_subsample, webp->near_lossless,
		webp->alpha_q, webp->effort,
		webp->min_size, webp->mixed, webp->kmin, webp->kmax,
		save->strip, webp->profile ) ) {
		VIPS_UNREF( target );
		return( -1 );
	}

	g_object_get( target, "blob", &blob, NULL );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	VIPS_UNREF( target );

	return( 0 );
}

static void
vips_foreign_save_webp_buffer_class_init( 
	VipsForeignSaveWebpBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "webpsave_buffer";
	object_class->description = _( "save image to webp buffer" );
	object_class->build = vips_foreign_save_webp_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveWebpBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_save_webp_buffer_init( VipsForeignSaveWebpBuffer *file )
{
}

typedef struct _VipsForeignSaveWebpMime {
	VipsForeignSaveWebp parent_object;

} VipsForeignSaveWebpMime;

typedef VipsForeignSaveWebpClass VipsForeignSaveWebpMimeClass;

G_DEFINE_TYPE( VipsForeignSaveWebpMime, vips_foreign_save_webp_mime, 
	vips_foreign_save_webp_get_type() );

static int
vips_foreign_save_webp_mime_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveWebp *webp = (VipsForeignSaveWebp *) object;

	VipsTarget *target;
	VipsBlob *blob;
	void *data;
	size_t len;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_mime_parent_class )->
		build( object ) )
		return( -1 );

	if( !(target = vips_target_new_to_memory()) )
		return( -1 );

	if( vips__webp_write_target( save->ready, target,
		webp->Q, webp->lossless, webp->preset,
		webp->smart_subsample, webp->near_lossless,
		webp->alpha_q, webp->effort,
		webp->min_size, webp->mixed, webp->kmin, webp->kmax,
		save->strip, webp->profile ) ) {
		VIPS_UNREF( target );
		return( -1 );
	}

	g_object_get( target, "blob", &blob, NULL );
	data = VIPS_AREA( blob )->data;
	len = VIPS_AREA( blob )->length;
	vips_area_unref( VIPS_AREA( blob ) );

	printf( "Content-length: %zu\r\n", len );
	printf( "Content-type: image/webp\r\n" );
	printf( "\r\n" );
	(void) fwrite( data, sizeof( char ), len, stdout );
	fflush( stdout );

	VIPS_UNREF( target );

	return( 0 );
}

static void
vips_foreign_save_webp_mime_class_init( VipsForeignSaveWebpMimeClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	object_class->nickname = "webpsave_mime";
	object_class->description = _( "save image to webp mime" );
	object_class->build = vips_foreign_save_webp_mime_build;

}

static void
vips_foreign_save_webp_mime_init( VipsForeignSaveWebpMime *mime )
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
