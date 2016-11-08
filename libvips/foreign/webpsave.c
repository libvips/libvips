/* save to webp
 *
 * 24/11/11
 * 	- wrap a class around the webp writer
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
#include <vips/intl.h>

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
		_( "lossless" ), 
		_( "enable lossless compression" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveWebp, lossless ),
		FALSE ); 

	VIPS_ARG_ENUM( class, "preset", 12,
		_( "preset" ),
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

}

static void
vips_foreign_save_webp_init( VipsForeignSaveWebp *webp )
{
	webp->Q = 75;
	webp->alpha_q = 100;
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

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_file_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__webp_write_file( save->ready, file->filename, 
		webp->Q, webp->lossless, webp->preset,
		webp->smart_subsample, webp->near_lossless,
		webp->alpha_q, save->strip ) )
		return( -1 );

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
	VipsForeignSaveWebpBuffer *file = (VipsForeignSaveWebpBuffer *) object;

	void *obuf;
	size_t olen;
	VipsBlob *blob;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_buffer_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__webp_write_buffer( save->ready, &obuf, &olen, 
		webp->Q, webp->lossless, webp->preset,
		webp->smart_subsample, webp->near_lossless,
		webp->alpha_q, save->strip ) )
		return( -1 );

	/* obuf is a g_free() buffer, not vips_free().
	 */
	blob = vips_blob_new( (VipsCallbackFn) g_free, obuf, olen );
	g_object_set( file, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

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

	void *obuf;
	size_t olen;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_webp_mime_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__webp_write_buffer( save->ready, &obuf, &olen, 
		webp->Q, webp->lossless, webp->preset,
		webp->smart_subsample, webp->near_lossless,
		webp->alpha_q, save->strip ) )
		return( -1 );

	printf( "Content-length: %zu\r\n", olen );
	printf( "Content-type: image/webp\r\n" );
	printf( "\r\n" );
	if( fwrite( obuf, sizeof( char ), olen, stdout ) != olen ) {
		vips_error( "VipsWebp", "%s", _( "error writing output" ) );
		return( -1 );
	}
	fflush( stdout );

	g_free( obuf );

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
 * vips_webpsave:
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
 * * @strip: %gboolean, remove all metadata from image
 *
 * Write an image to a file in WebP format. 
 *
 * By default, images are saved in lossy format, with 
 * @Q giving the WebP quality factor. It has the range 0 - 100, with the
 * default 75.
 *
 * Use @preset to hint the image type to the lossy compressor. The default is
 * #VIPS_FOREIGN_WEBP_PRESET_DEFAULT. 
 * Set @smart_subsample to enable high quality chroma subsampling.
 * Use @alpha_q to set the quality for the alpha channel in lossy mode. It has
 * the range 1 - 100, with the default 100.
 *
 * Set @lossless to use lossless compression, or combine @near_lossless
 * with @Q 80, 60, 40 or 20 to apply increasing amounts of preprocessing
 * which improves the near-lossless compression ratio by up to 50%.
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
 * vips_webpsave_buffer:
 * @in: image to save 
 * @buf: return output buffer here
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
 * * @strip: %gboolean, remove all metadata from image
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
 * vips_webpsave_mime:
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
 * * @strip: %gboolean, remove all metadata from image
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
