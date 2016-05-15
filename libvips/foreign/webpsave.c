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

#ifdef HAVE_LIBWEBP

#include <stdlib.h>

#include <vips/vips.h>

#include "webp.h"

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
		webp->alpha_q ) )
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
		webp->alpha_q ) )
		return( -1 );

	blob = vips_blob_new( (VipsCallbackFn) vips_free, obuf, olen );
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
		webp->alpha_q ) )
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
