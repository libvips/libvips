/* save with libMagick
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#if HAVE_MAGICK || HAVE_MAGICK7

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "pforeign.h"

typedef struct _VipsForeignSaveMagick {
	VipsForeignSave parent_object;

} VipsForeignSaveMagick;

typedef VipsForeignSaveClass VipsForeignSaveMagickClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveMagick, vips_foreign_save_magick,
	VIPS_TYPE_FOREIGN_SAVE );

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT
#define UI VIPS_FORMAT_UINT
#define F VIPS_FORMAT_FLOAT
#define D VIPS_FORMAT_DOUBLE

static int bandfmt_magick[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, US, UI, UI, F,  F,  D,  D
};

static void
vips_foreign_save_magick_class_init( VipsForeignSaveMagickClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magicksave_base";
	object_class->description = _( "save with ImageMagick" );

	/* We need to be well to the back of the queue since vips's
	* dedicated savers are usually preferable.
	*/
	foreign_class->priority = -100;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_magick;
}

static void
vips_foreign_save_magick_init( VipsForeignSaveMagick *magick )
{
}

typedef struct _VipsForeignSaveMagickFile {
	VipsForeignSaveMagick parent_object;

	char *filename;
	char *format;
	int quality;

} VipsForeignSaveMagickFile;

typedef VipsForeignSaveMagickClass VipsForeignSaveMagickFileClass;

G_DEFINE_TYPE( VipsForeignSaveMagickFile, vips_foreign_save_magick_file,
	vips_foreign_save_magick_get_type() );

static int
vips_foreign_save_magick_file_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) object;
	VipsForeignSaveMagickFile *file = (VipsForeignSaveMagickFile *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_magick_file_parent_class )->
			build( object ) )
		return( -1 );

	if( vips__magick_write( save->ready, file->filename, file->format,
			file->quality ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_magick_file_class_init(
	VipsForeignSaveMagickFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magicksave";
	object_class->description = _( "save file with ImageMagick" );
	object_class->build = vips_foreign_save_magick_file_build;

	VIPS_ARG_STRING( class, "filename", 1,
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickFile, filename ),
		NULL );

	VIPS_ARG_STRING( class, "format", 2,
		_( "Format" ),
		_( "Format to save in" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickFile, format ),
		NULL );

	VIPS_ARG_INT( class, "quality", 3,
		_( "Quality" ),
		_( "Quality to use" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickFile, quality ),
		0, 100, 0 );

}

static void
vips_foreign_save_magick_file_init( VipsForeignSaveMagickFile *file )
{
}

typedef struct _VipsForeignSaveMagickBuffer {
	VipsForeignSaveMagick parent_object;

	/* Save to a buffer.
	 */
	VipsArea *buf;
	char *format;
	int quality;

} VipsForeignSaveMagickBuffer;

typedef VipsForeignSaveMagickClass VipsForeignSaveMagickBufferClass;

G_DEFINE_TYPE( VipsForeignSaveMagickBuffer, vips_foreign_save_magick_buffer, 
	vips_foreign_save_magick_get_type() );

static int
vips_foreign_save_magick_buffer_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveMagick *magick = (VipsForeignSaveMagick *) object;
	VipsForeignSaveMagickBuffer *buffer = (VipsForeignSaveMagickBuffer *) object;

	void *obuf;
	size_t olen;
	VipsBlob *blob;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_magick_buffer_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__magick_write_buf( save->ready, &obuf, &olen,
			buffer->format, buffer->quality ) )
		return( -1 );

	/* obuf is a g_free() buffer, not vips_free().
	 */
	blob = vips_blob_new( (VipsCallbackFn) g_free, obuf, olen );
	g_object_set( buffer, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_magick_buffer_class_init( VipsForeignSaveMagickBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "magicksave_buffer";
	object_class->description = _( "save image to magick buffer" );
	object_class->build = vips_foreign_save_magick_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1,
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickBuffer, buf ),
		VIPS_TYPE_BLOB );

	VIPS_ARG_STRING( class, "format", 2,
		_( "Format" ),
		_( "Format to save in" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickBuffer, format ),
		NULL );

	VIPS_ARG_INT( class, "quality", 3,
		_( "Quality" ),
		_( "Quality to use" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveMagickBuffer, quality ),
		0, 100, 0 );
}

static void
vips_foreign_save_magick_buffer_init( VipsForeignSaveMagickBuffer *buffer )
{
}

#endif /*HAVE_MAGICK || HAVE_MAGICK7*/
