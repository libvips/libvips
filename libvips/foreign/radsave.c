/* save to rad
 *
 * 2/12/11
 * 	- wrap a class around the rad writer
 * 23/5/16
 *  - split into file and buffer save classes
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#ifdef HAVE_RADIANCE

#include "radiance.h"

typedef struct _VipsForeignSaveRad {
	VipsForeignSave parent_object;

	char *filename; 
} VipsForeignSaveRad;

typedef VipsForeignSaveClass VipsForeignSaveRadClass;

G_DEFINE_TYPE( VipsForeignSaveRad, vips_foreign_save_rad, 
	VIPS_TYPE_FOREIGN_SAVE );

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static int vips_foreign_save_rad_format_table[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   F,  F,  F,  F,  F,  F,  F,  F,  F,  F
};

static void
vips_foreign_save_rad_class_init( VipsForeignSaveRadClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "radsave_base";
	object_class->description = _( "save Radiance" );

	save_class->saveable = VIPS_SAVEABLE_RGB;
	save_class->format_table = vips_foreign_save_rad_format_table;
	save_class->coding[VIPS_CODING_NONE] = FALSE;
	save_class->coding[VIPS_CODING_RAD] = TRUE;

}

static void
vips_foreign_save_rad_init( VipsForeignSaveRad *rad )
{
}

typedef struct _VipsForeignSaveRadFile {
	VipsForeignSaveRad parent_object;

	char *filename; 
} VipsForeignSaveRadFile;

typedef VipsForeignSaveRadClass VipsForeignSaveRadFileClass;

G_DEFINE_TYPE( VipsForeignSaveRadFile, vips_foreign_save_rad_file,
	vips_foreign_save_rad_get_type() );

static int
vips_foreign_save_rad_file_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveRadFile *file = (VipsForeignSaveRadFile *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_rad_file_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__rad_save( save->ready, file->filename ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_rad_file_class_init( VipsForeignSaveRadFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	foreign_class->suffs = vips__rad_suffs;

	object_class->nickname = "radsave";
	object_class->description = _( "save image to Radiance file" );
	object_class->build = vips_foreign_save_rad_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveRadFile, filename ),
		NULL );
}

static void
vips_foreign_save_rad_file_init( VipsForeignSaveRadFile *file )
{
}

typedef struct _VipsForeignSaveRadBuffer {
	VipsForeignSaveRad parent_object;

	VipsArea *buf;
} VipsForeignSaveRadBuffer;

typedef VipsForeignSaveRadClass VipsForeignSaveRadBufferClass;

G_DEFINE_TYPE( VipsForeignSaveRadBuffer, vips_foreign_save_rad_buffer, 
	vips_foreign_save_rad_get_type() );

static int
vips_foreign_save_rad_buffer_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;

	void *obuf;
	size_t olen;
	VipsBlob *blob;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_rad_buffer_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__rad_save_buf( save->ready, &obuf, &olen ) )
		return( -1 );

	blob = vips_blob_new( (VipsCallbackFn) vips_free, obuf, olen );
	g_object_set( object, "buffer", blob, NULL );
	vips_area_unref( VIPS_AREA( blob ) );

	return( 0 );
}

static void
vips_foreign_save_rad_buffer_class_init( VipsForeignSaveRadBufferClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "radsave_buffer";
	object_class->description = _( "save image to Radiance buffer" );
	object_class->build = vips_foreign_save_rad_buffer_build;

	VIPS_ARG_BOXED( class, "buffer", 1, 
		_( "Buffer" ),
		_( "Buffer to save to" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveRadBuffer, buf ),
		VIPS_TYPE_BLOB );
}

static void
vips_foreign_save_rad_buffer_init( VipsForeignSaveRadBuffer *buffer )
{
}


#endif /*HAVE_RADIANCE*/

/**
 * vips_radsave:
 * @in: image to save 
 * @filename: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write a VIPS image in Radiance (HDR) format.
 *
 * Sections of this reader from Greg Ward and Radiance with kind permission. 
 *
 * See also: vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_radsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "radsave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_radsave_buffer:
 * @in: image to save 
 * @buf: return output buffer here
 * @len: return output length here
 * @...: %NULL-terminated list of optional named arguments
 *
 * As vips_radsave(), but save to a memory buffer. 
 *
 * The address of the buffer is returned in @obuf, the length of the buffer in
 * @olen. You are responsible for freeing the buffer with g_free() when you
 * are done with it.
 *
 * See also: vips_radsave(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_radsave_buffer( VipsImage *in, void **buf, size_t *len, ... )
{
	va_list ap;
	VipsArea *area;
	int result;

	area = NULL; 

	va_start( ap, len );
	result = vips_call_split( "radsave_buffer", ap, in, &area );
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
