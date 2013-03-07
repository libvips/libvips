/* save to raw
 *
 * Write raw image data to file. Usefull when defining new formats...
 *
 * Jesper Friis
 *
 * 10/06/08 JF
 *	- initial code based on im_vips2ppm()
 *
 * 04/07/08 JF
 *      - replaced FILE with plain file handlers for reducing
 *        confusion about binary vs. non-binary file modes.
 * 4/2/10
 * 	- gtkdoc
 * 15/12/11
 * 	- rework as a class
 * 	- added save raw to filename
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsForeignSaveRaw {
	VipsForeignSave parent_object;

	char *filename;

	int fd;
} VipsForeignSaveRaw;

typedef VipsForeignSaveClass VipsForeignSaveRawClass;

G_DEFINE_TYPE( VipsForeignSaveRaw, vips_foreign_save_raw, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_raw_dispose( GObject *gobject )
{
	VipsForeignSaveRaw *raw = (VipsForeignSaveRaw *) gobject;

	VIPS_FREEF( vips_tracked_close, raw->fd );

	G_OBJECT_CLASS( vips_foreign_save_raw_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_save_raw_write( VipsRegion *region, Rect *area, void *a )
{
	VipsForeignSave *save = (VipsForeignSave *) a;
	VipsForeignSaveRaw *raw = (VipsForeignSaveRaw *) a;
	int i;
  
	for( i = 0; i < area->height; i++ ) {
		VipsPel *p = 
			VIPS_REGION_ADDR( region, area->left, area->top + i );

		if( vips__write( raw->fd, p, 
			VIPS_IMAGE_SIZEOF_PEL( save->in ) * area->width ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_foreign_save_raw_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveRaw *raw = (VipsForeignSaveRaw *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_raw_parent_class )->
		build( object ) )
		return( -1 );

	if( (raw->fd = vips__open_image_write( raw->filename, FALSE )) < 0 ||
		vips_image_pio_input( save->in ) || 
		vips_sink_disc( save->in, vips_foreign_save_raw_write, raw ) ) 
		return( -1 );

	return( 0 );
}

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

/* Type promotion for division. Sign and value preserving. Make sure 
 * these match the case statement in complexform_buffer() above.
 */
static int vips_bandfmt_raw[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   UC, C,  US, S,  UI, I, F, X, D, DX
};

static void
vips_foreign_save_raw_class_init( VipsForeignSaveRawClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_raw_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "rawsave";
	object_class->description = _( "save image to raw file" );
	object_class->build = vips_foreign_save_raw_build;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = vips_bandfmt_raw;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveRaw, filename ),
		NULL );
}

static void
vips_foreign_save_raw_init( VipsForeignSaveRaw *raw )
{
}

/**
 * vips_rawsave:
 * @in: image to save 
 * @filename: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Writes the pixels in @in to the file @filename with no header or other
 * metadata. 
 *
 * See also: vips_image_write_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_rawsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "rawsave", ap, filename );
	va_end( ap );

	return( result );
}

/* And with an fd rather than a filename.
 */

typedef struct _VipsForeignSaveRawFd {
	VipsForeignSave parent_object;

	int fd;
} VipsForeignSaveRawFd;

typedef VipsForeignSaveClass VipsForeignSaveRawFdClass;

G_DEFINE_TYPE( VipsForeignSaveRawFd, vips_foreign_save_raw_fd, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_raw_fd_write( VipsRegion *region, Rect *area, void *a )
{
	VipsForeignSave *save = (VipsForeignSave *) a;
	VipsForeignSaveRawFd *fd = (VipsForeignSaveRawFd *) a;
	int i;
  
	for( i = 0; i < area->height; i++ ) {
		VipsPel *p = 
			VIPS_REGION_ADDR( region, area->left, area->top + i );

		if( vips__write( fd->fd, p, 
			VIPS_IMAGE_SIZEOF_PEL( save->in ) * area->width ) )
			return( -1 );
	}

	return( 0 );
}

static int
vips_foreign_save_raw_fd_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveRawFd *fd = (VipsForeignSaveRawFd *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_raw_fd_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_image_pio_input( save->in ) || 
		vips_sink_disc( save->in, 
			vips_foreign_save_raw_fd_write, fd ) ) 
		return( -1 );

	return( 0 );
}

static void
vips_foreign_save_raw_fd_class_init( VipsForeignSaveRawFdClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "rawsave_fd";
	object_class->description = _( "write raw image to file descriptor" );
	object_class->build = vips_foreign_save_raw_fd_build;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = vips_bandfmt_raw;

	VIPS_ARG_INT( class, "fd", 1, 
		_( "File descriptor" ),
		_( "File descriptor to write to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveRawFd, fd ),
		0, 10000, 0 );
}

static void
vips_foreign_save_raw_fd_init( VipsForeignSaveRawFd *fd )
{
}

/**
 * vips_rawsave_fd:
 * @in: image to save 
 * @fd: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Writes the pixels in @in to the @fd with no header or other
 * metadata.  Handy for implementing other savers.
 *
 * See also: vips_rawsave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_rawsave_fd( VipsImage *in, int fd, ... )
{
	va_list ap;
	int result;

	va_start( ap, fd );
	result = vips_call_split( "rawsave_fd", ap, fd );
	va_end( ap );

	return( result );
}
