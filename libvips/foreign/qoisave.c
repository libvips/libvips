/* save to qoi
 *
 * 2/12/11
 * 	- wrap a class around the qoi writer
 * 13/11/19
 * 	- redone with targets
 * 18/6/20
 * 	- add "bitdepth" param, cf. tiffsave
 * 27/6/20
 * 	- add qoisave_target
 * 20/11/20
 * 	- byteswap on save, if necessary [ewelot]
 * 2/12/20
 * 	- don't add date with @strip [ewelot]
 * 28/10/21
 * 	- add @format, default type by filename
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

#define QOI_IMPLEMENTATION
#include "qoi/qoi.h"

typedef struct _VipsForeignSaveQoi VipsForeignSaveQoi;

struct _VipsForeignSaveQoi {
	VipsForeignSave parent_object;

	VipsTarget *target;
};

typedef VipsForeignSaveClass VipsForeignSaveQoiClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveQoi, vips_foreign_save_qoi, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_qoi_dispose( GObject *gobject )
{
	VipsForeignSaveQoi *qoi = (VipsForeignSaveQoi *) gobject;

	if( qoi->target ) 
		vips_target_finish( qoi->target );
	VIPS_UNREF( qoi->target );

	G_OBJECT_CLASS( vips_foreign_save_qoi_parent_class )->
		dispose( gobject );
}

static int
vips_foreign_save_qoi_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveQoi *qoi = (VipsForeignSaveQoi *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *memory;
	qoi_desc desc;
	int size;
        void *encoded;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_qoi_parent_class )->
		build( object ) )
		return( -1 );

	/* qoi.h can only save entire images.
	 */
	if( !(memory = vips_image_copy_memory( save->ready )) ) 
		return( -1 );

	desc.width = memory->Xsize;
	desc.height = memory->Ysize;
	desc.channels = memory->Bands;
	desc.colorspace = QOI_SRGB;
	encoded = qoi_encode( VIPS_IMAGE_ADDR( memory, 0, 0 ), &desc, &size );
	if( !encoded ) {
		vips_error( class->nickname, "%s", _( "unable to encode" ) ); 
		VIPS_UNREF( memory );
		return( -1 );
	}
	VIPS_UNREF( memory );

	if( vips_target_write( qoi->target, encoded, size ) ) {
		QOI_FREE( encoded );
		return( -1 );
	}
	QOI_FREE( encoded );

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR

static int bandfmt_qoi[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, UC, UC, UC, UC, UC, UC, UC, UC
};

static void
vips_foreign_save_qoi_class_init( VipsForeignSaveQoiClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_qoi_dispose;

	object_class->nickname = "qoisave_base";
	object_class->description = _( "save as QOI" );
	object_class->build = vips_foreign_save_qoi_build;

	operation_class->flags = VIPS_OPERATION_UNTRUSTED;

	save_class->saveable = VIPS_SAVEABLE_RGBA_ONLY;
	save_class->format_table = bandfmt_qoi;

}

static void
vips_foreign_save_qoi_init( VipsForeignSaveQoi *qoi )
{
}

typedef struct _VipsForeignSaveQoiFile {
	VipsForeignSaveQoi parent_object;

	char *filename; 
} VipsForeignSaveQoiFile;

typedef VipsForeignSaveQoiClass VipsForeignSaveQoiFileClass;

G_DEFINE_TYPE( VipsForeignSaveQoiFile, vips_foreign_save_qoi_file, 
	vips_foreign_save_qoi_get_type() );

static int
vips_foreign_save_qoi_file_build( VipsObject *object )
{
	VipsForeignSaveQoi *qoi = (VipsForeignSaveQoi *) object;
	VipsForeignSaveQoiFile *file = (VipsForeignSaveQoiFile *) object;

	if( file->filename &&
		!(qoi->target = vips_target_new_to_file( file->filename )) )
		return( -1 );

	return( VIPS_OBJECT_CLASS( vips_foreign_save_qoi_file_parent_class )->
		build( object ) );
}

const char *vips__qoi_suffs[] = { ".qoi", NULL };

static void
vips_foreign_save_qoi_file_class_init( VipsForeignSaveQoiFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "qoisave";
	object_class->description = _( "save image to file as QOI" );
	object_class->build = vips_foreign_save_qoi_file_build;

	foreign_class->suffs = vips__qoi_suffs;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveQoiFile, filename ),
		NULL );

}

static void
vips_foreign_save_qoi_file_init( VipsForeignSaveQoiFile *file )
{
}

typedef struct _VipsForeignSaveQoiTarget {
	VipsForeignSaveQoi parent_object;

	VipsTarget *target;
} VipsForeignSaveQoiTarget;

typedef VipsForeignSaveQoiClass VipsForeignSaveQoiTargetClass;

G_DEFINE_TYPE( VipsForeignSaveQoiTarget, vips_foreign_save_qoi_target, 
	vips_foreign_save_qoi_get_type() );

static int
vips_foreign_save_qoi_target_build( VipsObject *object )
{
	VipsForeignSaveQoi *qoi = (VipsForeignSaveQoi *) object;
	VipsForeignSaveQoiTarget *target = 
		(VipsForeignSaveQoiTarget *) object;

	if( target->target ) {
		qoi->target = target->target; 
		g_object_ref( qoi->target );
	}

	return( VIPS_OBJECT_CLASS( 
		vips_foreign_save_qoi_target_parent_class )->
			build( object ) );
}

static void
vips_foreign_save_qoi_target_class_init( 
	VipsForeignSaveQoiTargetClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "qoisave_target";
	object_class->build = vips_foreign_save_qoi_target_build;

	foreign_class->suffs = vips__save_qoi_suffs;

	VIPS_ARG_OBJECT( class, "target", 1,
		_( "Target" ),
		_( "Target to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveQoiTarget, target ),
		VIPS_TYPE_TARGET );

}

static void
vips_foreign_save_qoi_target_init( VipsForeignSaveQoiTarget *target )
{
}

/**
 * vips_qoisave: (method)
 * @in: image to save 
 * @filename: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write to a file as QOI. Images are saved as 8-bit RGB or RGBA.
 *
 * See also: vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_qoisave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "qoisave", ap, in, filename );
	va_end( ap );

	return( result );
}

/**
 * vips_qoisave_target: (method)
 * @in: image to save 
 * @target: save image to this target
 * @...: %NULL-terminated list of optional named arguments
 *
 * As vips_qoisave(), but save to a target.
 *
 * See also: vips_qoisave().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_qoisave_target( VipsImage *in, VipsTarget *target, ... )
{
	va_list ap;
	int result;

	va_start( ap, target );
	result = vips_call_split( "qoisave_target", ap, in, target );
	va_end( ap );

	return( result );
}
