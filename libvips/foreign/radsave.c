/* save to rad
 *
 * 2/12/11
 * 	- wrap a class around the rad writer
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

#include "radiance.h"

typedef struct _VipsForeignSaveRad {
	VipsForeignSave parent_object;

	char *filename; 
} VipsForeignSaveRad;

typedef VipsForeignSaveClass VipsForeignSaveRadClass;

G_DEFINE_TYPE( VipsForeignSaveRad, vips_foreign_save_rad, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_rad_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveRad *rad = (VipsForeignSaveRad *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_rad_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__rad_save( save->ready, rad->filename ) )
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

static int bandfmt_rad[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   F,  F,  F,  F,  F,  F,  F,  F,  F,  F
};

static void
vips_foreign_save_rad_class_init( VipsForeignSaveRadClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "radsave";
	object_class->description = _( "save image to Radiance file" );
	object_class->build = vips_foreign_save_rad_build;

	foreign_class->suffs = vips__rad_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGB;
	save_class->format_table = bandfmt_rad;
	save_class->coding = VIPS_CODING_RAD;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveRad, filename ),
		NULL );
}

static void
vips_foreign_save_rad_init( VipsForeignSaveRad *rad )
{
}

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
 * See also: vips_image_write_file().
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
