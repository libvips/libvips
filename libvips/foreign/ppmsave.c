/* save to ppm
 *
 * 2/12/11
 * 	- wrap a class around the ppm writer
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

#ifdef HAVE_PPM

#include "ppm.h"

typedef struct _VipsForeignSavePpm {
	VipsForeignSave parent_object;

	char *filename; 
	gboolean ascii;
	gboolean squash;
} VipsForeignSavePpm;

typedef VipsForeignSaveClass VipsForeignSavePpmClass;

G_DEFINE_TYPE( VipsForeignSavePpm, vips_foreign_save_ppm, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_ppm_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSavePpm *ppm = (VipsForeignSavePpm *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_ppm_parent_class )->
		build( object ) )
		return( -1 );

	if( vips__ppm_save( save->ready, ppm->filename, 
		ppm->ascii, ppm->squash ) )
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

static int bandfmt_ppm[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, US, UI, UI, F,  F,  F,  F
};

static void
vips_foreign_save_ppm_class_init( VipsForeignSavePpmClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "ppmsave";
	object_class->description = _( "save image to ppm file" );
	object_class->build = vips_foreign_save_ppm_build;

	foreign_class->suffs = vips__ppm_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGB;
	save_class->format_table = bandfmt_ppm;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSavePpm, filename ),
		NULL );

	VIPS_ARG_BOOL( class, "ascii", 10, 
		_( "ASCII" ), 
		_( "save as ascii" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePpm, ascii ),
		FALSE );

	VIPS_ARG_BOOL( class, "squash", 11, 
		_( "Squash" ), 
		_( "save as one bit" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSavePpm, squash ),
		FALSE );
}

static void
vips_foreign_save_ppm_init( VipsForeignSavePpm *ppm )
{
}

#endif /*HAVE_PPM*/

/**
 * vips_ppmsave:
 * @in: image to save 
 * @filename: file to write to
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @ascii: save as ASCII rather than binary
 * @squash: squash 8-bit images down to one bit
 *
 * Write a VIPS image to a file as PPM. It can write 1, 8, 16 or
 * 32 bit unsigned integer images, float images, colour or monochrome, 
 * stored as binary or ASCII. 
 * Integer images of more than 8 bits can only be stored in ASCII.
 *
 * When writing float (PFM) images the scale factor is set from the 
 * "pfm-scale" metadata.
 *
 * Set @ascii to %TRUE to write as human-readable ASCII. Normally data is
 * written in binary. 
 *
 * Set @squash to %TRUE to squash 8-bit images down to one bit. The saver does
 * no dithering, that's up to you.
 *
 * See also: vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_ppmsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "ppmsave", ap, in, filename );
	va_end( ap );

	return( result );
}
