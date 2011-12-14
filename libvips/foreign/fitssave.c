/* save to fits
 *
 * 2/12/11
 * 	- wrap a class around the fits writer
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

#include "fits.h"

typedef struct _VipsForeignSaveFits {
	VipsForeignSave parent_object;

	/* Filename for save.
	 */
	char *filename; 

} VipsForeignSaveFits;

typedef VipsForeignSaveClass VipsForeignSaveFitsClass;

G_DEFINE_TYPE( VipsForeignSaveFits, vips_foreign_save_fits, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_fits_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveFits *fits = (VipsForeignSaveFits *) object;
	VipsImage *t;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_fits_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_flip( save->ready, &t, VIPS_DIRECTION_VERTICAL, NULL ) )
		return( -1 );
	if( vips__fits_write( t, fits->filename ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

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

static int bandfmt_fits[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, US, UI, UI, F,  X,  D,  DX
};

static void
vips_foreign_save_fits_class_init( VipsForeignSaveFitsClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "fitssave";
	object_class->description = _( "save image to fits file" );
	object_class->build = vips_foreign_save_fits_build;

	foreign_class->suffs = vips__fits_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_fits;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveFits, filename ),
		NULL );
}

static void
vips_foreign_save_fits_init( VipsForeignSaveFits *fits )
{
}
