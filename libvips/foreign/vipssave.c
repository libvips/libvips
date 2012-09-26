/* save to vips
 *
 * 24/11/11
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

typedef struct _VipsForeignSaveVips {
	VipsForeignSave parent_object;

	char *filename;

} VipsForeignSaveVips;

typedef VipsForeignSaveClass VipsForeignSaveVipsClass;

G_DEFINE_TYPE( VipsForeignSaveVips, vips_foreign_save_vips, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_vips_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveVips *vips = (VipsForeignSaveVips *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_vips_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_image_write_to_file( save->ready, vips->filename ) )
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

static int vips_bandfmt_vips[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   UC, C,  US, S,  UI, I, F, X, D, DX
};

static const char *vips_suffs[] = { ".v", NULL };

static void
vips_foreign_save_vips_class_init( VipsForeignSaveVipsClass *class )
{
	int i;

	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "vipssave";
	object_class->description = _( "save image to vips file" );
	object_class->build = vips_foreign_save_vips_build;

	foreign_class->suffs = vips_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = vips_bandfmt_vips;
	for( i = 0; i < VIPS_CODING_LAST; i++ )
		save_class->coding[i] = TRUE;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveVips, filename ),
		NULL );
}

static void
vips_foreign_save_vips_init( VipsForeignSaveVips *vips )
{
}

