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

typedef VipsFileSave VipsFileSaveVips;
typedef VipsFileSaveClass VipsFileSaveVipsClass;

G_DEFINE_TYPE( VipsFileSaveVips, vips_file_save_vips, VIPS_TYPE_FILE_SAVE );

static int
vips_file_save_vips_build( VipsObject *object )
{
	VipsFile *file = (VipsFile *) object;
	VipsFileSave *save = (VipsFileSave *) object;

	if( VIPS_OBJECT_CLASS( vips_file_save_vips_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_image_write_to_file( save->in, file->filename ) )
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
static int vips_bandfmt_vips[10] = {
/* UC  C   US  S   UI  I  F  X  D  DX */
   UC, C,  US, S,  UI, I, F, X, D, DX
};

static const char *vips_suffs[] = { ".v", NULL };

static void
vips_file_save_vips_class_init( VipsFileSaveVipsClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFileClass *file_class = (VipsFileClass *) class;
	VipsFileSaveClass *save_class = (VipsFileSaveClass *) class;

	object_class->nickname = "vipssave";
	object_class->description = _( "save image to vips file" );
	object_class->build = vips_file_save_vips_build;

	file_class->suffs = vips_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = vips_bandfmt_vips;

}

static void
vips_file_save_vips_init( VipsFileSaveVips *vips )
{
}

