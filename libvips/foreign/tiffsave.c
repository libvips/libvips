/* save to tiff
 *
 * 2/12/11
 * 	- wrap a class around the tiff writer
 * 17/3/12
 * 	- argh xres/yres macro was wrong
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

#ifdef HAVE_TIFF

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "tiff.h"

typedef struct _VipsForeignSaveTiff {
	VipsForeignSave parent_object;

	/* Filename for save.
	 */
	char *filename; 

	/* Many options argh.
	 */
	VipsForeignTiffCompression compression;
	int Q;
	VipsForeignTiffPredictor predictor;
	char *profile; 
	gboolean tile;
	int tile_width;
	int tile_height;
	gboolean pyramid;
	gboolean squash;
	VipsForeignTiffResunit resunit;
	double xres;
	double yres;
	gboolean bigtiff;
} VipsForeignSaveTiff;

typedef VipsForeignSaveClass VipsForeignSaveTiffClass;

G_DEFINE_TYPE( VipsForeignSaveTiff, vips_foreign_save_tiff, 
	VIPS_TYPE_FOREIGN_SAVE );

static int
vips_foreign_save_tiff_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveTiff *tiff = (VipsForeignSaveTiff *) object;

	char *p;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_tiff_parent_class )->
		build( object ) )
		return( -1 );

	/* Default xres/yres to the values from the image.
	 */
	if( !vips_object_argument_isset( object, "xres" ) )
		tiff->xres = save->ready->Xres * 10.0;
	if( !vips_object_argument_isset( object, "yres" ) )
		tiff->yres = save->ready->Yres * 10.0;

	/* resunit param overrides resunit metadata.
	 */
	if( !vips_object_argument_isset( object, "resunit" ) &&
		vips_image_get_typeof( save->ready, 
			VIPS_META_RESOLUTION_UNIT ) &&
		!vips_image_get_string( save->ready, 
			VIPS_META_RESOLUTION_UNIT, &p ) &&
		vips_isprefix( "in", p ) ) 
		tiff->resunit = VIPS_FOREIGN_TIFF_RESUNIT_INCH;

	if( tiff->resunit == VIPS_FOREIGN_TIFF_RESUNIT_INCH ) {
		tiff->xres *= 2.54;
		tiff->yres *= 2.54;
	}

	if( vips__tiff_write( save->ready, tiff->filename,
		tiff->compression, tiff->Q, tiff->predictor,
		tiff->profile,
		tiff->tile, tiff->tile_width, tiff->tile_height,
		tiff->pyramid,
		tiff->squash,
		tiff->resunit, tiff->xres, tiff->yres,
		tiff->bigtiff ) )
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

static int bandfmt_tiff[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, S,  US, US, F,  F,  F,  F
};

static void
vips_foreign_save_tiff_class_init( VipsForeignSaveTiffClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "tiffsave";
	object_class->description = _( "save image to tiff file" );
	object_class->build = vips_foreign_save_tiff_build;

	foreign_class->suffs = vips__foreign_tiff_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = bandfmt_tiff;
	save_class->coding[VIPS_CODING_LABQ] = TRUE;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveTiff, filename ),
		NULL );

	VIPS_ARG_ENUM( class, "compression", 6, 
		_( "Compression" ), 
		_( "Compression for this file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, compression ),
		VIPS_TYPE_FOREIGN_TIFF_COMPRESSION, 
			VIPS_FOREIGN_TIFF_COMPRESSION_NONE ); 

	VIPS_ARG_INT( class, "Q", 7, 
		_( "Q" ), 
		_( "Q factor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, Q ),
		1, 100, 75 );

	VIPS_ARG_ENUM( class, "predictor", 8, 
		_( "predictor" ), 
		_( "Compression prediction" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, predictor ),
		VIPS_TYPE_FOREIGN_TIFF_PREDICTOR, 
			VIPS_FOREIGN_TIFF_PREDICTOR_NONE ); 

	VIPS_ARG_STRING( class, "profile", 9, 
		_( "profile" ), 
		_( "ICC profile to embed" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, profile ),
		NULL );

	VIPS_ARG_BOOL( class, "tile", 10, 
		_( "Tile" ), 
		_( "Write a tiled tiff" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, tile ),
		FALSE );

	VIPS_ARG_INT( class, "tile_width", 11, 
		_( "Tile width" ), 
		_( "Tile width in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, tile_width ),
		1, 1024, 128 );

	VIPS_ARG_INT( class, "tile_height", 12, 
		_( "Tile height" ), 
		_( "Tile height in pixels" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, tile_height ),
		1, 1024, 128 );

	VIPS_ARG_BOOL( class, "pyramid", 13, 
		_( "Pyramid" ), 
		_( "Write a pyramidal tiff" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, pyramid ),
		FALSE );

	VIPS_ARG_BOOL( class, "squash", 14, 
		_( "Squash" ), 
		_( "Squash images down to 1 bit" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, squash ),
		FALSE );

	VIPS_ARG_ENUM( class, "resunit", 15, 
		_( "Resolution unit" ), 
		_( "Resolution unit" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, resunit ),
		VIPS_TYPE_FOREIGN_TIFF_RESUNIT, 
			VIPS_FOREIGN_TIFF_RESUNIT_CM ); 

	VIPS_ARG_DOUBLE( class, "xres", 16, 
		_( "Xres" ), 
		_( "Horizontal resolution in pixels/mm" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, xres ),
		-0.0, 1000000, 0 );

	VIPS_ARG_DOUBLE( class, "yres", 17, 
		_( "Yres" ), 
		_( "Vertical resolution in pixels/mm" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, yres ),
		-0.0, 1000000, 0 );

	VIPS_ARG_BOOL( class, "bigtiff", 18, 
		_( "Bigtiff" ), 
		_( "Write a bigtiff image" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveTiff, bigtiff ),
		FALSE );
}

static void
vips_foreign_save_tiff_init( VipsForeignSaveTiff *tiff )
{
	tiff->compression = VIPS_FOREIGN_TIFF_COMPRESSION_NONE;
	tiff->Q = 75;
	tiff->predictor = VIPS_FOREIGN_TIFF_PREDICTOR_NONE;
	tiff->tile_width = 128;
	tiff->tile_height = 128;
	tiff->resunit = VIPS_FOREIGN_TIFF_RESUNIT_CM;
	tiff->xres = 1.0;
	tiff->yres = 1.0;
}

#endif /*HAVE_TIFF*/
