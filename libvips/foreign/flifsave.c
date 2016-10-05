/* save to FLIF
 *
 * 4/10/16
 * 	- from flifsave.c
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

#include <stdlib.h>

#include <vips/vips.h>

#ifdef HAVE_LIBFLIF

#include "flif.h"

typedef struct _VipsForeignSaveFlif {
	VipsForeignSave parent_object;

	/* 0 = -N, 1 = -I (default: -I)
	 */
	int interlaced;

	/* default: 2 (-R)
	 */
	int learn_repeats;

	/* 0 = -B, 1 = default
	 */
	int acb;

	/* default: 512
	 */
	int palette_size;

	/* default: 1 (-L)
	 */
	int lookback;

	/* default: 30 (-D)
	 */
	int divisor;

	/* default: 50 (-M)
	 */
	int min_size;

	/* default: 64 (-T)
	 */
	int threshold;

	/* 0 = default, 1 = -K
	 */
	int alpha_zero_lossless;

	/* default: 19 (-Z)
	 */
	int alpha;

	/* 0 = no CRC, 1 = add CRC
	 */
	int crc_check;

	/* 0 = -C, 1 = default
	 */
	int plc;

	/* 0 = -Y, 1 = default
	 */
	int ycocg;

	/* 0 = -S, 1 = default
	 */
	int frs;

	FLIF_ENCODER *encoder;
	FLIF_IMAGE *image;

} VipsForeignSaveFlif;

typedef VipsForeignSaveClass VipsForeignSaveFlifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveFlif, vips_foreign_save_flif, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_flif_dispose( GObject *gobject )
{
	VipsForeignSaveFlif *flif = (VipsForeignSaveFlif *) gobject;

	VIPS_FREEF( flif_destroy_encoder, flif->encoder ); 

	G_OBJECT_CLASS( vips_foreign_save_flif_parent_class )->
		dispose( gobject );
}

#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT

static int vips_foreign_flif_bandfmt[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, UC, US, US, US, US, US, US, US, US
};

static const char *vips_foreign_flif_suffs[] = {
	".flif",
	NULL
};

static void
vips_foreign_save_flif_class_init( VipsForeignSaveFlifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_flif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "flifsave_base";
	object_class->description = _( "save flif" );

	foreign_class->suffs = vips_foreign_flif_suffs;

	save_class->saveable = VIPS_SAVEABLE_RGBA_ONLY;
	save_class->format_table = vips_foreign_flif_bandfmt;

}

static void
vips_foreign_save_flif_init( VipsForeignSaveFlif *flif )
{
}

typedef struct _VipsForeignSaveFlifFile {
	VipsForeignSaveFlif parent_object;

	/* Filename for save.
	 */
	char *filename; 

} VipsForeignSaveFlifFile;

typedef VipsForeignSaveFlifClass VipsForeignSaveFlifFileClass;

G_DEFINE_TYPE( VipsForeignSaveFlifFile, vips_foreign_save_flif_file, 
	vips_foreign_save_flif_get_type() );

static int
vips_foreign_save_flif_file_write( VipsRegion *region, VipsRect *area, void *a )
{
	VipsForeignSaveFlif *flif = (VipsForeignSaveFlif *) a;

	int y;

	for( y = 0; y < area->height; y++ ) 
		flif_image_write_row_RGBA8( flif->image, area->top + y,
			VIPS_REGION_ADDR( region, 0, area->top + y ),
			VIPS_IMAGE_SIZEOF_LINE( region->im ) ); 

	return( 0 );
}

static int
vips_foreign_save_flif_file_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveFlif *flif = (VipsForeignSaveFlif *) object;
	VipsForeignSaveFlifFile *file = (VipsForeignSaveFlifFile *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_flif_file_parent_class )->
		build( object ) )
		return( -1 );

	if( !(flif->image = flif_create_image( 
		save->ready->Xsize, save->ready->Ysize )) ) {
		vips_error( class->nickname, "unable to create image buffer" );
		return( -1 );
	}

	printf( "Xsize = %d\n", save->ready->Xsize );
	printf( "Ysize = %d\n", save->ready->Ysize );

	if( vips_sink_disc( save->ready, 
		vips_foreign_save_flif_file_write, flif ) ) {
		flif_destroy_image( flif->image );
		return( -1 );
	}

	if( !(flif->encoder = flif_create_encoder()) ) {
		flif_destroy_image( flif->image );
		vips_error( class->nickname, "unable to create encoder" );
		return( -1 );
	}

	flif_encoder_set_interlaced( flif->encoder, 1 );
	flif_encoder_set_learn_repeat( flif->encoder, 3 );
	flif_encoder_set_auto_color_buckets( flif->encoder, 1 );
	flif_encoder_set_palette_size( flif->encoder, 512 );
	flif_encoder_set_lookback( flif->encoder, 1 );

	flif_encoder_add_image( flif->encoder, flif->image );

	if( !flif_encoder_encode_file( flif->encoder, file->filename ) ) {
		vips_error( class->nickname, "unable to encode file" );
		return( -1 );
	}

	flif_destroy_encoder( flif->encoder );
	flif->encoder = NULL;

	printf( "success\n" ); 

	return( 0 );
}

static void
vips_foreign_save_flif_file_class_init( VipsForeignSaveFlifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "flifsave";
	object_class->description = _( "save image to flif file" );
	object_class->build = vips_foreign_save_flif_file_build;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveFlifFile, filename ),
		NULL );
}

static void
vips_foreign_save_flif_file_init( VipsForeignSaveFlifFile *file )
{
}

#endif /*HAVE_LIBFLIF*/

/**
 * vips_flifsave:
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @Q: %gint quality factor
 * * @lossless: %gboolean enables lossless compression
 * * @preset: #VipsForeignFlifPreset choose lossy compression preset
 * * @smart_subsample: %gboolean enables high quality chroma subsampling
 * * @near_lossless: %gboolean preprocess in lossless mode (controlled by Q)
 * * @alpha_q: %gint set alpha quality in lossless mode
 *
 * Write an image to a file in WebP format. 
 *
 * By default, images are saved in lossy format, with 
 * @Q giving the WebP quality factor. It has the range 0 - 100, with the
 * default 75.
 *
 * Use @preset to hint the image type to the lossy compressor. The default is
 * #VIPS_FOREIGN_FLIF_PRESET_DEFAULT. 
 * Set @smart_subsample to enable high quality chroma subsampling.
 * Use @alpha_q to set the quality for the alpha channel in lossy mode. It has
 * the range 1 - 100, with the default 100.
 *
 * Set @lossless to use lossless compression, or combine @near_lossless
 * with @Q 80, 60, 40 or 20 to apply increasing amounts of preprocessing
 * which improves the near-lossless compression ratio by up to 50%.
 *
 * See also: vips_flifload(), vips_image_write_to_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_flifsave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "flifsave", ap, in, filename );
	va_end( ap );

	return( result );
}
