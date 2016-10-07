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

	/* 0 - 100 "effort" rating ... if set, sets many other options.
	 */
	int effort;

	/* 0 = -N, 1 = -I (default: -I)
	 */
	int interlaced;

	/* default: 2 (-R)
	 */
	int learn_repeat;

	/* 0 = -B, 1 = default
	 */
	int auto_color_buckets;

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
	int split_threshold;

	/* 0 = default, 1 = -K
	 */
	gboolean alpha_zero_lossless;

	/* default: 2  (-X)
	 */
	int chance_cutoff;

	/* default: 19 (-Z)
	 */
	int chance_alpha;

	/* 0 = no CRC, 1 = add CRC
	 */
	int crc_check;

	/* 0 = -C, 1 = default
	 */
	int channel_compact;

	/* 0 = -Y, 1 = default
	 */
	int ycocg;

	/* 0 = -S, 1 = default
	 */
	int frame_shape;

	/* default 0 (lossless)
	 */
	int lossy; 

	FLIF_ENCODER *encoder;
	FLIF_IMAGE *image;

} VipsForeignSaveFlif;

typedef VipsForeignSaveClass VipsForeignSaveFlifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignSaveFlif, vips_foreign_save_flif, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_flif_close( VipsForeignSaveFlif *flif ) 
{
	VIPS_FREEF( flif_destroy_image, flif->image ); 
	VIPS_FREEF( flif_destroy_encoder, flif->encoder ); 
}

static void
vips_foreign_save_flif_dispose( GObject *gobject )
{
	VipsForeignSaveFlif *flif = (VipsForeignSaveFlif *) gobject;

	vips_foreign_save_flif_close( flif ); 

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

	save_class->saveable = VIPS_SAVEABLE_RGBA_STRICT;
	save_class->format_table = vips_foreign_flif_bandfmt;

	VIPS_ARG_INT( class, "effort", 100,
		_( "Effort" ),
		_( "Effort" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, effort ),
		0, 100, 60 );

	VIPS_ARG_INT( class, "lossy", 101,
		_( "Lossy" ),
		_( "Lossy" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, lossy ),
		-100, 100, 0 );

	VIPS_ARG_INT( class, "interlaced", 102,
		_( "Interlaced" ),
		_( "Interlaced" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, interlaced ),
		0, 1, 1 );

	VIPS_ARG_INT( class, "learn_repeat", 103,
		_( "Learn repeat" ),
		_( "Learn repeat" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, learn_repeat ),
		0, 4, 2 );

	VIPS_ARG_INT( class, "auto_color_buckets", 104,
		_( "Auto color buckets" ),
		_( "Auto color buckets" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, auto_color_buckets ),
		0, 3, 1 );

	VIPS_ARG_INT( class, "palette_size", 105,
		_( "Palette size" ),
		_( "Palette size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, palette_size ),
		1, 10000, 512 );

	VIPS_ARG_INT( class, "lookback", 106,
		_( "Lookback" ),
		_( "Lookback" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, lookback ),
		1, 100, 1 );

	VIPS_ARG_INT( class, "divisor", 107,
		_( "Divisor" ),
		_( "Divisor" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, divisor ),
		1, 100, 30 );

	VIPS_ARG_INT( class, "min_size", 108,
		_( "Min size" ),
		_( "Min size" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, min_size ),
		1, 100, 50 );

	VIPS_ARG_INT( class, "split_threshold", 109,
		_( "Split threshold" ),
		_( "Split threshold" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, split_threshold ),
		1, 100000, 64 );

	VIPS_ARG_BOOL( class, "alpha_zero_lossless", 13,
		_( "Alpha zero lossless" ),
		_( "Alpha zero lossless" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, alpha_zero_lossless ),
		FALSE );

	VIPS_ARG_INT( class, "chance_cutoff", 110,
		_( "Chance cutoff" ),
		_( "Chance cutoff" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, chance_cutoff ),
		1, 100, 2 );

	VIPS_ARG_INT( class, "chance_alpha", 111,
		_( "Chance alpha" ),
		_( "Chance alpha" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, chance_alpha ),
		1, 100, 19 );

	VIPS_ARG_INT( class, "crc_check", 112,
		_( "CRC check" ),
		_( "CRC check" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, crc_check ),
		0, 1, 0 );

	VIPS_ARG_INT( class, "channel_compact", 113,
		_( "Channel compact" ),
		_( "Channel compact" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, channel_compact ),
		0, 1, 1 );

	VIPS_ARG_INT( class, "ycocg", 114,
		_( "YCOCG" ),
		_( "YCOCG" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, ycocg ),
		0, 1, 1 );

	VIPS_ARG_INT( class, "frame_shape", 115,
		_( "Frame shape" ),
		_( "Frame shape" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignSaveFlif, frame_shape ),
		0, 1, 1 );

}

static void
vips_foreign_save_flif_init( VipsForeignSaveFlif *flif )
{
	flif->effort = 60;
	flif->interlaced = 1;
	flif->learn_repeat = 2;
	flif->auto_color_buckets = 1;
	flif->palette_size = 512;
	flif->lookback = 1;
	flif->divisor = 30;
	flif->min_size = 50;
	flif->split_threshold = 64;
	flif->alpha_zero_lossless = FALSE;
	flif->chance_cutoff = 2;
	flif->chance_alpha = 19;
	flif->crc_check = 0;
	flif->channel_compact = 1;
	flif->ycocg = 1;
	flif->frame_shape = 1;
	flif->lossy = 0; 
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

typedef void (*WriterFn)( FLIF_IMAGE *image, 
	uint32_t row, const void *buffer, size_t buffer_size_bytes );

static int
vips_foreign_save_flif_file_write( VipsRegion *region, VipsRect *area, void *a )
{
	VipsForeignSaveFlif *flif = (VipsForeignSaveFlif *) a;

	int y;
	WriterFn write_fn = region->im->BandFmt == VIPS_FORMAT_UCHAR ? 
		flif_image_write_row_RGBA8 : 
		flif_image_write_row_RGBA16;

	for( y = 0; y < area->height; y++ ) 
		write_fn( flif->image, area->top + y,
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

	if( !(flif->encoder = flif_create_encoder()) ) {
		vips_error( class->nickname, "unable to create encoder" );
		return( -1 );
	}

	/* "effort" is a meta option that sets a lot of others.
	 */
	if( vips_object_argument_isset( object, "effort" ) ) {
		if( flif->effort < 10 ) 
			flif->learn_repeat = 0;
		else if( flif->effort <= 50 ) {
			flif->learn_repeat = 1; 
			flif->split_threshold = 5461 * 8 * 5;
		}
		else if( flif->effort <= 70 ) {
			flif->learn_repeat = 2;
			flif->split_threshold = 5461 * 8 * 8;
		}
		else if( flif->effort <= 90 ) {
			flif->learn_repeat = 3; 
			flif->split_threshold = 5461 * 8 * 10;
		}
		else if( flif->effort <= 100 ) {
			flif->learn_repeat = 4; 
			flif->split_threshold = 5461 * 8 * 12;
		}

		if( flif->effort < 5 ) 
			flif->auto_color_buckets = 0;
		if( flif->effort < 8 ) 
			flif->palette_size = 0;
		if( flif->effort < 25 ) 
			flif->channel_compact = 0;
		if( flif->effort < 30 ) 
			flif->lookback = 0;
		if( flif->effort < 5 ) 
			flif->frame_shape = 0;
	}

	flif_encoder_set_interlaced( flif->encoder, flif->interlaced );
	flif_encoder_set_learn_repeat( flif->encoder, flif->learn_repeat );
	flif_encoder_set_auto_color_buckets( flif->encoder, 
		flif->auto_color_buckets );
	flif_encoder_set_palette_size( flif->encoder, flif->palette_size );
	flif_encoder_set_lookback( flif->encoder, flif->lookback );
	flif_encoder_set_divisor( flif->encoder, flif->divisor );
	flif_encoder_set_min_size( flif->encoder, flif->min_size );
	flif_encoder_set_split_threshold( flif->encoder, flif->split_threshold );
	if( flif->alpha_zero_lossless )
		flif_encoder_set_alpha_zero_lossless( flif->encoder );  
	flif_encoder_set_chance_cutoff( flif->encoder, flif->chance_cutoff );
	flif_encoder_set_chance_alpha( flif->encoder, flif->chance_alpha );
	flif_encoder_set_crc_check( flif->encoder, flif->crc_check );
	flif_encoder_set_channel_compact( flif->encoder, flif->channel_compact );
	flif_encoder_set_ycocg( flif->encoder, flif->ycocg );
	flif_encoder_set_frame_shape( flif->encoder, flif->frame_shape );
	flif_encoder_set_lossy( flif->encoder, flif->lossy );

	if( !(flif->image = flif_create_image( 
		save->ready->Xsize, save->ready->Ysize )) ) {
		vips_error( class->nickname, "unable to create image buffer" );
		return( -1 );
	}

	/*
	printf( "Xsize = %d\n", save->ready->Xsize );
	printf( "Ysize = %d\n", save->ready->Ysize );
	printf( "Bands = %d\n", save->ready->Bands );
	 */

	if( vips_sink_disc( save->ready, 
		vips_foreign_save_flif_file_write, flif ) ) 
		return( -1 );

	/* You must fill the image with data before attaching it.
	 */
	flif_encoder_add_image( flif->encoder, flif->image );

	if( !flif_encoder_encode_file( flif->encoder, file->filename ) ) {
		vips_error( class->nickname, "unable to encode file" );
		return( -1 );
	}

	/* Shut down the encoder as soon as we can to save mem.
	 */
	vips_foreign_save_flif_close( flif ); 

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
 * * @effort: %gint
 * * @interlaced: %gint
 * * @learn_repeat: %gint
 * * @auto_color_buckets: %gint
 * * @palette_size: %gint
 * * @lookback: %gint
 * * @divisor: %gint
 * * @min_size: %gint
 * * @split_threshold: %gint
 * * @alpha_zero_lossless: %gboolean
 * * @chance_cutoff: %gint
 * * @chance_alpha: %gint
 * * @crc_check: %gint
 * * @channel_compact: %gint
 * * @ycocg: %gint
 * * @frame_shape: %gint
 * * @lossy: %gint
 *
 * Write an image to a file in FLIF format. 
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
