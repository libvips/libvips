/* load FLIF with libflif
 *
 * 4/10/16
 * 	- from gifload.c
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/buf.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef HAVE_LIBFLIF

#include <flif.h>

typedef struct _VipsForeignLoadFlif {
	VipsForeignLoad parent_object;

	/* Load this page (frame number).
	 */
	int page;

	/* Do CRC checks.
	 */
	int crc_check;

	/* Decode quality.
	 */
	int Q;

	/* ^2 shrink on load factor.
	 */
	int shrink;

	/* Resize to this during load.
	 */
	int resize_width;
	int resize_height;

	/* Fit to this rectangle during load.
	 */
	int fit_width;
	int fit_height;

	FLIF_DECODER *decoder;
	FLIF_INFO *info;

	/* Non-NULL for file load.
	 */
	char *filename;

} VipsForeignLoadFlif;

typedef VipsForeignLoadClass VipsForeignLoadFlifClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadFlif, vips_foreign_load_flif, 
	VIPS_TYPE_FOREIGN_LOAD );

static void
vips_foreign_load_flif_close( VipsForeignLoadFlif *flif )
{
	VIPS_FREEF( flif_destroy_info, flif->info ); 
	VIPS_FREEF( flif_abort_decoder, flif->decoder ); 
	VIPS_FREEF( flif_destroy_decoder, flif->decoder ); 
}

static void
vips_foreign_load_flif_dispose( GObject *gobject )
{
	VipsForeignLoadFlif *flif = (VipsForeignLoadFlif *) gobject;

	vips_foreign_load_flif_close( flif ); 

	G_OBJECT_CLASS( vips_foreign_load_flif_parent_class )->
		dispose( gobject );
}

static VipsForeignFlags
vips_foreign_load_flif_get_flags_filename( const char *filename )
{
	/* We can render any part of the image on demand, since we have the
	 * entire thing in memory.
	 */
	return( VIPS_FOREIGN_PARTIAL );
}

static VipsForeignFlags
vips_foreign_load_flif_get_flags( VipsForeignLoad *load )
{
	/* We can render any part of the image on demand, since we have the
	 * entire thing in memory.
	 */
	return( VIPS_FOREIGN_PARTIAL );
}

static gboolean
vips_foreign_load_flif_is_a_buffer( const void *buf, size_t len )
{
	const guchar *str = (const guchar *) buf;

	if( len >= 4 &&
		str[0] == 'F' && 
		str[1] == 'L' &&
		str[2] == 'I' &&
		str[3] == 'F' )
		return( 1 );

	return( 0 );
}

static gboolean
vips_foreign_load_flif_is_a( const char *filename )
{
	unsigned char buf[4];

	if( vips__get_bytes( filename, buf, 4 ) &&
		vips_foreign_load_flif_is_a_buffer( buf, 4 ) )
		return( 1 );

	return( 0 );
}

static int
vips_foreign_load_flif_to_memory16( FLIF_IMAGE *image, VipsImage *out )
{
	int y; 

	vips_image_init_fields( out, 
		flif_image_get_width( image ), 
		flif_image_get_height( image ),
		4, VIPS_FORMAT_USHORT,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_RGB16, 1.0, 1.0 );

	/* We will have the whole FLIF frame in memory, so we can render any 
	 * area.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_ANY, NULL );

	/* Turn @out into a memory image which we then render the FLIF frames
	 * into.
	 */
	if( vips_image_write_prepare( out ) )
		return( -1 );

	for( y = 0; y < out->Ysize; y++ ) 
		flif_image_read_row_RGBA16( image, y, 
			VIPS_IMAGE_ADDR( out, 0, y ), 
			VIPS_IMAGE_SIZEOF_LINE( out ) );

	return( 0 );
}

static int
vips_foreign_load_flif_to_memory8( FLIF_IMAGE *image, VipsImage *out )
{
	int y; 

	vips_image_init_fields( out, 
		flif_image_get_width( image ), 
		flif_image_get_height( image ),
		4, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 1.0, 1.0 );

	/* We will have the whole FLIF frame in memory, so we can render any 
	 * area.
	 */
        vips_image_pipelinev( out, VIPS_DEMAND_STYLE_ANY, NULL );

	/* Turn @out into a memory image which we then render the FLIF frames
	 * into.
	 */
	if( vips_image_write_prepare( out ) )
		return( -1 );

	for( y = 0; y < out->Ysize; y++ ) 
		flif_image_read_row_RGBA8( image, y, 
			VIPS_IMAGE_ADDR( out, 0, y ), 
			VIPS_IMAGE_SIZEOF_LINE( out ) );

	return( 0 );
}

static int
vips_foreign_load_flif_load( VipsForeignLoad *load )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( load );
	VipsObject *object = VIPS_OBJECT( load );
	VipsForeignLoadFlif *flif = (VipsForeignLoadFlif *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( load ), 4 );

	VipsImage *im;
	FLIF_IMAGE *image;

	flif->decoder = flif_create_decoder();
	flif_decoder_set_crc_check( flif->decoder, flif->crc_check ); 
	flif_decoder_set_quality( flif->decoder, flif->Q ); 
	flif_decoder_set_scale( flif->decoder, flif->shrink ); 

	if( vips_object_argument_isset( object, "resize_width" ) ||
		vips_object_argument_isset( object, "resize_height" ) ) 
		flif_decoder_set_resize( flif->decoder, 
			flif->resize_width, flif->resize_height ); 
	if( vips_object_argument_isset( object, "fit_width" ) ||
		vips_object_argument_isset( object, "fit_height" ) ) 
		flif_decoder_set_resize( flif->decoder, 
			flif->fit_width, flif->fit_height ); 

	if( flif->filename &&
		!flif_decoder_decode_file( flif->decoder, flif->filename ) ) {
		vips_error( class->nickname, "unable to decode file" );
		return( -1 );
	}

	VIPS_DEBUG_MSG( "flif_decoder_num_images() = %zd\n", 
		flif_decoder_num_images( flif->decoder ) ); 

	if( !(image = flif_decoder_get_image( flif->decoder, flif->page )) ) {
		vips_error( class->nickname, 
			"unable to get image %d", flif->page );
		return( -1 );
	}

	VIPS_DEBUG_MSG( "flif_image_get_nb_channels() = %d\n", 
		flif_image_get_nb_channels( image ) ); 
	VIPS_DEBUG_MSG( "flif_image_get_depth() = %d\n", 
		flif_image_get_depth( image ) ); 

	/* Render to a memory image.
	 */
	im = t[0] = vips_image_new_memory();

	switch( flif_image_get_depth( image ) ) {
	case 8:
		if( vips_foreign_load_flif_to_memory8( image, im ) )
			return( -1 );
		break;

	case 16:
		if( vips_foreign_load_flif_to_memory16( image, im ) )
			return( -1 );
		break;

	default:
		vips_error( class->nickname, 
			"unsupported depth %d", flif_image_get_depth( image ) );
		return( -1 );
	}

	/* We've rendered to a memory image ... we can shut down the FLIF
	 * reader now.
	 */
	vips_foreign_load_flif_close( flif ); 

	/* We always load as RGBA. Cut down the number of channels.
	 */
	switch( flif_image_get_nb_channels( image ) ) {
	case 4:
		break;

	case 3:
		if( vips_extract_band( im, &t[1], 0, "n", 3, NULL ) )
			return( -1 );
		im = t[1];
		break;

	case 1:
		if( vips_extract_band( im, &t[1], 1, "n", 1, NULL ) )
			return( -1 );
		im = t[1];
		break;

	default:
		vips_error( class->nickname, 
			"unsupported number of channels %d", 
			flif_image_get_nb_channels( image ) ); 
		return( -1 ); 
	}

	if( vips_image_write( im, load->out ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_flif_class_init( VipsForeignLoadFlifClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_flif_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "flifload";
	object_class->description = _( "load FLIF with fliflib" );

	load_class->get_flags_filename = 
		vips_foreign_load_flif_get_flags_filename;
	load_class->get_flags = vips_foreign_load_flif_get_flags;

	VIPS_ARG_INT( class, "page", 10,
		_( "Page" ),
		_( "Load this page from the file" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadFlif, page ),
		0, 100000, 0 );

	VIPS_ARG_BOOL( class, "crc_check", 11,
		_( "CRC check" ),
		_( "Perform a CRC check during load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadFlif, crc_check ),
		FALSE );

	VIPS_ARG_INT( class, "Q", 12,
		_( "Q" ),
		_( "Load at this quality steting" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadFlif, Q ),
		0, 100, 100 );

	VIPS_ARG_INT( class, "shrink", 13, 
		_( "Shrink" ), 
		_( "Shrink factor on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadFlif, shrink ),
		1, 128, 1 );

	VIPS_ARG_INT( class, "resize-width", 14, 
		_( "Rezize width" ), 
		_( "Resize to this max width on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadFlif, resize_width ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "resize-height", 15, 
		_( "Rezize height" ), 
		_( "Resize to this max height on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadFlif, resize_height ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "fit-width", 16, 
		_( "Fit width" ), 
		_( "Fit to this max width on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadFlif, fit_width ),
		1, VIPS_MAX_COORD, 1 );

	VIPS_ARG_INT( class, "fit-height", 17, 
		_( "Fit height" ), 
		_( "Fit to this max height on load" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsForeignLoadFlif, fit_height ),
		1, VIPS_MAX_COORD, 1 );
}

static void
vips_foreign_load_flif_init( VipsForeignLoadFlif *flif )
{
	flif->page = 0;
	flif->crc_check = 0;
	flif->Q = 100;
	flif->shrink = 1;
	flif->resize_width = 0;
	flif->resize_height = 0;
	flif->fit_width = 0;
	flif->fit_height = 0;
}

typedef struct _VipsForeignLoadFlifFile {
	VipsForeignLoadFlif parent_object;

	/* Filename for load.
	 */
	char *filename; 

} VipsForeignLoadFlifFile;

typedef VipsForeignLoadFlifClass VipsForeignLoadFlifFileClass;

G_DEFINE_TYPE( VipsForeignLoadFlifFile, vips_foreign_load_flif_file, 
	vips_foreign_load_flif_get_type() );

static int
vips_foreign_load_flif_file_header( VipsForeignLoad *load )
{
	VipsForeignLoadFlif *flif = (VipsForeignLoadFlif *) load;
	VipsForeignLoadFlifFile *file = (VipsForeignLoadFlifFile *) load;

	flif->filename = file->filename;
	VIPS_SETSTR( load->out->filename, file->filename );

	return( vips_foreign_load_flif_load( load ) );
}

static const char *vips_foreign_flif_suffs[] = {
	".flif",
	NULL
};

static void
vips_foreign_load_flif_file_class_init( 
	VipsForeignLoadFlifFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "flifload";
	object_class->description = _( "load FLIF with fliflib" );

	foreign_class->suffs = vips_foreign_flif_suffs;

	load_class->is_a = vips_foreign_load_flif_is_a;
	load_class->header = vips_foreign_load_flif_file_header;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadFlifFile, filename ),
		NULL );

}

static void
vips_foreign_load_flif_file_init( VipsForeignLoadFlifFile *file )
{
}

#endif /*HAVE_FLIFLIB*/

/**
 * vips_flifload:
 * @filename: file to load
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @page: %gint, page (frame) to read
 * * @crc_check: %gboolean, if %TRUE, do a CRC check during load
 * * @Q: %gint, load quality setting, 1-100
 * * @shrink: %gint, shrink by this much during load, 1, 2, 4, 8 ..
 * * @resize_width: %gint, resize to fit within this width
 * * @resize_height: %gint, resize to fit within this height
 * * @fit_width: %gint, resize to fit this width
 * * @fit_height: %gint, resize to fit this height
 *
 * Read a FLIF file into a VIPS image. Rendering uses the libflif library.
 *
 * Use @page to set page number (frame number) to read.
 *
 * The whole FLIF is loaded into memory on header access. The output image
 * will be 1, 3 or 4 bands depending on what the reader finds in the file, and
 * can be 8 or 16-bit.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_flifload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "flifload", ap, filename, out );
	va_end( ap );

	return( result );
}
