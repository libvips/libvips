/* load qoi
 *
 * 25/4/22
 * 	- from qoiload.c
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pforeign.h"
#include "qoi/qoi.h"

typedef struct _VipsForeignLoadQoi {
	VipsForeignLoad parent_object;

	VipsSource *source;

	/* Properties of this qoi, from the header.
	 */
	int width;
	int height;
	int bands;

	int scale;

	gboolean have_read_header;


} VipsForeignLoadQoi;

static const char *qoi_magic = "qoif";

typedef VipsForeignLoadClass VipsForeignLoadQoiClass;

G_DEFINE_ABSTRACT_TYPE( VipsForeignLoadQoi, vips_foreign_load_qoi, 
	VIPS_TYPE_FOREIGN_LOAD );

static gboolean
vips_foreign_load_qoi_is_a_source(VipsSource *source)
{
    const unsigned char *data;

    if ((data = vips_source_sniff(source, 4))) {
        if (memcmp(data, qoi_magic, 4) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static void
vips_foreign_load_qoi_dispose( GObject *gobject )
{
	VipsForeignLoadQoi *qoi = (VipsForeignLoadQoi *) gobject;

#ifdef DEBUG
	printf( "vips_foreign_load_qoi_dispose: %p\n", qoi );
#endif /*DEBUG*/

	VIPS_UNREF( qoi->source );

	G_OBJECT_CLASS( vips_foreign_load_qoi_parent_class )->
		dispose( gobject );
}

/* Scan the header into our class.
 */
static int
vips_foreign_load_qoi_parse_header( VipsForeignLoadQoi *qoi )
{
	unsigned char header[14];
	
	if( vips_source_read( qoi->source, header, 14 ) != 14 ) {
		vips_error( "VipsForeignLoadQoi",
			_( "unable to read QOI header" ), NULL );
		return( -1 );
	}

printf("Read header:\n");
for (int i = 0; i < 14; i++) {
    printf("%02X ", header[i]);
}
printf("\nMagic: %.4s\n", header);
	
	
	/* Check magic bytes.
	 */
	if( memcmp( header, qoi_magic, 4 ) != 0 ) {
		vips_error( "VipsForeignLoadQoi",
			_( "bad QOI magic" ), NULL );
		return( -1 );
	}
	
	/* Read width and height (big-endian).
	 */
	qoi->width = (header[4] << 24) | (header[5] << 16) | (header[6] << 8) | header[7];
	qoi->height = (header[8] << 24) | (header[9] << 16) | (header[10] << 8) | header[11];
	
	/* Read channels.
	 */
	qoi->bands = header[12];
	
	/* Validate header values.
	 */
	if( qoi->width == 0 || qoi->height == 0 ) {
		vips_error( "VipsForeignLoadQoi",
			_( "bad QOI dimensions" ), NULL );
		return( -1 );
	}
	
	if( qoi->bands != 3 && qoi->bands != 4 ) {
		vips_error( "VipsForeignLoadQoi",
			_( "bad QOI channels" ), NULL );
		return( -1 );
	}
		qoi->have_read_header = TRUE;

	
	return( 0 );
}

static VipsForeignFlags
vips_foreign_load_qoi_get_flags( VipsForeignLoad *load )
{
	VipsForeignLoadQoi *qoi = (VipsForeignLoadQoi *) load;

	VipsForeignFlags flags;

	flags = 0;

	return( flags );
}

static int
vips_foreign_load_qoi_header( VipsForeignLoad *load )
{
	VipsForeignLoadQoi *qoi = (VipsForeignLoadQoi *) load;

	vips_source_minimise( qoi->source );

	if( vips_foreign_load_qoi_parse_header( qoi ) )
		return( -1 );

	return( 0 );
}

/* Read a qoi file using mmap().
 */
static VipsImage *
vips_foreign_load_qoi_map( VipsForeignLoadQoi *qoi )
{
	gint64 header_offset;
	size_t length;
	const void *data;
	VipsImage *out;
	qoi_desc desc;
	void *decoded_data;

#ifdef DEBUG
	printf( "vips_foreign_load_qoi_map:\n" );
#endif /*DEBUG*/

	header_offset = vips_source_seek( qoi->source, 0, SEEK_CUR );
	data = vips_source_map( qoi->source, &length );
	if( header_offset < 0 || 
		!data )
		return( NULL );
	//data = (char *) data + header_offset;
	//length -= header_offset;

	printf( "QOI Decode: length = %zu, width = %d, height = %d, channels = %d\n",
		length, qoi->width, qoi->height, qoi->bands );

	/* Decode the QOI data */
	decoded_data = qoi_decode( data, length, &desc, 0 );
	if( !decoded_data ) {
		printf( "QOI Decode Failed: length = %zu, width = %d, height = %d, channels = %d\n",
			length, qoi->width, qoi->height, qoi->bands );
		printf( "Expected length: %d\n", qoi->width * qoi->height * qoi->bands + 14 + 8 );
		printf( "Header: magic = %08X, width = %d, height = %d, channels = %d, colorspace = %d\n",
			*(unsigned int*)data, qoi->width, qoi->height, qoi->bands, ((unsigned char*)data)[13]);
		printf( "First 20 bytes: ");
		for (int i = 0; i < 20; i++) {
			printf( "%02X ", ((unsigned char*)data)[i] );
		}
		printf( "\n" );
		vips_error( "VipsForeignLoadQoi",
			_( "unable to decode QOI data" ), NULL );
		return( NULL );
	}

	if( !(out = vips_image_new_from_memory( decoded_data, desc.width * desc.height * desc.channels,
		desc.width, desc.height, desc.channels, VIPS_FORMAT_UCHAR )) )
		return( NULL );

	vips_image_init_fields(out,
		desc.width, desc.height, desc.channels, VIPS_FORMAT_UCHAR,
		VIPS_CODING_NONE, VIPS_INTERPRETATION_sRGB, 1.0, 1.0);

	/* Free the decoded data */
	free( decoded_data );

	return( out );
}

static int
vips_foreign_load_qoi_load( VipsForeignLoad *load )
{
	VipsForeignLoadQoi *qoi = (VipsForeignLoadQoi *) load;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( (VipsObject *) load, 2 );

	if( !qoi->have_read_header &&
		vips_foreign_load_qoi_parse_header( qoi ) )
		return( 0 );

	/* If the source is mappable and this is a binary file, we can map it.
	 */
	if( vips_source_is_mappable( qoi->source ) ) {
		if( !(t[0] = vips_foreign_load_qoi_map( qoi )) ) 
			return( -1 );
	}
	else {
		/* QOI is always binary, so we should not reach here for non-mappable sources.
		 * Fall back to map-based loading if possible.
		 */
		if( !(t[0] = vips_foreign_load_qoi_map( qoi )) )
			return( -1 );
	}

#ifdef DEBUG
	printf( "vips_foreign_load_qoi: byteswap = %d\n", 
		vips_amiMSBfirst() != qoi->msb_first );
#endif /*DEBUG*/

	if( vips_source_decode( qoi->source ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_load_qoi_build( VipsObject *object )
{
	VipsForeignLoadQoi *qoi = (VipsForeignLoadQoi *) object;

	/* Ensure the source is set.
	 */
	if( !qoi->source ) {
		vips_error( "VipsForeignLoadQoi",
			_( "no source set" ), NULL );
		return( -1 );
	}

	/* Chain up to the parent class.
	 */
	if( VIPS_OBJECT_CLASS( vips_foreign_load_qoi_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_qoi_class_init( VipsForeignLoadQoiClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->dispose = vips_foreign_load_qoi_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "qoiload_base";
	object_class->description = _( "load qoi base class" );
	object_class->build = vips_foreign_load_qoi_build;

	/* You're unlikely to want to use this on untrusted files.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	foreign_class->suffs = vips__qoi_suffs;

	/* We are fast at is_a(), so high priority.
	 */
	foreign_class->priority = 200;

	load_class->get_flags = vips_foreign_load_qoi_get_flags;
	load_class->header = vips_foreign_load_qoi_header;
	load_class->load = vips_foreign_load_qoi_load;

}



static void
vips_foreign_load_qoi_init( VipsForeignLoadQoi *qoi )
{
	qoi->scale = 1.0;
}

typedef struct _VipsForeignLoadQoiFile {
	VipsForeignLoadQoi parent_object;

	char *filename;

} VipsForeignLoadQoiFile;

typedef VipsForeignLoadQoiClass VipsForeignLoadQoiFileClass;

G_DEFINE_TYPE( VipsForeignLoadQoiFile, vips_foreign_load_qoi_file, 
	vips_foreign_load_qoi_get_type() );

static gboolean
vips_foreign_load_qoi_file_is_a( const char *filename )
{
	VipsSource *source;
	gboolean result;

	if( !(source = vips_source_new_from_file( filename )) )
		return( FALSE );
	result = vips_foreign_load_qoi_is_a_source( source );
	VIPS_UNREF( source );

	return( result );
}

static int
vips_foreign_load_qoi_file_build( VipsObject *object )
{
	VipsForeignLoadQoiFile *file = (VipsForeignLoadQoiFile *) object;
	VipsForeignLoadQoi *qoi = (VipsForeignLoadQoi *) object;

	if( file->filename &&
		!(qoi->source = vips_source_new_from_file( file->filename )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_foreign_load_qoi_file_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_qoi_file_class_init( VipsForeignLoadQoiClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "qoiload";
	object_class->description = _( "load qoi from file" );
	object_class->build = vips_foreign_load_qoi_file_build;

	load_class->is_a = vips_foreign_load_qoi_file_is_a;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadQoiFile, filename ),
		NULL );
}

static void
vips_foreign_load_qoi_file_init( VipsForeignLoadQoiFile *file )
{
}

typedef struct _VipsForeignLoadQoiSource {
	VipsForeignLoadQoi parent_object;

	VipsSource *source;

} VipsForeignLoadQoiSource;

typedef VipsForeignLoadQoiClass VipsForeignLoadQoiSourceClass;

G_DEFINE_TYPE( VipsForeignLoadQoiSource, vips_foreign_load_qoi_source,
	vips_foreign_load_qoi_get_type() );

static int
vips_foreign_load_qoi_source_build( VipsObject *object )
{
	VipsForeignLoadQoi *qoi = (VipsForeignLoadQoi *) object;
	VipsForeignLoadQoiSource *source = (VipsForeignLoadQoiSource *) object;

	if( source->source ) {
		qoi->source = source->source;
		g_object_ref( qoi->source );
	}

	if( VIPS_OBJECT_CLASS( vips_foreign_load_qoi_source_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_foreign_load_qoi_source_class_init( VipsForeignLoadQoiFileClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignLoadClass *load_class = (VipsForeignLoadClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "qoiload_source";
	object_class->build = vips_foreign_load_qoi_source_build;

	operation_class->flags = VIPS_OPERATION_NOCACHE;

	load_class->is_a_source = vips_foreign_load_qoi_is_a_source;

	VIPS_ARG_OBJECT( class, "source", 1,
		_( "Source" ),
		_( "Source to load from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignLoadQoiSource, source ),
		VIPS_TYPE_SOURCE );

}

static void
vips_foreign_load_qoi_source_init( VipsForeignLoadQoiSource *source )
{
}

/**
 * vips_qoiload:
 * @filename: file to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Read a QOI image. Images are RGB or RGBA, 8 bits.
 *
 * See also: vips_image_new_from_file().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_qoiload( const char *filename, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "qoiload", ap, filename, out ); 
	va_end( ap );

	return( result );
}

/**
 * vips_qoiload_source:
 * @source: source to load
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Exactly as vips_qoiload(), but read from a source. 
 *
 * See also: vips_qoiload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_qoiload_source( VipsSource *source, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "qoiload_source", ap, source, out ); 
	va_end( ap );

	return( result );
}
