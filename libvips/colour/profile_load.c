/* Load profiles as blobs. 
 *
 * 10/1/19
 *      - from CMYK2XYZ.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>

#include <stdio.h>
#include <math.h>

#include <vips/internal.h>

#include "profiles.h"
#include "pcolour.h"

typedef struct _VipsProfileLoad {
	VipsOperation parent_instance;

	const char *name;
	VipsBlob *profile;

} VipsProfileLoad;

typedef VipsOperationClass VipsProfileLoadClass;

G_DEFINE_TYPE( VipsProfileLoad, vips_profile_load, VIPS_TYPE_OPERATION );

static const void *
vips_profile_fallback_get( const char *name, size_t *length )
{
	int i;
	VipsProfileFallback *fallback;

	for( i = 0; (fallback = vips__profile_fallback_table[i]); i++ ) 
		if( g_ascii_strcasecmp( fallback->name, name ) == 0 ) {
			void *data;
			GConverter *converter;
			GConverterResult res;
			gsize bytes_read;
			gsize bytes_written;

			data = g_malloc0( fallback->length );
			converter = G_CONVERTER( g_zlib_decompressor_new(
				G_ZLIB_COMPRESSOR_FORMAT_ZLIB ) );

			res = g_converter_convert( converter,
				fallback->data, fallback->length,
				data, fallback->length,
				G_CONVERTER_INPUT_AT_END,
				&bytes_read, &bytes_written, NULL );
			g_object_unref( converter );

			if( res == G_CONVERTER_FINISHED ) {
				*length = fallback->length;
				return( data );
			} else {
				g_free( data );
				g_warning( "fallback profile "
					"decompression failed" );
			}
		}

	return( NULL );
}

static int
vips_profile_load_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsProfileLoad *load = (VipsProfileLoad *) object;

	size_t length;
	const void *data;
	VipsBlob *profile; 

	if( VIPS_OBJECT_CLASS( vips_profile_load_parent_class )->
		build( object ) )
		return( -1 );

	if( g_ascii_strcasecmp( load->name, "none" ) == 0 ) 
		profile = NULL;
	else if( (data = vips_profile_fallback_get( load->name, &length )) ) 
		profile = vips_blob_new(
			(VipsCallbackFn) vips_area_free_cb, data, length );
	else if( (data = vips__file_read_name( load->name, 
		vips__icc_dir(), &length )) ) 
		profile = vips_blob_new( 
			(VipsCallbackFn) vips_area_free_cb, data, length );
	else {
		vips_error( class->nickname, 
			_( "unable to load profile \"%s\"" ), load->name );
		return( -1 );
	}

	g_object_set( object, "profile", profile, NULL ); 

	if( profile ) {
		vips_area_unref( (VipsArea *) profile );
		profile = NULL;
	}

	return( 0 );
}

static void
vips_profile_load_class_init( VipsProfileLoadClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "profile_load";
	object_class->description = _( "load named ICC profile" );
	object_class->build = vips_profile_load_build;

	VIPS_ARG_STRING( class, "name", 1, 
		_( "Name" ), 
		_( "Profile name" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsProfileLoad, name ), 
		NULL );

	VIPS_ARG_BOXED( class, "profile", 2, 
		_( "Profile" ), 
		_( "Loaded profile" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsProfileLoad, profile ), 
		VIPS_TYPE_BLOB );

}

static void
vips_profile_load_init( VipsProfileLoad *load )
{
}

/**
 * vips_profile_load: 
 * @name: name of profile to load
 * @profile: (out): loaded profile
 * @...: %NULL-terminated list of optional named arguments
 *
 * Load a named profile. 
 *
 * Profiles are loaded from four sources:
 *
 * - The special name `"none"` means no profile. @profile will be %NULL in this
 *   case.
 *
 * - @name can be the name of one of the ICC profiles embedded in libvips.
 *   These names can be at least `"cmyk"`, `"p3"` and `"srgb"`.
 *
 * - @name can be the full path to a file.
 *
 * - @name can be the name of an ICC profile in the system profile directory
 *   for your platform.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_profile_load( const char *name, VipsBlob **profile, ... )
{
	va_list ap;
	int result;

	va_start( ap, profile );
	result = vips_call_split( "profile_load", ap, name, profile );
	va_end( ap );

	return( result );
}

/* Set (or remove) a named profile on an image. 
 */
int
vips__profile_set( VipsImage *image, const char *name )
{
	VipsBlob *profile;

	if( vips_profile_load( name, &profile, NULL ) ) 
		return( -1 );

	if( profile ) {
		GValue value = { 0 };

		g_value_init( &value, VIPS_TYPE_BLOB );
		g_value_set_boxed( &value, profile );
		vips_image_set( image, VIPS_META_ICC_NAME, &value );
		g_value_unset( &value );
	}
	else 
		vips_image_remove( image, VIPS_META_ICC_NAME );

	if( profile ) {
		vips_area_unref( (VipsArea *) profile );
		profile = NULL;
	}

	return( 0 );
}
