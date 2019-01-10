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

/* Created on first use from a base64 string in profiles.c.
 */
typedef struct _VipsFallbackProfile {
	const char *name;
	void *data;
	size_t data_length;
} VipsFallbackProfile;

static GSList *vips_fallback_profile_list = NULL;

static void *
vips_fallback_profile_get_init( void )
{
	int i;

	for( i = 0; vips__coded_profiles[i].name; i++ ) {
		size_t data_length;
		unsigned char *data;
		VipsFallbackProfile *fallback;

		if( !(data = vips__b64_decode( 
			vips__coded_profiles[i].data, &data_length )) )
			return( NULL );
		fallback = g_new( VipsFallbackProfile,1 );
		fallback->name = vips__coded_profiles[i].name;
		fallback->data = data;
		fallback->data_length = data_length;
		vips_fallback_profile_list = g_slist_prepend( 
			vips_fallback_profile_list, fallback );
	}

	return( NULL );
}

static void *
vips_fallback_profile_get( const char *name, size_t *length )
{
	GOnce once = G_ONCE_INIT;

	GSList *p;

	VIPS_ONCE( &once, (GThreadFunc) vips_fallback_profile_get_init, NULL );

	for( p = vips_fallback_profile_list; p; p = p->next ) {
		VipsFallbackProfile *fallback = (VipsFallbackProfile *) p->data;

		if( strcasecmp( fallback->name, name ) == 0 ) {
			*length = fallback->data_length;

			return( fallback->data );
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

	if( strcasecmp( load->name, "none" ) == 0 ) {
		profile = NULL;
	}
	else if( (data = vips_fallback_profile_get( load->name, &length )) ) {
		profile = vips_blob_new( NULL, data, length );
	}
	else if( (data = vips__file_read_name( load->name, 
		vips__icc_dir(), &length )) ) {
		profile = vips_blob_new( NULL, data, length );
	}
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
 * Load a named profile. If the name is one of the built in ICC profiles, then
 * that is returmed, otherwise a profile is loaded from the system profile
 * area.
 *
 * The special name "none" will make this operation return NULL for @profile.
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
	void *data;
	size_t length;

	if( vips_profile_load( name, &profile, NULL ) ) 
		return( -1 );

	if( profile ) { 
		data = ((VipsArea *) profile)->data;
		length = ((VipsArea *) profile)->length;
		vips_image_set_blob( image, VIPS_META_ICC_NAME, 
			(VipsCallbackFn) NULL, data, length );
	}
	else 
		vips_image_remove( image, VIPS_META_ICC_NAME );

	if( profile ) {
		vips_area_unref( (VipsArea *) profile );
		profile = NULL;
	}

	return( 0 );
}
