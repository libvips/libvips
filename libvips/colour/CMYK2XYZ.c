/* Use lcms to move from CMYK to XYZ, if we can. This needs a working
 * vips_icc_import.
 *
 * 21/12/18
 *      - from scRGB2XYZ.c
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

#ifdef HAVE_LCMS2

#include <stdio.h>
#include <math.h>

#include <vips/internal.h>

#include "profiles.h"
#include "pcolour.h"

typedef struct _VipsCMYK2XYZ {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
} VipsCMYK2XYZ;

typedef VipsColourCodeClass VipsCMYK2XYZClass;

G_DEFINE_TYPE( VipsCMYK2XYZ, vips_CMYK2XYZ, VIPS_TYPE_OPERATION );

/* Created on first use from a base64 string in profiles.c.
 */
typedef struct _VipsFallbackProfile {
	const char *name;
	void *data;
	size_t data_length;
} VipsFallbackProfile;

static GSList *vips_fallback_profile_list = NULL;

static void *
vips__fallback_profile_get_init( void )
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
		vips_fallback_profile_list = g_slist_append( 
			vips_fallback_profile_list, fallback );
	}

	return( NULL );
}

/* Shared with icc_transform.c
 */
void *
vips__fallback_profile_get( const char *name, size_t *length )
{
	GOnce once = G_ONCE_INIT;

	GSList *p;

	VIPS_ONCE( &once, (GThreadFunc) vips__fallback_profile_get_init, NULL );

	for( p = vips_fallback_profile_list; p; p = p->next ) {
		VipsFallbackProfile *fallback = (VipsFallbackProfile *) p->data;

		if( strcasecmp( fallback->name, name ) == 0 ) {
			*length = fallback->data_length;

			return( fallback->data );
		}
	}

	return( NULL );
}

/* Shared with XYZ2CMYK.c.
 */
int
vips__fallback_profile_set( const char *name, VipsImage *image )
{
	size_t data_length;
	unsigned char *data;

	/* Already a profile? Do nothing. We could remove and replace non-CMYK
	 * profiles I guess.
	 */
	if( vips_image_get_typeof( image, VIPS_META_ICC_NAME ) )
		return( 0 );

	if( !(data = vips__fallback_profile_get( name, &data_length )) ) {
		vips_error( "fallback", 
			_( "unknown fallback profile \"%s\"" ), name ); 
		return( -1 );
	}

	vips_image_set_blob( image, VIPS_META_ICC_NAME,
		NULL, data, data_length );

	return( 0 );
}

/* Our actual processing, as a VipsColourTransformFn.
 */
static int
vips_CMYK2XYZ_process( VipsImage *in, VipsImage **out, ... )
{
	return( vips_icc_import( in, out,
		"embedded", TRUE,
		"pcs", VIPS_PCS_XYZ,
		NULL ) );
}

static int
vips_CMYK2XYZ_build( VipsObject *object )
{
	VipsCMYK2XYZ *CMYK2XYZ = (VipsCMYK2XYZ *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *out; 

	if( VIPS_OBJECT_CLASS( vips_CMYK2XYZ_parent_class )->build( object ) )
		return( -1 );

	out = vips_image_new();
	g_object_set( object, "out", out, NULL ); 

	if( vips_copy( CMYK2XYZ->in, &t[0], NULL ) ||
		vips__fallback_profile_set( "cmyk", t[0] ) ||
		vips__colourspace_process_n( "CMYK2XYZ", 
			t[0], &t[1], 4, vips_CMYK2XYZ_process ) ||
		vips_image_write( t[1], out ) )
		return( -1 );

	return( 0 );
}

static void
vips_CMYK2XYZ_class_init( VipsCMYK2XYZClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "CMYK2XYZ";
	object_class->description = _( "transform CMYK to XYZ" );
	object_class->build = vips_CMYK2XYZ_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsCMYK2XYZ, in ) );

	VIPS_ARG_IMAGE( class, "out", 100, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsCMYK2XYZ, out ) );

}

static void
vips_CMYK2XYZ_init( VipsCMYK2XYZ *CMYK2XYZ )
{
}

#endif /*HAVE_LCMS2*/

/**
 * vips_CMYK2XYZ: (method)
 * @in: input image
 * @out: (out): output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Turn CMYK to XYZ. If the image has an embedded ICC profile this will be
 * used for the conversion. If there is no embedded profile, a generic
 * fallback profile will be used. 
 *
 * Conversion is to D65 XYZ with relative intent. If you need more control 
 * over the process, use vips_icc_import() instead.
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_CMYK2XYZ( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "CMYK2XYZ", ap, in, out );
	va_end( ap );

	return( result );
}
